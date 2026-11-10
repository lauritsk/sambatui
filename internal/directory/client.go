package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/configfile"
	"github.com/lauritsk/sambatui/internal/invariant"
)

type Config struct {
	Server, BaseDN, User, Encryption, Auth, Cache, KerberosConfig, CAFile string
	Password, CacheContents                                               auth.Secret
	PageSize                                                              uint32
	Timeout                                                               time.Duration
}

func (settings Config) Format(state fmt.State, verb rune) {
	fmt.Fprintf(
		state,
		"LDAPConfig{DC:%q, Auth:%q, credentials:[redacted]}",
		settings.Server,
		settings.Auth,
	)
}

func (client Client) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "LDAPClient{DC:%q, credentials:[redacted]}", client.settings.Server)
}

type Session interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Add(*ldap.AddRequest) error
	Modify(*ldap.ModifyRequest) error
	Del(*ldap.DelRequest) error
	Close() error
}
type (
	Factory func(context.Context, Config) (Session, error)
	Client  struct {
		settings Config
		connect  Factory
	}
)

func New(settings Config) *Client {
	return NewWithFactory(settings, Dial)
}

func NewWithFactory(settings Config, factory Factory) *Client {
	invariant.Require(factory != nil, "LDAP client requires a session factory")
	return &Client{settings: settings, connect: factory}
}

func Endpoint(settings Config) (host, address string, err error) {
	if settings.Encryption != "ldaps" && settings.Encryption != "starttls" {
		return "", "", errors.New("LDAP requires certificate-verified ldaps or starttls")
	}
	if settings.Server == "" {
		return "", "", errors.New("select an individual DC hostname")
	}
	raw := settings.Server
	if !strings.Contains(raw, "://") {
		raw = map[string]string{"ldaps": "ldaps://", "starttls": "ldap://"}[settings.Encryption] +
			raw
	}
	endpoint, currentErr := url.Parse(raw)
	if currentErr != nil {
		return "", "", errors.New("invalid LDAP DC endpoint")
	}
	if endpoint.User != nil || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", "", errors.New("invalid LDAP DC endpoint")
	}
	if (endpoint.Scheme == "ldap" && settings.Encryption != "starttls") ||
		(endpoint.Scheme == "ldaps" && settings.Encryption != "ldaps") ||
		(endpoint.Scheme != "ldap" && endpoint.Scheme != "ldaps") {
		return "", "", errors.New("LDAP URL and TLS mode must agree")
	}
	host = endpoint.Hostname()
	if host == "" {
		return "", "", errors.New("missing LDAP hostname")
	}
	port := endpoint.Port()
	if port == "" {
		if settings.Encryption == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	currentPort, currentErr := strconv.Atoi(port)
	if currentErr != nil || currentPort < 1 || currentPort > 65535 {
		return "", "", errors.New("invalid LDAP port")
	}
	return host, net.JoinHostPort(host, port), nil
}

func Dial(operationContext context.Context, settings Config) (Session, error) {
	host, address, err := Endpoint(settings)
	if err != nil {
		return nil, err
	}
	if settings.Timeout <= 0 {
		settings.Timeout = 10 * time.Second
	}
	tlsConfig, err := dialTLSConfig(settings, host)
	if err != nil {
		return nil, err
	}
	conn, err := dialTLS(operationContext, settings, address, tlsConfig)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(operationContext, func() {
		conn.Close()
	})
	defer stop()

	session, err := dialBind(operationContext, settings, host, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return session, nil
}

func dialTLSConfig(settings Config, host string) (*tls.Config, error) {
	certificates, err := x509.SystemCertPool()
	if err != nil {
		certificates = x509.NewCertPool()
	}
	if settings.CAFile != "" {
		data, err := configfile.Read(settings.CAFile, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		if !certificates.AppendCertsFromPEM(data) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	return &tls.Config{ServerName: host, RootCAs: certificates, MinVersion: tls.VersionTLS12}, nil
}

func dialTLS(
	operationContext context.Context, settings Config, address string, tlsConfig *tls.Config,
) (*tls.Conn, error) {
	raw, err := (&net.Dialer{Timeout: settings.Timeout}).DialContext(
		operationContext,
		"tcp",
		address,
	)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(operationContext, func() {
		raw.Close()
	})
	defer stop()

	// Bound StartTLS and handshake as well as application requests. Never bind
	// before certificate verification; deadline failures must fail closed.
	if err = raw.SetDeadline(time.Now().Add(settings.Timeout)); err != nil {
		return nil, err
	}
	if settings.Encryption == "starttls" {
		if err = startTLS(raw); err != nil {
			return nil, fmt.Errorf("LDAP StartTLS: %w", err)
		}
	}
	conn := tls.Client(raw, tlsConfig)
	if err = conn.HandshakeContext(operationContext); err != nil {
		return nil, fmt.Errorf("LDAP TLS certificate verification/handshake: %w", err)
	}
	if len(conn.ConnectionState().VerifiedChains) == 0 {
		return nil, errors.New("LDAP TLS certificate not verified")
	}
	success = true
	return conn, nil
}

func dialBind(
	operationContext context.Context,
	settings Config,
	host string,
	conn *tls.Conn,
) (Session, error) {
	var binding []byte
	var err error
	if settings.Auth == "kerberos" || strings.Contains(settings.User, `\`) {
		binding, err = auth.ChannelBinding(conn.ConnectionState().PeerCertificates[0])
		if err != nil {
			return nil, err
		}
	}
	ntlmBound := false
	if (settings.Auth == "" || settings.Auth == "password") &&
		strings.Contains(settings.User, `\`) {
		if settings.Password.Reveal() == "" {
			return nil, errors.New("LDAP requires a nonempty password")
		}
		if err = bindNTLM(
			operationContext,
			conn,
			settings.User,
			settings.Password,
			"ldap/"+host,
			binding,
		); err != nil {
			return nil, fmt.Errorf("LDAP NTLM bind: %w", err)
		}
		ntlmBound = true
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	session := ldap.NewConn(&framedConn{Conn: conn}, true)
	session.SetTimeout(settings.Timeout)
	session.Start()
	switch settings.Auth {
	case "", "password":
		if settings.Password.Reveal() == "" || settings.User == "" {
			err = errors.New("LDAP requires username and nonempty password")
		} else if !ntlmBound {
			err = session.Bind(settings.User, settings.Password.Reveal())
		}
	case "kerberos":
		var kerberos *auth.Kerberos
		kerberos, err = auth.NewKerberos(
			operationContext, settings.Cache, settings.KerberosConfig,
			settings.CacheContents, binding, settings.Timeout,
		)
		if err == nil {
			defer kerberos.DeleteSecContext()
			err = session.GSSAPIBind(kerberos, "ldap/"+host, "")
		}
	default:
		err = errors.New("LDAP auth must be password or kerberos")
	}
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("LDAP bind: %w", err)
	}
	return session, nil
}

func (client *Client) with(operationContext context.Context, operation func(Session) error) error {
	invariant.Require(operationContext != nil, "LDAP operation requires a context")
	invariant.Require(operation != nil, "LDAP operation requires a callback")
	if err := operationContext.Err(); err != nil {
		return err
	}
	currentSession, err := client.connect(operationContext, client.settings)
	if err != nil {
		return err
	}
	invariant.Require(currentSession != nil, "LDAP factory returned no session or error")
	defer currentSession.Close()
	stop := context.AfterFunc(operationContext, func() {
		currentSession.Close()
	})
	defer stop()
	return operation(currentSession)
}

func (client *Client) Check(operationContext context.Context) error {
	return client.with(operationContext, func(Session) error {
		return nil
	})
}

var (
	Attributes = []string{
		"cn",
		"name",
		"sAMAccountName",
		"userPrincipalName",
		"displayName",
		"description",
		"mail",
		"memberOf",
		"member",
		"objectClass",
		"distinguishedName",
		"userAccountControl",
		"lastLogonTimestamp",
		"lastLogon",
		"whenCreated",
		"whenChanged",
		"uSNChanged",
		"pwdLastSet",
		"accountExpires",
		"primaryGroupID",
		"dNSHostName",
		"servicePrincipalName",
		"proxyAddresses",
	}
	filters = map[string]string{
		"users":     "(&(objectCategory=person)(objectClass=user))",
		"groups":    "(objectCategory=group)",
		"computers": "(objectCategory=computer)",
		"ous":       "(objectClass=organizationalUnit)",
		"all": "(|(&(objectCategory=person)(objectClass=user))" +
			"(objectCategory=group)(objectCategory=computer)(objectClass=organizationalUnit))",
		"containers": "(|(objectClass=organizationalUnit)(objectClass=container)" +
			"(objectClass=builtinDomain))",
	}
)

type Entry struct {
	DN, Kind, Name, Revision string
	Attributes               map[string][]string
}

const (
	searchRowsMax     = 5000
	searchPagesMax    = 10000
	searchPageDefault = 200
)
