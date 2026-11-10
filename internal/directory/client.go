package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/lauritsk/sambatui/internal/auth"
)

type Config struct {
	Server, BaseDN, User, Encryption, Auth, Cache, KerberosConfig, CAFile string
	Password, CacheContents                                               auth.Secret
	PageSize                                                              uint32
	Timeout                                                               time.Duration
}

func (c Config) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "LDAPConfig{DC:%q, Auth:%q, credentials:[redacted]}", c.Server, c.Auth)
}

func (c Client) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "LDAPClient{DC:%q, credentials:[redacted]}", c.cfg.Server)
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
		cfg     Config
		connect Factory
	}
)

func New(cfg Config) *Client                       { return NewWithFactory(cfg, Dial) }
func NewWithFactory(cfg Config, f Factory) *Client { return &Client{cfg, f} }

func Endpoint(cfg Config) (host, address string, err error) {
	if cfg.Encryption != "ldaps" && cfg.Encryption != "starttls" {
		return "", "", errors.New("LDAP requires certificate-verified ldaps or starttls")
	}
	if cfg.Server == "" {
		return "", "", errors.New("select an individual DC hostname")
	}
	raw := cfg.Server
	if !strings.Contains(raw, "://") {
		raw = map[string]string{"ldaps": "ldaps://", "starttls": "ldap://"}[cfg.Encryption] + raw
	}
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("invalid LDAP DC endpoint")
	}
	if (u.Scheme == "ldap" && cfg.Encryption != "starttls") || (u.Scheme == "ldaps" && cfg.Encryption != "ldaps") || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
		return "", "", errors.New("LDAP URL and TLS mode must agree")
	}
	host = u.Hostname()
	if host == "" {
		return "", "", errors.New("missing LDAP hostname")
	}
	port := u.Port()
	if port == "" {
		if cfg.Encryption == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 1 || p > 65535 {
		return "", "", errors.New("invalid LDAP port")
	}
	return host, net.JoinHostPort(host, port), nil
}

func Dial(ctx context.Context, cfg Config) (Session, error) {
	host, address, err := Endpoint(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	tlsConfig, err := dialTLSConfig(cfg, host)
	if err != nil {
		return nil, err
	}
	conn, err := dialTLS(ctx, cfg, address, tlsConfig)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	session, err := dialBind(ctx, cfg, host, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return session, nil
}

func dialTLSConfig(cfg Config, host string) (*tls.Config, error) {
	certificates, err := x509.SystemCertPool()
	if err != nil {
		certificates = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		data, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		if !certificates.AppendCertsFromPEM(data) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	return &tls.Config{
		ServerName: host, RootCAs: certificates, MinVersion: tls.VersionTLS12,
	}, nil
}

func dialTLS(
	ctx context.Context, cfg Config, address string, tlsConfig *tls.Config,
) (*tls.Conn, error) {
	raw, err := (&net.Dialer{Timeout: cfg.Timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()

	// Bound StartTLS and handshake as well as application requests. Never bind
	// before certificate verification; deadline failures must fail closed.
	if err = raw.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return nil, err
	}
	if cfg.Encryption == "starttls" {
		if err = startTLS(raw); err != nil {
			return nil, fmt.Errorf("LDAP StartTLS: %w", err)
		}
	}
	conn := tls.Client(raw, tlsConfig)
	if err = conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("LDAP TLS certificate verification/handshake: %w", err)
	}
	if len(conn.ConnectionState().VerifiedChains) == 0 {
		return nil, errors.New("LDAP TLS certificate not verified")
	}
	success = true
	return conn, nil
}

func dialBind(ctx context.Context, cfg Config, host string, conn *tls.Conn) (Session, error) {
	var binding []byte
	var err error
	if cfg.Auth == "kerberos" || strings.Contains(cfg.User, `\`) {
		binding, err = auth.ChannelBinding(conn.ConnectionState().PeerCertificates[0])
		if err != nil {
			return nil, err
		}
	}
	ntlmBound := false
	if (cfg.Auth == "" || cfg.Auth == "password") && strings.Contains(cfg.User, `\`) {
		if cfg.Password.Reveal() == "" {
			return nil, errors.New("LDAP requires a nonempty password")
		}
		if err = bindNTLM(ctx, conn, cfg.User, cfg.Password, "ldap/"+host, binding); err != nil {
			return nil, fmt.Errorf("LDAP NTLM bind: %w", err)
		}
		ntlmBound = true
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	session := ldap.NewConn(conn, true)
	session.SetTimeout(cfg.Timeout)
	session.Start()
	switch cfg.Auth {
	case "", "password":
		if cfg.Password.Reveal() == "" || cfg.User == "" {
			err = errors.New("LDAP requires username and nonempty password")
		} else if !ntlmBound {
			err = session.Bind(cfg.User, cfg.Password.Reveal())
		}
	case "kerberos":
		var kerberos *auth.Kerberos
		kerberos, err = auth.NewKerberos(
			ctx, cfg.Cache, cfg.KerberosConfig, cfg.CacheContents, binding, cfg.Timeout,
		)
		if err == nil {
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

func (c *Client) with(ctx context.Context, f func(Session) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	s, e := c.connect(ctx, c.cfg)
	if e != nil {
		return e
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	return f(s)
}

func (c *Client) Check(ctx context.Context) error {
	return c.with(ctx, func(Session) error { return nil })
}

var (
	Attributes = []string{"cn", "name", "sAMAccountName", "userPrincipalName", "displayName", "description", "mail", "memberOf", "member", "objectClass", "distinguishedName", "userAccountControl", "lastLogonTimestamp", "lastLogon", "whenCreated", "whenChanged", "uSNChanged", "pwdLastSet", "accountExpires", "primaryGroupID", "dNSHostName", "servicePrincipalName", "proxyAddresses"}
	filters    = map[string]string{
		"users": "(&(objectCategory=person)(objectClass=user))", "groups": "(objectCategory=group)", "computers": "(objectCategory=computer)", "ous": "(objectClass=organizationalUnit)",
		"all":        "(|(&(objectCategory=person)(objectClass=user))(objectCategory=group)(objectCategory=computer)(objectClass=organizationalUnit))",
		"containers": "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))",
	}
)

func Filter(kind, text string) (string, error) {
	base, ok := filters[kind]
	if !ok {
		return "", errors.New("LDAP search kind must be users, groups, computers, ous, all or containers")
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return base, nil
	}
	needle := ldap.EscapeFilter(text)
	var b strings.Builder
	b.WriteString("(&" + base + "(|")
	for _, a := range []string{"cn", "name", "sAMAccountName", "userPrincipalName", "displayName", "mail", "proxyAddresses", "dNSHostName", "distinguishedName"} {
		b.WriteString("(" + a + "=*" + needle + "*)")
	}
	b.WriteString("))")
	return b.String(), nil
}

type Entry struct {
	DN, Kind, Name, Revision string
	Attributes               map[string][]string
}

func (e Entry) First(name string) string {
	v := e.Attributes[strings.ToLower(name)]
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

func normalize(e *ldap.Entry) Entry {
	out := Entry{DN: e.DN, Attributes: map[string][]string{}}
	for _, a := range e.Attributes {
		key := strings.ToLower(a.Name)
		out.Attributes[key] = append(out.Attributes[key], a.Values...)
	}
	classes := out.Attributes["objectclass"]
	out.Kind = "object"
	for _, k := range []string{"user", "group", "computer", "organizationalUnit"} {
		for _, v := range classes {
			if strings.EqualFold(v, k) {
				out.Kind = k
			}
		}
	}
	if out.Kind == "organizationalUnit" {
		out.Kind = "ou"
	}
	out.Name = out.First("name")
	if out.Name == "" {
		out.Name = out.First("cn")
	}
	if v := out.Attributes["usnchanged"]; len(v) == 1 && decimal(v[0]) {
		out.Revision = v[0]
	}
	return out
}

const (
	searchRowsMax     = 5000
	searchPagesMax    = 10000
	searchPageDefault = 200
)

func (c *Client) Search(ctx context.Context, base, kind, text string, limit int) ([]Entry, error) {
	if limit < 0 || limit > searchRowsMax {
		return nil, fmt.Errorf("LDAP row limit must be 0–%d", searchRowsMax)
	}
	if base == "" {
		base = c.cfg.BaseDN
	}
	if !InScope(base, c.cfg.BaseDN) {
		return nil, errors.New("LDAP search base outside configured scope")
	}
	filter, err := Filter(kind, text)
	if err != nil {
		return nil, err
	}
	scope := ldap.ScopeWholeSubtree
	if kind == "containers" {
		scope = ldap.ScopeSingleLevel
	}
	pageSize := c.cfg.PageSize
	if pageSize == 0 {
		pageSize = searchPageDefault
	}
	if pageSize > searchRowsMax {
		return nil, errors.New("LDAP page size exceeds read safety limit")
	}
	request := ldap.NewSearchRequest(
		base, scope, ldap.NeverDerefAliases, 0, 0, false, filter,
		append([]string(nil), Attributes...), nil,
	)
	var rows []Entry
	err = c.with(ctx, func(session Session) error {
		var err error
		rows, err = searchPages(ctx, session, request, pageSize, limit)
		return err
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func searchPages(
	ctx context.Context, session Session, request *ldap.SearchRequest, pageSize uint32, limit int,
) ([]Entry, error) {
	control := ldap.NewControlPaging(pageSize)
	request.Controls = []ldap.Control{
		control, ldap.NewControlString(ldap.ControlTypeMicrosoftDomainScope, true, ""),
	}
	rows := []Entry{}
	for page := 0; page < searchPagesMax; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := session.Search(request)
		if err != nil {
			return nil, fmt.Errorf("LDAP search: %w", err)
		}
		if result == nil {
			return nil, errors.New("LDAP search returned no result")
		}
		if len(result.Referrals) > 0 {
			return nil, errors.New("LDAP search returned referrals; select the appropriate individual DC")
		}
		for _, entry := range result.Entries {
			if entry == nil || !InScope(entry.DN, request.BaseDN) {
				return nil, errors.New("LDAP server returned an entry outside the selected search scope")
			}
			// A zero caller limit requests a complete result, not unbounded memory.
			if len(rows) == searchRowsMax {
				return nil, errors.New("LDAP search exceeds read safety limit; no partial result returned")
			}
			if err := expandRanges(ctx, session, entry); err != nil {
				return nil, err
			}
			rows = append(rows, normalize(entry))
			if limit > 0 && len(rows) == limit {
				return rows, nil
			}
		}
		paging := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if paging == nil {
			return rows, nil
		}
		next, ok := paging.(*ldap.ControlPaging)
		if !ok || next == nil {
			return nil, errors.New("LDAP malformed paging control")
		}
		if len(next.Cookie) == 0 {
			return rows, nil
		}
		// Cookies are opaque: Samba may reuse the same handle on successive pages.
		control.SetCookie(append([]byte(nil), next.Cookie...))
	}
	return nil, fmt.Errorf("LDAP paging exceeds %d pages", searchPagesMax)
}
