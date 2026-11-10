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
	host, address, e := Endpoint(cfg)
	if e != nil {
		return nil, e
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	ca, e := x509.SystemCertPool()
	if e != nil {
		ca = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		b, e := os.ReadFile(cfg.CAFile)
		if e != nil {
			return nil, fmt.Errorf("read CA certificate: %w", e)
		}
		if !ca.AppendCertsFromPEM(b) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	tc := &tls.Config{ServerName: host, RootCAs: ca, MinVersion: tls.VersionTLS12}
	raw, e := (&net.Dialer{Timeout: cfg.Timeout}).DialContext(ctx, "tcp", address)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	// Bound handshake as well as application requests. Never bind before TLS.
	raw.SetDeadline(time.Now().Add(cfg.Timeout))
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if cfg.Encryption == "starttls" {
		if e = startTLS(raw); e != nil {
			return nil, fmt.Errorf("LDAP StartTLS: %w", e)
		}
	}
	conn := tls.Client(raw, tc)
	if e = conn.HandshakeContext(ctx); e != nil {
		return nil, fmt.Errorf("LDAP TLS certificate verification/handshake: %w", e)
	}
	st := conn.ConnectionState()
	if len(st.VerifiedChains) == 0 {
		return nil, errors.New("LDAP TLS certificate not verified")
	}
	var binding []byte
	if cfg.Auth == "kerberos" || strings.Contains(cfg.User, `\`) {
		binding, e = auth.ChannelBinding(st.PeerCertificates[0])
		if e != nil {
			return nil, e
		}
	}
	ntlmBound := false
	if (cfg.Auth == "" || cfg.Auth == "password") && strings.Contains(cfg.User, `\`) {
		if cfg.Password.Reveal() == "" {
			return nil, errors.New("LDAP requires a nonempty password")
		}
		if e = bindNTLM(ctx, conn, cfg.User, cfg.Password, "ldap/"+host, binding); e != nil {
			return nil, fmt.Errorf("LDAP NTLM bind: %w", e)
		}
		ntlmBound = true
	}
	raw.SetDeadline(time.Time{})
	l := ldap.NewConn(conn, true)
	l.SetTimeout(cfg.Timeout)
	l.Start()
	switch cfg.Auth {
	case "", "password":
		if cfg.Password.Reveal() == "" || cfg.User == "" {
			e = errors.New("LDAP requires username and nonempty password")
			break
		}
		if !ntlmBound {
			e = l.Bind(cfg.User, cfg.Password.Reveal())
		}
	case "kerberos":
		var k *auth.Kerberos
		k, e = auth.NewKerberos(ctx, cfg.Cache, cfg.KerberosConfig, cfg.CacheContents, binding, cfg.Timeout)
		if e == nil {
			e = l.GSSAPIBind(k, "ldap/"+host, "")
		}
	default:
		e = errors.New("LDAP auth must be password or kerberos")
	}
	if e != nil {
		l.Close()
		return nil, fmt.Errorf("LDAP bind: %w", e)
	}
	success = true
	return l, nil
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

func (c *Client) Search(ctx context.Context, base, kind, text string, limit int) ([]Entry, error) {
	if base == "" {
		base = c.cfg.BaseDN
	}
	if !InScope(base, c.cfg.BaseDN) {
		return nil, errors.New("LDAP search base outside configured scope")
	}
	filter, e := Filter(kind, text)
	if e != nil {
		return nil, e
	}
	scope := ldap.ScopeWholeSubtree
	if kind == "containers" {
		scope = ldap.ScopeSingleLevel
	}
	rows := []Entry{}
	e = c.with(ctx, func(s Session) error {
		page := c.cfg.PageSize
		if page == 0 {
			page = 200
		}
		control := ldap.NewControlPaging(page)
		pages := 0
		for {
			if e := ctx.Err(); e != nil {
				return e
			}
			req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, append([]string(nil), Attributes...), []ldap.Control{control, ldap.NewControlString(ldap.ControlTypeMicrosoftDomainScope, true, "")})
			result, e := s.Search(req)
			if e != nil {
				return fmt.Errorf("LDAP search: %w", e)
			}
			if len(result.Referrals) > 0 {
				return errors.New("LDAP search returned referrals; no automatic referral chasing or partial-success result is allowed. Select the appropriate individual DC")
			}
			for _, entry := range result.Entries {
				if !InScope(entry.DN, base) {
					return errors.New("LDAP server returned an entry outside the selected search scope")
				}
				if e := expandRanges(ctx, s, entry); e != nil {
					return e
				}
				rows = append(rows, normalize(entry))
				if limit > 0 && len(rows) >= limit {
					return nil
				}
			}
			pc := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
			if pc == nil {
				return nil
			}
			p, ok := pc.(*ldap.ControlPaging)
			if !ok {
				return errors.New("LDAP malformed paging control")
			}
			if len(p.Cookie) == 0 {
				return nil
			}
			pages++
			if pages > 10000 {
				return errors.New("LDAP paging exceeds 10000 pages")
			}
			// Cookies are opaque: Samba may reuse the same handle on successive pages.
			control.SetCookie(append([]byte(nil), p.Cookie...))
		}
	})
	if e != nil {
		return nil, e
	}
	return rows, nil
}
