package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/privatefile"
)

type Settings struct {
	Server          string      `json:"server"`
	Domain          string      `json:"domain"`
	LastZone        string      `json:"last_zone"`
	User            string      `json:"user"`
	Auth            string      `json:"auth"`
	DNSAuth         string      `json:"dns_password_auth"`
	Cache           string      `json:"cache"`
	KerberosConfig  string      `json:"kerberos_config"`
	BaseDN          string      `json:"base_dn"`
	Encryption      string      `json:"encryption"`
	CAFile          string      `json:"ca_file"`
	PasswordFile    string      `json:"password_file"`
	AutoPTR         string      `json:"auto_ptr"`
	Days            int         `json:"days"`
	DisabledDays    int         `json:"disabled_days"`
	NeverLoggedDays int         `json:"never_logged_days"`
	MaxRows         int         `json:"max_rows"`
	LDAPMaxRows     int         `json:"ldap_max_rows"`
	TimeoutSeconds  int         `json:"timeout_seconds"`
	Password        auth.Secret `json:"-"`
	CacheContents   auth.Secret `json:"-"`
	CacheIdentity   string      `json:"-"`
}

func (s Settings) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "Settings{DC:%q, Auth:%q, TLS:%q, credentials:[redacted]}", s.Server, s.Auth, s.Encryption)
}

func Defaults() Settings {
	return Settings{Auth: "password", DNSAuth: "ntlm", Encryption: "ldaps", AutoPTR: "ask", Days: 90, DisabledDays: 180, NeverLoggedDays: 30, MaxRows: 500, LDAPMaxRows: 200, TimeoutSeconds: 10}
}

func DefaultPath() (string, error) {
	dir, e := os.UserConfigDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(dir, "sambatui", "config.json"), nil
}

func Load(path string, env func(string) (string, bool)) (Settings, error) {
	cfg := Defaults()
	b, e := os.ReadFile(path)
	if e == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if e = dec.Decode(&cfg); e != nil {
			return cfg, fmt.Errorf("invalid configuration: %w", e)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return cfg, e
	}
	vars := map[string]*string{"SERVER": &cfg.Server, "DOMAIN": &cfg.Domain, "ZONE": &cfg.LastZone, "USER": &cfg.User, "AUTH": &cfg.Auth, "DNS_PASSWORD_AUTH": &cfg.DNSAuth, "KRB5_CCACHE": &cfg.Cache, "KRB5_CONFIG": &cfg.KerberosConfig, "LDAP_BASE": &cfg.BaseDN, "LDAP_ENCRYPTION": &cfg.Encryption, "CA_FILE": &cfg.CAFile, "PASSWORD_FILE": &cfg.PasswordFile, "AUTO_PTR": &cfg.AutoPTR}
	for name, dst := range vars {
		if v, ok := env("SAMBATUI_" + name); ok {
			*dst = v
		}
	}
	_, explicitCache := env("SAMBATUI_KRB5_CCACHE")
	if cfg.Cache == "" && !explicitCache {
		cfg.Cache, _ = env("KRB5CCNAME")
	}
	if cfg.PasswordFile == "" {
		cfg.PasswordFile = filepath.Join(filepath.Dir(path), "password")
	}
	if cfg.BaseDN == "" && cfg.Domain != "" {
		cfg.BaseDN = "DC=" + strings.ReplaceAll(strings.TrimSuffix(cfg.Domain, "."), ".", ",DC=")
	}
	if value, ok := env("SAMBATUI_PASSWORD"); ok {
		cfg.Password = auth.NewSecret(value)
	} else {
		password, e := ReadPassword(cfg.PasswordFile)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return cfg, e
		}
		cfg.Password = auth.NewSecret(password)
	}
	if e := cfg.Validate(false); e != nil {
		return cfg, e
	}
	return cfg.Freeze()
}

func (s Settings) Validate(connection bool) error {
	if s.Auth != "password" && s.Auth != "kerberos" {
		return errors.New("auth must be password or kerberos")
	}
	if s.DNSAuth != "ntlm" && s.DNSAuth != "kerberos" {
		return errors.New("dns_password_auth must be ntlm or kerberos; no automatic authentication downgrade")
	}
	if s.Encryption != "ldaps" && s.Encryption != "starttls" {
		return errors.New("LDAP encryption must be ldaps or starttls; certificate verification cannot be disabled")
	}
	if s.AutoPTR != "off" && s.AutoPTR != "ask" && s.AutoPTR != "on" {
		return errors.New("auto_ptr must be off, ask or on")
	}
	if s.TimeoutSeconds < 1 || s.TimeoutSeconds > 300 {
		return errors.New("timeout_seconds must be 1–300")
	}
	if s.Days < 1 || s.Days > 100000 || s.DisabledDays < 1 || s.DisabledDays > 100000 || s.NeverLoggedDays < 1 || s.NeverLoggedDays > 100000 || s.MaxRows < 1 || s.MaxRows > 5000 || s.LDAPMaxRows < 1 || s.LDAPMaxRows > 5000 {
		return errors.New("day thresholds must be 1–100000; max_rows and ldap_max_rows must be 1–5000")
	}
	if !connection {
		return nil
	}
	if _, _, e := directory.Endpoint(s.LDAP()); e != nil {
		return e
	}
	if s.BaseDN == "" || !directory.InScope(s.BaseDN, s.BaseDN) {
		return errors.New("valid LDAP base DN required")
	}
	if s.Auth == "password" && (s.User == "" || s.Password.Reveal() == "") {
		return errors.New("enter username and password")
	}
	if s.Auth == "kerberos" {
		path, e := auth.CachePath(s.Cache)
		if e != nil {
			return e
		}
		if _, e = os.Stat(path); e != nil && s.CacheContents.Reveal() == "" {
			return fmt.Errorf("selected Kerberos cache: %w", e)
		}
	}
	return nil
}

func (s Settings) Freeze() (Settings, error) {
	s.CacheContents = auth.Secret{}
	s.CacheIdentity = ""
	if s.Auth == "kerberos" {
		blob, identity, e := auth.CacheSnapshot(s.Cache)
		if e != nil {
			return s, e
		}
		s.CacheContents = blob
		s.CacheIdentity = identity
	}
	return s, nil
}

func (s Settings) LDAP() directory.Config {
	return directory.Config{Server: s.Server, BaseDN: s.BaseDN, User: s.User, Password: s.Password, Encryption: s.Encryption, Auth: s.Auth, Cache: s.Cache, CacheContents: s.CacheContents, KerberosConfig: s.KerberosConfig, CAFile: s.CAFile, PageSize: 200, Timeout: time.Duration(s.TimeoutSeconds) * time.Second}
}

func (s Settings) DNS() dnsrpc.Config {
	host, _, e := directory.Endpoint(s.LDAP())
	if e != nil {
		host = s.Server
	}
	return dnsrpc.Config{Server: host, User: s.User, Password: dnsrpc.NewPassword(s.Password.Reveal()), Auth: s.Auth, PasswordAuth: s.DNSAuth, Cache: s.Cache, CacheContents: s.CacheContents, KerberosConfig: s.KerberosConfig, Timeout: time.Duration(s.TimeoutSeconds) * time.Second}
}

func Save(path string, s Settings) error {
	if e := s.Validate(false); e != nil {
		return e
	}
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	return PrivateWrite(path, append(b, '\n'))
}

func SavePassword(path string, password auth.Secret) error {
	if strings.ContainsAny(password.Reveal(), "\r\n") {
		return errors.New("password files support one line only")
	}
	return PrivateWrite(path, []byte(password.Reveal()+"\n"))
}

func ReadPassword(path string) (string, error) {
	f, e := privatefile.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	// Only the first line, without its line ending. All other whitespace is data.
	line, e := bufio.NewReader(io.LimitReader(f, (1<<20)+1)).ReadString('\n')
	if e != nil && !errors.Is(e, io.EOF) {
		return "", e
	}
	if len(line) > 1<<20 {
		return "", errors.New("password first line exceeds 1 MiB")
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func PrivateWrite(path string, b []byte) error {
	parent := filepath.Dir(path)
	if e := os.MkdirAll(parent, 0o700); e != nil {
		return e
	}
	f, e := os.CreateTemp(parent, ".sambatui-*")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	if e = f.Chmod(0o600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(temp, path); e != nil {
		return e
	}
	dir, e := os.Open(parent)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
