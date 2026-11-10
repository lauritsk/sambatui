package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

const (
	configBytesMax       = 1 << 20
	passwordLineBytesMax = 1 << 20
)

type Settings struct {
	Server         string      `json:"server"`
	Domain         string      `json:"domain"`
	LastZone       string      `json:"last_zone"`
	User           string      `json:"user"`
	Auth           string      `json:"auth"`
	DNSAuth        string      `json:"dns_password_auth"`
	Cache          string      `json:"cache"`
	KerberosConfig string      `json:"kerberos_config"`
	BaseDN         string      `json:"base_dn"`
	Encryption     string      `json:"encryption"`
	CAFile         string      `json:"ca_file"`
	PasswordFile   string      `json:"password_file"`
	AutoPTR        string      `json:"auto_ptr"`
	LDAPMaxRows    int         `json:"ldap_max_rows"`
	TimeoutSeconds int32       `json:"timeout_seconds"`
	Password       auth.Secret `json:"-"`
	CacheContents  auth.Secret `json:"-"`
	CacheIdentity  string      `json:"-"`
}

func (settings Settings) Format(state fmt.State, verb rune) {
	fmt.Fprintf(
		state,
		"Settings{DC:%q, Auth:%q, TLS:%q, credentials:[redacted]}",
		settings.Server,
		settings.Auth,
		settings.Encryption,
	)
}

func Defaults() Settings {
	return Settings{
		Auth:           "password",
		DNSAuth:        "ntlm",
		Encryption:     "ldaps",
		AutoPTR:        "ask",
		LDAPMaxRows:    200,
		TimeoutSeconds: 10,
	}
}

func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sambatui", "config.json"), nil
}

func Load(path string, env func(string) (string, bool)) (Settings, error) {
	if env == nil {
		panic("configuration loading requires an environment lookup")
	}
	settings := Defaults()
	if err := loadFile(path, &settings); err != nil {
		return settings, err
	}
	vars := map[string]*string{
		"SERVER":            &settings.Server,
		"DOMAIN":            &settings.Domain,
		"ZONE":              &settings.LastZone,
		"USER":              &settings.User,
		"AUTH":              &settings.Auth,
		"DNS_PASSWORD_AUTH": &settings.DNSAuth,
		"KRB5_CCACHE":       &settings.Cache,
		"KRB5_CONFIG":       &settings.KerberosConfig,
		"LDAP_BASE":         &settings.BaseDN,
		"LDAP_ENCRYPTION":   &settings.Encryption,
		"CA_FILE":           &settings.CAFile,
		"PASSWORD_FILE":     &settings.PasswordFile,
		"AUTO_PTR":          &settings.AutoPTR,
	}
	for name, target := range vars {
		if currentValue, ok := env("SAMBATUI_" + name); ok {
			*target = currentValue
		}
	}
	_, explicitCache := env("SAMBATUI_KRB5_CCACHE")
	if settings.Cache == "" && !explicitCache {
		settings.Cache, _ = env("KRB5CCNAME")
	}
	if settings.PasswordFile == "" {
		settings.PasswordFile = filepath.Join(filepath.Dir(path), "password")
	}
	if settings.BaseDN == "" && settings.Domain != "" {
		settings.BaseDN = "DC=" +
			strings.ReplaceAll(strings.TrimSuffix(settings.Domain, "."), ".", ",DC=")
	}
	if value, ok := env("SAMBATUI_PASSWORD"); ok {
		settings.Password = auth.NewSecret(value)
	} else {
		password, currentErr := ReadPassword(settings.PasswordFile)
		if currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) {
			return settings, currentErr
		}
		settings.Password = auth.NewSecret(password)
	}
	if currentErr := settings.Validate(false); currentErr != nil {
		return settings, currentErr
	}
	return settings.Freeze()
}

func (settings Settings) Validate(connection bool) error {
	if err := settings.validateSize(); err != nil {
		return err
	}
	if settings.Auth != "password" && settings.Auth != "kerberos" {
		return errors.New("auth must be password or kerberos")
	}
	if settings.DNSAuth != "ntlm" && settings.DNSAuth != "kerberos" {
		return errors.New(
			"dns_password_auth must be ntlm or kerberos; no automatic " +
				"authentication downgrade",
		)
	}
	if settings.Encryption != "ldaps" && settings.Encryption != "starttls" {
		return errors.New(
			"LDAP encryption must be ldaps or starttls; certificate " +
				"verification cannot be disabled",
		)
	}
	if settings.AutoPTR != "off" && settings.AutoPTR != "ask" && settings.AutoPTR != "on" {
		return errors.New("auto_ptr must be off, ask or on")
	}
	if settings.TimeoutSeconds < 1 || settings.TimeoutSeconds > 300 {
		return errors.New("timeout_seconds must be 1–300")
	}
	if settings.LDAPMaxRows < 1 || settings.LDAPMaxRows > 5000 {
		return errors.New("ldap_max_rows must be 1–5000")
	}
	if !connection {
		return nil
	}
	if _, _, currentErr := directory.Endpoint(settings.LDAP()); currentErr != nil {
		return currentErr
	}
	if settings.BaseDN == "" || !directory.InScope(settings.BaseDN, settings.BaseDN) {
		return errors.New("valid LDAP base DN required")
	}
	if settings.Auth == "password" && (settings.User == "" || settings.Password.Reveal() == "") {
		return errors.New("enter username and password")
	}
	if settings.Auth == "kerberos" {
		path, currentErr := auth.CachePath(settings.Cache)
		if currentErr != nil {
			return currentErr
		}
		if settings.CacheContents.Reveal() == "" {
			if _, currentErr = os.Stat(path); currentErr != nil {
				return fmt.Errorf("selected Kerberos cache: %w", currentErr)
			}
		}
	}
	return nil
}

func (settings Settings) Freeze() (Settings, error) {
	if err := settings.Validate(false); err != nil {
		return settings, err
	}
	settings.CacheContents = auth.Secret{}
	settings.CacheIdentity = ""
	if settings.Auth == "kerberos" {
		blob, identity, currentErr := auth.CacheSnapshot(settings.Cache)
		if currentErr != nil {
			return settings, currentErr
		}
		settings.CacheContents = blob
		settings.CacheIdentity = identity
	}
	return settings, nil
}

func (settings Settings) LDAP() directory.Config {
	return directory.Config{
		Server:         settings.Server,
		BaseDN:         settings.BaseDN,
		User:           settings.User,
		Password:       settings.Password,
		Encryption:     settings.Encryption,
		Auth:           settings.Auth,
		Cache:          settings.Cache,
		CacheContents:  settings.CacheContents,
		KerberosConfig: settings.KerberosConfig,
		CAFile:         settings.CAFile,
		PageSize:       200,
		Timeout:        time.Duration(settings.TimeoutSeconds) * time.Second,
	}
}

func (settings Settings) DNS() dnsrpc.Config {
	host, _, err := directory.Endpoint(settings.LDAP())
	if err != nil {
		host = settings.Server
	}
	return dnsrpc.Config{
		Server:         host,
		User:           settings.User,
		Password:       dnsrpc.NewPassword(settings.Password.Reveal()),
		Auth:           settings.Auth,
		PasswordAuth:   settings.DNSAuth,
		Cache:          settings.Cache,
		CacheContents:  settings.CacheContents,
		KerberosConfig: settings.KerberosConfig,
		Timeout:        time.Duration(settings.TimeoutSeconds) * time.Second,
	}
}
