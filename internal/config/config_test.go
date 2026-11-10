package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lauritsk/sambatui/internal/auth"
)

func TestPrivatePasswordAndPreferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native", "config.json")
	cfg := Defaults()
	cfg.User = "test"
	cfg.Password = auth.NewSecret("  significant whitespace \t")
	if e := Save(path, cfg); e != nil {
		t.Fatal(e)
	}
	if e := SavePassword(filepath.Join(filepath.Dir(path), "password"), cfg.Password); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "significant") {
		t.Fatal("password leaked to preferences")
	}
	loaded, e := Load(path, func(string) (string, bool) { return "", false })
	if e != nil {
		t.Fatal(e)
	}
	if loaded.Password.Reveal() != cfg.Password.Reveal() {
		t.Fatal("password whitespace lost")
	}
	for _, p := range []string{path, filepath.Join(filepath.Dir(path), "password")} {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Fatal("credentials not private")
		}
	}
	if strings.Contains(fmt.Sprintf("%#v", loaded), "significant") {
		t.Fatal("settings debug leak")
	}
}

func TestPasswordFirstLineAndUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	if e := os.WriteFile(path, []byte("  first line \t\r\nignored\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	v, e := ReadPassword(path)
	if e != nil || v != "  first line \t" {
		t.Fatalf("%q %v", v, e)
	}
	os.Chmod(path, 0o644)
	if _, e = ReadPassword(path); e == nil {
		t.Fatal("world-readable secret loaded")
	}
	os.Chmod(path, 0o600)
	link := filepath.Join(dir, "symlink")
	os.Symlink(path, link)
	if _, e = ReadPassword(link); e == nil {
		t.Fatal("symlink secret loaded")
	}
	if _, e = ReadPassword(dir); e == nil {
		t.Fatal("directory secret loaded")
	}
}

func TestEmptyExplicitCacheDoesNotUseAmbientIdentity(t *testing.T) {
	_, e := Load(filepath.Join(t.TempDir(), "config.json"), func(k string) (string, bool) {
		switch k {
		case "SAMBATUI_AUTH":
			return "kerberos", true
		case "SAMBATUI_KRB5_CCACHE":
			return "", true
		case "KRB5CCNAME":
			return "FILE:/ambient-identity", true
		}
		return "", false
	})
	if e == nil || !strings.Contains(e.Error(), "explicit FILE") {
		t.Fatal("empty explicit selection fell back to ambient cache", e)
	}
}

func TestThresholdsCannotOverflowRemediationCutoffs(t *testing.T) {
	for _, days := range []int32{-1, 0, 100001, 1<<31 - 1} {
		s := Defaults()
		s.Days = days
		if e := s.Validate(false); e == nil {
			t.Fatal("unsafe day threshold accepted", days)
		}
	}
}

func TestDocumentedConfigurationSchema(t *testing.T) {
	cfg, e := Load("../../config.example.json", func(string) (string, bool) { return "", false })
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Password.Reveal() != "" || cfg.LDAPMaxRows != 200 || cfg.MaxRows != 500 || cfg.DNSAuth != "ntlm" {
		t.Fatal("documented defaults differ from native settings")
	}
}

func TestExplicitPasswordEnvironmentPreservesWhitespace(t *testing.T) {
	cfg, e := Load(filepath.Join(t.TempDir(), "missing.json"), func(k string) (string, bool) {
		switch k {
		case "SAMBATUI_PASSWORD":
			return "  exact \t", true
		case "SAMBATUI_KRB5_CCACHE":
			return "FILE:/selected", true
		case "KRB5CCNAME":
			return "FILE:/ambient", true
		}
		return "", false
	})
	if e != nil || cfg.Password.Reveal() != "  exact \t" || cfg.Cache != "FILE:/selected" {
		t.Fatal(cfg, e)
	}
}
