package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKerberosConfigurationIsBoundedBeforeParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(path, []byte("[libdefaults]\n default_realm = LAB.INVALID\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", path)
	if settings, err := LoadKerberosConfig(""); err != nil || settings.LibDefaults.DefaultRealm != "LAB.INVALID" {
		t.Fatalf("selected configuration: %v %v", settings, err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("#", kerberosConfigBytesMax+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if settings, err := LoadKerberosConfig(path); err == nil || settings != nil {
		t.Fatal("oversized configuration accepted")
	}
}
