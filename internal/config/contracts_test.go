package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationRequiresObjectAndRejectsOversizedEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	emptyEnvironment := func(string) (string, bool) { return "", false }
	for _, data := range []string{"null", "[]", "{}", "{} {}"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path, emptyEnvironment)
		if (err == nil) != (data == "{}") {
			t.Fatalf("%q: %v", data, err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, func(name string) (string, bool) {
		if name == "SAMBATUI_SERVER" {
			return strings.Repeat("x", configBytesMax+1), true
		}
		return "", false
	})
	if err == nil {
		t.Fatal("oversized environment bypassed file limit")
	}
}
