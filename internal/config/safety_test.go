package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lauritsk/sambatui/internal/auth"
)

func TestConfigurationRejectsTrailingDataAndOversizeFiles(t *testing.T) {
	for name, data := range map[string]string{
		"second object":    "{} {}",
		"trailing garbage": "{} broken",
		"unknown field":    "{\"unexpected\":true}",
		"oversize":         strings.Repeat(" ", configBytesMax+1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path, func(string) (string, bool) { return "", false }); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestPasswordSaveAndReadHaveTheSameBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	password := strings.Repeat("x", passwordLineBytesMax-1)
	if err := SavePassword(path, auth.NewSecret(password)); err != nil {
		t.Fatal(err)
	}
	if actual, err := ReadPassword(path); err != nil || actual != password {
		t.Fatalf("saved password cannot be read: %v", err)
	}
	if err := SavePassword(path, auth.NewSecret(password+"x")); err == nil {
		t.Fatal("oversized password saved")
	}
	if actual, err := ReadPassword(path); err != nil || actual != password {
		t.Fatal("rejected write replaced the original password")
	}
}

func TestOversizeConfigurationDoesNotReplaceOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	settings := Defaults()
	if err := Save(path, settings); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	settings.Server = strings.Repeat("x", configBytesMax)
	if err := Save(path, settings); err == nil {
		t.Fatal("oversized configuration saved")
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(original) {
		t.Fatal("rejected write replaced the original configuration")
	}
}
