//go:build linux || darwin || freebsd || openbsd || netbsd

package configfile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPublicConfigurationBoundsAndFileKinds(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "public.conf")
	if err := os.WriteFile(path, []byte("1234"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, selected := range []string{path, link} {
		if data, err := Read(selected, 4); err != nil || string(data) != "1234" {
			t.Fatalf("public configuration rejected: %q %v", data, err)
		}
		if data, err := Read(selected, 3); err == nil || data != nil {
			t.Fatal("oversized configuration accepted")
		}
	}
	fifo := filepath.Join(directory, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, selected := range []string{directory, fifo} {
		if _, err := Read(selected, 4); err == nil {
			t.Fatal("nonregular configuration accepted")
		}
	}
}
