package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCLIHelpAndInvalidInputsDoNotDispatchWorkflows(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module github.com/lauritsk/sambatui\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	for _, arguments := range [][]string{{"--help"}, {"release", "--help"}} {
		if err := run(arguments); err != nil {
			t.Fatal("help treated as an operational failure", err)
		}
	}
	for _, arguments := range [][]string{
		nil,
		{"unknown"},
		{"check", "extra"},
		{"integration", "extra"},
		{"release"},
		{"release", "--version", "../escape"},
		{"release", "--version", "v1", "unnamed"},
	} {
		if err := run(arguments); err == nil {
			t.Fatal("invalid arguments accepted", arguments)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "dist")); !os.IsNotExist(err) {
		t.Fatal("invalid CLI invocation created output", err)
	}
}
