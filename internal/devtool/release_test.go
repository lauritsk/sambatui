package devtool

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testTools(t *testing.T) *Tools {
	t.Helper()
	root := t.TempDir()
	files := append([]string{"go.mod"}, releaseDocuments[:]...)
	for _, name := range files {
		contents := name + "\n"
		if name == "go.mod" {
			contents = "module github.com/lauritsk/sambatui\n"
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tools, err := New(root, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return tools
}

func fakeBuild(_ context.Context, specification command) (string, error) {
	index := slices.Index(specification.arguments, "-o")
	if specification.name != "go" || index < 0 {
		return "", errors.New("unexpected build command")
	}
	return "", os.WriteFile(specification.arguments[index+1], []byte("native binary"), 0o755)
}

func TestReleaseRejectsUnsafeVersionsAndExistingOutputBeforeCommands(t *testing.T) {
	tools := testTools(t)
	tools.execute = func(context.Context, command) (string, error) {
		t.Fatal("invalid release dispatched a command")
		return "", nil
	}
	for _, version := range []string{"", "../other", "-v1", ".hidden", "v1\n", "é", strings.Repeat("v", 65)} {
		if err := tools.Release(context.Background(), version, "dist"); err == nil {
			t.Fatalf("unsafe version accepted: %q", version)
		}
	}
	output := filepath.Join(tools.root, "dist")
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := tools.Release(context.Background(), "v1.2.3", output); err == nil {
		t.Fatal("existing output accepted")
	}
}

func TestReleasePublishesOnlyCompleteDeterministicArchives(t *testing.T) {
	tools := testTools(t)
	tools.execute = fakeBuild
	for _, output := range []string{"first", "second"} {
		if err := tools.Release(context.Background(), "v1.2.3", output); err != nil {
			t.Fatal(err)
		}
		manifest, err := os.ReadFile(filepath.Join(tools.root, output, "sambatui-v1.2.3-checksums.txt"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
		if len(lines) != len(releaseTargets) {
			t.Fatal("manifest does not enumerate the exact release set")
		}
		for _, line := range lines {
			digest, name, found := strings.Cut(line, "  ")
			if !found {
				t.Fatal("invalid checksum entry", line)
			}
			data, err := os.ReadFile(filepath.Join(tools.root, output, name))
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != digest {
				t.Fatal("archive checksum mismatch", err)
			}
			checkArchive(t, data)
			if output == "second" {
				previous, err := os.ReadFile(filepath.Join(tools.root, "first", name))
				if err != nil || !bytes.Equal(previous, data) {
					t.Fatal("release depends on host metadata", err)
				}
			}
		}
	}
}

func checkArchive(t *testing.T, data []byte) {
	t.Helper()
	compressed, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	expected := append([]string{"sambatui"}, releaseDocuments[:]...)
	for index := 0; index <= len(expected); index++ {
		header, err := archive.Next()
		if index == len(expected) {
			if !errors.Is(err, io.EOF) {
				t.Fatal("unexpected archive member", header, err)
			}
			break
		}
		if err != nil || header.Name != expected[index] || header.Uid != 0 || header.Gid != 0 {
			t.Fatal("invalid archive member", header, err)
		}
		if !header.ModTime.IsZero() && header.ModTime.Unix() != 0 {
			t.Fatal("archive timestamp is not fixed")
		}
	}
}

func TestFailedReleaseCleansStageAndDoesNotPublish(t *testing.T) {
	for _, failureAt := range []int{1, 2, 4} {
		tools := testTools(t)
		failure := errors.New("injected build failure")
		calls := 0
		tools.execute = func(ctx context.Context, specification command) (string, error) {
			calls++
			if calls == failureAt {
				return "", failure
			}
			return fakeBuild(ctx, specification)
		}
		if err := tools.Release(context.Background(), "v1", "dist"); !errors.Is(err, failure) {
			t.Fatal("build failure was hidden", err)
		}
		if _, err := os.Lstat(filepath.Join(tools.root, "dist")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed release published output", err)
		}
		stages, err := filepath.Glob(filepath.Join(tools.root, ".sambatui-release-*"))
		if err != nil || len(stages) != 0 {
			t.Fatal("failed release leaked staging data", stages, err)
		}
	}
}
