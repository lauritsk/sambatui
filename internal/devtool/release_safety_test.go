package devtool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseReservesDestinationAndNeverRemovesAnotherReservation(t *testing.T) {
	tools := testTools(t)
	tools.execute = func(context.Context, command) (string, error) {
		t.Fatal("reserved destination dispatched build")
		return "", nil
	}
	reservation := filepath.Join(tools.root, "dist.lock")
	if err := os.WriteFile(reservation, []byte("other owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tools.Release(context.Background(), "v1", "dist"); err == nil {
		t.Fatal("concurrent reservation accepted")
	}
	if contents, err := os.ReadFile(reservation); err != nil || string(contents) != "other owner" {
		t.Fatal("another owner's reservation was altered", err)
	}
}

func TestReleaseRechecksDestinationBeforePublication(t *testing.T) {
	tools := testTools(t)
	calls := 0
	tools.execute = func(ctx context.Context, specification command) (string, error) {
		calls++
		if calls == len(releaseTargets) {
			if err := os.Mkdir(filepath.Join(tools.root, "dist"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		return fakeBuild(ctx, specification)
	}
	if err := tools.Release(context.Background(), "v1", "dist"); err == nil {
		t.Fatal("release overwrote a newly created destination")
	}
	entries, err := os.ReadDir(filepath.Join(tools.root, "dist"))
	if err != nil || len(entries) != 0 {
		t.Fatal("external destination was replaced", err)
	}
	if _, err := os.Lstat(filepath.Join(tools.root, "dist.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("release leaked its reservation", err)
	}
}

func TestArchiveRejectsSymlinksAndOversizedInputs(t *testing.T) {
	tools := testTools(t)
	target := filepath.Join(tools.root, "binary")
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tools.root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.releaseArchive(context.Background(), filepath.Join(tools.root, "link.tar.gz"), link); err == nil {
		t.Fatal("symlinked release input accepted")
	}
	if err := os.Truncate(target, releaseFileBytesMax+1); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.releaseArchive(context.Background(), filepath.Join(tools.root, "large.tar.gz"), target); err == nil {
		t.Fatal("unbounded release input accepted")
	}
}
