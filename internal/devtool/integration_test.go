package devtool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestIntegrationCleanupOwnsNameAndOutlivesCanceledOperation(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("fixture binaries are supported only on amd64/arm64")
	}
	tools := testTools(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var name, stage string
	removed := false
	tools.execute = func(operation context.Context, specification command) (string, error) {
		if specification.name == "go" {
			index := slices.Index(specification.arguments, "-o")
			stage = filepath.Dir(specification.arguments[index+1])
			return "", nil
		}
		switch specification.arguments[0] {
		case "run":
			index := slices.Index(specification.arguments, "--name")
			name = specification.arguments[index+1]
			cancel()
			return "", context.Canceled
		case "container":
			if operation.Err() != nil || !slices.Contains(specification.arguments, "name=^/"+name+"$") {
				t.Fatal("cleanup reused cancellation or broadened its ownership")
			}
			return "owned-container-id", nil
		case "rm":
			removed = slices.Equal(specification.arguments, []string{"rm", "--force", name})
			return "", nil
		default:
			t.Fatal("unexpected fixture command", specification)
			return "", nil
		}
	}
	if err := tools.Integration(ctx, "test-image"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was hidden", err)
	}
	if !removed || !strings.HasPrefix(name, "sambatui-lab-") {
		t.Fatal("fixture was not cleaned up", name)
	}
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture binaries were not cleaned up", err)
	}
}

func TestIntegrationRefusesToHideCleanupFailure(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("fixture binaries are supported only on amd64/arm64")
	}
	tools := testTools(t)
	failure, cleanupFailure := errors.New("run failed"), errors.New("daemon unavailable")
	tools.execute = func(_ context.Context, specification command) (string, error) {
		if specification.name == "go" {
			return "", nil
		}
		if specification.arguments[0] == "run" {
			return "", failure
		}
		return "", cleanupFailure
	}
	err := tools.Integration(context.Background(), "test-image")
	if !errors.Is(err, failure) || !errors.Is(err, cleanupFailure) {
		t.Fatal("primary or cleanup failure was lost", err)
	}
}

func TestFixtureStartHasExplicitIsolationAndResourceBounds(t *testing.T) {
	arguments := fixtureStart("owned", "test-image").arguments
	for _, pair := range [][2]string{
		{"--network", "none"},
		{"--memory", "1g"},
		{"--cpus", "2"},
		{"--pids-limit", "512"},
		{"--stop-timeout", "5"},
		{"--log-opt", "max-size=1m"},
		{"--log-opt", "max-file=2"},
	} {
		if !strings.Contains(strings.Join(arguments, "\x00"), strings.Join(pair[:], "\x00")) {
			t.Fatal("fixture limit missing", pair)
		}
	}
	for _, forbidden := range []string{"--privileged", "--mount", "--volume", "--publish"} {
		if slices.Contains(arguments, forbidden) {
			t.Fatal("fixture escapes isolation", forbidden)
		}
	}
	if !slices.Equal(arguments[len(arguments)-2:], []string{"--", "test-image"}) {
		t.Fatal("image is not separated from Docker options")
	}
}

func TestStoppedFixtureFailsBeforeReadinessPolling(t *testing.T) {
	tools := testTools(t)
	calls := 0
	tools.execute = func(context.Context, command) (string, error) {
		calls++
		return "false\n", nil
	}
	if err := tools.fixtureReady(context.Background(), "owned"); err == nil || calls != 1 {
		t.Fatal("stopped server was retried or reported ready", calls, err)
	}
}
