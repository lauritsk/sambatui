package devtool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lauritsk/sambatui/internal/invariant"
)

const fixtureImage = "sambatui-go-test-server"

func (tools *Tools) Integration(ctx context.Context, image string) (result error) {
	invariant.Require(ctx != nil, "workflow requires a context")
	invariant.Require(tools.execute != nil, "workflow requires a command runner")
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("disposable integration tests require amd64 or arm64")
	}
	stage, err := os.MkdirTemp("", "sambatui-lab-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(stage)) }()
	name := filepath.Base(stage)
	if image == "" {
		image = fixtureImage
		if _, err := tools.execute(ctx, command{
			name: "docker", arguments: []string{"build", "--tag", image, "integration"},
			timeout: 10 * time.Minute,
		}); err != nil {
			return err
		}
	}
	if err := tools.fixtureBuild(ctx, stage); err != nil {
		return err
	}
	// Cleanup gets its own deadline; the operation context may already be canceled.
	defer func() { result = errors.Join(result, tools.fixtureRemove(name)) }()
	if _, err := tools.execute(ctx, fixtureStart(name, image)); err != nil {
		return err
	}
	if err := tools.fixtureReady(ctx, name); err != nil {
		_, logErr := tools.execute(ctx, command{
			name: "docker", arguments: []string{"logs", "--tail", "100", name},
			timeout: 10 * time.Second,
		})
		return errors.Join(err, logErr)
	}
	for _, file := range []string{"dnsrpc.test", "directory.test", "integration.test", "sambatui"} {
		if _, err := tools.execute(ctx, command{
			name: "docker", timeout: 30 * time.Second,
			arguments: []string{"cp", filepath.Join(stage, file), name + ":/tmp/native-ad/" + file},
		}); err != nil {
			return err
		}
	}
	return tools.fixtureTests(ctx, name)
}

func (tools *Tools) fixtureBuild(ctx context.Context, stage string) error {
	for _, packagePath := range []string{"internal/dnsrpc", "internal/directory", "integration"} {
		binary := filepath.Join(stage, filepath.Base(packagePath)+".test")
		if _, err := tools.execute(ctx, command{
			name: "go", timeout: commandTimeout,
			arguments:   []string{"test", "-c", "-o", binary, "./" + packagePath},
			environment: []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + runtime.GOARCH},
		}); err != nil {
			return err
		}
	}
	_, err := tools.execute(ctx, command{
		name: "go", timeout: commandTimeout,
		arguments: []string{
			"build", "-trimpath", "-o", filepath.Join(stage, "sambatui"),
			"./cmd/sambatui",
		},
		environment: []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + runtime.GOARCH},
	})
	return err
}

func fixtureStart(name, image string) command {
	return command{
		name: "docker", timeout: 30 * time.Second,
		arguments: []string{
			"run", "--detach", "--name", name, "--network", "none", "--hostname", "dc",
			"--memory", "1g", "--cpus", "2", "--pids-limit", "512", "--stop-timeout", "5",
			"--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2",
			"--env", "SAMBATUI_SERVER_FIXTURE=DISPOSABLE", "--", image,
		},
	}
}

func (tools *Tools) fixtureReady(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for attempt := uint32(0); attempt < 90; attempt++ {
		running, err := tools.execute(ctx, command{
			name: "docker", timeout: 5 * time.Second, capture: true,
			arguments: []string{"inspect", "--format", "{{.State.Running}}", name},
		})
		if err != nil {
			return err
		}
		if strings.TrimSpace(running) != "true" {
			return errors.New("disposable server stopped before readiness")
		}
		if _, err := tools.execute(ctx, command{
			name: "docker", timeout: 5 * time.Second,
			arguments: []string{"exec", name, "test", "-f", "/tmp/native-ad/ready"},
		}); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("disposable server exceeded readiness attempt limit")
}

func (tools *Tools) fixtureRemove(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// A failed Docker run can still have created a container. Inspect only our
	// unique reserved name, and distinguish absence from an unavailable daemon.
	containers, err := tools.execute(ctx, command{
		name: "docker", timeout: 10 * time.Second, capture: true,
		arguments: []string{
			"container", "ls", "--all", "--quiet", "--filter", "name=^/" + name + "$",
		},
	})
	if err != nil {
		return fmt.Errorf("inspect fixture cleanup: %w", err)
	}
	if strings.TrimSpace(containers) == "" {
		return nil
	}
	_, err = tools.execute(ctx, command{
		name: "docker", arguments: []string{"rm", "--force", name}, timeout: 15 * time.Second,
	})
	return err
}
