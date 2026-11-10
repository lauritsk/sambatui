package devtool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/lauritsk/sambatui/internal/invariant"
)

func (tools *Tools) Check(ctx context.Context) (result error) {
	invariant.Require(ctx != nil, "workflow requires a context")
	invariant.Require(tools.execute != nil, "workflow requires a command runner")
	stage, err := os.MkdirTemp("", "sambatui-check-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(stage)) }()

	formatting, err := tools.execute(ctx, command{
		name: "gofumpt", arguments: []string{"-l", "cmd", "internal", "integration"},
		timeout: commandTimeout, capture: true,
	})
	if err != nil {
		return err
	}
	if formatting != "" {
		return errors.New("unformatted Go files:\n" + formatting)
	}
	binary := filepath.Join(stage, "sambatui")
	for _, specification := range []command{
		{
			name: "go", arguments: []string{"vet", "./..."},
			environment: nativeEnvironment("0"), timeout: commandTimeout,
		},
		{
			name: "go", arguments: []string{"test", "-timeout=120s", "./..."},
			environment: nativeEnvironment("0"), timeout: commandTimeout,
		},
		{
			name: "go", arguments: []string{"test", "-race", "-timeout=120s", "./..."},
			environment: nativeEnvironment("1"), timeout: commandTimeout,
		},
		{
			name: "go",
			arguments: []string{
				"build", "-buildvcs=false", "-trimpath", "-o", binary, "./cmd/sambatui",
			},
			environment: nativeEnvironment("0"), timeout: commandTimeout,
		},
		{name: binary, arguments: []string{"-version"}, timeout: commandTimeout},
		{
			name: "python3", timeout: commandTimeout,
			arguments: []string{
				"-I", "-W", "error", "-m", "unittest", "discover",
				"--start-directory", "integration", "--pattern", "server_test.py",
			},
		},
	} {
		if _, err := tools.execute(ctx, specification); err != nil {
			return err
		}
	}
	return nil
}

func nativeEnvironment(cgo string) []string {
	invariant.Require(cgo == "0" || cgo == "1", "CGO setting must be explicit")
	return []string{"CGO_ENABLED=" + cgo, "GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH}
}
