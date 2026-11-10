// Package devtool owns bounded development workflows. Commands never pass
// through a shell, and cancellation terminates the entire owned process group.
package devtool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lauritsk/sambatui/internal/configfile"
	"github.com/lauritsk/sambatui/internal/invariant"
)

const (
	commandTimeout     = 5 * time.Minute
	captureBytesMax    = 64 << 10
	commandLogBytesMax = 16 << 20
)

type Tools struct {
	root    string
	execute func(context.Context, command) (string, error)
}

type command struct {
	name        string
	arguments   []string
	environment []string
	timeout     time.Duration
	capture     bool
}

func New(root string, output io.Writer) (*Tools, error) {
	invariant.Require(output != nil, "tooling requires an output writer")
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	manifest, err := configfile.Read(filepath.Join(root, "go.mod"), 1<<20)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(manifest, []byte("module github.com/lauritsk/sambatui\n")) {
		return nil, errors.New("run development commands from the sambatui checkout root")
	}
	tools := &Tools{root: root}
	tools.execute = func(ctx context.Context, specification command) (string, error) {
		return executeCommand(ctx, root, output, specification)
	}
	return tools, nil
}

func executeCommand(
	ctx context.Context, root string, output io.Writer, specification command,
) (string, error) {
	invariant.Require(specification.name != "", "command requires an executable")
	invariant.Require(specification.timeout > 0, "command requires a deadline")
	invariant.Require(specification.timeout <= 10*time.Minute, "command deadline exceeds budget")
	invariant.Require(len(specification.arguments) <= 64, "command has too many arguments")
	invariant.Require(len(specification.environment) <= 16, "command has too many overrides")
	ctx, cancel := context.WithTimeout(ctx, specification.timeout)
	defer cancel()
	process := exec.CommandContext(ctx, specification.name, specification.arguments...)
	process.Dir = root
	process.Env = commandEnvironment(os.Environ(), specification.environment)
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	process.Cancel = func() error {
		err := syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	process.WaitDelay = 5 * time.Second
	captured := &commandCapture{}
	log := &commandLog{target: output, remainingBytes: commandLogBytesMax}
	process.Stdout, process.Stderr = log, log
	if specification.capture {
		process.Stdout = captured
	}
	if err := process.Run(); err != nil {
		return "", fmt.Errorf("%s: %w", specification.name, errors.Join(err, ctx.Err()))
	}
	return captured.String(), nil
}

func commandEnvironment(inherited, overrides []string) []string {
	result := make([]string, 0, len(inherited)+len(overrides))
	for _, value := range inherited {
		name, _, _ := strings.Cut(value, "=")
		replaced := false
		for _, override := range overrides {
			key, _, _ := strings.Cut(override, "=")
			if key == name {
				replaced = true
			}
		}
		if !replaced {
			result = append(result, value)
		}
	}
	return append(result, overrides...)
}

type commandLog struct {
	target         io.Writer
	remainingBytes int
}

func (log *commandLog) Write(data []byte) (int, error) {
	invariant.Require(log.remainingBytes >= 0, "command log budget underflow")
	if len(data) > log.remainingBytes {
		return 0, errors.New("command log exceeds 16 MiB safety limit")
	}
	count, err := log.target.Write(data)
	log.remainingBytes -= count
	if err == nil && count != len(data) {
		err = io.ErrShortWrite
	}
	return count, err
}

type commandCapture struct{ data bytes.Buffer }

func (capture *commandCapture) String() string {
	return capture.data.String()
}

func (capture *commandCapture) Write(data []byte) (int, error) {
	invariant.Require(capture.data.Len() <= captureBytesMax, "command output budget underflow")
	if len(data) > captureBytesMax-capture.data.Len() {
		return 0, errors.New("command output exceeds capture safety limit")
	}
	return capture.data.Write(data)
}
