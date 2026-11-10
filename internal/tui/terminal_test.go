//go:build linux

package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"
	"github.com/lauritsk/sambatui/internal/config"
	"golang.org/x/sys/unix"
)

func TestTerminalChild(t *testing.T) {
	if os.Getenv("SAMBATUI_PTY_CHILD") != "1" {
		t.Skip("PTY subprocess helper")
	}
	model := New(config.Defaults(), "/not-used", &fakeService{})
	if err := model.SetTheme(os.Getenv("SAMBATUI_PTY_THEME")); err != nil {
		t.Fatal(err)
	}
	if _, err := tea.NewProgram(model, tea.WithAltScreen()).Run(); err != nil {
		t.Fatal(err)
	}
}

const terminalCaptureBytesMax = 1 << 20

type terminalOutput struct {
	mutex sync.Mutex
	data  []byte
	err   error
}

func (output *terminalOutput) append(data []byte) bool {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	if len(data) > terminalCaptureBytesMax-len(output.data) {
		output.err = errors.New("PTY transcript exceeds 1 MiB")
		return false
	}
	output.data = append(output.data, data...)
	return true
}

func (output *terminalOutput) read(operationContext context.Context, descriptor int32, done chan<- struct{}) {
	defer close(done)
	buffer := make([]byte, 4096)
	polls := []unix.PollFd{{Fd: descriptor, Events: unix.POLLIN}}
	// One reader owns this descriptor. Poll makes cancellation independent of
	// blocking os.File.Close behavior when another process still owns a slave.
	for operationContext.Err() == nil {
		ready, err := unix.Poll(polls, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err == nil && ready == 0 {
			continue
		}
		if err == nil {
			var count int
			count, err = unix.Read(int(descriptor), buffer)
			if count > 0 && !output.append(buffer[:count]) {
				return
			}
			if count == 0 && err == nil {
				return
			}
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			// Linux reports EIO when the last slave closes; that is normal EOF.
			if !errors.Is(err, unix.EIO) {
				output.mutex.Lock()
				output.err = err
				output.mutex.Unlock()
			}
			return
		}
	}
}

func (output *terminalOutput) snapshot() string {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return string(output.data)
}

func (output *terminalOutput) wait(t *testing.T, needle string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		output.mutex.Lock()
		found, err := bytes.Contains(output.data, []byte(needle)), output.err
		if !found {
			found = strings.Contains(ansi.Strip(string(output.data)), needle)
		}
		output.mutex.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if found {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("terminal did not display %q: %q", needle, output.snapshot())
}

type terminalSession struct {
	master, slave *os.File
	command       *exec.Cmd
	cancel        context.CancelFunc
	done          chan struct{}
	output        terminalOutput
	before        *unix.Termios
	waited        bool
}

func startTerminalSession(t *testing.T, theme, noColor string) *terminalSession {
	t.Helper()
	operationContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	session := &terminalSession{cancel: cancel}
	t.Cleanup(func() { session.close(t) })
	var err error
	session.master, session.slave, err = pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	if session.master.Fd() > math.MaxInt32 {
		t.Fatal("PTY descriptor exceeds poll API range")
	}
	if err := pty.Setsize(session.master, &pty.Winsize{Rows: 24, Cols: 80}); err != nil {
		t.Fatal(err)
	}
	session.before, err = unix.IoctlGetTermios(int(session.slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	session.startChild(t, operationContext, theme, noColor)
	session.output.data = make([]byte, 0, terminalCaptureBytesMax)
	session.done = make(chan struct{})
	go session.output.read(operationContext, int32(session.master.Fd()), session.done)
	return session
}

func (session *terminalSession) startChild(
	t *testing.T, operationContext context.Context, theme, noColor string,
) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(operationContext, executable, "-test.run=^TestTerminalChild$")
	command.Env = append(os.Environ(), "SAMBATUI_PTY_CHILD=1",
		"SAMBATUI_PTY_THEME="+theme, "NO_COLOR="+noColor, "CLICOLOR_FORCE=1",
		"COLORTERM=truecolor", "TERM=xterm-256color")
	command.Stdin, command.Stdout, command.Stderr = session.slave, session.slave, session.slave
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	session.command = command
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
}

func (session *terminalSession) close(t *testing.T) {
	t.Helper()
	session.cancel()
	if session.command != nil && session.command.Process != nil && !session.waited {
		err := session.command.Wait()
		// Cancellation deliberately kills the owned process group. Other exit
		// failures remain visible alongside the original test failure.
		var exitError *exec.ExitError
		expectedKill := errors.As(err, &exitError) &&
			exitError.Sys().(syscall.WaitStatus).Signal() == syscall.SIGKILL
		if err != nil && !expectedKill {
			t.Errorf("PTY subprocess cleanup: %v", err)
		}
	}
	if session.done != nil {
		select {
		case <-session.done:
		case <-time.After(2 * time.Second):
			t.Error("PTY reader did not stop after cancellation")
		}
	}
	for _, file := range []*os.File{session.slave, session.master} {
		if file != nil {
			if err := file.Close(); err != nil {
				t.Errorf("PTY close: %v", err)
			}
		}
	}
	session.output.mutex.Lock()
	defer session.output.mutex.Unlock()
	if session.output.err != nil {
		t.Errorf("PTY capture: %v", session.output.err)
	}
}

func (session *terminalSession) send(t *testing.T, input string) {
	t.Helper()
	if count, err := io.WriteString(session.master, input); err != nil || count != len(input) {
		t.Fatalf("PTY input: wrote %d/%d bytes: %v", count, len(input), err)
	}
}

func (session *terminalSession) checkRestoration(t *testing.T, noColor string) {
	t.Helper()
	err := session.command.Wait()
	session.waited = true
	if err != nil {
		t.Fatal(err, session.output.snapshot())
	}
	after, err := unix.IoctlGetTermios(int(session.slave.Fd()), unix.TCGETS)
	if err != nil || *session.before != *after {
		t.Fatal("terminal echo/raw state was not restored", err)
	}
	for _, sequence := range []string{"\x1b[?1049l", "\x1b[?25h", "\x1b[?2004l"} {
		session.output.wait(t, sequence)
	}
	transcript := session.output.snapshot()
	color := regexp.MustCompile(`\x1b\[(?:[0-9]+;)*(?:[349][0-7]|10[0-7]|[34]8;[0-9;]+)m`)
	if noColor != "" && color.MatchString(transcript) {
		t.Fatal("NO_COLOR lost precedence over forced truecolor")
	}
	if noColor == "" && !strings.Contains(transcript, "38;2;") {
		t.Fatal("truecolor terminal did not receive the semantic palette")
	}
}

func TestTerminalCaptureRejectsOverflowAtomically(t *testing.T) {
	output := &terminalOutput{data: make([]byte, 0, terminalCaptureBytesMax)}
	if !output.append(make([]byte, terminalCaptureBytesMax)) {
		t.Fatal("exact transcript budget rejected")
	}
	if output.append([]byte("x")) || len(output.data) != terminalCaptureBytesMax {
		t.Fatal("overflowing transcript changed the retained capture")
	}
	if output.err == nil {
		t.Fatal("capture overflow was silently discarded")
	}
}

func TestTerminalReaderReportsDescriptorErrors(t *testing.T) {
	operationContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	output := &terminalOutput{}
	done := make(chan struct{})
	output.read(operationContext, math.MaxInt32, done)
	if !errors.Is(output.err, unix.EBADF) {
		t.Fatal("invalid descriptor was not reported", output.err)
	}
	select {
	case <-done:
	default:
		t.Fatal("terminal reader did not release ownership")
	}
}

func TestPTYTypingPasteResizeAndTerminalRestoration(t *testing.T) {
	for _, variant := range []struct{ theme, noColor string }{
		{"dark", "1"}, {"light", "1"}, {"dark", ""}, {"light", ""},
	} {
		t.Run(variant.theme+"/NO_COLOR="+variant.noColor, func(t *testing.T) {
			session := startTerminalSession(t, variant.theme, variant.noColor)
			session.output.wait(t, "Connection")
			// Printable commands and pasted newlines belong to the form, not global actions.
			session.send(t, "\x15\x1b[200~qj/\nQ\x1b[201~")
			session.output.wait(t, "qj/Q_")
			if err := pty.Setsize(session.master, &pty.Winsize{Rows: 12, Cols: 40}); err != nil {
				t.Fatal(err)
			}
			if err := session.command.Process.Signal(unix.SIGWINCH); err != nil {
				t.Fatal(err)
			}
			session.send(t, "\x1b")
			session.output.wait(t, "No records")
			session.output.wait(t, "Ctrl+O setup")
			session.send(t, "?")
			session.output.wait(t, "Help")
			session.send(t, "\x1b")
			// Wait for modal dismissal before quitting to avoid ambiguous Escape sequences.
			session.output.wait(t, "Q quit")
			time.Sleep(50 * time.Millisecond)
			session.send(t, "Q")
			session.checkRestoration(t, variant.noColor)
		})
	}
}
