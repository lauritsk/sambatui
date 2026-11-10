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
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCommandEnvironmentOverridesWithoutDuplicates(t *testing.T) {
	actual := commandEnvironment([]string{"GOOS=wrong", "CGO_ENABLED=1", "OTHER=kept"},
		[]string{"GOOS=linux", "CGO_ENABLED=0"})
	if !slices.Equal(actual, []string{"OTHER=kept", "GOOS=linux", "CGO_ENABLED=0"}) {
		t.Fatal("inherited environment redirected command", actual)
	}
}

func TestCommandOutputBoundCannotBeBypassedByCopyOptimization(t *testing.T) {
	for _, count := range []int{captureBytesMax, captureBytesMax + 1} {
		capture := &commandCapture{}
		_, err := io.Copy(capture, strings.NewReader(strings.Repeat("x", count)))
		if (err == nil) != (count == captureBytesMax) {
			t.Fatalf("capture size %d: %v", count, err)
		}
		if len(capture.String()) > captureBytesMax {
			t.Fatal("capture exceeded allocation bound")
		}
	}
	var output bytes.Buffer
	log := &commandLog{target: &output, remainingBytes: 3}
	if _, err := log.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Write([]byte("d")); err == nil || output.String() != "abc" {
		t.Fatal("log overflow was not rejected atomically")
	}
}

func TestCommandFailureTimeoutAndCapture(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "failure", "timeout", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			specification := command{
				name: executable, arguments: []string{"-test.run=^TestToolProcessHelper$", "--", mode},
				environment: []string{"SAMBATUI_TOOL_PROCESS_HELPER=YES"},
				timeout:     3 * time.Second, capture: true,
			}
			if mode == "timeout" {
				specification.timeout = 50 * time.Millisecond
			}
			output, err := executeCommand(context.Background(), t.TempDir(), io.Discard, specification)
			if mode == "success" {
				if err != nil || output != "completed" {
					t.Fatal(output, err)
				}
			} else if err == nil {
				t.Fatal("command failure was hidden")
			}
			if mode == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline cause was lost", err)
			}
		})
	}
}

func TestToolProcessHelper(t *testing.T) {
	if os.Getenv("SAMBATUI_TOOL_PROCESS_HELPER") != "YES" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "success":
		fmt.Print("completed")
	case "failure":
		os.Exit(7)
	case "timeout":
		time.Sleep(time.Minute)
	case "overflow":
		fmt.Print(strings.Repeat("x", captureBytesMax+1))
	case "descendant":
		executable, err := os.Executable()
		if err != nil {
			os.Exit(10)
		}
		child := exec.Command(executable, "-test.run=^TestToolProcessHelper$", "--", "child")
		if err := child.Run(); err != nil {
			os.Exit(11)
		}
	case "child":
		marker, err := os.OpenFile(os.Getenv("SAMBATUI_TOOL_MARKER"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			os.Exit(12)
		}
		defer marker.Close()
		for count := 0; count < 100; count++ {
			if _, err := marker.Write([]byte("x")); err != nil {
				os.Exit(13)
			}
			time.Sleep(50 * time.Millisecond)
		}
	default:
		os.Exit(9)
	}
	os.Exit(0)
}

func TestCancellationTerminatesOwnedDescendants(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "owned-child")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := executeCommand(ctx, filepath.Dir(marker), io.Discard, command{
			name: executable, arguments: []string{"-test.run=^TestToolProcessHelper$", "--", "descendant"},
			environment: []string{"SAMBATUI_TOOL_PROCESS_HELPER=YES", "SAMBATUI_TOOL_MARKER=" + marker},
			timeout:     3 * time.Second,
		})
		done <- err
	}()
	started := false
	for attempt := 0; attempt < 100; attempt++ {
		if metadata, err := os.Stat(marker); err == nil && metadata.Size() > 0 {
			started = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation cause lost", err)
	}
	if !started {
		t.Fatal("descendant did not start within startup budget")
	}
	before, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	after, err := os.Stat(marker)
	if err != nil || after.Size() != before.Size() {
		t.Fatal("descendant continued after cancellation", err)
	}
}

func TestCheckStopsAtFormattingFailure(t *testing.T) {
	tools := testTools(t)
	calls := 0
	tools.execute = func(context.Context, command) (string, error) {
		calls++
		return "internal/unformatted.go\n", nil
	}
	if err := tools.Check(context.Background()); err == nil || calls != 1 {
		t.Fatal("formatting failure did not stop verification", err)
	}
}
