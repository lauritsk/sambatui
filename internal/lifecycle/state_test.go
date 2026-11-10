package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/config"
)

func TestSnapshotsStaleResultsAndPendingConfirmations(t *testing.T) {
	cfg := config.Defaults()
	cfg.Server = "original-dc"
	cfg.Password = auth.NewSecret("original secret")
	state := New(cfg)
	f, e := state.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = state.Begin(); !errors.Is(e, ErrBusy) {
		t.Fatal("confirmations not serialized")
	}
	old := state.Snapshot()
	cfg.Server = "new-dc"
	cfg.Password = auth.NewSecret("new secret")
	state.Change(cfg)
	if state.Current(old.Generation) {
		t.Fatal("stale response accepted")
	}
	f.Run(context.Background(), func(_ context.Context, snapshot config.Settings) Outcome {
		if snapshot.Server != "original-dc" || snapshot.Password.Reveal() != "original secret" {
			t.Fatal("write redirected by connection edit")
		}
		return Outcome{}
	})
	if _, e = state.Begin(); e != nil {
		t.Fatal(e)
	}
}

func TestCancellationRetainsOwnershipUntilWorkerDrainsAndThenRequiresReconciliation(t *testing.T) {
	state := New(config.Defaults())
	f, _ := state.Begin()
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan Outcome, 1)
	go func() {
		done <- f.Run(ctx, func(context.Context, config.Settings) Outcome { close(entered); <-release; return Outcome{} })
	}()
	<-entered
	cancel()
	f.Abort()
	if _, e := state.Begin(); !errors.Is(e, ErrBusy) {
		t.Fatal("overlapping write while canceled worker still active")
	}
	select {
	case <-done:
		t.Fatal("returned before worker drain")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	out := <-done
	if !out.Uncertain || !errors.Is(out.Err, ErrCancelled) {
		t.Fatal(out)
	}
	if _, e := state.Begin(); !errors.Is(e, ErrReconcile) {
		t.Fatal("unknown outcome did not block writes")
	}
	state.Change(config.Defaults())
	if _, e := state.Begin(); !errors.Is(e, ErrReconcile) {
		t.Fatal("connection change cleared uncertainty")
	}
	snap, ok := state.Uncertain()
	if !ok {
		t.Fatal("lost uncertain snapshot")
	}
	bad := snap
	bad.Generation++
	if e := state.Reconciled(bad); e == nil {
		t.Fatal("wrong DC reconciliation accepted")
	}
	if e := state.Reconciled(snap); e != nil {
		t.Fatal(e)
	}
	f, e := state.Begin()
	if e != nil {
		t.Fatal(e)
	}
	f.Abort()
}

func TestCancelledBeforeDispatchDoesNotRunWrite(t *testing.T) {
	state := New(config.Defaults())
	f, _ := state.Begin()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := f.Run(ctx, func(context.Context, config.Settings) Outcome {
		t.Fatal("write dispatched after cancellation")
		return Outcome{}
	})
	if out.Uncertain {
		t.Fatal("undispatched write marked uncertain")
	}
	next, e := state.Begin()
	if e != nil {
		t.Fatal(e)
	}
	next.Abort()
}
