package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lauritsk/sambatui/internal/config"
)

var (
	ErrBusy      = errors.New("another write flow is still active")
	ErrReconcile = errors.New("previous write outcome is uncertain; reconcile against the original DC before another write")
	ErrCancelled = errors.New("write cancelled; cancellation is not rollback; reconcile server state before retrying")
)

type Snapshot struct {
	Settings   config.Settings
	Generation uint64
}
type State struct {
	mu        sync.Mutex
	current   Snapshot
	active    *Flow
	uncertain *Snapshot
}

func (*State) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "WriteState{credentials:[redacted]}")
}

func New(cfg config.Settings) *State { return &State{current: Snapshot{cfg, 1}} }
func (s *State) Snapshot() Snapshot  { s.mu.Lock(); defer s.mu.Unlock(); return s.current }

// Change must be followed by immediately clearing UI rows/selections. Even a
// failed refresh must not leave selections valid for a changed target.
func (s *State) Change(cfg config.Settings) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = Snapshot{cfg, s.current.Generation + 1}
	return s.current
}

func (s *State) Current(generation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current.Generation == generation
}

func (s *State) Begin() (*Flow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil {
		return nil, ErrBusy
	}
	if s.uncertain != nil {
		return nil, ErrReconcile
	}
	f := &Flow{state: s, Snapshot: s.current}
	s.active = f
	return f, nil
}

// RestoreUncertain is used only for a durable pending intent after restart,
// or when clearing that intent failed. It never releases a live worker.
func (s *State) RestoreUncertain(snapshot Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil {
		return ErrBusy
	}
	s.uncertain = &snapshot
	return nil
}

func (s *State) Uncertain() (Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uncertain == nil {
		return Snapshot{}, false
	}
	return *s.uncertain, true
}

// Reconciled is an explicit acknowledgement after successful reads against the
// original immutable target/identity. Connection changes alone never clear it.
func (s *State) Reconciled(snapshot Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil {
		return ErrBusy
	}
	if s.uncertain == nil {
		return nil
	}
	if *s.uncertain != snapshot {
		return errors.New("reconciliation does not match uncertain write's connection snapshot")
	}
	s.uncertain = nil
	return nil
}

type Outcome struct {
	Err       error
	Uncertain bool
}
type Flow struct {
	state    *State
	Snapshot Snapshot
	running  bool
	finished bool
}

// Abort is only for forms/confirmation before dispatch. It cannot release a
// running worker. Cancellation of an active operation goes through Run.
func (f *Flow) RetainUncertain() error { return f.state.RestoreUncertain(f.Snapshot) }

func (f *Flow) Abort() {
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.finished || f.running {
		return
	}
	f.finished = true
	if s.active == f {
		s.active = nil
	}
}

func (f *Flow) Run(ctx context.Context, fn func(context.Context, config.Settings) Outcome) Outcome {
	s := f.state
	s.mu.Lock()
	if f.finished || f.running || s.active != f {
		s.mu.Unlock()
		return Outcome{Err: errors.New("write flow does not own reservation")}
	}
	if e := ctx.Err(); e != nil {
		s.mu.Unlock()
		f.Abort()
		return Outcome{Err: e}
	}
	f.running = true
	s.mu.Unlock()
	// Wait for the worker to settle even if the UI has already requested cancel.
	// A canceled context is never interpreted as undoing a transmitted request.
	result := make(chan Outcome, 1)
	go func() { result <- fn(ctx, f.Snapshot.Settings) }()
	out := <-result
	if ctx.Err() != nil {
		out.Uncertain = true
		out.Err = ErrCancelled
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f.finished = true
	f.running = false
	if out.Uncertain {
		snap := f.Snapshot
		s.uncertain = &snap
	}
	if s.active == f {
		s.active = nil
	}
	return out
}
