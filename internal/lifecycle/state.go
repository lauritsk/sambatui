package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/invariant"
)

var (
	ErrBusy      = errors.New("another write flow is still active")
	ErrReconcile = errors.New(
		"previous write outcome is uncertain; reconcile against the " +
			"original DC before another write",
	)
	ErrCancelled = errors.New(
		"write cancelled; cancellation is not rollback; reconcile " +
			"server state before retrying",
	)
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

func New(settings config.Settings) *State {
	return &State{current: Snapshot{Settings: settings, Generation: 1}}
}

func (writeState *State) Snapshot() Snapshot {
	writeState.mu.Lock()
	defer writeState.mu.Unlock()
	writeState.assertLocked()
	return writeState.current
}

// Change must be followed by immediately clearing UI rows/selections. Even a
// failed refresh must not leave selections valid for a changed target.
func (writeState *State) Change(settings config.Settings) Snapshot {
	writeState.mu.Lock()
	defer writeState.mu.Unlock()
	writeState.assertLocked()
	writeState.current = Snapshot{
		Settings:   settings,
		Generation: invariant.Next(writeState.current.Generation),
	}
	return writeState.current
}

func (writeState *State) Current(generation uint64) bool {
	writeState.mu.Lock()
	defer writeState.mu.Unlock()
	return writeState.current.Generation == generation
}

func (writeState *State) Begin() (*Flow, error) {
	writeState.mu.Lock()
	defer writeState.mu.Unlock()
	if writeState.active != nil {
		return nil, ErrBusy
	}
	if writeState.uncertain != nil {
		return nil, ErrReconcile
	}
	writeState.assertLocked()
	flow := &Flow{state: writeState, Snapshot: writeState.current}
	writeState.active = flow
	return flow, nil
}

// RestoreUncertain is used only for a durable pending intent after restart,
// or when clearing that intent failed. It never releases a live worker.
func (writeState *State) RestoreUncertain(snapshot Snapshot) error {
	writeState.mu.Lock()
	defer writeState.mu.Unlock()
	if writeState.active != nil {
		return ErrBusy
	}
	if snapshot.Generation == 0 {
		return errors.New("uncertain write requires a connection generation")
	}
	writeState.uncertain = &snapshot
	writeState.assertLocked()
	return nil
}

func (writeState *State) Uncertain() (Snapshot, bool) {
	writeState.mu.Lock()
	defer writeState.mu.Unlock()
	if writeState.uncertain == nil {
		return Snapshot{}, false
	}
	return *writeState.uncertain, true
}

// Reconciled is an explicit acknowledgement after successful reads against the
// original immutable target/identity. Connection changes alone never clear it.
func (writeState *State) Reconciled(snapshot Snapshot) error {
	writeState.mu.Lock()
	defer writeState.mu.Unlock()
	if writeState.active != nil {
		return ErrBusy
	}
	if writeState.uncertain == nil {
		return nil
	}
	if *writeState.uncertain != snapshot {
		return errors.New("reconciliation does not match uncertain write's connection snapshot")
	}
	writeState.uncertain = nil
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

// RetainUncertain restores the guard when durable intent cleanup fails.
func (flow *Flow) RetainUncertain() error {
	return flow.state.RestoreUncertain(flow.Snapshot)
}

// Abort is only for forms/confirmation before dispatch. It cannot release a
// running worker. Cancellation of an active operation goes through Run.
func (flow *Flow) Abort() {
	writeState := flow.state
	writeState.mu.Lock()
	defer writeState.mu.Unlock()
	if flow.finished || flow.running {
		return
	}
	flow.finished = true
	if writeState.active == flow {
		writeState.active = nil
	}
}

func (flow *Flow) Run(
	operationContext context.Context,
	fn func(context.Context, config.Settings) Outcome,
) Outcome {
	invariant.Require(operationContext != nil, "write flow requires a context")
	invariant.Require(fn != nil, "write flow requires an operation")
	writeState := flow.state
	writeState.mu.Lock()
	if flow.finished || flow.running || writeState.active != flow {
		writeState.mu.Unlock()
		return Outcome{Err: errors.New("write flow does not own reservation")}
	}
	if err := operationContext.Err(); err != nil {
		writeState.mu.Unlock()
		flow.Abort()
		return Outcome{Err: err}
	}
	flow.running = true
	writeState.mu.Unlock()
	// Run synchronously inside the caller's worker. Returning only after the
	// operation settles retains ownership without an extra goroutine or queue.
	// A canceled context is never interpreted as undoing a transmitted request.
	out := fn(operationContext, flow.Snapshot.Settings)
	if operationContext.Err() != nil {
		out.Uncertain = true
		out.Err = ErrCancelled
	}
	writeState.mu.Lock()
	defer writeState.mu.Unlock()
	invariant.Require(writeState.active == flow, "running write lost its reservation")
	invariant.Require(flow.running, "write must be running until settlement")
	flow.finished = true
	flow.running = false
	if out.Uncertain {
		snap := flow.Snapshot
		writeState.uncertain = &snap
	}
	if writeState.active == flow {
		writeState.active = nil
	}
	writeState.assertLocked()
	return out
}

// Call only while holding mu: an active worker and an uncertain outcome must
// never coexist, and completed workers must no longer own the reservation.
func (writeState *State) assertLocked() {
	invariant.Require(
		writeState.current.Generation > 0,
		"connection generation must be initialized",
	)
	if writeState.active != nil {
		invariant.Require(writeState.active.state == writeState, "write belongs to another state")
		invariant.Require(!writeState.active.finished, "finished write still owns reservation")
		invariant.Require(writeState.uncertain == nil, "uncertain state cannot admit a new write")
	}
}
