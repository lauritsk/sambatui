package backend

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func TestExecutionFailureKeepsPartialAndUnknownPlansGuarded(t *testing.T) {
	// Inject dispatch, not protocol behavior: verify sequencing and the guard
	// for both explicit refusals and replies lost after dispatch.
	refused := errors.New("refused")
	for _, test := range []struct {
		name      string
		failAt    int
		cause     error
		uncertain bool
	}{
		{"first refusal", 0, refused, false},
		{"partial refusal", 1, refused, true},
		{"DNS lost reply", 0, &dnsrpc.UncertainError{Cause: refused}, true},
		{"LDAP lost reply", 0, &directory.UncertainError{Cause: refused}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			action := Action{Kind: "dns_add", Zone: "lab.invalid", Name: "x", Type: "A", Value: "192.0.2.1"}
			plan := Plan{Actions: []Action{action, action, action}}
			calls := 0
			outcome := executePlan(context.Background(), config.Defaults(), plan,
				func(context.Context, config.Settings, Action) error {
					index := calls
					calls++
					if index == test.failAt {
						return test.cause
					}
					return nil
				})
			if !errors.Is(outcome.Err, test.cause) || outcome.Uncertain != test.uncertain {
				t.Fatalf("outcome: %+v", outcome)
			}
			if calls != test.failAt+1 {
				t.Fatalf("retried or continued after failure: %d calls", calls)
			}
		})
	}
}

func TestPlanActionBoundaries(t *testing.T) {
	action := Action{Kind: "dns_add", Zone: "lab.invalid", Name: "x", Type: "A", Value: "192.0.2.1"}
	for _, count := range []int{0, 1, MaxActions, MaxActions + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			plan := Plan{Actions: make([]Action, count)}
			for index := range plan.Actions {
				plan.Actions[index] = action
			}
			err := plan.Validate(config.Defaults())
			valid := count > 0 && count <= MaxActions
			if (err == nil) != valid {
				t.Fatalf("count %d: %v", count, err)
			}
		})
	}
}

func TestCancellationBetweenActionsRequiresReconciliation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	action := Action{Kind: "dns_add", Zone: "lab.invalid", Name: "x", Type: "A", Value: "192.0.2.1"}
	calls := 0
	outcome := executePlan(ctx, config.Defaults(), Plan{Actions: []Action{action, action}},
		func(context.Context, config.Settings, Action) error {
			calls++
			cancel()
			return nil
		})
	if !errors.Is(outcome.Err, context.Canceled) || !outcome.Uncertain || calls != 1 {
		t.Fatalf("outcome %+v, calls %d", outcome, calls)
	}
}
