package tui

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lauritsk/sambatui/internal/discovery"
)

type discoveryResolverFunc func(context.Context, string, string, string) (string, []*net.SRV, error)

func (resolve discoveryResolverFunc) LookupSRV(
	operationContext context.Context, service, protocol, name string,
) (string, []*net.SRV, error) {
	return resolve(operationContext, service, protocol, name)
}

func TestDiscoveryWorkerFreezesIdentityAndOwnsItsDeadline(t *testing.T) {
	model := testModel()
	generation := model.state.Snapshot().Generation
	var workerContext context.Context
	queries := 0
	resolver := discoveryResolverFunc(func(
		operationContext context.Context, service, protocol, name string,
	) (string, []*net.SRV, error) {
		workerContext = operationContext
		deadline, exists := operationContext.Deadline()
		if !exists || time.Until(deadline) > discoveryTimeout {
			t.Fatal("discovery has no bounded deadline")
		}
		if service != "" || protocol != "" || !strings.HasSuffix(name, ".lab.invalid") {
			t.Fatalf("unexpected SRV query: %q %q %q", service, protocol, name)
		}
		queries++
		return "", []*net.SRV{{Target: "dc.lab.invalid.", Port: 389}}, nil
	})
	command := model.startDiscovery("lab.invalid", resolver)
	requestID := model.readID
	// The worker must not consult later live model values.
	model.readID++
	result := command().(discovered)
	if result.generation != generation || result.requestID != requestID ||
		result.domain != "lab.invalid" || result.err != nil || len(result.services) != 2 {
		t.Fatalf("discovery changed request identity or result: %+v", result)
	}
	if queries != 2 || !errors.Is(workerContext.Err(), context.Canceled) {
		t.Fatal("worker did not finish both lookups and release its context")
	}
	model.Update(result)
	if model.form != nil {
		t.Fatal("superseded discovery opened a form")
	}
}

func TestNewReadIntentsCancelDiscovery(t *testing.T) {
	for _, intent := range []string{"refresh", "connection", "discovery", "reconcile"} {
		t.Run(intent, func(t *testing.T) {
			model := testModel()
			resolver := discoveryResolverFunc(func(
				context.Context, string, string, string,
			) (string, []*net.SRV, error) {
				t.Fatal("superseded discovery performed a lookup")
				return "", nil, nil
			})
			command := model.startDiscovery("lab.invalid", resolver)
			switch intent {
			case "refresh":
				model.load("zones")
			case "connection":
				model.setConnection(model.settings)
			case "discovery":
				model.startDiscovery("other.invalid", resolver)
			case "reconcile":
				if err := model.state.RestoreUncertain(model.state.Snapshot()); err != nil {
					t.Fatal(err)
				}
				if model.reconcile() == nil {
					t.Fatal("reconciliation was not scheduled")
				}
			}
			defer model.readCancel()
			result := command().(discovered)
			if !errors.Is(result.err, context.Canceled) {
				t.Fatalf("discovery was not canceled: %v", result.err)
			}
			status := model.status
			model.Update(result)
			if model.form != nil || model.status != status {
				t.Fatal("canceled discovery changed the current interaction")
			}
		})
	}
}

func TestDiscoveryCancelsAndSupersedesOutstandingReads(t *testing.T) {
	model := testModel()
	operationContext, cancel := model.startRead(time.Second)
	defer cancel()
	previousRequestID := model.readID
	model.startDiscovery("lab.invalid", nil)
	defer model.readCancel()
	if !errors.Is(operationContext.Err(), context.Canceled) || model.readID <= previousRequestID {
		t.Fatal("discovery did not cancel and supersede the previous read")
	}
	status := model.status
	model.Update(readResult{
		generation: model.state.Snapshot().Generation, requestID: previousRequestID,
		kind: "dns", err: errors.New("late read failure"),
	})
	if len(model.records) != 0 || model.status != status {
		t.Fatal("superseded read replaced discovery state")
	}
}

func discoveryResult(model *Model) discovered {
	return discovered{
		generation: model.state.Snapshot().Generation, requestID: model.readID,
		domain:   "lab.invalid",
		services: []discovery.Service{{Kind: "ldap", Target: "dc.lab.invalid", Port: 389}},
	}
}

func TestDiscoveryCannotReplaceNewerInteractions(t *testing.T) {
	for _, interaction := range []string{
		"generation", "request", "form", "write form", "worker", "details",
	} {
		t.Run(interaction, func(t *testing.T) {
			model := testModel()
			model.readID = 1
			result := discoveryResult(model)
			switch interaction {
			case "generation":
				model.state.Change(model.settings)
			case "request":
				model.readID++
			case "form":
				model.searchForm()
			case "write form":
				model.zone = "lab.invalid"
				model.writeForm("a")
				if model.flow == nil || model.form == nil {
					t.Fatal("write reservation was not established")
				}
			case "worker":
				var err error
				model.flow, err = model.state.Begin()
				if err != nil {
					t.Fatal(err)
				}
			case "details":
				model.showDetails("current details")
			}
			if model.flow != nil {
				defer model.flow.Abort()
			}
			originalForm, originalFlow, status := model.form, model.flow, model.status
			// Even a late error must not obscure the newer interaction's status.
			for _, failure := range []error{nil, errors.New("late discovery failure")} {
				result.err = failure
				model.Update(result)
				if model.form != originalForm || model.flow != originalFlow || model.status != status {
					t.Fatal("discovery replaced an interaction or orphaned its write reservation")
				}
			}
		})
	}
}

func TestDiscoverySelectionRequiresCurrentRequest(t *testing.T) {
	for _, changed := range []string{"none", "generation", "request", "flow"} {
		t.Run(changed, func(t *testing.T) {
			model := testModel()
			model.readID = 1
			model.Update(discoveryResult(model))
			if model.form == nil || model.form.Title != "Select discovered DC" {
				t.Fatal("current discovery did not offer selection")
			}
			accept := model.form.Accept
			model.form = nil
			switch changed {
			case "generation":
				model.state.Change(model.settings)
			case "request":
				model.readID++
			case "flow":
				var err error
				model.flow, err = model.state.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer model.flow.Abort()
			}
			original := model.settings
			accept([]string{"selected.lab.invalid"})
			if changed != "none" {
				if model.settings != original || model.form != nil {
					t.Fatal("stale selection changed the connection")
				}
				return
			}
			if model.settings.Server != "selected.lab.invalid" ||
				model.settings.Domain != "lab.invalid" || model.settings.BaseDN != "DC=lab,DC=invalid" ||
				model.form == nil || model.form.Title != "Connection settings" {
				t.Fatal("selection bypassed connection review or lost its domain")
			}
		})
	}
}

func TestDiscoveryFailureAndEmptyResultsDoNotOfferSelection(t *testing.T) {
	failure := errors.New("lookup failed")
	for _, lookupError := range []error{nil, failure} {
		model := testModel()
		model.readID = 1
		result := discoveryResult(model)
		result.services, result.err = nil, lookupError
		model.Update(result)
		want := "No AD service endpoints discovered"
		if lookupError != nil {
			want = lookupError.Error()
		}
		if model.form != nil || model.status != want {
			t.Fatalf("unexpected discovery failure state: %s", model.status)
		}
	}
}
