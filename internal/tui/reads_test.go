package tui

import (
	"context"
	"errors"
	"reflect"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/miekg/dns"
)

type readService struct {
	fakeService
	search func(context.Context, config.Settings, string, string, string, int) ([]directory.Entry, error)
}

func (service *readService) Search(
	ctx context.Context, settings config.Settings, base, kind, query string, limit int,
) ([]directory.Entry, error) {
	return service.search(ctx, settings, base, kind, query, limit)
}

func TestStartupReadsOnlyTheSelectedDNSZone(t *testing.T) {
	model := testModel()
	model.zone = "lab.invalid"
	service := &readService{search: func(
		context.Context, config.Settings, string, string, string, int,
	) ([]directory.Entry, error) {
		t.Fatal("DNS startup performed an LDAP search")
		return nil, nil
	}}
	calls := 0
	service.records = func(
		_ context.Context, settings config.Settings, zone, name string, recordType uint16,
	) ([]dnsrpc.Row, error) {
		calls++
		if settings.Server != model.settings.Server || zone != "lab.invalid" ||
			name != "@" || recordType != dns.TypeANY {
			t.Fatal("startup read outside the selected DNS zone")
		}
		return []dnsrpc.Row{{Name: "host", Type: "A", Value: "192.0.2.1"}}, nil
	}
	model.service = service
	command := model.Init()
	if command == nil {
		t.Fatal("startup did not enumerate zones")
	}
	_, command = model.Update(command())
	if command == nil {
		t.Fatal("startup did not load the selected zone")
	}
	model.Update(command())
	if calls != 1 || model.mode != "dns" || len(model.records) != 1 {
		t.Fatalf("unexpected startup state: calls=%d records=%d", calls, len(model.records))
	}
}

func TestLDAPReadsOnlyTheRequestedViewAndContainers(t *testing.T) {
	for _, failed := range []bool{false, true} {
		model := testModel()
		model.base = "OU=People," + model.settings.BaseDN
		model.query = "alice"
		calls := []string{}
		failure := errors.New("search refused")
		service := &readService{search: func(
			_ context.Context, settings config.Settings, base, kind, query string, limit int,
		) ([]directory.Entry, error) {
			calls = append(calls, kind)
			if base != model.base || limit != settings.LDAPMaxRows {
				t.Fatal("LDAP view lost its requested scope or limit")
			}
			if kind == "users" {
				if query != "alice" {
					t.Fatal("LDAP view lost its query")
				}
				if failed {
					return nil, failure
				}
				return []directory.Entry{{Name: "Alice"}}, nil
			}
			if kind != "containers" || query != "" {
				t.Fatal("LDAP view performed an unrelated search")
			}
			return []directory.Entry{{Name: "People"}}, nil
		}}
		model.service = service
		model.Update(model.load("ldap")())
		want := []string{"users", "containers"}
		if failed {
			want = []string{"users"}
			if model.status != failure.Error() || len(model.entries) != 0 {
				t.Fatal("failed LDAP search published rows or hid the failure")
			}
		} else if len(model.entries) != 1 || len(model.folders) != 1 {
			t.Fatal("LDAP view did not publish entries and containers")
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("searches: %v, want %v", calls, want)
		}
	}
}

func TestRemovedActionsCannotStartWork(t *testing.T) {
	for _, mode := range []string{"dns", "ldap"} {
		model := testModel()
		model.setMode(mode)
		for _, key := range "12345678hf" {
			_, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
			if command != nil || model.form != nil || model.flow != nil || model.mode != mode {
				t.Fatalf("unbound key %q started work", key)
			}
		}
		for _, command := range []string{"health", "fix", "thresholds"} {
			model.commandForm()
			if submit(model, command) != nil || model.form != nil || model.flow != nil ||
				model.status != "Unknown command" {
				t.Fatalf("removed command %q started work", command)
			}
		}
	}
}
