package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lauritsk/sambatui/internal/config"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func TestCoalescedNavigationDoesNotRecurseAndPasteCannotExecute(t *testing.T) {
	model := testModel()
	model.records = []dnsrpc.Row{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("jj")})
	if model.cursor != 2 {
		t.Fatalf("coalesced navigation moved to %d", model.cursor)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("daQ"), Paste: true})
	if model.form != nil || model.flow != nil {
		t.Fatal("paste opened a write flow")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(strings.Repeat("d", commandRunesMax+1))})
	if model.form != nil || model.flow != nil {
		t.Fatal("oversized message executed commands")
	}
}

func TestFormPasteIsBoundedAndAtomic(t *testing.T) {
	model := testModel()
	model.searchForm()
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("one\x1btwo"), Paste: true})
	if actual := model.form.Fields[0].text(); actual != "onetwo" {
		t.Fatalf("unfiltered paste: %q", actual)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(strings.Repeat("x", formFieldBytesMax))})
	if actual := model.form.Fields[0].text(); actual != "onetwo" {
		t.Fatal("rejected paste partially modified field")
	}
}

func TestFormInputPreservesSecretWhitespaceAndUTF8Boundaries(t *testing.T) {
	secret := field{Value: " \t", Secret: true}
	if actual, err := formInput(secret, []rune("é\t ")); err != nil || actual != " \té\t " {
		t.Fatalf("secret whitespace changed: %q %v", actual, err)
	}
	current := field{Value: strings.Repeat("x", formFieldBytesMax-2)}
	if value, err := formInput(current, []rune("é")); err != nil || len(value) != formFieldBytesMax {
		t.Fatal("exact byte boundary rejected", err)
	}
	if _, err := formInput(current, []rune("€")); err == nil {
		t.Fatal("multibyte input exceeded byte bound")
	}
}

func TestIncompleteDNSHealthNeverOffersCrossZoneFixes(t *testing.T) {
	service := &fakeService{records: func(
		_ context.Context, _ config.Settings, zone, _ string, _ uint16,
	) ([]dnsrpc.Row, error) {
		if zone == "lab.invalid" {
			return []dnsrpc.Row{{Name: "host", Type: "A", Value: "192.0.2.1"}}, nil
		}
		return nil, errors.New("reverse zone unavailable")
	}}
	findings, complete := readHealthDNS(context.Background(), service, config.Defaults(), 8)
	if complete || len(findings) != 1 || findings[0].Severity != "error" {
		t.Fatalf("incomplete read reported clean: %+v", findings)
	}
	for _, finding := range findings {
		if finding.Fix != "" {
			t.Fatal("incomplete DNS evidence offered a fix")
		}
	}
}

func TestDNSHealthBudgetBoundaries(t *testing.T) {
	rows := []dnsrpc.Row{{Name: "a", Type: "A", Value: "1"}}
	if size, err := readHealthDNSBudget(rows, 1, 3); err != nil || size != 3 {
		t.Fatalf("exact budget: %d, %v", size, err)
	}
	if _, err := readHealthDNSBudget(rows, 0, 3); err == nil {
		t.Fatal("exceeded row budget")
	}
	if _, err := readHealthDNSBudget(rows, 1, 2); err == nil {
		t.Fatal("exceeded byte budget")
	}
}

func TestDNSHealthStopsImmediatelyWhenBudgetIsExceeded(t *testing.T) {
	calls := 0
	service := &fakeService{records: func(
		context.Context, config.Settings, string, string, uint16,
	) ([]dnsrpc.Row, error) {
		calls++
		return make([]dnsrpc.Row, healthDNSRowsMax+1), nil
	}}
	findings, complete := readHealthDNS(context.Background(), service, config.Defaults(), 8)
	if complete || calls != 1 || len(findings) != 1 || findings[0].Severity != "error" {
		t.Fatalf("oversize read: complete %v, calls %d, findings %+v", complete, calls, findings)
	}
}
