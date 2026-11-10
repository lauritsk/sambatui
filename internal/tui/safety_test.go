package tui

import (
	"strings"
	"testing"

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
