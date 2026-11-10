package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func TestValidationKeepsTheOriginalDraftAndWriteReservation(t *testing.T) {
	model := testModel()
	model.zone = "lab.invalid"
	model.records = []dnsrpc.Row{{Name: "host", Type: "A", Value: "192.0.2.1", TTL: 900}}
	model.writeForm("u")
	draft, owner := model.form, model.flow
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("invalid-address")})
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if model.form != draft || model.flow != owner {
		t.Fatal("validation discarded the draft or its owner")
	}
	draft.Fields[0].setText("192.0.2.2")
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if model.form == nil || model.form == draft || model.form.Owner != owner {
		t.Fatal("correction changed the write owner")
	}
	model.closeForm()
}

func TestConnectionValidationPreservesAnInvalidTimeoutForCorrection(t *testing.T) {
	model := testModel()
	model.connectionForm()
	draft := model.form
	draft.Fields[len(draft.Fields)-1].setText("0")
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if model.form != draft || model.errorUnread {
		t.Fatal("inline validation discarded the draft or produced a second notification")
	}
}
