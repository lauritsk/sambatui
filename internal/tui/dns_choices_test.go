package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestDNSRecordTypeChoicePreservesTheReservedFlow(t *testing.T) {
	model := testModel()
	model.zone = "lab.invalid"
	model.writeForm("a")
	owner := model.flow
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("not-a-type"), Paste: true})
	if model.form.Fields[0].text() != "A" {
		t.Fatal("paste introduced an invalid record type")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRight})
	if model.form.Fields[0].text() != "AAAA" {
		t.Fatal("arrow did not select the next record type")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if model.form == nil || model.form.Owner != owner || model.flow != owner {
		t.Fatal("type selection lost its original write reservation")
	}
	model.closeForm()
}
