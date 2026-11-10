package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestFilterPasteDoesNotSubmitButEnterAppliesIt(t *testing.T) {
	model := testModel()
	model.searchForm()
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("value\n"), Paste: true})
	if model.form == nil || model.form.Fields[0].text() != "value" {
		t.Fatal("paste submitted the dialog or retained a control character")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.form != nil || model.search != "value" {
		t.Fatal("Enter did not apply the local filter")
	}
}

func TestCommandPickerSearchesLabelsAndExecutesOnlyASelectedMatch(t *testing.T) {
	model := testModel()
	model.commandForm()
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("ldap")})
	if items := model.form.filteredItems(); len(items) != 1 || items[0] != "directory" {
		t.Fatal("visible labels are not searchable", items)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.form == nil || model.form.Title != "LDAP search" {
		t.Fatal("selected command did not run")
	}
	model.closeForm()
	model.commandForm()
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("zzzz")})
	before := model.form
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.form != before {
		t.Fatal("an empty result set submitted a command")
	}
}
