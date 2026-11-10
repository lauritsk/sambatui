package tui

import (
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestOrdinaryTerminalKeepsZoneNamesAndTTLVisible(t *testing.T) {
	model := visualModel(t, "browser")
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	screen := assertFrame(t, model)
	for _, value := range []string{"2.0.192.in-addr.arpa", "TTL", "3600", "192.0.2.20"} {
		if !strings.Contains(screen, value) {
			t.Fatalf("80-column browser lost %q: %s", value, screen)
		}
	}
	indices := model.visible()
	before := model.tableGeometry(indices, 45)
	model.move(2)
	if after := model.tableGeometry(model.visible(), 45); before != after {
		t.Fatal("moving the cursor reflowed table columns", before, after)
	}
}

func TestLDAPNavigationSeparatesFiltersAndContainers(t *testing.T) {
	model := visualModel(t, "ldap")
	model.kind = "users"
	view := model.navigationView()
	if len(view.rows) != len(view.items)+1 || view.rows[5] != -1 {
		t.Fatal("navigation does not separate object kinds from paths", view.rows)
	}
	if view.items[0].label != "Users" || view.items[5].label != "Base/" ||
		view.items[6].label != "People/" {
		t.Fatal("navigation roles are ambiguous", view.items)
	}
	model.sideCursor = 4
	model.sidebar = true
	model.move(1)
	if model.sideCursor != 5 || model.navigationView().cursor != 6 {
		t.Fatal("keyboard focus stopped on a visual separator")
	}
	model.sideCursor = 1
	if model.navigationActive(model.navigationItems()[1]) ||
		!model.navigationActive(model.navigationItems()[0]) {
		t.Fatal("moving focus changed the active object kind")
	}
	command := model.activateSide()
	if command == nil || model.kind != "groups" {
		t.Fatal("activating a kind did not preserve its semantic target")
	}
	defer model.readCancel()
	model.Update(command())
}

func TestFormRowsAlignOnWideScreensAndStackOnNarrowOnes(t *testing.T) {
	model := visualModel(t, "form")
	model.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	wide := assertFrame(t, model)
	found := false
	for _, line := range strings.Split(wide, "\n") {
		if strings.Contains(line, "DC hostname") && strings.Contains(line, "dc.lab.invalid_") {
			found = true
		}
	}
	if !found || model.form.fieldLineCount(68) != 1 {
		t.Fatal("wide form does not align labels with their values", wide)
	}
	model.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	if model.form.fieldLineCount(36) != 2 {
		t.Fatal("narrow form did not switch to stacked fields")
	}
	assertFrame(t, model)
}

func TestChoiceControlsDoNotExposeInvalidEnumValues(t *testing.T) {
	model := visualModel(t, "form")
	current := model.form
	current.Cursor = connectionAuthField
	model.Update(tea.KeyMsg{Type: tea.KeyRight})
	if current.Fields[connectionAuthField].text() != "kerberos" {
		t.Fatal("right did not choose the next authentication mode")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("not-an-auth-mode"), Paste: true})
	if current.Fields[connectionAuthField].text() != "kerberos" {
		t.Fatal("paste introduced an invalid choice")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if current.Fields[connectionAuthField].text() != "password" {
		t.Fatal("left did not restore the previous choice")
	}
}

func TestCommandPaletteFiltersAndActivatesItsSelectedResult(t *testing.T) {
	model := visualModel(t, "browser")
	model.commandForm()
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("dir")})
	if items := model.form.filteredItems(); !reflect.DeepEqual(items, []string{"directory"}) {
		t.Fatal("palette did not filter its results", items)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("ldap")})
	if items := model.form.filteredItems(); !reflect.DeepEqual(items, []string{"directory"}) {
		t.Fatal("visible action labels are not searchable", items)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.form == nil || model.form.Title != "LDAP search" {
		t.Fatal("Enter did not activate the selected command")
	}
	model.closeForm()
	model.commandForm()
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("zzzz")})
	before := model.form
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.form != before || !strings.Contains(assertFrame(t, model), "No matching commands") {
		t.Fatal("an empty picker submitted or lost its query")
	}
}

func TestEditingUsesGraphemeBoundariesAndAnActualCaret(t *testing.T) {
	model := testModel()
	model.searchForm()
	current := model.form
	current.Fields[0].setText("A👩‍💻éZ")
	for _, key := range []tea.KeyType{tea.KeyHome, tea.KeyRight, tea.KeyRight, tea.KeyDelete} {
		model.Update(tea.KeyMsg{Type: key})
	}
	model.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if current.Fields[0].text() != "AZ" || current.caret(0) != 1 {
		t.Fatal("editing split an emoji or combining sequence", current.Fields[0].text())
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("é")})
	if current.Fields[0].text() != "AéZ" || current.caret(0) != len("Aé") {
		t.Fatal("insertion ignored the caret or split the inserted grapheme")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyHome})
	if screen := assertFrame(t, model); !strings.Contains(screen, "_AéZ") {
		t.Fatal("the displayed insertion point does not match the editor", screen)
	}
}

func TestInsertionBudgetIncludesTheUnchangedSuffix(t *testing.T) {
	model := testModel()
	model.searchForm()
	value := strings.Repeat("x", formFieldBytesMax)
	model.form.Fields[0].setText(value)
	model.Update(tea.KeyMsg{Type: tea.KeyHome})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if model.form.Fields[0].text() != value || model.form.caret(0) != 0 {
		t.Fatal("rejected insertion changed the value or caret")
	}
}
