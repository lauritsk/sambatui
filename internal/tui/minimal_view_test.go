package tui

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestBrowserUsesOneContextRowAndOneFooter(t *testing.T) {
	for _, width := range []int{40, 80, 120} {
		model := visualModel(t, "browser")
		model.Update(tea.WindowSizeMsg{Width: width, Height: 24})
		screen := assertFrame(t, model)
		rows := strings.Split(screen, "\n")
		if !strings.Contains(rows[0], model.settings.Server) ||
			!strings.Contains(rows[0], model.zone) {
			t.Fatal("context row lost the target", rows[0])
		}
		if !strings.ContainsAny(rows[1], "╭┏") || !strings.ContainsAny(rows[22], "╰┗") {
			t.Fatal("data panes do not use all rows between the header and footer", screen)
		}
		if !strings.Contains(rows[23], "? help") || !strings.Contains(rows[23], "Q quit") {
			t.Fatal("footer lost help or quit", rows[23])
		}
		for _, redundant := range []string{
			"sambatui", "Ready", "Auth:", "TLS:", "0 selected", "Name asc",
			"[ ]", "Preview ", "Field ", "not rollback", "! error",
		} {
			if strings.Contains(screen, redundant) {
				t.Fatalf("idle view contains %q: %s", redundant, screen)
			}
		}
	}
}

func TestSelectionAndSortIndicatorsAppearOnlyWhenActive(t *testing.T) {
	model := visualModel(t, "browser")
	before := assertFrame(t, model)
	if strings.Contains(before, "selected") || strings.Contains(before, "TYPE ↓") {
		t.Fatal("idle view shows inactive state", before)
	}
	model.selected[model.visible()[model.cursor]] = true
	if screen := assertFrame(t, model); !strings.Contains(screen, "1 selected") ||
		!strings.Contains(screen, ">* ") {
		t.Fatal("selection is not explicit", screen)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	if screen := assertFrame(t, model); !strings.Contains(screen, "TYPE ↓") {
		t.Fatal("changed sort is not shown in the column heading", screen)
	}
}

func TestSingleFieldDialogDoesNotDuplicateLabelsOrFillTheViewport(t *testing.T) {
	model := visualModel(t, "filter")
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	screen := assertFrame(t, model)
	nonempty := []string{}
	for _, row := range strings.Split(screen, "\n") {
		if strings.TrimSpace(row) != "" {
			nonempty = append(nonempty, row)
		}
	}
	if !strings.Contains(nonempty[0], model.zone) {
		t.Fatal("filter dialog lost the data scope", nonempty[0])
	}
	if len(nonempty) != 5 || strings.Count(screen, "Filter") != 1 {
		t.Fatal("single-field dialog has unnecessary rows or repeated headings", screen)
	}
	for _, redundant := range []string{
		"Search", "Tab next", "Preview", "Field 1/", "local filter",
	} {
		if strings.Contains(screen, redundant) {
			t.Fatalf("filter contains redundant %q: %s", redundant, screen)
		}
	}
}

func TestScrollHintsRequireHiddenContent(t *testing.T) {
	model := visualModel(t, "browser")
	model.showDetails("Short detail")
	if screen := assertFrame(t, model); strings.Contains(screen, "PgUp/Dn") {
		t.Fatal("short detail advertises unavailable scrolling", screen)
	}
	model.showDetails(strings.Repeat("Long detail\n", 100))
	if screen := assertFrame(t, model); !strings.Contains(screen, "PgUp/Dn") {
		t.Fatal("hidden detail content has no scroll affordance", screen)
	}
	if scrollHint(0, 3, 20) != "" || scrollHint(0, 30, 20) != "↓" ||
		scrollHint(29, 30, 20) != "↑" {
		t.Fatal("list scroll hints do not reflect hidden content")
	}
}

func TestRoutineReadsAndDismissalsLeaveNoStatusChatter(t *testing.T) {
	model := visualModel(t, "browser")
	model.searchForm()
	model.closeForm()
	if model.status != "" {
		t.Fatal("dismissal left a status notice")
	}
	command := model.load("dns")
	if screen := assertFrame(t, model); strings.Count(screen, "Loading dns") != 1 ||
		strings.Contains(screen, "No records") {
		t.Fatal("loading state is repeated or contradicted", screen)
	}
	model.Update(command())
	if model.status != "" || strings.Contains(assertFrame(t, model), "Loaded") {
		t.Fatal("successful read left a redundant completion notice")
	}
}

func TestFooterPreservesErrorAccessAndWriteSafety(t *testing.T) {
	model := visualModel(t, "browser")
	model.width = 40
	model.error(errors.New(strings.Repeat("network error ", 20)))
	footer := ansi.Strip(model.footerLine(len(model.records)))
	if !strings.Contains(footer, "Error:") || !strings.Contains(footer, "! details") {
		t.Fatal("error message hid its recovery action", footer)
	}
	operationContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	model.writeCancel = cancel
	model.lastWrite = model.state.Snapshot()
	footer = ansi.Strip(model.footerLine(len(model.records)))
	if !strings.Contains(footer, "Ctrl+C") || !strings.Contains(footer, "not rollback") ||
		strings.Contains(footer, "! error") {
		t.Fatal("stale error displaced write cancellation guidance", footer)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if operationContext.Err() == nil ||
		!strings.Contains(ansi.Strip(model.footerLine(0)), "Cancelling") {
		t.Fatal("write cancellation is not explicit")
	}
}

func TestConnectionOnlyShowsFieldsUsedByItsAuthenticationMode(t *testing.T) {
	model := testModel()
	model.connectionForm()
	current := model.form
	password := current.Fields[connectionPasswordField].text()
	for _, index := range []int{connectionCacheField, connectionKerberosConfigField} {
		if slices.Contains(current.fieldIndices(), index) {
			t.Fatal("password/NTLM setup shows unused Kerberos settings")
		}
	}
	current.Cursor = connectionCAField
	model.Update(tea.KeyMsg{Type: tea.KeyTab})
	if current.Cursor != connectionPTRField {
		t.Fatal("Tab focused a hidden field")
	}
	current.Cursor = connectionAuthField
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("kerberos")})
	for _, index := range []int{
		connectionUserField, connectionPasswordField,
		connectionDNSAuthField, connectionPasswordFileField,
	} {
		if slices.Contains(current.fieldIndices(), index) {
			t.Fatal("Kerberos setup shows unused password settings")
		}
	}
	for _, index := range []int{connectionCacheField, connectionKerberosConfigField} {
		if !slices.Contains(current.fieldIndices(), index) {
			t.Fatal("Kerberos setup hid a required setting")
		}
	}
	model.Update(tea.KeyMsg{Type: tea.KeyTab})
	if current.Cursor != connectionTLSField {
		t.Fatal("Tab did not follow the visible Kerberos fields")
	}
	current.Cursor = connectionAuthField
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("password")})
	if current.Fields[connectionPasswordField].text() != password {
		t.Fatal("hiding a field discarded its editing state")
	}
}

func TestViewedErrorStaysRetrievableWithoutAnUnreadBadge(t *testing.T) {
	model := visualModel(t, "browser")
	model.error(errors.New("network unavailable"))
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("!")})
	if model.errorUnread || !strings.Contains(model.detail, "network unavailable") {
		t.Fatal("viewing the error did not acknowledge it")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if strings.Contains(assertFrame(t, model), "! error") || model.lastError == "" {
		t.Fatal("viewed error remained noisy or was discarded")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("!")})
	if !strings.Contains(model.detail, "network unavailable") {
		t.Fatal("acknowledged error is no longer retrievable")
	}
}

func TestCommandsOnlyAdvertiseAvailableActions(t *testing.T) {
	model := testModel()
	model.settings.Server = ""
	want := []string{"connection", "discover", "help"}
	if names := model.commandNames(); !slices.Equal(names, want) {
		t.Fatal("unconfigured view advertises unavailable commands", names)
	}
	model = visualModel(t, "browser")
	if names := model.commandNames(); slices.Contains(names, "error") ||
		slices.Contains(names, "reconcile") || !slices.Contains(names, "delete") {
		t.Fatal("command list includes inactive recovery or misses a valid action", names)
	}
	if err := model.state.RestoreUncertain(model.state.Snapshot()); err != nil {
		t.Fatal(err)
	}
	names := model.commandNames()
	if !slices.Contains(names, "reconcile") || slices.Contains(names, "add") ||
		slices.Contains(names, "update") || slices.Contains(names, "delete") {
		t.Fatal("uncertain outcome advertises blocked writes", names)
	}
}

func TestDecliningConfirmationIsNotRecordedAsAnError(t *testing.T) {
	model := visualModel(t, "browser")
	model.writeForm("d")
	command := submit(model, "no")
	if command != nil || model.flow != nil || model.lastError != "" ||
		len(model.service.(*fakeService).plans) != 0 {
		t.Fatal("declining a write dispatched work or created a durable error")
	}
}
