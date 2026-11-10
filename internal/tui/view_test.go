package tui

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func assertFrame(t *testing.T, model *Model) string {
	t.Helper()
	view := model.View()
	lines := strings.Split(view, "\n")
	if len(lines) > model.height {
		t.Fatalf("frame has %d lines in %d rows", len(lines), model.height)
	}
	for index, line := range lines {
		if width := ansi.StringWidth(line); width > model.width {
			t.Fatalf("line %d is %d cells in %d columns: %q", index, width, model.width, line)
		}
	}
	return ansi.Strip(view)
}

func TestEveryViewFitsThroughRapidResizes(t *testing.T) {
	for _, theme := range []string{"dark", "light"} {
		for _, kind := range []string{"browser", "sidebar", "form", "details", "error"} {
			t.Run(theme+"/"+kind, func(t *testing.T) {
				model := testModel()
				if err := model.SetTheme(theme); err != nil {
					t.Fatal(err)
				}
				model.zones = []string{strings.Repeat("界é", 50)}
				model.records = []dnsrpc.Row{{Name: "界é🇪🇪", Type: "TXT", Value: strings.Repeat("long ", 100)}}
				model.status = strings.Repeat("status ", 100)
				switch kind {
				case "sidebar":
					model.sidebar = true
				case "form":
					model.connectionForm()
					model.form.Cursor = len(model.form.Fields) - 1
				case "details":
					model.showDetails(strings.Repeat("界é🇪🇪 long detail ", 100))
				case "error":
					model.error(errors.New(strings.Repeat("failure ", 100)))
				}
				for _, size := range [][2]int{
					{140, 42},
					{80, 24},
					{40, 12},
					{20, 8},
					{1, 1},
					{0, 0},
					{40, 8},
					{100, 30},
					{80, 24},
					{40, 12},
					{140, 42},
				} {
					model.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
					assertFrame(t, model)
				}
			})
		}
	}
}

func TestNarrowLayoutKeepsFocusedPaneAndRestoresContext(t *testing.T) {
	model := testModel()
	model.records = make([]dnsrpc.Row, 30)
	model.zones = make([]string, 30)
	for index := range model.records {
		model.records[index].Name = fmt.Sprintf("record-%02d", index)
		model.zones[index] = fmt.Sprintf("zone-%02d", index)
	}
	model.cursor, model.sideCursor = 28, 27
	model.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	if view := assertFrame(t, model); !strings.Contains(view, ">  record-28") ||
		strings.Contains(view, "zone-27") {
		t.Fatal("narrow layout did not prioritize focused results", view)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyTab})
	if view := assertFrame(t, model); !strings.Contains(view, ">  zone-27") ||
		strings.Contains(view, "record-28") {
		t.Fatal("Tab did not reveal the retained sidebar cursor", view)
	}
	model.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	view := assertFrame(t, model)
	if !strings.Contains(view, "record-28") || !strings.Contains(view, "zone-27") {
		t.Fatal("widening did not restore both panes", view)
	}
}

func TestSidebarCursorClampsWhenRefreshRemovesItems(t *testing.T) {
	model := testModel()
	model.zones = []string{"old-1.invalid", "old-2.invalid", "old-3.invalid"}
	model.sidebar, model.sideCursor = true, 2
	_, command := model.Update(readResult{
		generation: model.state.Snapshot().Generation,
		requestID:  model.readID,
		kind:       "zones", zones: []string{"remaining.invalid"},
	})
	if command != nil {
		defer model.readCancel()
	}
	if model.sideCursor != 0 || model.sideLabels()[model.sideCursor] != "remaining.invalid" {
		t.Fatal("sidebar action target did not follow the clamped viewport")
	}
}

func TestModalOwnsPrintableInputAndRestoresFocus(t *testing.T) {
	model := testModel()
	model.sidebar, model.sideCursor = true, 2
	model.searchForm()
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("qj/!d"), Paste: true})
	if model.form.Fields[0].text() != "qj/!d" || model.flow != nil || model.detail != "" {
		t.Fatal("text input fired a global action")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.form != nil || !model.sidebar || model.sideCursor != 2 {
		t.Fatal("closing the modal did not restore browser focus")
	}
}

func TestFormKeepsActiveFieldAndInsertionPointVisible(t *testing.T) {
	model := testModel()
	model.connectionForm()
	model.form.Cursor = len(model.form.Fields) - 1
	current := &model.form.Fields[model.form.Cursor]
	current.setText(strings.Repeat("界é", 40) + "END")
	model.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	view := assertFrame(t, model)
	if !strings.Contains(view, Literal(current.Label)) || !strings.Contains(view, "END_") {
		t.Fatal("active field or insertion point is offscreen", view)
	}
	model.form.Context = strings.Repeat("preview text ", 100)
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	for index := 0; index < 100; index++ {
		model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	}
	before := model.form.ContextOffset
	model.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	if model.form.ContextOffset >= before {
		t.Fatal("preview overscroll swallowed page-up")
	}
}

func TestWrappedDetailsScrollToEndWithoutChangingBrowser(t *testing.T) {
	model := testModel()
	model.width, model.height = 40, 12
	model.cursor, model.sideCursor, model.sidebar = 7, 3, true
	model.showDetails(strings.Repeat("one line of long content ", 60) + "THE-END")
	for index := 0; index < 100; index++ {
		model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	}
	if view := assertFrame(t, model); !strings.Contains(view, "THE-END") {
		t.Fatal("wrapped detail tail cannot be reached", view)
	}
	model.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	model.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	if model.detailOffset != 0 {
		t.Fatal("resize left the detail cursor beyond the new viewport")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.cursor != 7 || model.sideCursor != 3 || !model.sidebar {
		t.Fatal("detail overlay changed browser state")
	}
}

func TestErrorIsRetrievableAfterStatusChangesAndRedacted(t *testing.T) {
	model := testModel()
	model.error(errors.New("failed: " + model.settings.Password.Reveal() + "\x1b[2J"))
	model.status = "Loading another view"
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("!")})
	view := assertFrame(t, model)
	if !strings.Contains(view, "Last error") || !strings.Contains(view, "[redacted]") ||
		!strings.Contains(view, `\u001b[2J`) || strings.Contains(view, "secret password") {
		t.Fatal("last error disappeared or exposed unsafe content", view)
	}
}

func TestRenderingDoesNotMutateStateAndLoadingRejectsStaleCompletion(t *testing.T) {
	model := testModel()
	model.cursor, model.sideCursor, model.detailOffset = 100, 100, 100
	before := *model
	model.View()
	if !reflect.DeepEqual(*model, before) {
		t.Fatal("drawing mutated state")
	}
	command := model.load("dns")
	defer model.readCancel()
	model.Update(readResult{generation: model.state.Snapshot().Generation, requestID: model.readID - 1})
	if model.loading != "dns" {
		t.Fatal("stale completion hid active loading state")
	}
	model.Update(command())
	if model.loading != "" {
		t.Fatal("current completion retained loading state")
	}
}

func TestPreviewCannotBeSubmittedWhenItIsHidden(t *testing.T) {
	model := testModel()
	model.records = []dnsrpc.Row{{Name: "host", Type: "A", Value: "192.0.2.1"}}
	model.zone = "lab.invalid"
	model.width, model.height = 40, 6
	model.writeForm("d")
	model.form.Fields[0].setText("yes")
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if command != nil || model.form == nil || len(model.service.(*fakeService).plans) != 0 {
		t.Fatal("a hidden confirmation dispatched a write")
	}
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	_, command = model.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if command == nil {
		t.Fatal("resizing did not recover the reviewed confirmation")
	}
	model.Update(command())
}

func TestSuspendIsExplicitAndBlockedDuringWrites(t *testing.T) {
	model := testModel()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyCtrlZ})
	if command == nil {
		t.Fatal("Ctrl+Z was ignored")
	}
	if _, ok := command().(tea.SuspendMsg); !ok {
		t.Fatal("Ctrl+Z did not use the framework's terminal lifecycle")
	}
	model.records = []dnsrpc.Row{{Name: "host", Type: "A", Value: "192.0.2.1"}}
	model.zone = "lab.invalid"
	model.writeForm("d")
	write := submit(model, "yes")
	_, command = model.Update(tea.KeyMsg{Type: tea.KeyCtrlZ})
	if command != nil || !strings.Contains(model.status, "Cannot suspend") {
		t.Fatal("running write was suspended")
	}
	_, command = model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if command != nil || !strings.Contains(model.status, "not rollback") {
		t.Fatal("Ctrl+C quit instead of cancelling/draining the write")
	}
	model.Update(write())
}

func TestBackspaceErasesWholeGraphemes(t *testing.T) {
	for _, text := range []string{"é", "界", "🇪🇪", "👩‍💻", "👍🏽"} {
		value := "prefix" + text
		if actual := value[:previousBoundary(value, len(value))]; actual != "prefix" {
			t.Fatalf("backspace split %q: %q", text, actual)
		}
	}
	if previousBoundary("", 0) != 0 {
		t.Fatal("empty backspace changed the field")
	}
}
