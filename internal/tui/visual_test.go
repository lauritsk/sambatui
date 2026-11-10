package tui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func visualModel(t *testing.T, view string) *Model {
	t.Helper()
	model := testModel()
	model.configPath = t.TempDir() + "/preferences.json"
	model.zone = "lab.invalid"
	model.zones = []string{"lab.invalid", "_msdcs.lab.invalid", "2.0.192.in-addr.arpa"}
	model.records = []dnsrpc.Row{
		{Name: "@", Type: "NS", TTL: 3600, Value: "dc.lab.invalid."},
		{Name: "dc", Type: "A", TTL: 3600, Value: "192.0.2.10"},
		{Name: "files", Type: "A", TTL: 3600, Value: "192.0.2.20"},
		{Name: "mail", Type: "MX", TTL: 3600, Value: "10 mail.lab.invalid."},
		{Name: "www", Type: "CNAME", TTL: 3600, Value: "files.lab.invalid."},
		{Name: "_ldap._tcp", Type: "SRV", TTL: 600, Value: "0 100 389 dc.lab.invalid."},
		{Name: "notes", Type: "TXT", TTL: 300, Value: "Sample data — not a live directory"},
	}
	model.entries = []directory.Entry{
		{Name: "Alice Example", Kind: "user", DN: "CN=Alice,OU=People,DC=lab,DC=invalid"},
		{Name: "IT Administrators", Kind: "group", DN: "CN=IT Admins,DC=lab,DC=invalid"},
		{Name: "WORKSTATION-01", Kind: "computer", DN: "CN=WORKSTATION-01,DC=lab,DC=invalid"},
	}
	model.folders = []directory.Entry{{Name: "People", DN: "OU=People,DC=lab,DC=invalid"}}
	model.cursor = 3
	switch view {
	case "form":
		model.connectionForm()
	case "filter":
		model.searchForm()
	case "commands":
		model.commandForm()
	case "ldap-add":
		model.setMode("ldap")
		model.writeForm("a")
	case "ldap":
		model.setMode("ldap")
		model.kind = "all"
	case "details":
		model.details()
	}
	model.status = ""
	return model
}

func TestStructuredBrowserAndDialogFrames(t *testing.T) {
	for _, view := range []string{"browser", "ldap", "form", "details"} {
		t.Run(view, func(t *testing.T) {
			model := visualModel(t, view)
			model.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
			screen := assertFrame(t, model)
			if !strings.Contains(screen, "┏━") || !strings.Contains(screen, "┗━") {
				t.Fatal("focused region has no visible frame", screen)
			}
			if view == "browser" || view == "ldap" {
				for _, label := range []string{"╭─", "NAME"} {
					if !strings.Contains(screen, label) {
						t.Fatalf("missing browser structure %q: %s", label, screen)
					}
				}
			}
			if view == "browser" && !strings.Contains(screen, "TTL") {
				t.Fatal("wide DNS table has no TTL heading", screen)
			}
			if view == "form" && !strings.Contains(screen, "[hidden]") {
				t.Fatal("structured form did not mask the password", screen)
			}
		})
	}
}

func TestPanelFootprintsKeepBordersAndCellWidths(t *testing.T) {
	palette := newTheme(false)
	for _, width := range []int{8, 20, 40, terminalColumnsMax} {
		for _, focused := range []bool{false, true} {
			rows := palette.panel("界é title", "footer", []string{strings.Repeat("界é", 30)},
				width, 4, focused)
			if len(rows) != 4 {
				t.Fatal("panel changed its allocated height")
			}
			for _, row := range rows {
				if ansi.StringWidth(row) != width {
					t.Fatal("panel border or content escaped its width", row)
				}
			}
		}
	}
}

func TestTableHeaderAndWideNamesShareColumnGeometry(t *testing.T) {
	model := testModel()
	for _, mode := range []string{"dns", "ldap"} {
		model.setMode(mode)
		for _, width := range []int{32, 60, 90} {
			model.records = []dnsrpc.Row{{Name: "界é", Type: "A", TTL: ^uint32(0)}}
			model.entries = []directory.Entry{{Name: "界é", Kind: "A"}}
			geometry := model.tableGeometry([]int{0}, width)
			header := geometry.columns("NAME", "KIND", "TTL", "VALUE")
			row := geometry.columns("界é", "A", "4294967295", "192.0.2.10")
			headerWidth := ansi.StringWidth(header[:strings.Index(header, "VALUE")])
			rowWidth := ansi.StringWidth(row[:strings.Index(row, "192.0.2.10")])
			if headerWidth != rowWidth || ansi.StringWidth(row) != width {
				t.Fatal("column alignment changed with wide text or maximum TTL", header, row)
			}
		}
	}
}

// Keep the fake backend across updates; previews must never contact a DC.
type visualPreview struct{ *Model }

func (preview visualPreview) Init() tea.Cmd { return nil }

func (preview visualPreview) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	_, command := preview.Model.Update(message)
	return preview, command
}

func TestVisualPreview(t *testing.T) {
	if os.Getenv("SAMBATUI_VISUAL_PREVIEW") != "1" {
		t.Skip("opt-in local visual fixture")
	}
	model := visualModel(t, os.Getenv("SAMBATUI_VISUAL_VIEW"))
	if name := os.Getenv("SAMBATUI_VISUAL_THEME"); name != "" {
		if err := model.SetTheme(name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tea.NewProgram(visualPreview{model}, tea.WithAltScreen()).Run(); err != nil {
		t.Fatal(err)
	}
}
