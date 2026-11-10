package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/lauritsk/sambatui/internal/invariant"
)

const navigationHelp = "Tab pane · Enter details/open · z DNS · l LDAP · 1–8 findings · " +
	"a/u/d write · f fix\n/ search · space select · v range · s sort · r refresh · " +
	"R reconcile · Ctrl+O setup · ? help · Q quit"

func (model *Model) View() string {
	model.assertValid()
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	header := title.Render("sambatui — native Go") + fmt.Sprintf(
		"\nDC: %s  Auth: %s  TLS: %s\n",
		Literal(model.settings.Server), Literal(model.settings.Auth),
		Literal(model.settings.Encryption),
	)
	if model.form != nil {
		return header + model.formView() + "\n" + Literal(model.status)
	}
	if model.detail != "" {
		return header + model.viewDetail()
	}
	height := max(1, model.height-9)
	sideWidth := min(32, max(16, model.width/4))
	left := lipgloss.NewStyle().Width(sideWidth).MaxWidth(sideWidth).Render(
		strings.Join(model.viewSidebar(height), "\n"),
	)
	right := lipgloss.NewStyle().MaxWidth(max(1, model.width-sideWidth-2)).Render(
		strings.Join(model.viewRows(height), "\n"),
	)
	return header + fmt.Sprintf(
		"%s  zone=%s  base=%s  search=%s\n",
		model.mode, Literal(model.zone), Literal(model.base), Literal(model.search),
	) + lipgloss.JoinHorizontal(lipgloss.Top, left, " │ "+right) +
		"\n" + Literal(model.status) + "\n" + navigationHelp
}

func (model *Model) viewDetail() string {
	lines := strings.Split(model.detail, "\n")
	start := min(model.detailOffset, max(0, len(lines)-1))
	var output strings.Builder
	for _, line := range lines[start:min(len(lines), start+max(1, model.height-7))] {
		output.WriteString(Literal(line))
		output.WriteByte('\n')
	}
	output.WriteString("j/k scroll · Esc close\n")
	return output.String()
}

func (model *Model) viewSidebar(height int) []string {
	invariant.Require(height > 0, "sidebar requires a positive viewport")
	invariant.Require(height <= terminalRowsMax, "sidebar viewport exceeds terminal limit")
	labels := model.sideLabels()
	start := min(max(0, len(labels)-height), max(0, model.sideCursor-height+1))
	rows := make([]string, height)
	for index := start; index < min(len(labels), start+height); index++ {
		mark := "  "
		if index == model.sideCursor && model.sidebar {
			mark = "> "
		}
		rows[index-start] = mark + Literal(labels[index])
	}
	return rows
}

func (model *Model) viewRows(height int) []string {
	invariant.Require(height > 0, "results require a positive viewport")
	invariant.Require(height <= terminalRowsMax, "results viewport exceeds terminal limit")
	texts := model.rowTexts()
	indices := model.visibleTexts(texts)
	start := max(0, model.cursor-height+1)
	rows := make([]string, height)
	for position := start; position < min(len(indices), start+height); position++ {
		index := indices[position]
		mark := "  "
		if model.selected[index] {
			mark = "✓ "
		}
		if position == model.cursor && !model.sidebar {
			mark = "> " + mark
		}
		rows[position-start] = mark + texts[index]
	}
	return rows
}
