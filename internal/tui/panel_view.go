package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/invariant"
)

func (palette theme) panel(
	title, footer string, content []string, width, height int, focused bool,
) []string {
	invariant.Require(width >= 8 && width <= terminalColumnsMax, "invalid panel width")
	invariant.Require(height >= 3 && height <= terminalRowsMax, "invalid panel height")
	invariant.Require(len(content) <= height-2, "panel content exceeds its viewport")
	style := palette.border
	topLeft, topRight, bottomLeft, bottomRight, horizontal, vertical :=
		"╭", "╮", "╰", "╯", "─", "│"
	if focused {
		style = palette.focus
		topLeft, topRight, bottomLeft, bottomRight, horizontal, vertical =
			"┏", "┓", "┗", "┛", "━", "┃"
	}
	rows := make([]string, height)
	rows[0] = style.Render(panelEdge(title, width, topLeft, topRight, horizontal))
	side := style.Render(vertical)
	for index := 1; index < height-1; index++ {
		text := ""
		if index-1 < len(content) {
			text = content[index-1]
		}
		rows[index] = side + " " + cell(text, width-4) + " " + side
	}
	rows[height-1] = style.Render(
		panelEdge(footer, width, bottomLeft, bottomRight, horizontal),
	)
	return rows
}

func panelEdge(label string, width int, left, right, horizontal string) string {
	label = ansi.Truncate(" "+label+" ", width-4, "…")
	if strings.TrimSpace(label) == "" {
		label = ""
	}
	return left + horizontal + label +
		strings.Repeat(horizontal, width-3-ansi.StringWidth(label)) + right
}

func (model *Model) headerLine() string {
	text := "Not connected"
	if model.settings.Server != "" {
		text = Literal(model.settings.Server)
		if model.form == nil || model.form.ShowScope {
			text += " · " + strings.ToUpper(model.mode)
			scope := model.zone
			if model.mode == "ldap" {
				scope = model.base
			}
			if scope != "" {
				text += " · " + Literal(scope)
			}
		}
	}
	return model.theme.chrome.Bold(true).Render(cell(text, model.width))
}
