package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/invariant"
)

func (model *Model) bodyHeight() int {
	return max(2, model.height-2)
}

func (model *Model) View() string {
	model.assertValid()
	if model.width < 20 || model.height < 6 {
		return frame([]string{"Resize to 20x6", "Ctrl+C quit/cancel"}, model.width, model.height)
	}
	var body []string
	var indices []int
	switch {
	case model.form != nil:
		body = model.formLines(model.bodyHeight())
	case model.detail != "":
		body = model.detailLines(model.bodyHeight())
	default:
		indices = model.visible()
		body = model.browserLines(model.bodyHeight(), indices)
	}
	lines := make([]string, 0, model.height)
	lines = append(lines, model.headerLine())
	lines = append(lines, body...)
	lines = append(lines, model.footerLine(len(indices)))
	return frame(lines, model.width, model.height)
}

func frame(lines []string, width, height int) string {
	invariant.Require(width > 0 && width <= terminalColumnsMax, "invalid frame width")
	invariant.Require(height > 0 && height <= terminalRowsMax, "invalid frame height")
	rows := make([]string, height)
	for index := 0; index < min(len(lines), height); index++ {
		rows[index] = ansi.Truncate(lines[index], width, "…")
	}
	return strings.Join(rows, "\n")
}
