package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/invariant"
)

func (current *form) labelWidth(width int) int {
	indices := current.fieldIndices()
	if len(indices) == 1 && current.Fields[indices[0]].Label == "" {
		return 0
	}
	if width < 48 {
		return 0
	}
	labelWidth := 0
	for _, index := range indices {
		labelWidth = max(labelWidth, ansi.StringWidth(Literal(current.Fields[index].Label))+3)
	}
	return min(28, labelWidth)
}

func (current *form) fieldLineCount(width int) int {
	indices := current.fieldIndices()
	if current.labelWidth(width) > 0 ||
		(len(indices) == 1 && current.Fields[indices[0]].Label == "") {
		return 1
	}
	return 2
}

func formGeometry(current *form, width, height int) (fieldCount, contextHeight int) {
	current.assertValid()
	invariant.Require(height >= 2, "form geometry requires a label and value")
	invariant.Require(height <= terminalRowsMax, "form geometry exceeds terminal limit")
	fieldHeight := current.fieldLineCount(width)
	visibleCount := len(current.fieldIndices())
	if height < 4 {
		return min(visibleCount, max(1, height/fieldHeight)), 0
	}
	height -= 2
	if current.Context != "" {
		contextHeight = min(8, max(0, height-fieldHeight))
		if visibleCount > 1 {
			contextHeight = min(contextHeight, max(1, height/3))
		}
	}
	fieldCount = min(visibleCount, max(1, (height-contextHeight)/fieldHeight))
	return fieldCount, contextHeight
}

func (model *Model) fieldLines(width, count int) []string {
	current := model.form
	indices := current.fieldIndices()
	invariant.Require(count > 0 && count <= len(indices), "invalid visible field count")
	invariant.Require(width >= 3 && width <= terminalColumnsMax, "invalid field viewport")
	start := max(0, current.cursorPosition(indices)-count+1)
	fieldHeight, labelWidth := current.fieldLineCount(width), current.labelWidth(width)
	rows := make([]string, count*fieldHeight)
	for position := 0; position < count; position++ {
		index := indices[start+position]
		active := index == current.Cursor
		label := rowMark(active, ' ') + Literal(current.Fields[index].Label)
		labelStyle, valueStyle := model.theme.muted, model.theme.input
		if active {
			labelStyle, valueStyle = model.theme.focus, model.theme.cursor
		}
		valueWidth := width
		if labelWidth > 0 {
			valueWidth -= labelWidth + 1
		}
		value := fieldValueAt(current.Fields[index], valueWidth, active, current.caret(index))
		if current.Items != nil {
			valueStyle = model.theme.input
		}
		if len(current.Choices[index]) > 0 {
			value = "  " + Literal(current.Fields[index].text())
		}
		value = valueStyle.Render(cell(value, valueWidth))
		switch {
		case labelWidth > 0:
			rows[position] = labelStyle.Render(cell(label, labelWidth)) + " " + value
		case fieldHeight == 2:
			rows[position*2] = labelStyle.Render(label)
			rows[position*2+1] = value
		default:
			rows[position] = value
		}
	}
	return rows
}

func (model *Model) pickerLines(height int) []string {
	current := model.form
	width, capacity := model.modalContentSize(height)
	if height < 4 {
		rows := make([]string, height)
		copy(rows, model.fieldLines(width, 1))
		return rows
	}
	items := current.filteredItems()
	listHeight := min(max(1, capacity-1), max(1, len(current.Items)))
	cursor := min(current.ItemCursor, max(0, len(items)-1))
	start := max(0, cursor-listHeight+1)
	rows := make([]string, 1+listHeight)
	rows[0] = model.fieldLines(width, 1)[0]
	for index := start; index < min(len(items), start+listHeight); index++ {
		label := current.ItemLabels[items[index]]
		if label == "" {
			label = items[index]
		}
		text := cell(rowMark(index == cursor, ' ')+Literal(label), width)
		if index == cursor {
			text = model.theme.cursor.Render(text)
		}
		rows[index-start+1] = text
	}
	if len(items) == 0 {
		rows[1] = model.theme.muted.Render("No matching commands")
	}
	footer := scrollHint(cursor, len(items), listHeight)
	return model.placeModal(model.theme.panel(Literal(current.Title), footer, rows,
		model.modalWidth(), len(rows)+2, true), height)
}

func (model *Model) modalWidth() int {
	limit := modalWidthMax
	if model.form != nil {
		limit = 72
		if model.form.Items != nil {
			limit = 64
		} else if len(model.form.Fields) == 1 && model.form.Fields[0].Label == "" &&
			model.form.Context == "" {
			limit = 48
		}
	}
	return min(limit, model.width)
}

func formScrollHint(current *form, count int, page textPage, contextHeight int) string {
	hints := []string{}
	indices := current.fieldIndices()
	if fields := scrollHint(current.cursorPosition(indices), len(indices), count); fields != "" {
		hints = append(hints, fields+" fields")
	}
	if contextHeight > 0 {
		if preview := previewScrollHint(page, contextHeight); preview != "" {
			hints = append(hints, preview)
		}
	}
	return strings.Join(hints, " · ")
}
