package tui

import (
	"strings"

	"github.com/lauritsk/sambatui/internal/invariant"
)

const modalWidthMax = 80

func (model *Model) modalContentSize(height int) (width, rows int) {
	invariant.Require(height >= 2 && height <= terminalRowsMax, "invalid modal height")
	width, rows = model.modalWidth(), height
	if height >= 4 {
		width, rows = width-4, rows-2
	}
	return max(1, width), rows
}

func (model *Model) placeModal(content []string, height int) []string {
	invariant.Require(len(content) <= height, "dialog exceeds its viewport")
	invariant.Require(height > 0 && height <= terminalRowsMax, "invalid dialog viewport")
	padding := strings.Repeat(" ", max(0, (model.width-model.modalWidth())/2))
	rows := make([]string, height)
	start := min(2, (height-len(content))/2)
	for index, line := range content {
		rows[start+index] = padding + line
	}
	return rows
}

func (model *Model) detailViewport() (width, rows int) {
	height := model.bodyHeight()
	width, rows = model.modalContentSize(height)
	if height < 4 {
		rows--
	}
	return width, rows
}

func (model *Model) detailLines(height int) []string {
	invariant.Require(height >= 2, "details require a heading and one row")
	invariant.Require(height <= terminalRowsMax, "detail viewport exceeds terminal limit")
	width, rows := model.modalContentSize(height)
	if height < 4 {
		page := wrappedPage(model.detail, width, model.detailOffset, height-1)
		return append([]string{Literal(model.detailTitle)}, page.lines...)
	}
	page := wrappedPage(model.detail, width, model.detailOffset, rows)
	footer := previewScrollHint(page, rows)
	content := page.lines[:min(rows, page.totalRows)]
	return model.placeModal(model.theme.panel(Literal(model.detailTitle), footer, content,
		model.modalWidth(), len(content)+2, true), height)
}

func (model *Model) formView() string {
	return strings.Join(model.formLines(model.bodyHeight()), "\n")
}

func (model *Model) formLines(height int) []string {
	invariant.Require(model.form != nil, "form rendering requires an active form")
	invariant.Require(height >= 2 && height <= terminalRowsMax, "invalid form viewport")
	current := model.form
	current.assertValid()
	if current.Items != nil {
		return model.pickerLines(height)
	}
	width, _ := model.modalContentSize(height)
	if height < 4 {
		rows := make([]string, height)
		copy(rows, model.fieldLines(width, 1))
		return rows
	}
	fieldCount, contextHeight := formGeometry(current, width, height)
	page := textPage{totalRows: 1}
	if contextHeight > 0 {
		page = wrappedPage(current.Context, width, current.ContextOffset, contextHeight)
	}
	contextRows := min(contextHeight, page.totalRows)
	rows := make([]string, contextRows+fieldCount*current.fieldLineCount(width))
	copy(rows[:contextRows], page.lines)
	copy(rows[contextRows:], model.fieldLines(width, fieldCount))
	footer := formScrollHint(current, fieldCount, page, contextHeight)
	return model.placeModal(model.theme.panel(Literal(current.Title), footer, rows,
		model.modalWidth(), len(rows)+2, true), height)
}

func previewScrollHint(page textPage, height int) string {
	if page.totalRows <= height {
		return ""
	}
	hint := "PgUp/Dn"
	if page.startRow > 0 {
		hint = "↑ " + hint
	}
	if page.startRow+height < page.totalRows {
		hint += " ↓"
	}
	return hint
}
