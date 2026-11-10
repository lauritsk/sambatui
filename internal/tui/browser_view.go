package tui

import (
	"fmt"
	"strings"

	"github.com/lauritsk/sambatui/internal/invariant"
)

func (model *Model) browserLines(height int, indices []int) []string {
	invariant.Require(height >= 2, "browser requires heading and one row")
	invariant.Require(height <= terminalRowsMax, "browser viewport exceeds terminal limit")
	navigation := model.navigationView()
	if height < 4 {
		if model.sidebar {
			return append([]string{model.paneTitle(true)},
				model.viewSidebar(height-1, model.width, navigation)...)
		}
		return append([]string{model.paneTitle(false)},
			model.viewRows(height-1, model.tableGeometry(indices, model.width-3), indices)...)
	}
	if model.width < sidebarWidthMin {
		if model.sidebar {
			return model.sidebarPanel(model.width, height, navigation)
		}
		return model.resultsPanel(model.width, height, indices)
	}
	sideWidth := navigation.width(model.width)
	left := model.sidebarPanel(sideWidth, height, navigation)
	right := model.resultsPanel(model.width-sideWidth-1, height, indices)
	rows := make([]string, height)
	for index := range rows {
		rows[index] = left[index] + " " + right[index]
	}
	return rows
}

func (model *Model) sidebarPanel(width, height int, navigation navigationView) []string {
	footer := scrollHint(navigation.cursor, len(navigation.rows), height-2)
	return model.theme.panel(model.paneTitle(true), footer,
		model.viewSidebar(height-2, width-4, navigation), width, height, model.sidebar)
}

func (model *Model) resultsPanel(width, height int, indices []int) []string {
	invariant.Require(height >= 4, "results panel needs a header and one row")
	invariant.Require(width >= 20, "results panel needs readable columns")
	contentWidth := width - 4
	rows := make([]string, height-2)
	geometry := model.tableGeometry(indices, contentWidth-3)
	rows[0] = model.theme.chrome.Bold(true).Render(
		cell(model.tableHeader(geometry), contentWidth),
	)
	copy(rows[1:], model.viewRows(height-3, geometry, indices))
	footer := scrollHint(model.cursor, len(indices), height-3)
	if model.mode == "ldap" && len(model.entries) >= model.settings.LDAPMaxRows {
		action := "m more"
		if model.settings.LDAPMaxRows == 5000 {
			action = "l refine search"
		}
		footer = strings.TrimSpace(footer + " Row limit · " + action)
	}
	return model.theme.panel(model.paneTitle(false), footer, rows, width, height, !model.sidebar)
}

func (model *Model) paneTitle(sidebar bool) string {
	if sidebar {
		if model.mode == "ldap" {
			return "Directory"
		}
		return "Zones"
	}
	title := "Records"
	if model.mode == "ldap" {
		title = "Entries"
	}
	if model.search != "" {
		title += " · /" + Literal(model.search)
	}
	selectedCount := 0
	for _, selected := range model.selected {
		if selected {
			selectedCount++
		}
	}
	if selectedCount > 0 {
		title += fmt.Sprintf(" · %d selected", selectedCount)
	}
	return title
}

func scrollHint(cursor, total, height int) string {
	invariant.Require(cursor >= 0 && total >= 0, "invalid scroll position")
	invariant.Require(height > 0 && height <= terminalRowsMax, "invalid scroll viewport")
	start := max(0, min(cursor, max(0, total-1))-height+1)
	hint := ""
	if start > 0 {
		hint = "↑"
	}
	if start+height < total {
		hint += " ↓"
	}
	return strings.TrimSpace(hint)
}

func (model *Model) viewSidebar(height, width int, navigation navigationView) []string {
	invariant.Require(height > 0 && height <= terminalRowsMax, "invalid sidebar viewport")
	invariant.Require(width > 0 && width <= terminalColumnsMax, "invalid sidebar width")
	start := max(0, navigation.cursor-height+1)
	rows := make([]string, height)
	for position := start; position < min(len(navigation.rows), start+height); position++ {
		index := navigation.rows[position]
		if index < 0 {
			continue
		}
		item := navigation.items[index]
		state := ' '
		if model.navigationActive(item) {
			state = '·'
		}
		focused := position == navigation.cursor && model.sidebar
		text := cell(rowMark(focused, state)+Literal(item.label), width)
		if state != ' ' {
			text = model.theme.focus.Render(text)
		}
		if focused {
			text = model.theme.cursor.Render(text)
		}
		rows[position-start] = text
	}
	if len(navigation.items) == 0 && model.loading == "" {
		rows[0] = "No zones"
	}
	return rows
}

func (model *Model) viewRows(height int, geometry tableGeometry, indices []int) []string {
	width := geometry.width + 3
	invariant.Require(height > 0 && height <= terminalRowsMax, "invalid results viewport")
	invariant.Require(width > 3 && width <= terminalColumnsMax, "invalid results width")
	cursor := min(model.cursor, max(0, len(indices)-1))
	start := max(0, cursor-height+1)
	rows := make([]string, height)
	for position := start; position < min(len(indices), start+height); position++ {
		index := indices[position]
		state := ' '
		if model.selected[index] {
			state = '*'
		}
		mark := rowMark(position == cursor && !model.sidebar, state)
		text := cell(mark+model.rowColumns(index, geometry), width)
		if model.selected[index] {
			text = model.theme.selection.Render(text)
		}
		if position == cursor && !model.sidebar {
			text = model.theme.cursor.Render(text)
		}
		rows[position-start] = text
	}
	if len(indices) == 0 && model.loading == "" {
		rows[0] = "No records"
		if model.mode == "ldap" {
			rows[0] = "No entries"
		}
		if model.search != "" {
			rows[0] = "No matches"
		}
	}
	return rows
}
