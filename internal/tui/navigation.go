package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/invariant"
)

const sidebarWidthMin = 27 + 1 + 44

type navigationKind uint8

const (
	navigationZone navigationKind = iota
	navigationFilter
	navigationBase
)

type navigationItem struct {
	label, target string
	kind          navigationKind
}

type navigationView struct {
	items  []navigationItem
	rows   []int
	cursor int
}

func (model *Model) navigationItems() []navigationItem {
	if model.mode == "dns" {
		items := make([]navigationItem, len(model.zones))
		for index, zone := range model.zones {
			items[index] = navigationItem{zone, zone, navigationZone}
		}
		return items
	}
	items := make([]navigationItem, 0, 6+len(model.folders))
	for _, item := range []navigationItem{
		{"Users", "users", navigationFilter},
		{"Groups", "groups", navigationFilter},
		{"Computers", "computers", navigationFilter},
		{"OUs", "ous", navigationFilter},
		{"All", "all", navigationFilter},
		{"Base/", model.settings.BaseDN, navigationBase},
	} {
		items = append(items, item)
	}
	for _, entry := range model.folders {
		items = append(items, navigationItem{entry.Name + "/", entry.DN, navigationBase})
	}
	return items
}

func (model *Model) navigationView() navigationView {
	items := model.navigationItems()
	view := navigationView{items: items, rows: make([]int, 0, len(items)+2)}
	cursor := min(model.sideCursor, max(0, len(items)-1))
	for index, item := range items {
		if index > 0 && item.kind != items[index-1].kind {
			view.rows = append(view.rows, -1)
		}
		if index == cursor {
			view.cursor = len(view.rows)
		}
		view.rows = append(view.rows, index)
	}
	return view
}

func (view navigationView) width(available int) int {
	invariant.Require(available >= sidebarWidthMin, "split navigation needs a wide viewport")
	invariant.Require(available <= terminalColumnsMax, "navigation width exceeds terminal limit")
	width := 18
	for _, item := range view.items {
		width = max(width, min(32, ansi.StringWidth(Literal(item.label))+7))
	}
	return min(width, available-45)
}

func (model *Model) navigationActive(item navigationItem) bool {
	switch item.kind {
	case navigationZone:
		return model.zone == item.target
	case navigationFilter:
		return model.kind == item.target
	case navigationBase:
		return model.base == item.target
	default:
		panic("unknown navigation item")
	}
}

func (model *Model) sideLabels() []string {
	items := model.navigationItems()
	labels := make([]string, len(items))
	for index, item := range items {
		labels[index] = item.label
	}
	return labels
}

func (model *Model) activateSide() tea.Cmd {
	items := model.navigationItems()
	if len(items) == 0 {
		return nil
	}
	model.sideCursor = min(model.sideCursor, len(items)-1)
	item := items[model.sideCursor]
	switch item.kind {
	case navigationZone:
		model.zone, model.settings.LastZone = item.target, item.target
		if err := config.Save(model.configPath, model.settings); err != nil {
			model.error(err)
		}
		return model.load("dns")
	case navigationFilter:
		model.kind = item.target
	case navigationBase:
		model.base = item.target
	default:
		invariant.Require(false, "unknown navigation action")
	}
	return model.load("ldap")
}

func rowMark(focused bool, state rune) string {
	mark := ' '
	if focused {
		mark = '>'
	}
	return string([]rune{mark, state, ' '})
}
