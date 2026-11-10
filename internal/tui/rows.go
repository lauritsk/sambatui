package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lauritsk/sambatui/internal/directory"
)

func (model *Model) visible() []int {
	return model.visibleTexts(model.rowTexts())
}

func (model *Model) visibleTexts(values []string) []int {
	indices := make([]int, 0, len(values))
	needle := strings.ToLower(model.search)
	keys := make([]string, len(values))
	for index, text := range values {
		keys[index] = model.sortKey(index)
		if strings.Contains(strings.ToLower(text), needle) {
			indices = append(indices, index)
		}
	}
	sort.SliceStable(indices, func(index, rightIndex int) bool {
		left, right := keys[indices[index]], keys[indices[rightIndex]]
		if model.reverse {
			return left > right
		}
		return left < right
	})
	return indices
}

func (model *Model) sortKey(index int) string {
	switch model.mode {
	case "dns":
		row := model.records[index]
		return []string{row.Name, row.Type, row.Value}[model.sortField]
	case "ldap":
		entry := model.entries[index]
		return []string{entry.Name, entry.Kind, entry.DN}[model.sortField]
	default:
		panic("unknown view mode")
	}
}

func (model *Model) rowTexts() []string {
	count := len(model.records)
	if model.mode == "ldap" {
		count = len(model.entries)
	}
	texts := make([]string, 0, count)
	switch model.mode {
	case "dns":
		for _, row := range model.records {
			texts = append(
				texts,
				fmt.Sprintf(
					"%-28s %-6s %-8d %s",
					Literal(row.Name),
					Literal(row.Type),
					row.TTL,
					Literal(row.Value),
				),
			)
		}
	case "ldap":
		for _, entry := range model.entries {
			texts = append(texts,
				Literal(entry.Name)+"  "+Literal(entry.Kind)+"  "+Literal(entry.DN),
			)
		}
	}
	return texts
}

func (model *Model) cycleSort() {
	before := model.visible()
	focused, anchored := -1, -1
	if model.cursor < len(before) {
		focused = before[model.cursor]
	}
	if model.anchor >= 0 && model.anchor < len(before) {
		anchored = before[model.anchor]
	}
	model.sortField = (model.sortField + 1) % 3
	model.reverse = !model.reverse
	model.anchor = -1
	for position, index := range model.visible() {
		if index == focused {
			model.cursor = position
		}
		if index == anchored {
			model.anchor = position
		}
	}
}

func (model *Model) move(delta int) {
	if model.sidebar {
		model.sideCursor = max(0, min(model.sideCursor+delta, len(model.sideLabels())-1))
	} else {
		model.cursor = max(0, min(model.cursor+delta, len(model.visible())-1))
	}
}

func (model *Model) showDetails(text string) {
	if err := validateViewText(text); err != nil {
		model.error(err)
		return
	}
	model.detail = text
	model.detailTitle = "Details"
	model.detailOffset = 0
}

func (model *Model) showHelp() {
	model.showDetails(help)
	model.detailTitle = "Help"
}

func (model *Model) showLastError() {
	if model.lastError != "" {
		model.showDetails(model.lastError)
		model.detailTitle = "Last error"
		model.errorUnread = false
		model.status = ""
	}
}

func (model *Model) details() {
	indices := model.visible()
	if model.cursor >= len(indices) {
		return
	}
	index := indices[model.cursor]
	var text string
	switch model.mode {
	case "dns":
		row := model.records[index]
		text = fmt.Sprintf(
			"DC: %s\nZone: %s\nName: %s\nType: %s\nTTL: %d\nValue: %s",
			model.settings.Server,
			model.zone,
			row.Name,
			row.Type,
			row.TTL,
			row.Value,
		)
	case "ldap":
		text = directoryDetails(model.settings.Server, model.entries[index])
	}
	model.showDetails(text)
}

// Entries already passed the LDAP search byte/attribute budgets. Build details
// linearly within that bound, preserving deterministic attribute order.
func directoryDetails(server string, entry directory.Entry) string {
	var text strings.Builder
	fmt.Fprintf(&text, "DC: %s\nDN: %s\nRevision (DC-local): %s\n",
		server, entry.DN, entry.Revision,
	)
	keys := make([]string, 0, len(entry.Attributes))
	for key := range entry.Attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		text.WriteString(key)
		text.WriteString(": ")
		for index, value := range entry.Attributes[key] {
			if index > 0 {
				text.WriteString("; ")
			}
			text.WriteString(value)
		}
		text.WriteByte('\n')
	}
	return text.String()
}
