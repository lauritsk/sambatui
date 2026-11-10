package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/health"
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
		finding := model.findings[index]
		if model.healthCheck == 8 {
			return fmt.Sprintf("%02d:%09d", finding.Check, index)
		}
		return []string{
			fmt.Sprint(health.Rank(finding.Severity)),
			finding.Object,
			finding.Finding,
		}[model.sortField]
	}
}

func (model *Model) rowTexts() []string {
	out := []string{}
	switch model.mode {
	case "dns":
		for _, row := range model.records {
			out = append(
				out,
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
			out = append(out, Literal(entry.Name)+"  "+Literal(entry.Kind)+"  "+Literal(entry.DN))
		}
	case "health":
		for _, finding := range model.findings {
			out = append(
				out,
				Literal(finding.Severity)+"  "+Literal(finding.Object)+"  "+
					Literal(finding.Finding),
			)
		}
	}
	return out
}

func (model *Model) move(delta int) {
	if model.sidebar {
		model.sideCursor = max(0, min(model.sideCursor+delta, len(model.sideLabels())-1))
	} else {
		model.cursor = max(0, min(model.cursor+delta, len(model.visible())-1))
	}
}

func (model *Model) sideLabels() []string {
	if model.mode != "ldap" {
		return model.zones
	}
	out := []string{"↑ Configured base", "Users", "Groups", "Computers", "OUs", "All"}
	for _, entry := range model.folders {
		out = append(out, entry.Name)
	}
	return out
}

func (model *Model) activateSide() tea.Cmd {
	if model.mode != "ldap" {
		if model.sideCursor < len(model.zones) {
			model.zone = model.zones[model.sideCursor]
			model.settings.LastZone = model.zone
			if err := config.Save(model.configPath, model.settings); err != nil {
				model.error(err)
			}
			model.setMode("dns")
			return model.load("dns")
		}
		return nil
	}
	if model.sideCursor == 0 {
		model.base = model.settings.BaseDN
	} else if model.sideCursor < 6 {
		model.kind = []string{"users", "groups", "computers", "ous", "all"}[model.sideCursor-1]
	} else if model.sideCursor-6 < len(model.folders) {
		model.base = model.folders[model.sideCursor-6].DN
	}
	return model.load("ldap")
}

func (model *Model) showDetails(text string) {
	model.detail = text
	model.detailOffset = 0
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
		entry := model.entries[index]
		text = "DC: " + model.settings.Server + "\nDN: " + entry.DN + "\nRevision (DC-local): " +
			entry.Revision +
			"\n"
		keys := []string{}
		for key := range entry.Attributes {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			text += key + ": " + strings.Join(entry.Attributes[key], "; ") + "\n"
		}
	case "health":
		finding := model.findings[index]
		text = finding.Object + "\n" + finding.Finding + "\n" + finding.Evidence + "\nSuggested: " +
			finding.Action +
			"\nGuided fix: " +
			finding.Fix
	}
	model.showDetails(text)
}
