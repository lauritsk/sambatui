package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/invariant"
)

type tableGeometry struct {
	width, name, kind, ttl int
}

func cell(text string, width int) string {
	invariant.Require(width > 0, "cell width must be positive")
	invariant.Require(width <= terminalColumnsMax, "cell width exceeds terminal limit")
	text = ansi.Truncate(text, width, "…")
	return text + strings.Repeat(" ", max(0, width-ansi.StringWidth(text)))
}

func (model *Model) tableGeometry(indices []int, width int) tableGeometry {
	invariant.Require(width > 0 && width <= terminalColumnsMax, "invalid table width")
	invariant.Require(model.mode == "dns" || model.mode == "ldap", "unknown table mode")
	name, kind, ttl := 8, 4, 3
	for _, index := range indices {
		if model.mode == "dns" {
			row := model.records[index]
			name = max(name, min(32, ansi.StringWidth(Literal(row.Name))))
			kind = max(kind, min(10, ansi.StringWidth(Literal(row.Type))))
			ttl = max(ttl, len(strconv.FormatUint(uint64(row.TTL), 10)))
		} else {
			entry := model.entries[index]
			name = max(name, min(32, ansi.StringWidth(Literal(entry.Name))))
			kind = max(kind, min(10, ansi.StringWidth(Literal(entry.Kind))))
		}
	}
	if model.sortField == 1 {
		kind = max(kind, 6)
	}
	kind = min(kind, max(3, width-9))
	if model.mode != "dns" || width < 8+kind+ttl+3+12 {
		ttl = 0
	}
	remaining := width - kind - 2 - 12
	if ttl > 0 {
		remaining -= ttl + 1
	}
	geometry := tableGeometry{
		width: width, name: min(name, max(4, remaining)), kind: kind, ttl: ttl,
	}
	invariant.Require(geometry.name > 0, "table has no name column")
	return geometry
}

func (model *Model) tableHeader(geometry tableGeometry) string {
	kind, value := "TYPE", "VALUE"
	if model.mode == "ldap" {
		kind, value = "KIND", "DN"
	}
	headings := []string{"NAME", kind, value}
	if model.sortField != 0 || model.reverse {
		arrow := " ↑"
		if model.reverse {
			arrow = " ↓"
		}
		headings[model.sortField] += arrow
	}
	return "   " + geometry.columns(headings[0], headings[1], "TTL", headings[2])
}

func (model *Model) rowColumns(index int, geometry tableGeometry) string {
	invariant.Require(index >= 0, "negative display row index")
	invariant.Require(model.mode == "dns" || model.mode == "ldap", "unknown display row mode")
	if model.mode == "dns" {
		row := model.records[index]
		return geometry.columns(Literal(row.Name), Literal(row.Type),
			strconv.FormatUint(uint64(row.TTL), 10), Literal(row.Value))
	}
	entry := model.entries[index]
	return geometry.columns(Literal(entry.Name), Literal(entry.Kind), "", Literal(entry.DN))
}

func (geometry tableGeometry) columns(name, kind, ttl, value string) string {
	text := cell(name, geometry.name) + " " + cell(kind, geometry.kind) + " "
	if geometry.ttl > 0 {
		text += fmt.Sprintf("%*s ", geometry.ttl, ttl)
	}
	return cell(text+value, geometry.width)
}
