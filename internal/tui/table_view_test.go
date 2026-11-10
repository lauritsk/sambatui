package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func TestTableProjectionUsesOneCellGeometryForHeadersAndRecords(t *testing.T) {
	model := testModel()
	model.records = []dnsrpc.Row{
		{Name: "files", Type: "A", TTL: 4294967295, Value: "192.0.2.1"},
		{Name: strings.Repeat("long-name", 8), Type: "CNAME", Value: "dc.lab.invalid."},
	}
	for _, width := range []int{1, 12, 40, 80, terminalColumnsMax} {
		geometry := model.tableGeometry([]int{0, 1}, width)
		if ansi.StringWidth(model.tableHeader(geometry)) != width+3 {
			t.Fatal("table header diverged from its marker and data columns", width)
		}
		for index := range model.records {
			if ansi.StringWidth(model.rowColumns(index, geometry)) != width {
				t.Fatal("record diverged from shared column geometry", width, index)
			}
		}
	}
	if model.tableGeometry([]int{0, 1}, 80).ttl != 10 {
		t.Fatal("TTL geometry cannot hold the largest wire value")
	}
}

func TestTableCellsRespectWideAndCombiningCharacters(t *testing.T) {
	for _, width := range []int{1, 2, 7, 20} {
		for _, text := range []string{"界é🇪🇪", "plain", ""} {
			if actual := ansi.StringWidth(cell(text, width)); actual != width {
				t.Fatal("cell clipped or padded by bytes instead of terminal cells", actual, width)
			}
		}
	}
}
