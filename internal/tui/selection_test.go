package tui

import (
	"testing"

	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func TestSortPreservesFocusedIdentityAndRangeAnchor(t *testing.T) {
	model := testModel()
	model.records = []dnsrpc.Row{
		{Name: "b", Type: "A"}, {Name: "a", Type: "TXT"}, {Name: "c", Type: "MX"},
	}
	model.cursor, model.anchor = 1, 0
	model.selected[0] = true
	for index := 0; index < 6; index++ {
		model.cycleSort()
		visible := model.visible()
		if visible[model.cursor] != 0 || visible[model.anchor] != 1 || !model.selected[0] {
			t.Fatal("sorting moved focus, anchor or selection to another record")
		}
	}
}
