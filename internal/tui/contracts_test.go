package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestTerminalDimensionsAreBounded(t *testing.T) {
	model := testModel()
	for _, size := range []int{-1, 0, 1, int(^uint(0) >> 1)} {
		model.Update(tea.WindowSizeMsg{Width: size, Height: size})
		if model.width < 1 || model.width > terminalColumnsMax {
			t.Fatalf("unbounded width %d", model.width)
		}
		if model.height < 1 || model.height > terminalRowsMax {
			t.Fatalf("unbounded height %d", model.height)
		}
		model.View()
	}
}

func TestLateWriteResultCannotReleaseNewFlowOnSameConnection(t *testing.T) {
	model := testModel()
	previous, err := model.state.Begin()
	if err != nil {
		t.Fatal(err)
	}
	previous.Abort()
	current, err := model.state.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer current.Abort()
	model.flow = current
	model.lastWrite = current.Snapshot
	model.updateWrite(writeResult{
		generation: previous.Snapshot.Generation, flow: previous,
	})
	if model.flow != current {
		t.Fatal("late worker result released another flow")
	}
}

func TestStaleReconciliationCannotOpenFormOrOverrideAnExistingForm(t *testing.T) {
	model := testModel()
	snapshot := model.state.Snapshot()
	if err := model.state.RestoreUncertain(snapshot); err != nil {
		t.Fatal(err)
	}
	model.readID = 2
	model.reconcileRead(reconciledRead{snapshot: snapshot, requestID: 1})
	if model.form != nil {
		t.Fatal("stale inspection opened reconciliation")
	}
	model.searchForm()
	original := model.form
	model.reconcileRead(reconciledRead{snapshot: snapshot, requestID: 2})
	if model.form != original {
		t.Fatal("inspection replaced another form")
	}
	model.closeForm()
	model.reconcileRead(reconciledRead{snapshot: snapshot, requestID: 2})
	if model.form == nil {
		t.Fatal("current inspection did not open reconciliation")
	}
	accept := model.form.Accept
	model.form = nil
	model.readID++
	accept([]string{"reconciled"})
	if _, exists := model.state.Uncertain(); !exists {
		t.Fatal("stale acknowledgement released write guard")
	}
}
