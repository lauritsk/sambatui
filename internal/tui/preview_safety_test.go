package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestPreviewBudgetRejectsOversizeWithoutDispatchOrRetainedFlow(t *testing.T) {
	boundary := strings.Repeat("x", viewTextBytesMax)
	if err := validateViewText(boundary); err != nil {
		t.Fatal("exact preview budget rejected", err)
	}
	oversize := boundary + "x"
	if err := validateViewText(oversize); err == nil {
		t.Fatal("oversize preview accepted")
	}
	model := testModel()
	flow, err := model.state.Begin()
	if err != nil {
		t.Fatal(err)
	}
	model.flow = flow
	accepted := false
	model.openForm("Confirm write", oversize, []field{{"Yes", "yes", false}}, true,
		func([]string) tea.Cmd { accepted = true; return nil })
	if model.form != nil || model.flow != nil || accepted {
		t.Fatal("oversize preview retained a confirmation or write reservation")
	}
	next, err := model.state.Begin()
	if err != nil {
		t.Fatal("rejected preview did not release its reservation", err)
	}
	next.Abort()
	model.showDetails(oversize)
	if model.detail != "" || !strings.Contains(model.lastError, "16 MiB") {
		t.Fatal("oversize detail bypassed validation")
	}
}
