package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

type reconciledRead struct {
	snapshot  lifecycle.Snapshot
	requestID uint64
	report    string
	err       error
}

func (model *Model) reconcile() tea.Cmd {
	snapshot, unknown := model.state.Uncertain()
	if !unknown {
		model.status = "No uncertain write is awaiting reconciliation"
		return nil
	}
	if model.flow != nil {
		model.status = "Wait for canceled worker to drain before reconciliation"
		return nil
	}
	plan := model.lastPlan
	settings := snapshot.Settings
	if model.restarted != nil {
		var err error
		settings, err = model.restarted.ReconcileSettings(model.settings)
		if err != nil {
			model.error(err)
			return nil
		}
	}
	service := model.service
	operationContext, cancel := model.startRead(
		time.Duration(snapshot.Settings.TimeoutSeconds) * time.Second,
	)
	requestID := model.readID
	model.status = "Inspecting original DC (not the current connection)…"
	return func() tea.Msg {
		defer cancel()
		report, err := backend.Inspect(operationContext, service, settings, plan)
		return reconciledRead{snapshot: snapshot, requestID: requestID, report: report, err: err}
	}
}

func (model *Model) reconcileRead(result reconciledRead) tea.Cmd {
	if result.requestID != model.readID || !model.reconcileCurrent(result.snapshot) {
		return nil
	}
	if result.err != nil {
		model.error(result.err)
		return nil
	}
	model.openForm(
		"Reconcile uncertain outcome",
		"Original DC: "+result.snapshot.Settings.Server+"\n"+result.report+
			"\nInspect the target state above. Reads alone cannot prove "+
			"that a remote operation has stopped.\nIf it still may be "+
			"pending, cancel this form and investigate the original "+
			"DC.\nOnly acknowledge after independently establishing the "+
			"outcome and that no operation remains pending.",
		[]field{{"Type reconciled to accept responsibility for reconciliation", "", false}},
		false,
		func(values []string) tea.Cmd {
			if result.requestID != model.readID || !model.reconcileMatches(result.snapshot) {
				model.status = "Stale reconciliation ignored; inspect the current uncertain write."
				return nil
			}
			if values[0] != "reconciled" {
				model.status = "Uncertainty retained; writes remain blocked"
				return nil
			}
			if model.journal != nil {
				if currentErr := model.journal.Clear(); currentErr != nil {
					model.error(currentErr)
					return nil
				}
			}
			if currentErr := model.state.Reconciled(result.snapshot); currentErr != nil {
				model.error(currentErr)
			} else {
				model.restarted = nil
				model.status = fmt.Sprintf(
					"Reconciliation acknowledged for original DC %s. No write was "+"retried.",
					result.snapshot.Settings.Server,
				)
			}
			return nil
		},
	)
	return nil
}
