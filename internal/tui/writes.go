package tui

import (
	"context"
	"errors"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/invariant"
	"github.com/lauritsk/sambatui/internal/journal"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

// The event-loop owner freezes dependencies; the worker never touches Model.
func (model *Model) dispatchPlan(snapshot lifecycle.Snapshot, plan backend.Plan) tea.Cmd {
	invariant.Require(model.flow != nil, "dispatch requires a write reservation")
	invariant.Require(model.flow.Snapshot == snapshot, "dispatch changed write identity")
	model.readID = invariant.Next(model.readID)
	if model.readCancel != nil {
		model.readCancel()
	}
	model.lastPlan = plan
	model.lastWrite = snapshot
	operationContext, cancel := context.WithTimeout(
		context.Background(), time.Duration(snapshot.Settings.TimeoutSeconds)*time.Second,
	)
	model.writeCancel = cancel
	model.status = "Write in progress on " + snapshot.Settings.Server +
		". Ctrl+C requests cancel; not rollback."
	flow, service, store := model.flow, model.service, model.journal
	return func() tea.Msg {
		defer cancel()
		return runWrite(operationContext, service, store, flow, plan)
	}
}

func runWrite(
	operationContext context.Context, service backend.Service, store *journal.Store,
	flow *lifecycle.Flow, plan backend.Plan,
) writeResult {
	snapshot := flow.Snapshot
	if store != nil {
		if err := store.Start(snapshot, plan); err != nil {
			flow.Abort()
			return writeResult{snapshot.Generation, lifecycle.Outcome{Err: err}, flow}
		}
	}
	outcome := flow.Run(
		operationContext,
		func(operationContext context.Context, settings config.Settings) lifecycle.Outcome {
			return service.Execute(operationContext, settings, plan)
		},
	)
	if store != nil && !outcome.Uncertain {
		if err := store.Clear(); err != nil {
			outcome = lifecycle.Outcome{
				Err: fmt.Errorf(
					"cannot clear pending-write journal; reconcile before retrying: %w",
					err,
				),
				Uncertain: true,
			}
			if err := flow.RetainUncertain(); err != nil {
				outcome.Err = errors.Join(outcome.Err, err)
			}
		}
	}
	return writeResult{snapshot.Generation, outcome, flow}
}
