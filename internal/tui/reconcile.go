package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

type reconciledRead struct {
	snapshot lifecycle.Snapshot
	report   string
	err      error
}

func (m *Model) reconcile() tea.Cmd {
	snapshot, unknown := m.state.Uncertain()
	if !unknown {
		m.status = "No uncertain write is awaiting reconciliation"
		return nil
	}
	if m.flow != nil {
		m.status = "Wait for canceled worker to drain before reconciliation"
		return nil
	}
	p := m.lastPlan
	settings := snapshot.Settings
	if m.restarted != nil {
		var e error
		settings, e = m.restarted.ReconcileSettings(m.cfg)
		if e != nil {
			m.error(e)
			return nil
		}
	}
	service := m.service
	m.status = "Inspecting original DC (not the current connection)…"
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(snapshot.Settings.TimeoutSeconds)*time.Second)
		defer cancel()
		report, e := backend.Inspect(ctx, service, settings, p)
		return reconciledRead{snapshot, report, e}
	}
}

func (m *Model) reconcileRead(v reconciledRead) tea.Cmd {
	if v.err != nil {
		m.error(v.err)
		return nil
	}
	m.openForm("Reconcile uncertain outcome", "Original DC: "+v.snapshot.Settings.Server+"\n"+v.report+"\nInspect the target state above. Reads alone cannot prove that a remote operation has stopped.\nIf it still may be pending, cancel this form and investigate the original DC.\nOnly acknowledge after independently establishing the outcome and that no operation remains pending.", []field{{"Type reconciled to accept responsibility for reconciliation", "", false}}, false, func(values []string) tea.Cmd {
		if values[0] != "reconciled" {
			m.status = "Uncertainty retained; writes remain blocked"
			return nil
		}
		if m.journal != nil {
			if e := m.journal.Clear(); e != nil {
				m.error(e)
				return nil
			}
		}
		if e := m.state.Reconciled(v.snapshot); e != nil {
			m.error(e)
		} else {
			m.restarted = nil
			m.status = fmt.Sprintf("Reconciliation acknowledged for original DC %s. No write was retried.", v.snapshot.Settings.Server)
		}
		return nil
	})
	return nil
}
