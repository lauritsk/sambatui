package tui

import (
	"errors"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

func (model *Model) selectedIndices() []int {
	visible := model.visible()
	out := make([]int, 0, len(visible))
	for _, index := range visible {
		if model.selected[index] {
			out = append(out, index)
		}
	}
	if len(out) == 0 {
		if model.cursor < len(visible) {
			out = append(out, visible[model.cursor])
		}
	}
	return out
}

func (model *Model) rejectFlow(err error) tea.Cmd {
	if model.flow != nil {
		model.flow.Abort()
		model.flow = nil
	}
	model.error(err)
	return nil
}

func (model *Model) confirmPlan(plan backend.Plan) tea.Cmd {
	if model.flow == nil {
		return nil
	}
	snapshot := model.flow.Snapshot
	if err := plan.Validate(snapshot.Settings); err != nil {
		return model.rejectFlow(err)
	}
	plan = plan.Clone()
	identity := snapshot.Settings.User
	if snapshot.Settings.Auth == "kerberos" {
		identity = snapshot.Settings.CacheIdentity
	}
	description := "DC: " + Literal(snapshot.Settings.Server) + "\nLDAP base: " +
		Literal(snapshot.Settings.BaseDN) +
		"\nAuthentication: " +
		snapshot.Settings.Auth +
		"\nIdentity: " +
		Literal(identity) +
		"\n" +
		plan.Preview()
	model.openForm(
		"Confirm write — review original target",
		description,
		[]field{{"Type yes to execute exactly this plan", "", false}},
		true,
		func(values []string) tea.Cmd {
			if values[0] != "yes" {
				return model.rejectFlow(errors.New("Write not confirmed; nothing dispatched"))
			}
			return model.dispatchPlan(snapshot, plan)
		},
	)
	return nil
}

func (model *Model) writeForm(key string) tea.Cmd {
	if model.flow != nil {
		model.error(lifecycle.ErrBusy)
		return nil
	}
	flow, err := model.state.Begin()
	if err != nil {
		model.error(err)
		return nil
	}
	model.flow = flow
	if err = flow.Snapshot.Settings.Validate(true); err != nil {
		return model.rejectFlow(err)
	}
	indices := model.selectedIndices()
	switch model.mode {
	case "dns":
		return model.dnsWriteForm(key, indices)
	case "ldap":
		return model.ldapWriteForm(key, indices)
	default:
		return model.rejectFlow(errors.New("no writable view active"))
	}
}
