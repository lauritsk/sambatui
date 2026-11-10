package tui

import (
	"errors"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
)

func (model *Model) fixForm(key string) tea.Cmd {
	if key != "f" {
		return model.rejectFlow(errors.New("Use f for guided fixes in findings views"))
	}
	selected := model.selectedIndices()
	if len(selected) != 1 {
		return model.rejectFlow(errors.New("select one finding for a guided fix"))
	}
	finding := model.findings[selected[0]]
	switch finding.Fix {
	case "dns_add_ptr":
		return model.confirmPlan(
			backend.Plan{
				Title: "Guided missing PTR fix",
				Actions: []backend.Action{
					{
						Kind:  "dns_add",
						Zone:  finding.Zone,
						Name:  finding.Record.Name,
						Type:  "PTR",
						Value: finding.Record.Value,
					},
				},
			},
		)
	case "ldap_disable_account":
		if finding.Entry.Revision == "" {
			return model.rejectFlow(errors.New("missing revision; disable refused"))
		}
		return model.confirmPlan(
			backend.Plan{
				Title: "Guided account-disable fix",
				Actions: []backend.Action{
					{
						Kind:     "ldap_disable",
						DN:       finding.Entry.DN,
						Revision: finding.Entry.Revision,
						Flags:    finding.Flags,
					},
				},
			},
		)
	default:
		return model.rejectFlow(
			errors.New("This finding requires manual review; no safe guided fix available"),
		)
	}
}
