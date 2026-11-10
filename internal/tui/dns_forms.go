package tui

import (
	"errors"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/dnsdata"
)

func (model *Model) dnsWriteForm(key string, indices []int) tea.Cmd {
	if model.zone == "" {
		return model.rejectFlow(errors.New("select a zone first"))
	}
	if key == "a" {
		return model.dnsAddForm()
	}
	if len(indices) == 0 {
		return model.rejectFlow(errors.New("select a real DNS record first"))
	}
	if key == "d" {
		plan := backend.Plan{Title: "Delete selected DNS records"}
		for _, index := range indices {
			row := model.records[index]
			plan.Actions = append(
				plan.Actions,
				backend.Action{
					Kind:  "dns_delete",
					Zone:  model.zone,
					Name:  row.Name,
					Type:  row.Type,
					Value: row.Value,
				},
			)
		}
		return model.confirmPlan(plan)
	}
	if len(indices) != 1 {
		return model.rejectFlow(errors.New("update requires exactly one selected record"))
	}
	row := model.records[indices[0]]
	zone := model.zone
	model.openForm(
		"Update selected DNS record",
		"Name and type fixed: "+row.Name+" "+row.Type,
		[]field{{"New value", row.Value, false}},
		true,
		func(values []string) tea.Cmd {
			if _, err := dnsdata.Parse(row.Name, row.Type, values[0]); err != nil {
				return model.rejectFlow(err)
			}
			return model.confirmPlan(
				backend.Plan{
					Title: "Update DNS record",
					Actions: []backend.Action{
						{
							Kind:     "dns_update",
							Zone:     zone,
							Name:     row.Name,
							Type:     row.Type,
							OldValue: row.Value,
							Value:    values[0],
						},
					},
				},
			)
		},
	)
	return nil
}

func (model *Model) dnsAddForm() tea.Cmd {
	zone := model.zone
	model.openForm(
		"Choose DNS record type", "Zone: "+zone,
		[]field{{"Type", "A", false}},
		true, func(values []string) tea.Cmd {
			recordType := strings.ToUpper(values[0])
			fields, err := dnsAddFields(recordType)
			if err != nil {
				return model.rejectFlow(err)
			}
			model.openForm(
				"Add "+recordType+" DNS record",
				"Zone: "+zone+"\nTTL: 900 seconds (Samba default)", fields, true,
				func(values []string) tea.Cmd {
					return model.dnsAddPlan(backend.Action{
						Kind: "dns_add", Zone: zone, Name: values[0], Type: recordType,
						Value: strings.Join(values[1:], " "),
					})
				},
			)
			return nil
		},
	)
	if model.form != nil {
		model.form.setChoices(0, "A", "AAAA", "CNAME", "PTR", "TXT", "MX", "SRV", "NS")
	}
	return nil
}

func contains(values []string, text string) bool {
	for _, value := range values {
		if strings.EqualFold(value, text) {
			return true
		}
	}
	return false
}
