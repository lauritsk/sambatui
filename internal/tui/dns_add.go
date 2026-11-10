package tui

import (
	"errors"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/lauritsk/sambatui/internal/invariant"
)

func dnsAddFields(recordType string) ([]field, error) {
	fields := []field{{"Name (@ = zone root)", "", false}}
	switch recordType {
	case "A":
		fields = append(fields, field{"IPv4 address", "", false})
	case "AAAA":
		fields = append(fields, field{"IPv6 address", "", false})
	case "CNAME", "PTR", "NS":
		fields = append(fields, field{"Target hostname", "", false})
	case "TXT":
		fields = append(fields, field{"Text", "", false})
	case "MX":
		fields = append(fields, field{"Priority", "10", false}, field{"Mail exchanger", "", false})
	case "SRV":
		fields = append(fields,
			field{"Priority", "0", false}, field{"Weight", "100", false},
			field{"Port", "389", false}, field{"Target hostname", "", false},
		)
	default:
		return nil, errors.New("unsupported record type")
	}
	invariant.Require(len(fields) >= 2, "DNS form is missing RDATA")
	invariant.Require(len(fields) <= 5, "DNS form has unexpected fields")
	return fields, nil
}

func (model *Model) dnsAddPlan(action backend.Action) tea.Cmd {
	invariant.Require(model.flow != nil, "DNS add requires a write reservation")
	if _, err := dnsdata.Parse(action.Name, action.Type, action.Value); err != nil {
		return model.rejectFlow(err)
	}
	for _, row := range model.records {
		if strings.EqualFold(row.Name, action.Name) && row.Type == action.Type {
			if row.Value == action.Value {
				return model.rejectFlow(errors.New("duplicate record in loaded zone"))
			}
		}
	}
	plan := backend.Plan{Title: "Add DNS record", Actions: []backend.Action{action}}
	policy := model.flow.Snapshot.Settings.AutoPTR
	if action.Type != "A" || policy == "off" {
		return model.confirmPlan(plan)
	}
	zone, name, found := dnsdata.Reverse(action.Value, model.zones)
	if !found || !contains(model.zones, zone) {
		return model.confirmPlan(plan)
	}
	pointer := backend.Action{
		Kind: "dns_add", Zone: zone, Name: name, Type: "PTR",
		Value: dnsdata.FQDN(action.Name, action.Zone),
	}
	if policy == "on" {
		plan.Actions = append(plan.Actions, pointer)
		return model.confirmPlan(plan)
	}
	model.openForm(
		"Optional matching PTR", pointer.Zone+": "+pointer.Name+" PTR "+pointer.Value,
		[]field{{"Include PTR? yes / no", "no", false}}, true,
		func(values []string) tea.Cmd {
			if values[0] == "yes" {
				plan.Actions = append(plan.Actions, pointer)
			}
			return model.confirmPlan(plan)
		},
	)
	if model.form != nil {
		model.form.setChoices(0, "no", "yes")
	}
	return nil
}
