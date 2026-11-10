package tui

import (
	"errors"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/directory"
)

func (model *Model) ldapWriteForm(key string, indices []int) tea.Cmd {
	if key == "a" {
		return model.ldapAddForm()
	}
	if len(indices) == 0 {
		return model.rejectFlow(errors.New("select a directory entry first"))
	}
	if key == "d" {
		plan := backend.Plan{Title: "Delete selected directory entries"}
		for _, index := range indices {
			entry := model.entries[index]
			if entry.Revision == "" || directory.EqualDN(entry.DN, model.settings.BaseDN) {
				return model.rejectFlow(
					errors.New("missing revision or protected base DN; deletion refused"),
				)
			}
			action := backend.Action{Kind: "ldap_delete", DN: entry.DN, Revision: entry.Revision}
			plan.Actions = append(plan.Actions, action)
		}
		return model.confirmPlan(plan)
	}
	if len(indices) != 1 {
		return model.rejectFlow(errors.New("update requires one directory entry"))
	}
	entry := model.entries[indices[0]]
	if entry.Revision == "" {
		return model.rejectFlow(errors.New("entry has no unique revision; refresh before writing"))
	}
	attributes := directory.Editable[entry.Kind]
	if len(attributes) == 0 {
		return model.rejectFlow(errors.New("entry kind not editable"))
	}
	fields := []field{}
	for _, left := range attributes {
		fields = append(fields, field{left, entry.First(left), false})
	}
	model.openForm(
		"Edit LDAP entry",
		entry.DN+"\nRevision: "+entry.Revision,
		fields,
		true,
		func(values []string) tea.Cmd {
			changes := map[string]string{}
			for index, left := range attributes {
				if values[index] != entry.First(left) {
					changes[left] = values[index]
				}
			}
			if len(changes) == 0 {
				return model.rejectFlow(errors.New("no attributes changed"))
			}
			return model.confirmPlan(
				backend.Plan{
					Title: "Modify selected LDAP entry",
					Actions: []backend.Action{
						{
							Kind:       "ldap_modify",
							DN:         entry.DN,
							EntryKind:  entry.Kind,
							Revision:   entry.Revision,
							Attributes: changes,
						},
					},
				},
			)
		},
	)
	return nil
}

func (model *Model) ldapAddForm() tea.Cmd {
	parent := model.base
	model.openForm(
		"Add LDAP entry",
		"No password is set. Review the object kind and account name; "+
			"computer flags use the existing Samba defaults.",
		[]field{
			{"Kind: user/group/computer/ou", "group", false},
			{"Parent DN", parent, false},
			{"Name", "", false},
			{"sAMAccountName (optional)", "", false},
			{"Description", "", false},
			{"Mail", "", false},
			{"Display name", "", false},
			{"Computer DNS hostname", "", false},
			{"User principal name (UPN)", "", false},
		},
		true,
		func(values []string) tea.Cmd {
			attributes := map[string]string{
				"sAMAccountName":    values[3],
				"description":       values[4],
				"mail":              values[5],
				"displayName":       values[6],
				"dNSHostName":       values[7],
				"userPrincipalName": values[8],
			}
			if !directory.InScope(values[1], model.flow.Snapshot.Settings.BaseDN) ||
				!directory.InScope(values[1], parent) {
				return model.rejectFlow(errors.New("parent outside configured LDAP base"))
			}
			if _, err := directory.BuildAdd(
				values[0],
				values[1],
				values[2],
				attributes,
			); err != nil {
				return model.rejectFlow(err)
			}
			return model.confirmPlan(
				backend.Plan{
					Title: "Add LDAP entry",
					Actions: []backend.Action{
						{
							Kind:       "ldap_add",
							EntryKind:  values[0],
							Parent:     values[1],
							Name:       values[2],
							Attributes: attributes,
						},
					},
				},
			)
		},
	)
	return nil
}
