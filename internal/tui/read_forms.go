package tui

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsdata"
)

func (model *Model) searchForm() {
	model.openForm(
		"Filter",
		"",
		[]field{{"", model.search, false}},
		false,
		func(values []string) tea.Cmd {
			model.search = values[0]
			model.cursor = 0
			model.anchor = -1
			model.selected = map[int]bool{}
			return nil
		},
	)
	if model.form != nil {
		model.form.EnterSubmits = true
		model.form.ShowScope = true
	}
}

func (model *Model) queryForm() {
	if model.zone == "" {
		model.status = "Select a DNS zone first"
		return
	}
	model.openForm(
		"Query DNS",
		"Zone: "+model.zone,
		[]field{{"Name", "@", false}, {"Type", "ALL", false}},
		false,
		func(values []string) tea.Cmd {
			if !dnsdata.ValidName(values[0], true) {
				model.error(errors.New("invalid DNS query name"))
				return nil
			}
			if _, err := backend.ParseQueryType(strings.ToUpper(values[1])); err != nil {
				model.error(err)
				return nil
			}
			model.dnsQueryName = values[0]
			model.dnsQueryType = strings.ToUpper(values[1])
			return model.load("query")
		},
	)
}

func (model *Model) ldapForm() {
	model.openForm(
		"LDAP search",
		"",
		[]field{
			{"Base DN", model.base, false},
			{"Kind", model.kind, false},
			{"Search text", model.query, false},
			{"Max entries 1–5000", strconv.Itoa(model.settings.LDAPMaxRows), false},
		},
		false,
		func(values []string) tea.Cmd {
			count, err := strconv.Atoi(values[3])
			if err != nil || count < 1 || count > 5000 {
				model.error(errors.New("limit must be 1–5000"))
				return nil
			}
			if !directory.InScope(values[0], model.settings.BaseDN) {
				model.error(errors.New("search base outside configured scope"))
				return nil
			}
			if _, err = directory.Filter(values[1], values[2]); err != nil {
				model.error(err)
				return nil
			}
			model.base = values[0]
			model.kind = values[1]
			model.query = values[2]
			model.settings.LDAPMaxRows = count
			model.state.Change(model.settings)
			model.selected = map[int]bool{}
			return model.load("ldap")
		},
	)
	if model.form != nil {
		model.form.setChoices(1, "users", "groups", "computers", "ous", "all")
	}
}

func (model *Model) commandNames() []string {
	names := []string{"connection", "discover", "help"}
	_, uncertain := model.state.Uncertain()
	if model.settings.Server != "" {
		names = append(names, "zones", "directory")
		if model.flow == nil && !uncertain {
			if model.mode == "ldap" || model.zone != "" {
				names = append(names, "add")
			}
			if len(model.visible()) > 0 {
				names = append(names, "update", "delete")
			}
		}
	}
	if model.zone != "" {
		names = append(names, "query")
	}
	if uncertain && model.flow == nil {
		names = append(names, "reconcile")
	}
	if model.lastError != "" {
		names = append(names, "error")
	}
	sort.Strings(names)
	return names
}

func (model *Model) commandForm() {
	model.openForm(
		"Commands",
		"",
		[]field{{"", "", false}},
		false,
		func(values []string) tea.Cmd {
			switch strings.ToLower(values[0]) {
			case "zones":
				return model.load("zones")
			case "directory":
				model.ldapForm()
			case "query":
				model.queryForm()
			case "add":
				return model.writeForm("a")
			case "update":
				return model.writeForm("u")
			case "delete":
				return model.writeForm("d")
			case "connection":
				model.connectionForm()
			case "discover":
				return model.discoverForm()
			case "reconcile":
				return model.reconcile()
			case "help":
				model.showHelp()
			case "error":
				model.showLastError()
			default:
				model.status = "Unknown command"
			}
			return nil
		},
	)
	if model.form != nil {
		model.form.Items = model.commandNames()
		model.form.ItemLabels = map[string]string{
			"connection": "Connection", "discover": "Discover DC", "help": "Help",
			"zones": "DNS zones", "directory": "LDAP search", "query": "DNS query",
			"add": "Add", "update": "Edit", "delete": "Delete",
			"reconcile": "Reconcile write", "error": "Last error",
		}
		items, labels := model.form.Items, model.form.ItemLabels
		sort.SliceStable(items, func(left, right int) bool {
			return strings.ToLower(labels[items[left]]) < strings.ToLower(labels[items[right]])
		})
		model.form.EnterSubmits = true
		model.form.ShowScope = true
	}
}
