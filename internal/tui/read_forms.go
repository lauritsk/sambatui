package tui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/lauritsk/sambatui/internal/health"
)

func (model *Model) searchForm() {
	model.openForm(
		"Filter current results",
		"Literal case-insensitive local filter; LDAP server search is "+"available with l.",
		[]field{{"Search", model.search, false}},
		false,
		func(values []string) tea.Cmd {
			model.search = values[0]
			model.cursor = 0
			model.selected = map[int]bool{}
			return nil
		},
	)
}

func (model *Model) queryForm() {
	if model.zone == "" {
		model.status = "Select a DNS zone first"
		return
	}
	model.openForm(
		"Query DNS management records",
		"DC: "+model.settings.Server+"\nZone: "+model.zone,
		[]field{{"Name", "@", false}, {"Type / ALL", "ALL", false}},
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
		"Verified TLS; pinned to "+model.settings.Server,
		[]field{
			{"Base DN", model.base, false},
			{"Kind: users/groups/computers/ous/all", model.kind, false},
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
}

func (model *Model) commandForm() {
	model.openForm(
		"Command palette",
		"Commands: zones, directory, query, add, update, delete, fix, "+
			"health, connection, discover, thresholds, reconcile, help",
		[]field{{"Command", "", false}},
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
			case "fix":
				return model.writeForm("f")
			case "health":
				model.healthCheck = 8
				return model.load("health")
			case "connection":
				model.connectionForm()
			case "discover":
				return model.discoverForm()
			case "thresholds":
				model.thresholdForm()
			case "reconcile":
				return model.reconcile()
			case "help":
				model.showDetails(help)
			default:
				model.status = "Unknown command"
			}
			return nil
		},
	)
}

func (model *Model) findingsForm() {
	text := ""
	for index, label := range health.Labels {
		text += fmt.Sprintf("%d: %s\n", index+1, label)
	}
	model.openForm(
		"Choose findings view",
		text,
		[]field{{"View number 1–8", "8", false}},
		false,
		func(values []string) tea.Cmd {
			count, err := strconv.Atoi(values[0])
			if err != nil || count < 1 || count > 8 {
				model.error(errors.New("choose view 1–8"))
				return nil
			}
			model.healthCheck = count
			return model.load("health")
		},
	)
}
