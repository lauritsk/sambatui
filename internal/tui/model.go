package tui

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/discovery"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/invariant"
	"github.com/lauritsk/sambatui/internal/journal"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

type readResult struct {
	generation, requestID uint64
	kind, zone            string
	zones                 []string
	records               []dnsrpc.Row
	entries, folders      []directory.Entry
	err                   error
}
type writeResult struct {
	generation uint64
	out        lifecycle.Outcome
	flow       *lifecycle.Flow
}
type Model struct {
	state                                         *lifecycle.State
	journal                                       *journal.Store
	restarted                                     *journal.Record
	service                                       backend.Service
	settings                                      config.Settings
	configPath                                    string
	mode, zone, base, kind, query, search, status string
	dnsQueryType, dnsQueryName                    string
	filterByMode                                  map[string]string
	zones                                         []string
	records                                       []dnsrpc.Row
	entries, folders                              []directory.Entry
	selected                                      map[int]bool
	cursor, sideCursor                            int
	sidebar                                       bool
	width, height                                 int
	readID                                        uint64
	readCancel, writeCancel                       context.CancelFunc
	flow                                          *lifecycle.Flow
	form                                          *form
	detail                                        string
	detailOffset                                  int
	lastPlan                                      backend.Plan
	lastWrite                                     lifecycle.Snapshot
	sortField                                     int
	reverse                                       bool
	anchor                                        int
}

func (model Model) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "TUI{mode:%q, DC:%q, credentials:[redacted]}",
		model.mode, model.settings.Server,
	)
}

func New(settings config.Settings, path string, service backend.Service) *Model {
	if service == nil {
		service = backend.Native{}
	}
	return &Model{
		state:        lifecycle.New(settings),
		service:      service,
		settings:     settings,
		configPath:   path,
		mode:         "dns",
		zone:         settings.LastZone,
		base:         settings.BaseDN,
		kind:         "users",
		selected:     map[int]bool{},
		filterByMode: map[string]string{},
		status:       "Ctrl+O setup · z zones · l directory · ? help",
		width:        100,
		height:       30,
		anchor:       -1,
	}
}

func (model *Model) UseJournal(store *journal.Store) error {
	record, err := store.Load()
	if err != nil {
		return err
	}
	model.journal = store
	if record != nil {
		model.restarted = record
		model.lastPlan = record.Plan
		model.lastWrite = record.Snapshot
		return model.state.RestoreUncertain(record.Snapshot)
	}
	return nil
}

func (model *Model) Init() tea.Cmd {
	if model.settings.Server == "" {
		model.connectionForm()
		return nil
	}
	return model.load("zones")
}

// Literal escapes all control/format characters, including ESC, C1, OSC and
// bidi formatting. It is applied to server/error/form text, never ANSI-parsed.
func Literal(text string) string {
	return escape(text)
}

func escape(text string) string {
	var builder strings.Builder
	for _, character := range text {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			fmt.Fprintf(&builder, "\\u%04x", character)
		} else {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

func (model *Model) error(err error) {
	if err == nil {
		return
	}
	text := err.Error()
	for _, secret := range []string{
		model.settings.Password.Reveal(),
		model.lastWrite.Settings.Password.Reveal(),
	} {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	model.status = text
}

func (model *Model) setMode(mode string) {
	if model.mode != mode {
		model.filterByMode[model.mode] = model.search
		model.search = model.filterByMode[mode]
		model.mode = mode
		model.selected = map[int]bool{}
		model.cursor = 0
		model.anchor = -1
	}
}

func (model *Model) clear() {
	model.zones = nil
	model.records = nil
	model.entries = nil
	model.folders = nil
	model.selected = map[int]bool{}
	model.cursor = 0
	model.sideCursor = 0
	model.search = ""
	model.filterByMode = map[string]string{}
	model.zone = ""
	model.anchor = -1
	model.detail = ""
	model.readID = invariant.Next(model.readID)
	if model.readCancel != nil {
		model.readCancel()
	}
}

func (model *Model) setConnection(settings config.Settings) {
	model.settings = settings
	model.state.Change(settings)
	model.clear()
	model.base = settings.BaseDN
	model.status = "Connection changed; all loaded data and selections invalidated."
}

func (model *Model) load(kind string) tea.Cmd {
	if err := model.settings.Validate(true); err != nil {
		model.error(err)
		return nil
	}
	if model.readCancel != nil {
		model.readCancel()
	}
	snapshot := model.state.Snapshot()
	model.readID = invariant.Next(model.readID)
	operationContext, cancel := context.WithTimeout(
		context.Background(), time.Duration(snapshot.Settings.TimeoutSeconds)*time.Second,
	)
	model.readCancel = cancel
	request := readRequest{
		snapshot: snapshot, requestID: model.readID, kind: kind, zone: model.zone, base: model.base,
		searchKind: model.kind, query: model.query,
		queryType: model.dnsQueryType, queryName: model.dnsQueryName,
	}
	model.selected = map[int]bool{}
	model.cursor = 0
	model.anchor = -1
	switch kind {
	case "dns", "query":
		model.setMode("dns")
		model.records = nil
	case "ldap":
		model.setMode("ldap")
		model.entries = nil
		model.folders = nil
	}
	service := model.service
	model.status = "Loading " + kind + "…"
	return func() tea.Msg {
		defer cancel()
		return runRead(operationContext, service, request)
	}
}

func (model *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	model.assertValid()
	defer model.assertValid()
	switch value := message.(type) {
	case tea.WindowSizeMsg:
		// Terminal dimensions are external input; cap rendering and arithmetic.
		model.width = max(1, min(value.Width, terminalColumnsMax))
		model.height = max(1, min(value.Height, terminalRowsMax))
	case readResult:
		return model, model.updateRead(value)
	case discovered:
		return model, model.updateDiscovered(value)
	case reconciledRead:
		return model, model.reconcileRead(value)
	case writeResult:
		model.updateWrite(value)
	case tea.KeyMsg:
		return model, model.updateKey(value)
	}
	return model, nil
}

func (model *Model) updateRead(result readResult) tea.Cmd {
	if !model.state.Current(result.generation) || result.requestID != model.readID {
		return nil
	}
	if result.err != nil {
		model.error(result.err)
		return nil
	}
	model.selected = map[int]bool{}
	model.cursor = 0
	model.anchor = -1
	switch result.kind {
	case "zones":
		model.zones = result.zones
		model.status = fmt.Sprintf("Loaded %d zones", len(result.zones))
		if len(result.zones) > 0 {
			if !contains(result.zones, model.zone) {
				model.zone = result.zones[0]
			}
			return model.load("dns")
		}
	case "dns", "query":
		model.setMode("dns")
		model.records = result.records
		model.status = fmt.Sprintf("%d records from %s", len(result.records), model.zone)
	case "ldap":
		model.setMode("ldap")
		model.entries = result.entries
		model.folders = result.folders
		model.status = fmt.Sprintf(
			"%d entries (limit %d)",
			len(result.entries),
			model.settings.LDAPMaxRows,
		)
	}
	return nil
}

func (model *Model) updateDiscovered(discoveryResult discovered) tea.Cmd {
	if !model.state.Current(discoveryResult.generation) {
		return nil
	}
	if discoveryResult.err != nil {
		model.error(discoveryResult.err)
		return nil
	}
	text := "Discovered services (review before selecting):\n"
	for _, service := range discoveryResult.services {
		text += fmt.Sprintf(
			"%s %s:%d priority=%d weight=%d\n",
			service.Kind,
			Literal(service.Target),
			service.Port,
			service.Priority,
			service.Weight,
		)
	}
	preferred, ok := discovery.Preferred(discoveryResult.services)
	if !ok {
		model.status = "No AD service endpoints discovered"
		return nil
	}
	model.openForm(
		"Select discovered DC",
		text,
		[]field{{"DC hostname", preferred.Target, false}},
		false,
		func(values []string) tea.Cmd {
			settings := model.settings
			settings.Server = values[0]
			settings.Domain = discoveryResult.domain
			settings.BaseDN = "DC=" + strings.ReplaceAll(discoveryResult.domain, ".", ",DC=")
			model.setConnection(settings)
			model.connectionForm()
			return nil
		},
	)
	return nil
}

func (model *Model) updateWrite(result writeResult) {
	if result.flow != model.flow || model.flow == nil {
		return
	}
	if result.generation != model.lastWrite.Generation {
		return
	}
	model.flow = nil
	model.writeCancel = nil
	if result.out.Err != nil {
		model.error(result.out.Err)
	} else {
		model.status = "Write acknowledged by original DC. Refresh to inspect current state."
	}
	if result.out.Uncertain {
		model.status += " OUTCOME UNCERTAIN: further writes blocked. Press R to inspect/reconcile."
	}
}
