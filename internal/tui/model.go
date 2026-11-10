package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/discovery"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/health"
	"github.com/lauritsk/sambatui/internal/journal"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

type readResult struct {
	gen, id          uint64
	kind, zone       string
	zones            []string
	records          []dnsrpc.Row
	entries, folders []directory.Entry
	findings         []health.Finding
	err              error
}
type writeResult struct {
	generation uint64
	out        lifecycle.Outcome
}
type Model struct {
	state                                         *lifecycle.State
	journal                                       *journal.Store
	restarted                                     *journal.Record
	service                                       backend.Service
	cfg                                           config.Settings
	configPath                                    string
	mode, zone, base, kind, query, search, status string
	dnsQueryType, dnsQueryName                    string
	filterByMode                                  map[string]string
	zones                                         []string
	records                                       []dnsrpc.Row
	entries, folders                              []directory.Entry
	findings                                      []health.Finding
	healthCheck                                   int
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

func (m Model) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "TUI{mode:%q, DC:%q, credentials:[redacted]}", m.mode, m.cfg.Server)
}

func New(cfg config.Settings, path string, service backend.Service) *Model {
	if service == nil {
		service = backend.Native{}
	}
	return &Model{state: lifecycle.New(cfg), service: service, cfg: cfg, configPath: path, mode: "dns", zone: cfg.LastZone, base: cfg.BaseDN, kind: "users", selected: map[int]bool{}, filterByMode: map[string]string{}, status: "Ctrl+O setup · z zones · l directory · ? help", width: 100, height: 30, anchor: -1}
}

func (m *Model) UseJournal(store *journal.Store) error {
	r, e := store.Load()
	if e != nil {
		return e
	}
	m.journal = store
	if r != nil {
		m.restarted = r
		m.lastPlan = r.Plan
		m.lastWrite = r.Snapshot
		return m.state.RestoreUncertain(r.Snapshot)
	}
	return nil
}

func (m *Model) Init() tea.Cmd {
	if m.cfg.Server == "" {
		m.connectionForm()
		return nil
	}
	return m.load("zones")
}

// Literal escapes all control/format characters, including ESC, C1, OSC and
// bidi formatting. It is applied to server/error/form text, never ANSI-parsed.
func Literal(s string) string { return escape(s) }

func escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (m *Model) error(err error) {
	if err == nil {
		return
	}
	text := err.Error()
	for _, secret := range []string{m.cfg.Password.Reveal(), m.lastWrite.Settings.Password.Reveal()} {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	m.status = text
}

func (m *Model) setMode(mode string) {
	if m.mode != mode {
		m.filterByMode[m.mode] = m.search
		m.search = m.filterByMode[mode]
		m.mode = mode
		m.selected = map[int]bool{}
		m.cursor = 0
		m.anchor = -1
	}
}

func (m *Model) clear() {
	m.zones = nil
	m.records = nil
	m.entries = nil
	m.folders = nil
	m.findings = nil
	m.selected = map[int]bool{}
	m.cursor = 0
	m.sideCursor = 0
	m.search = ""
	m.filterByMode = map[string]string{}
	m.zone = ""
	m.anchor = -1
	m.detail = ""
	m.readID++
	if m.readCancel != nil {
		m.readCancel()
	}
}

func (m *Model) setConnection(s config.Settings) {
	m.cfg = s
	m.state.Change(s)
	m.clear()
	m.base = s.BaseDN
	m.status = "Connection changed; all loaded data and selections invalidated."
}

func (m *Model) load(kind string) tea.Cmd {
	if err := m.cfg.Validate(true); err != nil {
		m.error(err)
		return nil
	}
	if m.readCancel != nil {
		m.readCancel()
	}
	snapshot := m.state.Snapshot()
	m.readID++
	ctx, cancel := context.WithTimeout(
		context.Background(), time.Duration(snapshot.Settings.TimeoutSeconds)*time.Second,
	)
	m.readCancel = cancel
	request := readRequest{
		snapshot: snapshot, id: m.readID, kind: kind, zone: m.zone, base: m.base,
		searchKind: m.kind, query: m.query, check: m.healthCheck,
		queryType: m.dnsQueryType, queryName: m.dnsQueryName,
	}
	m.selected = map[int]bool{}
	m.cursor = 0
	m.anchor = -1
	switch kind {
	case "dns", "query":
		m.setMode("dns")
		m.records = nil
	case "ldap":
		m.setMode("ldap")
		m.entries = nil
		m.folders = nil
	case "health":
		m.setMode("health")
		m.findings = nil
	}
	service := m.service
	m.status = "Loading " + kind + "…"
	return func() tea.Msg {
		defer cancel()
		return runRead(ctx, service, request)
	}
}

func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch value := message.(type) {
	case tea.WindowSizeMsg:
		m.width = value.Width
		m.height = value.Height
	case readResult:
		return m, m.updateRead(value)
	case discovered:
		return m, m.updateDiscovered(value)
	case reconciledRead:
		return m, m.reconcileRead(value)
	case writeResult:
		m.updateWrite(value)
	case tea.KeyMsg:
		return m, m.updateKey(value)
	}
	return m, nil
}

func (m *Model) updateRead(v readResult) tea.Cmd {
	if !m.state.Current(v.gen) || v.id != m.readID {
		return nil
	}
	if v.err != nil {
		m.error(v.err)
		return nil
	}
	m.selected = map[int]bool{}
	m.cursor = 0
	m.anchor = -1
	switch v.kind {
	case "zones", "setup":
		m.zones = v.zones
		m.status = fmt.Sprintf("Loaded %d zones", len(v.zones))
		if len(v.zones) > 0 {
			if !contains(v.zones, m.zone) {
				m.zone = v.zones[0]
			}
			return m.load("dns")
		}
	case "dns", "query":
		m.setMode("dns")
		m.records = v.records
		m.status = fmt.Sprintf("%d records from %s", len(v.records), m.zone)
	case "ldap":
		m.setMode("ldap")
		m.entries = v.entries
		m.folders = v.folders
		m.status = fmt.Sprintf("%d entries (limit %d)", len(v.entries), m.cfg.LDAPMaxRows)
	case "health":
		m.setMode("health")
		m.findings = v.findings
		m.status = fmt.Sprintf("%d findings/check notices", len(v.findings))
	}
	return nil
}

func (m *Model) updateDiscovered(v discovered) tea.Cmd {
	if !m.state.Current(v.gen) {
		return nil
	}
	if v.err != nil {
		m.error(v.err)
		return nil
	}
	text := "Discovered services (review before selecting):\n"
	for _, s := range v.services {
		text += fmt.Sprintf("%s %s:%d priority=%d weight=%d\n", s.Kind, Literal(s.Target), s.Port, s.Priority, s.Weight)
	}
	preferred, ok := discovery.Preferred(v.services)
	if !ok {
		m.status = "No AD service endpoints discovered"
		return nil
	}
	m.openForm("Select discovered DC", text, []field{{"DC hostname", preferred.Target, false}}, false, func(values []string) tea.Cmd {
		s := m.cfg
		s.Server = values[0]
		s.Domain = v.domain
		s.BaseDN = "DC=" + strings.ReplaceAll(v.domain, ".", ",DC=")
		m.setConnection(s)
		m.connectionForm()
		return nil
	})
	return nil
}

func (m *Model) updateWrite(v writeResult) {
	m.flow = nil
	m.writeCancel = nil
	if v.out.Err != nil {
		m.error(v.out.Err)
	} else {
		m.status = "Write acknowledged by original DC. Refresh to inspect current state."
	}
	if v.out.Uncertain {
		m.status += " OUTCOME UNCERTAIN: further writes blocked. Press R to inspect/reconcile."
	}
}

func (m *Model) visible() []int {
	values := m.rowTexts()
	indices := make([]int, 0, len(values))
	needle := strings.ToLower(m.search)
	for i, s := range values {
		if strings.Contains(strings.ToLower(s), needle) {
			indices = append(indices, i)
		}
	}
	sort.SliceStable(indices, func(i, j int) bool {
		a, b := m.sortKey(indices[i]), m.sortKey(indices[j])
		if m.reverse {
			return a > b
		}
		return a < b
	})
	return indices
}

func (m *Model) sortKey(i int) string {
	switch m.mode {
	case "dns":
		r := m.records[i]
		return []string{r.Name, r.Type, r.Value}[m.sortField]
	case "ldap":
		r := m.entries[i]
		return []string{r.Name, r.Kind, r.DN}[m.sortField]
	default:
		r := m.findings[i]
		if m.healthCheck == 8 {
			return fmt.Sprintf("%02d:%09d", r.Check, i)
		}
		return []string{fmt.Sprint(health.Rank(r.Severity)), r.Object, r.Finding}[m.sortField]
	}
}

func (m *Model) rowTexts() []string {
	out := []string{}
	switch m.mode {
	case "dns":
		for _, r := range m.records {
			out = append(out, fmt.Sprintf("%-28s %-6s %-8d %s", Literal(r.Name), Literal(r.Type), r.TTL, Literal(r.Value)))
		}
	case "ldap":
		for _, r := range m.entries {
			out = append(out, Literal(r.Name)+"  "+Literal(r.Kind)+"  "+Literal(r.DN))
		}
	case "health":
		for _, r := range m.findings {
			out = append(out, Literal(r.Severity)+"  "+Literal(r.Object)+"  "+Literal(r.Finding))
		}
	}
	return out
}

func (m *Model) move(delta int) {
	if m.sidebar {
		m.sideCursor = max(0, min(m.sideCursor+delta, len(m.sideLabels())-1))
	} else {
		m.cursor = max(0, min(m.cursor+delta, len(m.visible())-1))
	}
}

func (m *Model) sideLabels() []string {
	if m.mode != "ldap" {
		return m.zones
	}
	out := []string{"↑ Configured base", "Users", "Groups", "Computers", "OUs", "All"}
	for _, e := range m.folders {
		out = append(out, e.Name)
	}
	return out
}

func (m *Model) activateSide() tea.Cmd {
	if m.mode != "ldap" {
		if m.sideCursor < len(m.zones) {
			m.zone = m.zones[m.sideCursor]
			m.cfg.LastZone = m.zone
			if e := config.Save(m.configPath, m.cfg); e != nil {
				m.error(e)
			}
			m.setMode("dns")
			return m.load("dns")
		}
		return nil
	}
	if m.sideCursor == 0 {
		m.base = m.cfg.BaseDN
	} else if m.sideCursor < 6 {
		m.kind = []string{"users", "groups", "computers", "ous", "all"}[m.sideCursor-1]
	} else if m.sideCursor-6 < len(m.folders) {
		m.base = m.folders[m.sideCursor-6].DN
	}
	return m.load("ldap")
}
func (m *Model) showDetails(s string) { m.detail = s; m.detailOffset = 0 }
func (m *Model) details() {
	indices := m.visible()
	if m.cursor >= len(indices) {
		return
	}
	i := indices[m.cursor]
	var text string
	switch m.mode {
	case "dns":
		r := m.records[i]
		text = fmt.Sprintf("DC: %s\nZone: %s\nName: %s\nType: %s\nTTL: %d\nValue: %s", m.cfg.Server, m.zone, r.Name, r.Type, r.TTL, r.Value)
	case "ldap":
		e := m.entries[i]
		text = "DC: " + m.cfg.Server + "\nDN: " + e.DN + "\nRevision (DC-local): " + e.Revision + "\n"
		keys := []string{}
		for k := range e.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			text += k + ": " + strings.Join(e.Attributes[k], "; ") + "\n"
		}
	case "health":
		f := m.findings[i]
		text = f.Object + "\n" + f.Finding + "\n" + f.Evidence + "\nSuggested: " + f.Action + "\nGuided fix: " + f.Fix
	}
	m.showDetails(text)
}

func (m *Model) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	out := title.Render("sambatui — native Go") + "\nDC: " + Literal(m.cfg.Server) + "  Auth: " + Literal(m.cfg.Auth) + "  TLS: " + Literal(m.cfg.Encryption) + "\n"
	if m.form != nil {
		return out + m.formView() + "\n" + Literal(m.status)
	}
	if m.detail != "" {
		lines := strings.Split(m.detail, "\n")
		start := min(m.detailOffset, max(0, len(lines)-1))
		for _, s := range lines[start:min(len(lines), start+max(1, m.height-7))] {
			out += Literal(s) + "\n"
		}
		return out + "j/k scroll · Esc close\n"
	}
	out += fmt.Sprintf("%s  zone=%s  base=%s  search=%s\n", m.mode, Literal(m.zone), Literal(m.base), Literal(m.search))
	labels := m.sideLabels()
	side := []string{}
	for i, s := range labels {
		mark := "  "
		if i == m.sideCursor && m.sidebar {
			mark = "> "
		}
		side = append(side, mark+Literal(s))
	}
	indices := m.visible()
	texts := m.rowTexts()
	height := max(1, m.height-9)
	start := max(0, m.cursor-height+1)
	rows := []string{}
	for pos := start; pos < min(len(indices), start+height); pos++ {
		i := indices[pos]
		mark := "  "
		if m.selected[i] {
			mark = "✓ "
		}
		if pos == m.cursor && !m.sidebar {
			mark = "> " + mark
		}
		rows = append(rows, mark+texts[i])
	}
	for len(rows) < height {
		rows = append(rows, "")
	}
	for len(side) < height {
		side = append(side, "")
	}
	sideStart := min(max(0, len(side)-height), max(0, m.sideCursor-height+1))
	sideEnd := min(len(side), sideStart+height)
	left := lipgloss.NewStyle().Width(min(32, max(16, m.width/4))).MaxWidth(min(32, max(16, m.width/4))).Render(strings.Join(side[sideStart:sideEnd], "\n"))
	right := lipgloss.NewStyle().MaxWidth(max(1, m.width-min(32, max(16, m.width/4))-2)).Render(strings.Join(rows, "\n"))
	out += lipgloss.JoinHorizontal(lipgloss.Top, left, " │ "+right) + "\n" + Literal(m.status) + "\n"
	out += "Tab pane · Enter details/open · z DNS · l LDAP · 1–8 findings · a/u/d write · f fix\n/ search · space select · v range · s sort · r refresh · R reconcile · Ctrl+O setup · ? help · Q quit"
	return out
}
