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
	"github.com/miekg/dns"
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
	if e := m.cfg.Validate(true); e != nil {
		m.error(e)
		return nil
	}
	if m.readCancel != nil {
		m.readCancel()
	}
	snap := m.state.Snapshot()
	m.readID++
	id := m.readID
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(snap.Settings.TimeoutSeconds)*time.Second)
	m.readCancel = cancel
	zone, base, searchKind, query, check := m.zone, m.base, m.kind, m.query, m.healthCheck
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
	queryType := m.dnsQueryType
	queryName := m.dnsQueryName
	if queryName == "" {
		queryName = "@"
	}
	service := m.service
	m.status = "Loading " + kind + "…"
	return func() tea.Msg {
		defer cancel()
		r := readResult{gen: snap.Generation, id: id, kind: kind, zone: zone}
		s := snap.Settings
		switch kind {
		case "zones", "setup":
			r.zones, r.err = service.Zones(ctx, s)
			if kind == "setup" && r.err == nil {
				r.err = service.CheckLDAP(ctx, s)
			}
		case "dns":
			r.records, r.err = service.Records(ctx, s, zone, "@", dns.TypeANY)
		case "query":
			typ, e := backend.ParseQueryType(strings.ToUpper(queryType))
			if e != nil {
				r.err = e
			} else {
				r.records, r.err = service.Records(ctx, s, zone, queryName, typ)
			}
		case "ldap":
			r.entries, r.err = service.Search(ctx, s, base, searchKind, query, s.LDAPMaxRows)
			if r.err == nil {
				r.folders, r.err = service.Search(ctx, s, base, "containers", "", s.LDAPMaxRows)
			}
		case "health":
			records := map[string][]dnsrpc.Row{}
			completeDNS := true
			completed := map[int]bool{}
			if check <= 3 || check == 8 {
				zones, e := service.Zones(ctx, s)
				if e != nil {
					r.findings = append(r.findings, health.Finding{Severity: "error", Finding: "DNS checks failed", Evidence: e.Error()})
					completeDNS = false
				} else {
					for _, z := range zones {
						rows, e := service.Records(ctx, s, z, "@", dns.TypeANY)
						if e != nil {
							r.findings = append(r.findings, health.Finding{Severity: "error", Object: z, Finding: "DNS zone check failed", Evidence: e.Error()})
							completeDNS = false
						} else {
							records[z] = rows
						}
					}
				}
				// Cross-zone negative findings would be misleading after a failed zone read.
				if completeDNS {
					for i := 1; i <= 3; i++ {
						completed[i] = true
					}
					for _, f := range health.DNS(records) {
						if check == 8 || f.Check == check {
							r.findings = append(r.findings, f)
						}
					}
				}
			}
			if check >= 4 {
				entries, e := service.Search(ctx, s, s.BaseDN, "all", "", s.MaxRows)
				if e != nil {
					r.findings = append(r.findings, health.Finding{Severity: "error", Finding: "LDAP checks failed", Evidence: e.Error()})
				} else {
					if len(entries) < s.MaxRows {
						for i := 4; i <= 7; i++ {
							completed[i] = true
						}
					}
					for _, f := range health.LDAP(entries, health.Options{Days: s.Days, DisabledDays: s.DisabledDays, NeverLoggedDays: s.NeverLoggedDays}) {
						if check == 8 || f.Check == check {
							r.findings = append(r.findings, f)
						}
					}
					if len(entries) >= s.MaxRows {
						r.findings = append(r.findings, health.Finding{Severity: "info", Finding: "LDAP check limited", Evidence: fmt.Sprintf("Only first %d entries checked; load more before concluding clean.", s.MaxRows)})
					}
				}
			}
			if check == 8 {
				r.findings = health.Dashboard(r.findings, completed)
			}
			if len(r.findings) == 0 {
				r.findings = append(r.findings, health.Finding{Severity: "info", Finding: "No findings in completed checks", Evidence: "This is hygiene evidence, not an authorization or security audit."})
			}
		}
		return r
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = v.Width
		m.height = v.Height
		return m, nil
	case readResult:
		if !m.state.Current(v.gen) || v.id != m.readID {
			return m, nil
		}
		if v.err != nil {
			m.error(v.err)
			return m, nil
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
				return m, m.load("dns")
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
		return m, nil
	case discovered:
		if !m.state.Current(v.gen) {
			return m, nil
		}
		if v.err != nil {
			m.error(v.err)
			return m, nil
		}
		text := "Discovered services (review before selecting):\n"
		for _, s := range v.services {
			text += fmt.Sprintf("%s %s:%d priority=%d weight=%d\n", s.Kind, Literal(s.Target), s.Port, s.Priority, s.Weight)
		}
		preferred, ok := discovery.Preferred(v.services)
		if !ok {
			m.status = "No AD service endpoints discovered"
			return m, nil
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
		return m, nil
	case reconciledRead:
		return m, m.reconcileRead(v)
	case writeResult:
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
		return m, nil
	case tea.KeyMsg:
		// Bubble Tea may coalesce consecutive printable keystrokes. Preserve
		// navigation repeats, but never interpret bracketed paste as commands.
		if m.form == nil && v.Type == tea.KeyRunes && len(v.Runes) > 1 && !v.Paste && !v.Alt {
			cmds := []tea.Cmd{}
			for _, r := range v.Runes {
				_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
				if cmd != nil {
					cmds = append(cmds, cmd)
				}
			}
			return m, tea.Batch(cmds...)
		}
		if m.form == nil && v.Paste {
			return m, nil
		}
		key := v.String()
		if key == "ctrl+c" {
			if m.writeCancel != nil {
				m.writeCancel()
				m.status = "Cancellation requested; waiting for worker cleanup. This is not rollback."
				return m, nil
			}
			if m.form != nil {
				m.closeForm()
				return m, nil
			}
			return m, tea.Quit
		}
		if m.form != nil {
			return m, m.updateForm(v)
		}
		if m.detail != "" {
			switch key {
			case "esc", "enter", "q":
				m.detail = ""
			case "j", "down":
				m.detailOffset++
			case "k", "up":
				m.detailOffset = max(0, m.detailOffset-1)
			case "pgdown":
				m.detailOffset += max(1, m.height-8)
			case "pgup":
				m.detailOffset = max(0, m.detailOffset-max(1, m.height-8))
			}
			return m, nil
		}
		switch key {
		case "Q":
			if m.flow != nil {
				m.status = "Cannot quit during a write; cancel and drain it first."
				return m, nil
			}
			return m, tea.Quit
		case "?":
			m.showDetails(help)
		case "h":
			m.findingsForm()
		case "ctrl+o":
			m.connectionForm()
		case "ctrl+p":
			m.commandForm()
		case "z":
			m.setMode("dns")
			return m, m.load("zones")
		case "l":
			m.ldapForm()
		case "q":
			m.queryForm()
		case "r":
			if m.mode == "ldap" {
				return m, m.load("ldap")
			}
			if m.mode == "health" {
				return m, m.load("health")
			}
			return m, m.load("dns")
		case "R":
			return m, m.reconcile()
		case "tab":
			m.sidebar = !m.sidebar
		case "j", "down":
			m.move(1)
		case "k", "up":
			m.move(-1)
		case "pgdown", "ctrl+d":
			m.move(max(1, (m.height-10)/2))
		case "pgup", "ctrl+u":
			m.move(-max(1, (m.height-10)/2))
		case "home", "g":
			m.move(-100000)
		case "end", "G":
			m.move(100000)
		case " ":
			if !m.sidebar {
				indices := m.visible()
				if m.cursor < len(indices) {
					i := indices[m.cursor]
					m.selected[i] = !m.selected[i]
					m.anchor = m.cursor
				}
			}
		case "v":
			if m.anchor < 0 {
				m.anchor = m.cursor
			} else {
				indices := m.visible()
				for i := min(m.anchor, m.cursor); i <= max(m.anchor, m.cursor) && i < len(indices); i++ {
					m.selected[indices[i]] = true
				}
				m.anchor = -1
			}
		case "esc":
			m.selected = map[int]bool{}
			m.search = ""
			m.anchor = -1
		case "/":
			m.searchForm()
		case "s":
			m.sortField = (m.sortField + 1) % 3
			m.reverse = !m.reverse
		case "enter":
			if m.sidebar {
				return m, m.activateSide()
			}
			m.details()
		case "a", "u", "e", "d", "f":
			return m, m.writeForm(key)
		case "m":
			if m.mode == "health" {
				m.cfg.MaxRows = min(5000, m.cfg.MaxRows+200)
			} else if m.mode == "ldap" {
				m.cfg.LDAPMaxRows = min(5000, m.cfg.LDAPMaxRows+200)
			} else {
				m.status = "Load more is available for directory/findings views"
				return m, nil
			}
			m.state.Change(m.cfg)
			m.selected = map[int]bool{}
			if m.mode == "health" {
				return m, m.load("health")
			}
			return m, m.load("ldap")
		case "p":
			password, e := config.ReadPassword(m.cfg.PasswordFile)
			if e != nil {
				m.error(e)
			} else {
				s := m.cfg
				s.Password = newSecret(password)
				m.setConnection(s)
			}
		case "P":
			m.savePasswordForm()
		case "1", "2", "3", "4", "5", "6", "7", "8":
			m.healthCheck = int(key[0] - '0')
			return m, m.load("health")
		}
	}
	return m, nil
}

func (m *Model) visible() []int {
	values := m.rowTexts()
	indices := []int{}
	for i, s := range values {
		if strings.Contains(strings.ToLower(s), strings.ToLower(m.search)) {
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
