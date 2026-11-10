package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/discovery"
	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/lauritsk/sambatui/internal/health"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

type field struct {
	Label  string
	Value  any // string, or auth.Secret for a password; never plaintext secret storage.
	Secret bool
}

func (f field) text() string {
	switch v := f.Value.(type) {
	case string:
		return v
	case auth.Secret:
		return v.Reveal()
	default:
		panic("invalid form field value type")
	}
}

func (f *field) setText(s string) {
	if f.Secret {
		f.Value = auth.NewSecret(s)
	} else {
		f.Value = s
	}
}

func (f field) String() string {
	if f.Secret {
		return f.Label + ": [redacted]"
	}
	return f.Label + ": " + Literal(f.text())
}
func (f field) GoString() string                  { return f.String() }
func (f field) Format(state fmt.State, verb rune) { io.WriteString(state, f.String()) }
func (f field) MarshalJSON() ([]byte, error)      { return json.Marshal(f.String()) }

type form struct {
	Title, Context string
	Fields         []field
	Cursor         int
	ContextOffset  int
	Accept         func([]string) tea.Cmd
	Write          bool
}

func newSecret(s string) auth.Secret { return auth.NewSecret(s) }
func (m *Model) openForm(title, context string, fields []field, write bool, accept func([]string) tea.Cmd) {
	for i := range fields {
		if _, ok := fields[i].Value.(auth.Secret); ok {
			fields[i].Secret = true
		}
		if fields[i].Secret {
			fields[i].setText(fields[i].text())
		}
	}
	m.form = &form{Title: title, Context: context, Fields: fields, Write: write, Accept: accept}
	m.status = "Tab/Enter next · Ctrl+S submit · Ctrl+U clear field · Esc cancel"
}

func (m *Model) closeForm() {
	if m.form != nil && m.form.Write && m.flow != nil {
		m.flow.Abort()
		m.flow = nil
	}
	m.form = nil
	m.status = "Form cancelled; no write dispatched."
}

func (m *Model) updateForm(k tea.KeyMsg) tea.Cmd {
	f := m.form
	switch k.String() {
	case "pgdown":
		f.ContextOffset += max(1, (m.height-12)/2)
		return nil
	case "pgup":
		f.ContextOffset = max(0, f.ContextOffset-max(1, (m.height-12)/2))
		return nil
	case "esc":
		m.closeForm()
		return nil
	case "ctrl+s":
		values := []string{}
		for _, v := range f.Fields {
			values = append(values, v.text())
		}
		m.form = nil
		return f.Accept(values)
	case "tab", "enter":
		f.Cursor = (f.Cursor + 1) % len(f.Fields)
	case "shift+tab":
		f.Cursor = (f.Cursor + len(f.Fields) - 1) % len(f.Fields)
	case "ctrl+u":
		f.Fields[f.Cursor].setText("")
	case "backspace", "ctrl+h":
		r := []rune(f.Fields[f.Cursor].text())
		if len(r) > 0 {
			f.Fields[f.Cursor].setText(string(r[:len(r)-1]))
		}
	default:
		if k.Type == tea.KeyRunes {
			for _, r := range k.Runes {
				if f.Fields[f.Cursor].Secret || (!unicode.IsControl(r) && !unicode.Is(unicode.Cf, r)) {
					f.Fields[f.Cursor].setText(f.Fields[f.Cursor].text() + string(r))
				}
			}
		}
	}
	return nil
}

func (m *Model) formView() string {
	f := m.form
	out := Literal(f.Title) + "\n"
	wrapped := []string{}
	for _, line := range strings.Split(f.Context, "\n") {
		wrapped = append(wrapped, ansi.Wrap(Literal(line), max(20, m.width-2), " "))
	}
	lines := strings.Split(strings.Join(wrapped, "\n"), "\n")
	page := max(2, m.height-14)
	offset := min(f.ContextOffset, max(0, len(lines)-page))
	for _, line := range lines[offset:min(len(lines), offset+page)] {
		out += line + "\n"
	}
	if len(lines) > page {
		out += fmt.Sprintf("Context lines %d–%d/%d · PgUp/PgDn scroll complete preview\n", offset+1, min(len(lines), offset+page), len(lines))
	}
	start := max(0, f.Cursor-5)
	for i := start; i < min(len(f.Fields), start+6); i++ {
		field := f.Fields[i]
		mark := "  "
		if i == f.Cursor {
			mark = "> "
		}
		value := Literal(field.text())
		if field.Secret {
			value = strings.Repeat("•", len([]rune(field.text())))
		}
		out += mark + Literal(field.Label) + ": " + value + "\n"
	}
	return out + "Tab/Enter next · Ctrl+S submit · Ctrl+U clear · Esc cancel"
}

func (m *Model) connectionForm() {
	s := m.cfg
	m.openForm("Connection settings", "Individual DC hostname required: revisions are DC-local. TLS verification cannot be disabled.", []field{{"DC hostname", s.Server, false}, {"AD DNS domain", s.Domain, false}, {"LDAP base DN", s.BaseDN, false}, {"Auth: password / kerberos", s.Auth, false}, {"User (UPN/DN or DOMAIN\\user)", s.User, false}, {"Password (whitespace preserved)", s.Password, true}, {"TLS: ldaps / starttls", s.Encryption, false}, {"CA PEM file (empty = system roots)", s.CAFile, false}, {"Selected Kerberos FILE cache", s.Cache, false}, {"Kerberos config file", s.KerberosConfig, false}, {"PTR: off / ask / on", s.AutoPTR, false}, {"DNS password auth: ntlm / kerberos", s.DNSAuth, false}, {"Password file path", s.PasswordFile, false}, {"Timeout seconds 1–300", strconv.Itoa(s.TimeoutSeconds), false}}, false, func(v []string) tea.Cmd {
		s.Server = strings.TrimSpace(v[0])
		s.Domain = strings.TrimRight(strings.TrimSpace(v[1]), ".")
		s.BaseDN = strings.TrimSpace(v[2])
		s.Auth = strings.TrimSpace(v[3])
		s.User = strings.TrimSpace(v[4])
		s.Password = newSecret(v[5])
		s.Encryption = strings.TrimSpace(v[6])
		s.CAFile = v[7]
		s.Cache = v[8]
		s.KerberosConfig = v[9]
		s.AutoPTR = v[10]
		s.DNSAuth = v[11]
		s.PasswordFile = v[12]
		timeout, e := strconv.Atoi(v[13])
		if e != nil {
			m.error(errors.New("timeout must be 1–300 seconds"))
			return nil
		}
		s.TimeoutSeconds = timeout
		if s.BaseDN == "" && s.Domain != "" {
			s.BaseDN = "DC=" + strings.ReplaceAll(s.Domain, ".", ",DC=")
		}
		var freezeErr error
		s, freezeErr = s.Freeze()
		if freezeErr != nil {
			m.error(freezeErr)
			return nil
		}
		if e := s.Validate(true); e != nil {
			m.error(e)
			return nil
		}
		m.setConnection(s)
		if e := config.Save(m.configPath, s); e != nil {
			m.error(e)
		}
		return m.load("setup")
	})
}

func (m *Model) searchForm() {
	m.openForm("Filter current results", "Literal case-insensitive local filter; LDAP server search is available with l.", []field{{"Search", m.search, false}}, false, func(v []string) tea.Cmd { m.search = v[0]; m.cursor = 0; m.selected = map[int]bool{}; return nil })
}

func (m *Model) queryForm() {
	if m.zone == "" {
		m.status = "Select a DNS zone first"
		return
	}
	m.openForm("Query DNS management records", "DC: "+m.cfg.Server+"\nZone: "+m.zone, []field{{"Name", "@", false}, {"Type / ALL", "ALL", false}}, false, func(v []string) tea.Cmd {
		if !dnsdata.ValidName(v[0], true) {
			m.error(errors.New("invalid DNS query name"))
			return nil
		}
		if _, e := backend.ParseQueryType(strings.ToUpper(v[1])); e != nil {
			m.error(e)
			return nil
		}
		m.dnsQueryName = v[0]
		m.dnsQueryType = strings.ToUpper(v[1])
		return m.load("query")
	})
}

func (m *Model) ldapForm() {
	m.openForm("LDAP search", "Verified TLS; pinned to "+m.cfg.Server, []field{{"Base DN", m.base, false}, {"Kind: users/groups/computers/ous/all", m.kind, false}, {"Search text", m.query, false}, {"Max entries 1–5000", strconv.Itoa(m.cfg.LDAPMaxRows), false}}, false, func(v []string) tea.Cmd {
		n, e := strconv.Atoi(v[3])
		if e != nil || n < 1 || n > 5000 {
			m.error(errors.New("limit must be 1–5000"))
			return nil
		}
		if !directory.InScope(v[0], m.cfg.BaseDN) {
			m.error(errors.New("search base outside configured scope"))
			return nil
		}
		if _, e = directory.Filter(v[1], v[2]); e != nil {
			m.error(e)
			return nil
		}
		m.base = v[0]
		m.kind = v[1]
		m.query = v[2]
		m.cfg.LDAPMaxRows = n
		m.state.Change(m.cfg)
		m.selected = map[int]bool{}
		return m.load("ldap")
	})
}

func (m *Model) commandForm() {
	m.openForm("Command palette", "Commands: zones, directory, query, add, update, delete, fix, health, connection, discover, thresholds, reconcile, help", []field{{"Command", "", false}}, false, func(v []string) tea.Cmd {
		switch strings.ToLower(v[0]) {
		case "zones":
			return m.load("zones")
		case "directory":
			m.ldapForm()
		case "query":
			m.queryForm()
		case "add":
			return m.writeForm("a")
		case "update":
			return m.writeForm("u")
		case "delete":
			return m.writeForm("d")
		case "fix":
			return m.writeForm("f")
		case "health":
			m.healthCheck = 8
			return m.load("health")
		case "connection":
			m.connectionForm()
		case "discover":
			return m.discoverForm()
		case "thresholds":
			m.thresholdForm()
		case "reconcile":
			return m.reconcile()
		case "help":
			m.showDetails(help)
		default:
			m.status = "Unknown command"
		}
		return nil
	})
}

func (m *Model) findingsForm() {
	text := ""
	for i, label := range health.Labels {
		text += fmt.Sprintf("%d: %s\n", i+1, label)
	}
	m.openForm("Choose findings view", text, []field{{"View number 1–8", "8", false}}, false, func(v []string) tea.Cmd {
		n, e := strconv.Atoi(v[0])
		if e != nil || n < 1 || n > 8 {
			m.error(errors.New("choose view 1–8"))
			return nil
		}
		m.healthCheck = n
		return m.load("health")
	})
}

func (m *Model) thresholdForm() {
	s := m.cfg
	m.openForm("Smart-view thresholds", "Days are conservative hygiene hints, not automatic deletion policy.", []field{{"Inactive days", strconv.Itoa(s.Days), false}, {"Disabled retention days", strconv.Itoa(s.DisabledDays), false}, {"Never logged in days", strconv.Itoa(s.NeverLoggedDays), false}, {"Max rows", strconv.Itoa(s.MaxRows), false}}, false, func(v []string) tea.Cmd {
		var e error
		s.Days, e = strconv.Atoi(v[0])
		if e == nil {
			s.DisabledDays, e = strconv.Atoi(v[1])
		}
		if e == nil {
			s.NeverLoggedDays, e = strconv.Atoi(v[2])
		}
		if e == nil {
			s.MaxRows, e = strconv.Atoi(v[3])
		}
		if e == nil {
			e = s.Validate(false)
		}
		if e != nil {
			m.error(e)
			return nil
		}
		m.cfg = s
		m.state.Change(s)
		m.error(config.Save(m.configPath, s))
		return nil
	})
}

// Discovery is an explicit user action. Selection still requires confirmation
// in the connection form, never silent failover for an active write.
type discovered struct {
	gen      uint64
	domain   string
	services []discovery.Service
	err      error
}

func (m *Model) discoverForm() tea.Cmd {
	m.openForm("Discover AD services", "Uses AD LDAP/Kerberos SRV queries; does not change an active connection automatically.", []field{{"AD DNS domain", m.cfg.Domain, false}}, false, func(v []string) tea.Cmd {
		domain, e := discovery.NormalizeDomain(v[0])
		if e != nil {
			m.error(e)
			return nil
		}
		snap := m.state.Snapshot()
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 10e9)
			defer cancel()
			services, e := discovery.Discover(ctx, domain, nil)
			return discovered{snap.Generation, domain, services, e}
		}
	})
	return nil
}

func (m *Model) savePasswordForm() {
	m.openForm("Save password file", "Destination: "+m.cfg.PasswordFile+"\nStored unencrypted with mode 0600. Preferences never contain the password.", []field{{"Type yes to save", "", false}}, false, func(v []string) tea.Cmd {
		if v[0] != "yes" {
			m.status = "Password not saved"
			return nil
		}
		if e := config.SavePassword(m.cfg.PasswordFile, m.cfg.Password); e != nil {
			m.error(e)
		} else {
			m.status = "Password saved privately"
		}
		return nil
	})
}

func (m *Model) selectedIndices() []int {
	out := []int{}
	for _, i := range m.visible() {
		if m.selected[i] {
			out = append(out, i)
		}
	}
	if len(out) == 0 {
		v := m.visible()
		if m.cursor < len(v) {
			out = append(out, v[m.cursor])
		}
	}
	return out
}

func (m *Model) rejectFlow(e error) tea.Cmd {
	if m.flow != nil {
		m.flow.Abort()
		m.flow = nil
	}
	m.error(e)
	return nil
}

func (m *Model) confirmPlan(plan backend.Plan) tea.Cmd {
	if m.flow == nil {
		return nil
	}
	snapshot := m.flow.Snapshot
	plan = plan.Clone()
	if e := plan.Validate(snapshot.Settings); e != nil {
		return m.rejectFlow(e)
	}
	identity := snapshot.Settings.User
	if snapshot.Settings.Auth == "kerberos" {
		identity = snapshot.Settings.CacheIdentity
	}
	description := "DC: " + Literal(snapshot.Settings.Server) + "\nLDAP base: " + Literal(snapshot.Settings.BaseDN) + "\nAuthentication: " + snapshot.Settings.Auth + "\nIdentity: " + Literal(identity) + "\n" + plan.Preview()
	m.openForm("Confirm write — review original target", description, []field{{"Type yes to execute exactly this plan", "", false}}, true, func(v []string) tea.Cmd {
		if v[0] != "yes" {
			return m.rejectFlow(errors.New("Write not confirmed; nothing dispatched"))
		}
		flow := m.flow
		m.lastPlan = plan
		m.lastWrite = snapshot
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(snapshot.Settings.TimeoutSeconds)*time.Second)
		service := m.service
		store := m.journal
		m.writeCancel = cancel
		m.status = "Write in progress on " + snapshot.Settings.Server + ". Ctrl+C requests cancel; not rollback."
		return func() tea.Msg {
			defer cancel()
			if store != nil {
				if e := store.Start(snapshot, plan); e != nil {
					flow.Abort()
					return writeResult{snapshot.Generation, lifecycle.Outcome{Err: e}}
				}
			}
			out := flow.Run(ctx, func(ctx context.Context, s config.Settings) lifecycle.Outcome { return service.Execute(ctx, s, plan) })
			if store != nil && !out.Uncertain {
				if e := store.Clear(); e != nil {
					out = lifecycle.Outcome{Err: fmt.Errorf("cannot clear pending-write journal; reconcile before retrying: %w", e), Uncertain: true}
					flow.RetainUncertain()
				}
			}
			return writeResult{snapshot.Generation, out}
		}
	})
	return nil
}

func (m *Model) writeForm(key string) tea.Cmd {
	if m.flow != nil {
		m.error(lifecycle.ErrBusy)
		return nil
	}
	flow, e := m.state.Begin()
	if e != nil {
		m.error(e)
		return nil
	}
	m.flow = flow
	if e = flow.Snapshot.Settings.Validate(true); e != nil {
		return m.rejectFlow(e)
	}
	if m.mode == "health" {
		return m.fixForm(key)
	}
	if key == "f" {
		return m.rejectFlow(errors.New("Guided fixes are available in findings views"))
	}
	indices := m.selectedIndices()
	if m.mode == "dns" {
		if m.zone == "" {
			return m.rejectFlow(errors.New("select a zone first"))
		}
		if key == "a" {
			return m.dnsAddForm()
		}
		if len(indices) == 0 {
			return m.rejectFlow(errors.New("select a real DNS record first"))
		}
		if key == "d" {
			p := backend.Plan{Title: "Delete selected DNS records"}
			for _, i := range indices {
				r := m.records[i]
				p.Actions = append(p.Actions, backend.Action{Kind: "dns_delete", Zone: m.zone, Name: r.Name, Type: r.Type, Value: r.Value})
			}
			return m.confirmPlan(p)
		}
		if len(indices) != 1 {
			return m.rejectFlow(errors.New("update requires exactly one selected record"))
		}
		r := m.records[indices[0]]
		zone := m.zone
		m.openForm("Update selected DNS record", "Name and type fixed: "+r.Name+" "+r.Type, []field{{"New value", r.Value, false}}, true, func(v []string) tea.Cmd {
			if _, e := dnsdata.Parse(r.Name, r.Type, v[0]); e != nil {
				return m.rejectFlow(e)
			}
			return m.confirmPlan(backend.Plan{Title: "Update DNS record", Actions: []backend.Action{{Kind: "dns_update", Zone: zone, Name: r.Name, Type: r.Type, OldValue: r.Value, Value: v[0]}}})
		})
		return nil
	}
	if m.mode == "ldap" {
		if key == "a" {
			return m.ldapAddForm()
		}
		if len(indices) == 0 {
			return m.rejectFlow(errors.New("select a directory entry first"))
		}
		if key == "d" {
			p := backend.Plan{Title: "Delete selected directory entries"}
			for _, i := range indices {
				r := m.entries[i]
				if r.Revision == "" || directory.EqualDN(r.DN, m.cfg.BaseDN) {
					return m.rejectFlow(errors.New("missing revision or protected base DN; deletion refused"))
				}
				p.Actions = append(p.Actions, backend.Action{Kind: "ldap_delete", DN: r.DN, Revision: r.Revision})
			}
			return m.confirmPlan(p)
		}
		if len(indices) != 1 {
			return m.rejectFlow(errors.New("update requires one directory entry"))
		}
		r := m.entries[indices[0]]
		if r.Revision == "" {
			return m.rejectFlow(errors.New("entry has no unique revision; refresh before writing"))
		}
		attrs := directory.Editable[r.Kind]
		if len(attrs) == 0 {
			return m.rejectFlow(errors.New("entry kind not editable"))
		}
		fields := []field{}
		for _, a := range attrs {
			fields = append(fields, field{a, r.First(a), false})
		}
		m.openForm("Edit LDAP entry", r.DN+"\nRevision: "+r.Revision, fields, true, func(v []string) tea.Cmd {
			changes := map[string]string{}
			for i, a := range attrs {
				if v[i] != r.First(a) {
					changes[a] = v[i]
				}
			}
			if len(changes) == 0 {
				return m.rejectFlow(errors.New("no attributes changed"))
			}
			return m.confirmPlan(backend.Plan{Title: "Modify selected LDAP entry", Actions: []backend.Action{{Kind: "ldap_modify", DN: r.DN, EntryKind: r.Kind, Revision: r.Revision, Attributes: changes}}})
		})
		return nil
	}
	return m.rejectFlow(errors.New("no writable view active"))
}

func (m *Model) dnsAddForm() tea.Cmd {
	zone := m.zone
	m.openForm("Choose DNS record type", "Zone: "+zone, []field{{"Type: A AAAA CNAME PTR TXT MX SRV NS", "A", false}}, true, func(v []string) tea.Cmd {
		typ := strings.ToUpper(v[0])
		fields := []field{{"Name (@ = zone root)", "", false}}
		switch typ {
		case "A":
			fields = append(fields, field{"IPv4 address", "", false})
		case "AAAA":
			fields = append(fields, field{"IPv6 address", "", false})
		case "CNAME", "PTR", "NS":
			fields = append(fields, field{"Target hostname", "", false})
		case "TXT":
			fields = append(fields, field{"Literal text or quoted DNS strings", "", false})
		case "MX":
			fields = append(fields, field{"Priority", "10", false}, field{"Mail exchanger", "", false})
		case "SRV":
			fields = append(fields, field{"Priority", "0", false}, field{"Weight", "100", false}, field{"Port", "389", false}, field{"Target hostname", "", false})
		default:
			return m.rejectFlow(errors.New("unsupported record type"))
		}
		m.openForm("Add "+typ+" DNS record", "Zone: "+zone+"\nTTL: 900 seconds (Samba default)", fields, true, func(v []string) tea.Cmd {
			value := strings.Join(v[1:], " ")
			if _, e := dnsdata.Parse(v[0], typ, value); e != nil {
				return m.rejectFlow(e)
			}
			for _, r := range m.records {
				if strings.EqualFold(r.Name, v[0]) && r.Type == typ && r.Value == value {
					return m.rejectFlow(errors.New("duplicate record in loaded zone"))
				}
			}
			p := backend.Plan{Title: "Add DNS record", Actions: []backend.Action{{Kind: "dns_add", Zone: zone, Name: v[0], Type: typ, Value: value}}}
			if typ == "A" && m.flow.Snapshot.Settings.AutoPTR != "off" {
				z, n, ok := dnsdata.Reverse(value, m.zones)
				if ok && contains(m.zones, z) {
					ptr := backend.Action{Kind: "dns_add", Zone: z, Name: n, Type: "PTR", Value: dnsdata.FQDN(v[0], zone)}
					if m.flow.Snapshot.Settings.AutoPTR == "on" {
						p.Actions = append(p.Actions, ptr)
					} else {
						m.openForm("Optional matching PTR", ptr.Zone+": "+ptr.Name+" PTR "+ptr.Value, []field{{"Include PTR? yes / no", "no", false}}, true, func(v []string) tea.Cmd {
							if v[0] == "yes" {
								p.Actions = append(p.Actions, ptr)
							}
							return m.confirmPlan(p)
						})
						return nil
					}
				}
			}
			return m.confirmPlan(p)
		})
		return nil
	})
	return nil
}

func contains(values []string, s string) bool {
	for _, v := range values {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func (m *Model) ldapAddForm() tea.Cmd {
	parent := m.base
	m.openForm("Add LDAP entry", "No password is set. Review the object kind and account name; computer flags use the existing Samba defaults.", []field{{"Kind: user/group/computer/ou", "group", false}, {"Parent DN", parent, false}, {"Name", "", false}, {"sAMAccountName (optional)", "", false}, {"Description", "", false}, {"Mail", "", false}, {"Display name", "", false}, {"Computer DNS hostname", "", false}, {"User principal name (UPN)", "", false}}, true, func(v []string) tea.Cmd {
		attrs := map[string]string{"sAMAccountName": v[3], "description": v[4], "mail": v[5], "displayName": v[6], "dNSHostName": v[7], "userPrincipalName": v[8]}
		if !directory.InScope(v[1], m.flow.Snapshot.Settings.BaseDN) || !directory.InScope(v[1], parent) {
			return m.rejectFlow(errors.New("parent outside configured LDAP base"))
		}
		if _, e := directory.BuildAdd(v[0], v[1], v[2], attrs); e != nil {
			return m.rejectFlow(e)
		}
		return m.confirmPlan(backend.Plan{Title: "Add LDAP entry", Actions: []backend.Action{{Kind: "ldap_add", EntryKind: v[0], Parent: v[1], Name: v[2], Attributes: attrs}}})
	})
	return nil
}

func (m *Model) fixForm(key string) tea.Cmd {
	if key != "f" {
		return m.rejectFlow(errors.New("Use f for guided fixes in findings views"))
	}
	selected := m.selectedIndices()
	if len(selected) != 1 {
		return m.rejectFlow(errors.New("select one finding for a guided fix"))
	}
	f := m.findings[selected[0]]
	switch f.Fix {
	case "dns_add_ptr":
		return m.confirmPlan(backend.Plan{Title: "Guided missing PTR fix", Actions: []backend.Action{{Kind: "dns_add", Zone: f.Zone, Name: f.Record.Name, Type: "PTR", Value: f.Record.Value}}})
	case "ldap_disable_account":
		if f.Entry.Revision == "" {
			return m.rejectFlow(errors.New("missing revision; disable refused"))
		}
		return m.confirmPlan(backend.Plan{Title: "Guided account-disable fix", Actions: []backend.Action{{Kind: "ldap_disable", DN: f.Entry.DN, Revision: f.Entry.Revision, Flags: f.Flags}}})
	default:
		return m.rejectFlow(errors.New("This finding requires manual review; no safe guided fix available"))
	}
}
