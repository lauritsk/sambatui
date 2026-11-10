package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/health"
	"github.com/lauritsk/sambatui/internal/journal"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

type fakeService struct {
	plans    []backend.Plan
	settings []config.Settings
	records  func(context.Context, config.Settings, string, string, uint16) ([]dnsrpc.Row, error)
}

func (f *fakeService) CheckLDAP(context.Context, config.Settings) error { return nil }
func (f *fakeService) Zones(context.Context, config.Settings) ([]string, error) {
	return []string{"lab.invalid", "2.0.192.in-addr.arpa"}, nil
}

func (f *fakeService) Records(ctx context.Context, c config.Settings, z, n string, typ uint16) ([]dnsrpc.Row, error) {
	if f.records != nil {
		return f.records(ctx, c, z, n, typ)
	}
	return []dnsrpc.Row{}, nil
}

func (f *fakeService) Search(context.Context, config.Settings, string, string, string, int) ([]directory.Entry, error) {
	return []directory.Entry{}, nil
}

func (f *fakeService) Execute(_ context.Context, s config.Settings, p backend.Plan) lifecycle.Outcome {
	f.plans = append(f.plans, p)
	f.settings = append(f.settings, s)
	return lifecycle.Outcome{}
}

func testModel() *Model {
	s := config.Defaults()
	s.Server = "dc.lab.invalid"
	s.BaseDN = "DC=lab,DC=invalid"
	s.User = "Admin@lab.invalid"
	s.Password = auth.NewSecret("  secret password ")
	return New(s, "/not-used", &fakeService{})
}

func submit(m *Model, values ...string) tea.Cmd { f := m.form; m.form = nil; return f.Accept(values) }

func TestConfirmationHasOriginalContextAndNeedsExplicitYes(t *testing.T) {
	m := testModel()
	m.zone = "lab.invalid"
	m.records = []dnsrpc.Row{{Name: "host", Type: "A", Value: "192.0.2.1"}}
	m.writeForm("d")
	if m.form == nil || !strings.Contains(m.form.Context, "dc.lab.invalid") || !strings.Contains(m.form.Context, `"host" A "192.0.2.1"`) {
		t.Fatal("missing confirmation target context")
	}
	if _, e := m.state.Begin(); !errors.Is(e, lifecycle.ErrBusy) {
		t.Fatal("confirmation did not reserve write")
	}
	submit(m, "")
	if m.flow != nil || len(m.service.(*fakeService).plans) != 0 {
		t.Fatal("default confirmation dispatched write")
	}
	m.writeForm("d")
	cmd := submit(m, "yes")
	if cmd == nil {
		t.Fatal("confirmed write not scheduled")
	}
	old := m.settings
	next := old
	next.Server = "different-dc"
	next.Password = auth.NewSecret("new secret")
	m.setConnection(next)
	m.Update(cmd())
	f := m.service.(*fakeService)
	if len(f.plans) != 1 || f.settings[0].Server != old.Server || f.settings[0].Password != old.Password {
		t.Fatal("confirmed write redirected")
	}
	if len(m.records) != 0 {
		t.Fatal("write completion restored old data")
	}
}

func TestConnectionChangeDiscardsLateReadsAndFailedRefreshLeavesNoSelection(t *testing.T) {
	m := testModel()
	m.records = []dnsrpc.Row{{Name: "old"}}
	m.selected[0] = true
	snap := m.state.Snapshot()
	m.readID = 7
	cfg := m.settings
	cfg.Server = "another-dc"
	m.setConnection(cfg)
	m.Update(readResult{generation: snap.Generation, requestID: 7, kind: "dns", records: []dnsrpc.Row{{Name: "late"}}})
	if len(m.records) != 0 || len(m.selected) != 0 {
		t.Fatal("stale rows or selection survived connection change")
	}
	m.Update(readResult{generation: m.state.Snapshot().Generation, requestID: m.readID, kind: "dns", err: errors.New("network down")})
	if len(m.records) != 0 || len(m.selected) != 0 {
		t.Fatal("refresh failure restored old selection")
	}
}

func TestLiteralRenderingProtectsTablesFormsDetailsAndErrors(t *testing.T) {
	hostile := "server\x1b]52;c;injected\a\x1b[2J\u009b31m\u202e[red]"
	m := testModel()
	m.zone = "lab.invalid"
	m.records = []dnsrpc.Row{{Name: "host", Type: "TXT", Value: hostile}}
	if s := m.rowTexts()[0]; strings.ContainsAny(s, "\x1b\a\u009b\u202e") {
		t.Fatal("server control sequence passed into table")
	}
	m.writeForm("d")
	if strings.ContainsAny(m.formView(), "\x1b\a\u009b\u202e") {
		t.Fatal("server control sequence passed into confirmation")
	}
	m.closeForm()
	m.details()
	if strings.ContainsAny(m.View(), "\a\u009b\u202e") {
		t.Fatal("server control sequence passed into details")
	}
	m.error(errors.New(hostile + "  secret password "))
	if strings.Contains(m.View(), "secret password") {
		t.Fatal("secret leaked in error")
	}
}

func TestFormsPreservePasswordWhitespaceAndCancelUndispatchedFlow(t *testing.T) {
	m := testModel()
	m.connectionForm()
	m.form.Cursor = 5
	m.form.Fields[5].Value = ""
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("  password \t")})
	if m.form.Fields[5].text() != "  password \t" {
		t.Fatal("password spaces lost")
	}
	if strings.Contains(m.formView(), "  password ") {
		t.Fatal("password shown in clear")
	}
	for _, format := range []string{"%v", "%#v", "%d", "%f", "%p"} {
		if strings.Contains(fmt.Sprintf(format, *m), "  password ") {
			t.Fatal("password leaked through model debug formatting")
		}
		if strings.Contains(fmt.Sprintf(format, m.form.Fields[5]), "  password ") {
			t.Fatal("password leaked through form-field formatting")
		}
	}
	m.closeForm()
	m.zone = "lab.invalid"
	m.writeForm("a")
	m.closeForm()
	f, e := m.state.Begin()
	if e != nil {
		t.Fatal("canceled form retained write lock")
	}
	f.Abort()
}

func TestGuidedPTRPlan(t *testing.T) {
	m := testModel()
	m.zone = "lab.invalid"
	m.zones = []string{"lab.invalid", "2.0.192.in-addr.arpa"}
	m.writeForm("a")
	submit(m, "A")
	submit(m, "host", "192.0.2.10")
	if m.form == nil || !strings.Contains(m.form.Title, "PTR") {
		t.Fatal("PTR prompt missing")
	}
	submit(m, "yes")
	cmd := submit(m, "yes")
	if cmd == nil {
		t.Fatal("write not scheduled")
	}
	m.Update(cmd())
	p := m.service.(*fakeService).plans[0]
	if len(p.Actions) != 2 || p.Actions[1].Zone != "2.0.192.in-addr.arpa" || p.Actions[1].Name != "10" || p.Actions[1].Value != "host.lab.invalid" {
		t.Fatal(p)
	}
}

func TestLDAPFormsMutationsAndGuidedDisable(t *testing.T) {
	m := testModel()
	m.mode = "ldap"
	m.entries = []directory.Entry{{DN: "CN=Alice,DC=lab,DC=invalid", Name: "Alice", Kind: "user", Revision: "42", Attributes: map[string][]string{"displayname": {"Alice"}, "mail": {"old@lab.invalid"}, "description": {"before"}}}}
	m.writeForm("u")
	submit(m, "Alice", "new@lab.invalid", "after")
	if m.form == nil || !strings.Contains(m.form.Context, "42") {
		t.Fatal("LDAP revision missing in confirmation")
	}
	cmd := submit(m, "yes")
	m.Update(cmd())
	p := m.service.(*fakeService).plans[0]
	if p.Actions[0].Revision != "42" || p.Actions[0].Attributes["description"] != "after" {
		t.Fatal(p)
	}
	m.writeForm("a")
	submit(m, "user", m.base, "NewUser", "new-user", "description", "mail@lab.invalid", "New User", "", "new-user@lab.invalid")
	if m.form == nil {
		t.Fatal("LDAP add did not preview")
	}
	cmd = submit(m, "yes")
	m.Update(cmd())
	p = m.service.(*fakeService).plans[1]
	if p.Actions[0].Attributes["userPrincipalName"] != "new-user@lab.invalid" {
		t.Fatal("UPN field lost")
	}
	m.mode = "health"
	m.findings = []health.Finding{{Fix: "ldap_disable_account", Entry: m.entries[0], Flags: 66048}}
	m.writeForm("f")
	cmd = submit(m, "yes")
	m.Update(cmd())
	p = m.service.(*fakeService).plans[2]
	if p.Actions[0].Flags != 66048 || p.Actions[0].Revision != "42" {
		t.Fatal("disable did not preserve flags/revision")
	}
	m.findings[0].Fix = ""
	m.writeForm("f")
	if m.form != nil || m.flow != nil {
		t.Fatal("unsupported fix reserved a mutation")
	}
}

func TestNavigationFiltersRangeSelectionAndPendingTargetInvalidation(t *testing.T) {
	m := testModel()
	m.configPath = t.TempDir() + "/config.json"
	m.zone = "old.invalid"
	m.zones = []string{"old.invalid", "new.invalid"}
	m.records = []dnsrpc.Row{{Name: "b", Type: "A"}, {Name: "a", Type: "TXT"}, {Name: "c", Type: "A"}}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("v")})
	m.move(2)
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("v")})
	if len(m.selected) != 3 {
		t.Fatal("range selection failed")
	}
	m.searchForm()
	submit(m, "TXT")
	if len(m.visible()) != 1 || len(m.selected) != 0 {
		t.Fatal("filter did not reset selection")
	}
	m.sidebar = true
	m.sideCursor = 1
	cmd := m.activateSide()
	if cmd == nil || len(m.records) != 0 || len(m.selected) != 0 {
		t.Fatal("zone change retained writable old rows")
	}
	m.Update(cmd())
	if m.zone != "new.invalid" {
		t.Fatal("wrong zone activation")
	}
}

func TestDashboardSurfacesFailedChecks(t *testing.T) {
	m := testModel()
	m.healthCheck = 8
	m.service.(*fakeService).records = func(context.Context, config.Settings, string, string, uint16) ([]dnsrpc.Row, error) {
		return nil, errors.New("zone unavailable")
	}
	cmd := m.load("health")
	if cmd == nil {
		t.Fatal("dashboard not scheduled")
	}
	m.Update(cmd())
	if m.mode != "health" || len(m.findings) < 7 {
		t.Fatal("dashboard summaries missing")
	}
	for _, r := range m.findings[:3] {
		if !strings.Contains(r.Finding, "incomplete") {
			t.Fatal("failed zone presented as clean", r)
		}
	}
}

func TestUncleanExitJournalBlocksWritesOnNextLaunch(t *testing.T) {
	m := testModel()
	path := t.TempDir() + "/config.json"
	store, e := journal.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	snap := m.state.Snapshot()
	p := backend.Plan{Title: "pending", Actions: []backend.Action{{Kind: "dns_add", Zone: "lab.invalid", Name: "x", Type: "A", Value: "192.0.2.1"}}}
	if e = store.Start(snap, p); e != nil {
		t.Fatal(e)
	}
	if e = m.UseJournal(store); e != nil {
		t.Fatal(e)
	}
	m.writeForm("a")
	if m.flow != nil || m.form != nil {
		t.Fatal("restarted write bypassed journal")
	}
	cmd := m.reconcile()
	if cmd == nil {
		t.Fatal("reconciliation not offered")
	}
	m.Update(cmd())
	if m.form == nil {
		t.Fatal("reconciliation confirmation missing")
	}
	submit(m, "not-reconciled")
	m.writeForm("a")
	if m.flow != nil {
		t.Fatal("negative acknowledgement released guard")
	}
}

func TestFiltersBelongToTheirView(t *testing.T) {
	m := testModel()
	m.search = "dns-only"
	m.setMode("ldap")
	if m.search != "" {
		t.Fatal("DNS filter hid LDAP entries")
	}
	m.search = "directory-only"
	m.setMode("health")
	if m.search != "" {
		t.Fatal("directory filter hid dashboard")
	}
	m.setMode("dns")
	if m.search != "dns-only" {
		t.Fatal("DNS filter was not restored")
	}
	m.setMode("ldap")
	if m.search != "directory-only" {
		t.Fatal("directory filter was not restored")
	}
}

func TestOnlyOneUIFlowUntilCompletionMessage(t *testing.T) {
	m := testModel()
	m.zone = "lab.invalid"
	m.records = []dnsrpc.Row{{Name: "x", Type: "A", Value: "192.0.2.1"}}
	m.writeForm("d")
	cmd := submit(m, "yes")
	msg := cmd()
	m.writeForm("d")
	if m.form != nil {
		t.Fatal("new UI flow before prior completion processed")
	}
	m.Update(msg)
	m.writeForm("d")
	if m.form == nil {
		t.Fatal("completed flow retained lock")
	}
	m.closeForm()
}
