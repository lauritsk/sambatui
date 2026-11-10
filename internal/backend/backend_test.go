package backend

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

type fake struct {
	reads    int
	settings config.Settings
}

func (f *fake) Zones(context.Context, config.Settings) ([]string, error) { return nil, nil }
func (f *fake) Records(_ context.Context, s config.Settings, z, n string, typ uint16) ([]dnsrpc.Row, error) {
	f.reads++
	f.settings = s
	return []dnsrpc.Row{{Name: n, Type: "A", Value: "192.0.2.10"}}, nil
}

func (f *fake) Search(_ context.Context, s config.Settings, base, kind, text string, limit int) ([]directory.Entry, error) {
	f.reads++
	f.settings = s
	return nil, nil
}

func (f *fake) Execute(context.Context, config.Settings, Plan) lifecycle.Outcome {
	panic("inspection must never write")
}

func TestReconciliationReadsOriginalTargetAndNeverWrites(t *testing.T) {
	s := config.Defaults()
	s.Server = "original-dc"
	s.BaseDN = "DC=lab,DC=invalid"
	f := &fake{}
	p := Plan{Title: "test", Actions: []Action{{Kind: "dns_add", Zone: "lab.invalid", Name: "host", Type: "A", Value: "192.0.2.10"}, {Kind: "ldap_add", EntryKind: "group", Name: "x", Parent: "DC=lab,DC=invalid"}}}
	report, e := Inspect(context.Background(), f, s, p)
	if e != nil || f.reads != 2 || f.settings.Server != "original-dc" || !strings.Contains(report, "192.0.2.10") {
		t.Fatal(report, e)
	}
}

func TestInvalidPlansFailBeforeNetwork(t *testing.T) {
	s := config.Defaults()
	for _, p := range []Plan{{}, {Actions: []Action{{Kind: "bogus"}}}, {Actions: []Action{{Kind: "dns_add", Zone: "invalid zone", Name: "x", Type: "A", Value: "192.0.2.1"}}}} {
		if e := p.Validate(s); e == nil {
			t.Fatalf("invalid plan accepted %+v", p)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := (Native{}).Execute(ctx, s, Plan{Actions: []Action{{Kind: "dns_add", Zone: "lab.invalid", Name: "x", Type: "A", Value: "192.0.2.1"}}})
	if !errors.Is(out.Err, context.Canceled) {
		t.Fatal(out)
	}
}

func TestPreviewLiteralsAndDeterminism(t *testing.T) {
	p := Plan{Actions: []Action{{Kind: "ldap_modify", DN: "CN=evil\x1b[2J\nConfirm", Revision: "42", Attributes: map[string]string{"mail": "x", "description": "[red]"}}}}
	for i := 0; i < 10; i++ {
		got := p.Preview()
		if strings.Contains(got, "\x1b") || strings.Contains(got, "\nConfirm") || got != p.Preview() {
			t.Fatal("unsafe/non-deterministic preview", got)
		}
	}
}
