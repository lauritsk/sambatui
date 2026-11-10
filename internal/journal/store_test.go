package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

func TestPendingIntentSurvivesRestartWithoutPersistingCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if concurrent, e := Open(path); e == nil {
		concurrent.Close()
		t.Fatal("concurrent client accepted")
	}
	cfg := config.Defaults()
	cfg.Server = "original-dc"
	cfg.User = "Alice"
	cfg.Password = auth.NewSecret("secret-password")
	cfg.CacheContents = auth.NewSecret("secret-ticket")
	snap := lifecycle.Snapshot{Settings: cfg, Generation: 8}
	p := backend.Plan{Title: "test", Actions: []backend.Action{{Kind: "dns_add", Zone: "lab.invalid", Name: "host", Type: "A", Value: "192.0.2.1"}}}
	if e = s.Start(snap, p); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(s.path)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), "secret-password") || strings.Contains(string(b), "secret-ticket") {
		t.Fatal("credentials persisted in write journal")
	}
	if e = s.Start(snap, p); e == nil {
		t.Fatal("unresolved intent overwritten")
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	pending, e := s.Load()
	if e != nil || pending == nil {
		t.Fatal("restart lost pending intent", e)
	}
	if pending.Snapshot.Settings.Server != "original-dc" || pending.Snapshot.Settings.Password.Reveal() != "" {
		t.Fatal("wrong recovery snapshot")
	}
	state := lifecycle.New(cfg)
	if e = state.RestoreUncertain(pending.Snapshot); e != nil {
		t.Fatal(e)
	}
	if _, e = state.Begin(); e == nil {
		t.Fatal("restart permitted unreconciled write")
	}
	if e = s.Clear(); e != nil {
		t.Fatal(e)
	}
	if pending, e = s.Load(); e != nil || pending != nil {
		t.Fatal(pending, e)
	}
}

func TestJournalCorruptionAndWrongReconciliationFailClosed(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = config.PrivateWrite(s.path, []byte("broken")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Load(); e == nil {
		t.Fatal("invalid journal ignored")
	}
	cfg := config.Defaults()
	cfg.Server = "original"
	r := Record{Snapshot: lifecycle.Snapshot{Settings: cfg}}
	cfg.Server = "another"
	if _, e = r.ReconcileSettings(cfg); e == nil {
		t.Fatal("wrong DC credentials used for reconciliation")
	}
}
