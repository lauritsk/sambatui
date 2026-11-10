package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

func TestUnrecoverableIntentsAreRejectedBeforePersistence(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	settings := config.Defaults()
	settings.Server = "original-dc"
	snapshot := lifecycle.Snapshot{Settings: settings, Generation: 1}
	action := backend.Action{Kind: "dns_add", Zone: "lab.invalid", Name: "host", Type: "A", Value: "192.0.2.1"}
	for _, plan := range []backend.Plan{
		{},
		{Actions: []backend.Action{{Kind: "unknown"}}},
		{Actions: make([]backend.Action, backend.MaxActions+1)},
		{Title: strings.Repeat("x", journalBytesMax), Actions: []backend.Action{action}},
	} {
		if err := store.Start(snapshot, plan); err == nil {
			t.Fatal("unrecoverable intent accepted")
		}
		if _, err := os.Stat(store.path); !os.IsNotExist(err) {
			t.Fatalf("rejected intent persisted: %v", err)
		}
	}
	if err := store.Start(snapshot, backend.Plan{Actions: []backend.Action{action}}); err != nil {
		t.Fatal(err)
	}
	if record, err := store.Load(); err != nil || record == nil {
		t.Fatalf("accepted intent was not recoverable: %v", err)
	}
}

func TestJournalLoadValidatesPlanNotOnlyPresence(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	data := []byte(`{"Snapshot":{"Settings":{"server":"dc"},"Generation":1},"Plan":{"Actions":[{"Kind":"unknown"}]}}`)
	if err := config.PrivateWrite(store.path, data); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("invalid persisted action accepted")
	}
}
