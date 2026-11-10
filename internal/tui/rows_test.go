package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/discovery"
)

func TestDirectoryDetailsAreCompleteAndDeterministic(t *testing.T) {
	entry := directory.Entry{
		DN: "CN=Alice,DC=lab,DC=invalid", Revision: "42",
		Attributes: map[string][]string{
			"zebra": {"last"}, "mail": {"one@lab.invalid", "two@lab.invalid"},
			"empty": nil, "displayName": {"Alice é\x1b"},
		},
	}
	want := "DC: dc.lab.invalid\nDN: CN=Alice,DC=lab,DC=invalid\nRevision (DC-local): 42\n" +
		"displayName: Alice é\x1b\nempty: \nmail: one@lab.invalid; two@lab.invalid\nzebra: last\n"
	for attempt := 0; attempt < 10; attempt++ {
		if actual := directoryDetails("dc.lab.invalid", entry); actual != want {
			t.Fatalf("incomplete or nondeterministic details: %q", actual)
		}
	}
	model := testModel()
	model.mode = "ldap"
	model.entries = []directory.Entry{entry}
	model.details()
	if model.detail != want || strings.Contains(ansi.Strip(model.View()), "\x1b") {
		t.Fatal("details changed content or bypassed literal rendering")
	}
}

func TestDiscoveryPreviewPreservesAllServicesAndEscapesTargets(t *testing.T) {
	services := []discovery.Service{
		{Kind: "ldap", Target: "dc.lab.invalid", Port: 389, Priority: 10, Weight: 20},
		{Kind: "kerberos", Target: "hostile\x1b", Port: 88, Priority: 30, Weight: 40},
	}
	want := "Discovered services (review before selecting):\n" +
		"ldap dc.lab.invalid:389 priority=10 weight=20\n" +
		"kerberos hostile\\u001b:88 priority=30 weight=40\n"
	if actual := discoveryPreview(services); actual != want {
		t.Fatalf("preview content changed: %q", actual)
	}
}

func TestFormViewMasksUnicodeSecretsAndKeepsFieldLayout(t *testing.T) {
	model := testModel()
	model.connectionForm()
	model.form.Cursor = 5
	model.form.Fields[5].setText("é\t🙂")
	view := ansi.Strip(model.View())
	if !strings.Contains(view, "[hidden]_") {
		t.Fatalf("secret rune masking or field layout changed: %q", view)
	}
	if strings.Contains(view, "é") || strings.Contains(view, "🙂") {
		t.Fatal("form rendered a secret")
	}
	if !strings.Contains(view, "Ctrl+S submit") {
		t.Fatal("form lost its navigation instructions")
	}
}

// A large but bounded entry catches repeated copying of the growing detail text.
func BenchmarkDirectoryDetails(b *testing.B) {
	entry := directory.Entry{Attributes: make(map[string][]string, 128)}
	value := strings.Repeat("x", 8192)
	for index := 0; index < 128; index++ {
		entry.Attributes[fmt.Sprintf("attribute%03d", index)] = []string{value}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for attempt := 0; attempt < b.N; attempt++ {
		if len(directoryDetails("dc.lab.invalid", entry)) < len(value)*len(entry.Attributes) {
			b.Fatal("truncated details")
		}
	}
}
