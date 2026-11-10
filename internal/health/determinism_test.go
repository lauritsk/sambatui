package health

import (
	"reflect"
	"testing"

	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func TestDNSFindingsAndEvidenceAreDeterministic(t *testing.T) {
	records := map[string][]dnsrpc.Row{
		"lab.invalid": {
			{Name: "host", Type: "A", Value: "192.0.2.1"},
			{Name: "host", Type: "A", Value: "192.0.2.2"},
			{Name: "duplicate", Type: "A", Value: "192.0.2.3"},
			{Name: "duplicate", Type: "A", Value: "192.0.2.3"},
		},
		"LAB.INVALID.": {
			{Name: "HOST", Type: "A", Value: "192.0.2.1"},
		},
		"2.0.192.in-addr.arpa": {
			{Name: "1", Type: "PTR", Value: "wrong.lab.invalid"},
			{Name: "1", Type: "PTR", Value: "other.lab.invalid"},
			{Name: "4", Type: "PTR", Value: "host.lab.invalid"},
		},
	}
	expected := DNS(records)
	if len(expected) == 0 {
		t.Fatal("fixture produced no findings")
	}
	for iteration := 0; iteration < 100; iteration++ {
		if actual := DNS(records); !reflect.DeepEqual(actual, expected) {
			t.Fatalf("map iteration changed findings or evidence: %+v", actual)
		}
	}
}
