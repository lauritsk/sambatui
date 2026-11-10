package health

import (
	"testing"

	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func TestIndexedReverseMatchesLongestZoneSelection(t *testing.T) {
	for _, zones := range [][]string{
		nil,
		{"lab.invalid"},
		{"0.192.in-addr.arpa", "2.0.192.in-addr.arpa"},
		{"in-addr.arpa", "1.2.0.192.in-addr.arpa", "2.0.192.in-addr.arpa"},
	} {
		records := map[string][]dnsrpc.Row{}
		for _, zone := range zones {
			records[zone] = nil
		}
		index := indexDNS(records)
		for _, address := range []string{"192.0.2.1", "192.0.2.2", "10.0.0.1", "::1", "invalid"} {
			wantZone, wantName, wantFound := dnsdata.Reverse(address, zones)
			zone, name, found := dnsReverse(index, address)
			if zone != wantZone || name != wantName || found != wantFound {
				t.Fatalf("%s in %v: got %s/%s/%v, want %s/%s/%v",
					address, zones, zone, name, found, wantZone, wantName, wantFound)
			}
		}
	}
}
