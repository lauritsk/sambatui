package health

import (
	"strings"

	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/lauritsk/sambatui/internal/invariant"
)

// IPv4 reverse names have six labels. Probe longest suffixes in the existing
// zone index: at 100k records and 10k zones this avoids a billion comparisons.
func dnsReverse(index *dnsIndex, address string) (string, string, bool) {
	zone, name, found := dnsdata.Reverse(address, nil)
	if !found {
		return "", "", false
	}
	labels := strings.Split(name+"."+zone, ".")
	invariant.Require(len(labels) == 6, "IPv4 reverse name must have six labels")
	invariant.Require(labels[5] == "arpa", "IPv4 reverse name must be under arpa")
	for offset := 0; offset < len(labels); offset++ {
		candidate := strings.Join(labels[offset:], ".")
		if _, loaded := index.records[candidate]; loaded {
			owner := strings.Join(labels[:offset], ".")
			if owner == "" {
				owner = "@"
			}
			return candidate, owner, true
		}
	}
	return zone, name, true
}
