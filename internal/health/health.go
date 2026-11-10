package health

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/invariant"
)

var Labels = []string{
	"DNS duplicates/conflicts",
	"DNS A records without matching PTR",
	"DNS PTR records without matching A",
	"LDAP inactive enabled users",
	"LDAP user cleanup candidates",
	"LDAP stale computer accounts",
	"LDAP users with no secondary groups",
	"Full health dashboard",
}

type Finding struct {
	Check                                       int
	Severity, Object, Finding, Evidence, Action string
	Fix                                         string
	Zone                                        string
	Record                                      dnsrpc.Row
	Entry                                       directory.Entry
	Flags                                       uint32
}
type Options struct {
	Days, DisabledDays, NeverLoggedDays int32
	Now                                 time.Time
}

func norm(text string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(text), "."))
}

// dnsIndex batches normalization and lookups so consistency checks do not scan
// all records for every forward/reverse relationship.
type dnsIndex struct {
	records            map[string][]dnsrpc.Row
	zones              []string
	pointers, forwards map[string]map[string]bool
	duplicates         map[string]int
	typesByName        map[string]map[string]bool
}

func DNS(records map[string][]dnsrpc.Row) []Finding {
	invariant.Require(len(records) <= 10000, "DNS health input exceeds zone budget")
	index := indexDNS(records)
	findings := dnsConflicts(index)
	for _, zone := range index.zones {
		for _, row := range index.records[zone] {
			var finding Finding
			var found bool
			switch row.Type {
			case "A":
				finding, found = dnsForward(index, zone, row)
			case "PTR":
				finding, found = dnsPointer(index, zone, row)
			}
			if found {
				findings = append(findings, finding)
			}
		}
	}
	// Map iteration must not change the order of evidence or guided fixes.
	sort.Slice(findings, func(left, right int) bool {
		leftFinding, rightFinding := findings[left], findings[right]
		if leftFinding.Check != rightFinding.Check {
			return leftFinding.Check < rightFinding.Check
		}
		if leftFinding.Object != rightFinding.Object {
			return leftFinding.Object < rightFinding.Object
		}
		return leftFinding.Finding < rightFinding.Finding
	})
	return findings
}

func indexDNS(records map[string][]dnsrpc.Row) *dnsIndex {
	index := &dnsIndex{
		records: map[string][]dnsrpc.Row{}, pointers: map[string]map[string]bool{},
		forwards: map[string]map[string]bool{}, duplicates: map[string]int{},
		typesByName: map[string]map[string]bool{},
	}
	originalZones := make([]string, 0, len(records))
	for zone := range records {
		originalZones = append(originalZones, zone)
	}
	sort.Strings(originalZones)
	for _, zone := range originalZones {
		key := norm(zone)
		index.records[key] = append(index.records[key], records[zone]...)
	}
	for zone, rows := range index.records {
		index.zones = append(index.zones, zone)
		for _, row := range rows {
			name := norm(dnsdata.FQDN(row.Name, zone))
			key := zone + ":" + norm(row.Name)
			value := norm(row.Value)
			if row.Type == "TXT" {
				value = row.Value
			}
			index.duplicates[key+":"+row.Type+":"+value]++
			dnsIndexValue(index.typesByName, key, row.Type)
			switch row.Type {
			case "PTR":
				dnsIndexValue(index.pointers, name, norm(row.Value))
			case "A":
				dnsIndexValue(index.forwards, name, row.Value)
			}
		}
	}
	sort.Strings(index.zones)
	return index
}

func dnsIndexValue(index map[string]map[string]bool, name, value string) {
	if index[name] == nil {
		index[name] = map[string]bool{}
	}
	index[name][value] = true
}

func dnsConflicts(index *dnsIndex) []Finding {
	findings := []Finding{}
	for key, count := range index.duplicates {
		if count > 1 {
			findings = append(findings, Finding{
				Check: 1, Severity: "medium", Object: key, Finding: "Duplicate DNS record",
				Evidence: fmt.Sprintf("%d identical records", count),
				Action:   "Remove duplicate copies; keep one valid record.",
			})
		}
	}
	for key, types := range index.typesByName {
		if types["CNAME"] && len(types) > 1 {
			findings = append(findings, Finding{
				Check: 1, Severity: "high", Object: key,
				Finding: "CNAME conflicts with other records",
				Action:  "Keep CNAME alone or replace it with address/alias records.",
			})
		}
	}
	return findings
}

func dnsForward(index *dnsIndex, zone string, row dnsrpc.Row) (Finding, bool) {
	reverseZone, name, ok := dnsReverse(index, row.Value)
	if !ok {
		return Finding{}, false
	}
	fqdn := norm(dnsdata.FQDN(row.Name, zone))
	finding := Finding{
		Check: 2, Severity: "medium", Object: fqdn + " A " + row.Value,
		Action: "Review forward/reverse DNS consistency.",
	}
	if _, loaded := index.records[reverseZone]; !loaded {
		finding.Severity = "low"
		finding.Finding = "No loaded reverse zone for A record"
		finding.Evidence = "Expected zone " + reverseZone
		return finding, true
	}
	targets := index.pointers[norm(dnsdata.FQDN(name, reverseZone))]
	if targets[fqdn] {
		return Finding{}, false
	}
	if len(targets) == 0 {
		finding.Finding = "A record missing PTR"
		finding.Fix = "dns_add_ptr"
		finding.Zone = reverseZone
		finding.Record = dnsrpc.Row{
			Name: name, Type: "PTR", Value: dnsdata.FQDN(row.Name, zone), TTL: 900,
		}
		finding.Evidence = name + "." + reverseZone + " PTR " + fqdn
	} else {
		finding.Finding = "A record PTR points elsewhere"
		finding.Evidence = dnsEvidence(targets)
	}
	return finding, true
}

func dnsPointer(index *dnsIndex, zone string, row dnsrpc.Row) (Finding, bool) {
	ip := dnsdata.ReverseIP(row.Name, zone)
	if ip == "" {
		return Finding{}, false
	}
	addresses := index.forwards[norm(row.Value)]
	if addresses[ip] {
		return Finding{}, false
	}
	finding := Finding{
		Check: 3, Severity: "medium",
		Object: dnsdata.FQDN(row.Name, zone) + " PTR " + row.Value,
		Action: "Review matching forward A record or stale PTR.",
	}
	if len(addresses) == 0 {
		finding.Finding = "PTR target missing forward A"
		finding.Evidence = "No loaded A record for " + row.Value
	} else {
		finding.Finding = "PTR does not match forward A"
		finding.Evidence = "PTR IP " + ip + "; forward IPs: " + dnsEvidence(addresses)
	}
	return finding, true
}

func dnsEvidence(values map[string]bool) string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return strings.Join(keys, " ") + " "
}

func adTime(text string) time.Time {
	if number, err := strconv.ParseInt(text, 10, 64); err == nil {
		if number <= 0 {
			return time.Time{}
		}
		return time.Unix(number/10000000-11644473600, (number%10000000)*100).UTC()
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"20060102150405.999999Z0700",
		"20060102150405Z0700",
		"2006-01-02 15:04:05Z07:00",
	} {
		if timestamp, err := time.Parse(layout, text); err == nil {
			return timestamp
		}
	}
	return time.Time{}
}

func firstTime(entry directory.Entry, attributes ...string) time.Time {
	for _, attribute := range attributes {
		if timestamp := adTime(entry.First(attribute)); !timestamp.IsZero() {
			return timestamp
		}
	}
	return time.Time{}
}

func ldapOptions(options Options) Options {
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	if options.Days < 1 {
		options.Days = 90
	}
	if options.DisabledDays < 1 {
		options.DisabledDays = 180
	}
	if options.NeverLoggedDays < 1 {
		options.NeverLoggedDays = 30
	}
	return options
}

func LDAP(rows []directory.Entry, options Options) []Finding {
	invariant.Require(len(rows) <= 5000, "LDAP health input exceeds entry budget")
	options = ldapOptions(options)
	invariant.Require(!options.Now.IsZero(), "LDAP health requires a reference time")
	findings := make([]Finding, 0, len(rows))
	for _, entry := range rows {
		switch entry.Kind {
		case "user":
			findings = append(findings, ldapUser(entry, options)...)
		case "computer":
			findings = append(findings, ldapComputer(entry, options)...)
		}
	}
	return findings
}
