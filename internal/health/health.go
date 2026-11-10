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
)

var Labels = []string{"DNS duplicates/conflicts", "DNS A records without matching PTR", "DNS PTR records without matching A", "LDAP inactive enabled users", "LDAP user cleanup candidates", "LDAP stale computer accounts", "LDAP users with no secondary groups", "Full health dashboard"}

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
	Days, DisabledDays, NeverLoggedDays int
	Now                                 time.Time
}

func norm(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

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
		a, b := findings[left], findings[right]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		if a.Object != b.Object {
			return a.Object < b.Object
		}
		return a.Finding < b.Finding
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
				Check: 1, Severity: "high", Object: key, Finding: "CNAME conflicts with other records",
				Action: "Keep CNAME alone or replace it with address/alias records.",
			})
		}
	}
	return findings
}

func dnsForward(index *dnsIndex, zone string, row dnsrpc.Row) (Finding, bool) {
	reverseZone, name, ok := dnsdata.Reverse(row.Value, index.zones)
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

func adTime(s string) time.Time {
	if n, e := strconv.ParseInt(s, 10, 64); e == nil {
		if n <= 0 {
			return time.Time{}
		}
		return time.Unix(n/10000000-11644473600, (n%10000000)*100).UTC()
	}
	for _, layout := range []string{time.RFC3339Nano, "20060102150405.999999Z0700", "20060102150405Z0700", "2006-01-02 15:04:05Z07:00"} {
		if d, e := time.Parse(layout, s); e == nil {
			return d
		}
	}
	return time.Time{}
}

func firstTime(e directory.Entry, attrs ...string) time.Time {
	for _, a := range attrs {
		if d := adTime(e.First(a)); !d.IsZero() {
			return d
		}
	}
	return time.Time{}
}

func ldapOptions(o Options) Options {
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.Days < 1 {
		o.Days = 90
	}
	if o.DisabledDays < 1 {
		o.DisabledDays = 180
	}
	if o.NeverLoggedDays < 1 {
		o.NeverLoggedDays = 30
	}
	return o
}

func LDAP(rows []directory.Entry, o Options) []Finding {
	o = ldapOptions(o)
	findings := []Finding{}
	age := func(d time.Time) int {
		if d.IsZero() {
			return 0
		}
		return max(0, int(o.Now.Sub(d).Hours()/24))
	}
	for _, e := range rows {
		flags64, flagErr := strconv.ParseUint(e.First("userAccountControl"), 10, 32)
		flags := uint32(flags64)
		disabled := flagErr == nil && flags&2 != 0
		last := firstTime(e, "lastLogonTimestamp", "lastLogon")
		created := firstTime(e, "whenCreated")
		changed := firstTime(e, "whenChanged")
		object := e.First("sAMAccountName")
		if object == "" {
			object = e.Name
		}
		if object == "" {
			object = e.DN
		}
		add := func(check int, severity, title, evidence, action string, disable bool) {
			f := Finding{Check: check, Severity: severity, Object: object, Finding: title, Evidence: evidence, Action: action}
			if disable && flagErr == nil && e.Revision != "" && len(e.Attributes["useraccountcontrol"]) == 1 {
				f.Fix = "ldap_disable_account"
				f.Entry = e
				f.Flags = flags
			}
			findings = append(findings, f)
		}
		if e.Kind == "user" {
			if !disabled && !last.IsZero() && last.Before(o.Now.Add(-time.Duration(o.Days)*24*time.Hour)) {
				add(4, "medium", "Enabled user inactive", fmt.Sprintf("lastLogonTimestamp %d days ago (replicated AD value)", age(last)), "Review owner; disable first, then delete after retention.", true)
			}
			if disabled {
				reference := changed
				if reference.IsZero() {
					reference = created
				}
				if !reference.IsZero() && reference.Before(o.Now.Add(-time.Duration(o.DisabledDays)*24*time.Hour)) {
					add(5, "medium", "Disabled user past retention", fmt.Sprintf("disabled; changed/created %d days ago (not the disable timestamp)", age(reference)), "Review retention policy before manual deletion.", false)
				}
			} else if last.IsZero() && !created.IsZero() && created.Before(o.Now.Add(-time.Duration(o.NeverLoggedDays)*24*time.Hour)) {
				add(5, "low", "User never logged in", fmt.Sprintf("created %d days ago; no lastLogonTimestamp", age(created)), "Confirm onboarding status; disable if abandoned.", true)
			}
			if !disabled && len(e.Attributes["memberof"]) == 0 {
				add(7, "low", "User has no secondary groups", "memberOf empty; primaryGroupID="+e.First("primaryGroupID")+" (AD primary group is not in memberOf)", "Confirm expected group membership or whether account is still needed.", false)
			}
		}
		if e.Kind == "computer" && !disabled {
			reference := last
			if reference.IsZero() {
				reference = created
			}
			if !reference.IsZero() && reference.Before(o.Now.Add(-time.Duration(o.Days)*24*time.Hour)) {
				add(6, "medium", "Stale computer account", fmt.Sprintf("last logon/created %d days ago", age(reference)), "Confirm device retired; disable and review DNS.", true)
			}
		}
	}
	return findings
}
