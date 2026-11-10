package health

import (
	"fmt"
	"testing"
	"time"

	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
)

func TestDNSChecksAndNarrowFixEvidence(t *testing.T) {
	records := map[string][]dnsrpc.Row{
		"lab.invalid":          {{Name: "missing", Type: "A", Value: "192.0.2.1"}, {Name: "wrong", Type: "A", Value: "192.0.2.2"}, {Name: "good", Type: "A", Value: "192.0.2.3"}, {Name: "dup", Type: "CNAME", Value: "good.lab.invalid."}, {Name: "dup", Type: "CNAME", Value: "good.lab.invalid."}, {Name: "dup", Type: "A", Value: "192.0.2.4"}},
		"2.0.192.in-addr.arpa": {{Name: "2", Type: "PTR", Value: "elsewhere.lab.invalid."}, {Name: "3", Type: "PTR", Value: "good.lab.invalid."}, {Name: "5", Type: "PTR", Value: "missing.lab.invalid."}, {Name: "6", Type: "PTR", Value: "absent.lab.invalid."}},
	}
	rows := DNS(records)
	titles := map[string]int{}
	fixes := 0
	for _, r := range rows {
		titles[r.Finding]++
		if r.Fix != "" {
			fixes++
			if r.Fix != "dns_add_ptr" || r.Zone != "2.0.192.in-addr.arpa" || r.Record.Type != "PTR" {
				t.Fatalf("unsafe fix %+v", r)
			}
		}
	}
	for _, title := range []string{"Duplicate DNS record", "CNAME conflicts with other records", "A record missing PTR", "A record PTR points elsewhere", "PTR target missing forward A", "PTR does not match forward A"} {
		if titles[title] == 0 {
			t.Fatal("missing check", title)
		}
	}
	if fixes != 2 {
		t.Fatalf("fixes=%d rows=%+v", fixes, rows)
	}
	delete(records, "2.0.192.in-addr.arpa")
	for _, r := range DNS(records) {
		if r.Fix != "" {
			t.Fatal("fix offered without reverse zone evidence")
		}
	}
}

func TestReverseZoneEvidenceUsesCaseInsensitiveDNSNames(t *testing.T) {
	rows := DNS(map[string][]dnsrpc.Row{"LAB.INVALID.": {{Name: "Host", Type: "A", Value: "192.0.2.10"}}, "2.0.192.IN-ADDR.ARPA.": {}})
	found := false
	for _, r := range rows {
		if r.Fix == "dns_add_ptr" {
			found = true
			if r.Zone != "2.0.192.in-addr.arpa" {
				t.Fatal(r)
			}
		}
	}
	if !found {
		t.Fatal("loaded reverse zone was not recognized")
	}
}

func TestTXTCaseIsNotAFalseDuplicate(t *testing.T) {
	rows := DNS(map[string][]dnsrpc.Row{"lab.invalid": {{Name: "txt", Type: "TXT", Value: `"Case"`}, {Name: "txt", Type: "TXT", Value: `"case"`}}})
	for _, r := range rows {
		if r.Check == 1 {
			t.Fatal("case-sensitive TXT data called duplicate", r)
		}
	}
}

func TestDirectoryHygieneAndMissingAmbiguousRevisions(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	old := now.Add(-400 * 24 * time.Hour)
	recent := now.Add(-time.Hour)
	entry := func(name, kind string, flags string, last time.Time) directory.Entry {
		e := directory.Entry{DN: "CN=" + name + ",DC=lab,DC=invalid", Name: name, Kind: kind, Revision: "42", Attributes: map[string][]string{"useraccountcontrol": {flags}, "whencreated": {old.Format(time.RFC3339)}, "whenchanged": {old.Format(time.RFC3339)}, "primarygroupid": {"513"}, "memberof": {"CN=Group"}}}
		if !last.IsZero() {
			e.Attributes["lastlogontimestamp"] = []string{fmt.Sprint((last.Unix() + 11644473600) * 10000000)}
		}
		return e
	}
	stale := entry("stale", "user", "66048", old)
	disabled := entry("disabled", "user", "66050", old)
	never := entry("never", "user", "512", time.Time{})
	computer := entry("retired", "computer", "4096", old)
	noGroups := entry("nogroups", "user", "512", recent)
	delete(noGroups.Attributes, "memberof")
	invalid := entry("invalid", "user", "512", old)
	invalid.Revision = ""
	ambiguous := entry("ambiguous", "user", "512", old)
	ambiguous.Attributes["useraccountcontrol"] = []string{"512", "514"}
	rows := LDAP([]directory.Entry{stale, disabled, never, computer, noGroups, invalid, ambiguous}, Options{Now: now})
	checks := map[int]int{}
	for _, r := range rows {
		checks[r.Check]++
		if r.Object == "invalid" || r.Object == "ambiguous" {
			if r.Fix != "" {
				t.Fatal("missing/ambiguous revision offered mutation")
			}
		}
		if r.Object == "stale" && r.Fix != "ldap_disable_account" {
			t.Fatal("inactive fix missing")
		}
		if r.Object == "disabled" && r.Fix != "" {
			t.Fatal("cleanup deletion must remain manual")
		}
	}
	for _, check := range []int{4, 5, 6, 7} {
		if checks[check] == 0 {
			t.Fatal("missing directory check", check)
		}
	}
	if len(LDAP([]directory.Entry{entry("fresh", "user", "512", recent)}, Options{Now: now})) != 0 {
		t.Fatal("recent user flagged inactive")
	}
}

func TestADTimeFormats(t *testing.T) {
	for _, s := range []string{"20261109120000.0Z", "20261109120000Z", "2026-11-09T12:00:00Z", "2026-11-09 12:00:00+00:00"} {
		if adTime(s).IsZero() {
			t.Fatal("failed to parse", s)
		}
	}
	for _, s := range []string{"", "0", "-1", "malformed"} {
		if !adTime(s).IsZero() {
			t.Fatal("invalid time", s)
		}
	}
}
