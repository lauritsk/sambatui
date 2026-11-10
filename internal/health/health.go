package health

import (
	"fmt"
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
func DNS(records map[string][]dnsrpc.Row) []Finding {
	normalized := map[string][]dnsrpc.Row{}
	for zone, rows := range records {
		key := norm(zone)
		normalized[key] = append(normalized[key], rows...)
	}
	records = normalized
	findings := []Finding{}
	zones := []string{}
	ptr := map[string]map[string]bool{}
	forward := map[string]map[string]bool{}
	dupes := map[string]int{}
	byname := map[string]map[string]bool{}
	for zone, rows := range records {
		zones = append(zones, zone)
		for _, r := range rows {
			name := norm(dnsdata.FQDN(r.Name, zone))
			key := norm(zone) + ":" + norm(r.Name)
			value := norm(r.Value)
			if r.Type == "TXT" {
				value = r.Value
			}
			identity := key + ":" + r.Type + ":" + value
			dupes[identity]++
			if byname[key] == nil {
				byname[key] = map[string]bool{}
			}
			byname[key][r.Type] = true
			if r.Type == "PTR" {
				if ptr[name] == nil {
					ptr[name] = map[string]bool{}
				}
				ptr[name][norm(r.Value)] = true
			}
			if r.Type == "A" {
				if forward[name] == nil {
					forward[name] = map[string]bool{}
				}
				forward[name][r.Value] = true
			}
		}
	}
	for key, count := range dupes {
		if count > 1 {
			findings = append(findings, Finding{Check: 1, Severity: "medium", Object: key, Finding: "Duplicate DNS record", Evidence: fmt.Sprintf("%d identical records", count), Action: "Remove duplicate copies; keep one valid record."})
		}
	}
	for key, types := range byname {
		if types["CNAME"] && len(types) > 1 {
			findings = append(findings, Finding{Check: 1, Severity: "high", Object: key, Finding: "CNAME conflicts with other records", Action: "Keep CNAME alone or replace it with address/alias records."})
		}
	}
	for zone, rows := range records {
		for _, r := range rows {
			if r.Type == "A" {
				z, n, ok := dnsdata.Reverse(r.Value, zones)
				if !ok {
					continue
				}
				fqdn := norm(dnsdata.FQDN(r.Name, zone))
				f := Finding{Check: 2, Severity: "medium", Object: fqdn + " A " + r.Value, Action: "Review forward/reverse DNS consistency."}
				if _, loaded := records[z]; !loaded {
					f.Severity = "low"
					f.Finding = "No loaded reverse zone for A record"
					f.Evidence = "Expected zone " + z
				} else {
					targets := ptr[norm(dnsdata.FQDN(n, z))]
					if targets[fqdn] {
						continue
					}
					if len(targets) == 0 {
						f.Finding = "A record missing PTR"
						f.Fix = "dns_add_ptr"
						f.Zone = z
						f.Record = dnsrpc.Row{Name: n, Type: "PTR", Value: dnsdata.FQDN(r.Name, zone), TTL: 900}
						f.Evidence = n + "." + z + " PTR " + fqdn
					} else {
						f.Finding = "A record PTR points elsewhere"
						for v := range targets {
							f.Evidence += v + " "
						}
					}
				}
				findings = append(findings, f)
			}
			if r.Type == "PTR" {
				ip := dnsdata.ReverseIP(r.Name, zone)
				if ip == "" {
					continue
				}
				ips := forward[norm(r.Value)]
				if ips[ip] {
					continue
				}
				f := Finding{Check: 3, Severity: "medium", Object: dnsdata.FQDN(r.Name, zone) + " PTR " + r.Value, Action: "Review matching forward A record or stale PTR."}
				if len(ips) == 0 {
					f.Finding = "PTR target missing forward A"
					f.Evidence = "No loaded A record for " + r.Value
				} else {
					f.Finding = "PTR does not match forward A"
					f.Evidence = "PTR IP " + ip + "; forward IPs: "
					for v := range ips {
						f.Evidence += v + " "
					}
				}
				findings = append(findings, f)
			}
		}
	}
	return findings
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

func LDAP(rows []directory.Entry, o Options) []Finding {
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
