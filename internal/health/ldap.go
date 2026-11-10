package health

import (
	"fmt"
	"strconv"
	"time"

	"github.com/lauritsk/sambatui/internal/directory"
	"github.com/lauritsk/sambatui/internal/invariant"
)

func ldapUser(entry directory.Entry, options Options) []Finding {
	flags, err := strconv.ParseUint(entry.First("userAccountControl"), 10, 32)
	disabled := err == nil && flags&2 != 0
	last := firstTime(entry, "lastLogonTimestamp", "lastLogon")
	created := firstTime(entry, "whenCreated")
	findings := make([]Finding, 0, 3)
	if disabled {
		reference := firstTime(entry, "whenChanged", "whenCreated")
		if olderThan(reference, options.Now, options.DisabledDays) {
			findings = append(findings, ldapFinding(entry, Finding{
				Check: 5, Severity: "medium", Finding: "Disabled user past retention",
				Evidence: fmt.Sprintf(
					"disabled; changed/created %d days ago (not the disable timestamp)",
					ageDays(reference, options.Now),
				),
				Action: "Review retention policy before manual deletion.",
			}, false))
		}
		return findings
	}
	if olderThan(last, options.Now, options.Days) {
		findings = append(findings, ldapFinding(entry, Finding{
			Check: 4, Severity: "medium", Finding: "Enabled user inactive",
			Evidence: fmt.Sprintf("lastLogonTimestamp %d days ago (replicated AD value)",
				ageDays(last, options.Now)),
			Action: "Review owner; disable first, then delete after retention.",
		}, true))
	}
	if last.IsZero() && olderThan(created, options.Now, options.NeverLoggedDays) {
		findings = append(findings, ldapFinding(entry, Finding{
			Check: 5, Severity: "low", Finding: "User never logged in",
			Evidence: fmt.Sprintf("created %d days ago; no lastLogonTimestamp",
				ageDays(created, options.Now)),
			Action: "Confirm onboarding status; disable if abandoned.",
		}, true))
	}
	if len(entry.Attributes["memberof"]) == 0 {
		findings = append(findings, ldapFinding(entry, Finding{
			Check: 7, Severity: "low", Finding: "User has no secondary groups",
			Evidence: "memberOf empty; primaryGroupID=" + entry.First("primaryGroupID") +
				" (AD primary group is not in memberOf)",
			Action: "Confirm expected group membership or whether account is still needed.",
		}, false))
	}
	invariant.Require(len(findings) <= 3, "user produced too many findings")
	return findings
}

func ldapComputer(entry directory.Entry, options Options) []Finding {
	flags, err := strconv.ParseUint(entry.First("userAccountControl"), 10, 32)
	if err == nil && flags&2 != 0 {
		return nil
	}
	reference := firstTime(entry, "lastLogonTimestamp", "lastLogon", "whenCreated")
	if !olderThan(reference, options.Now, options.Days) {
		return nil
	}
	return []Finding{ldapFinding(entry, Finding{
		Check: 6, Severity: "medium", Finding: "Stale computer account",
		Evidence: fmt.Sprintf("last logon/created %d days ago", ageDays(reference, options.Now)),
		Action:   "Confirm device retired; disable and review DNS.",
	}, true)}
}

func ldapFinding(entry directory.Entry, finding Finding, disable bool) Finding {
	invariant.Require(finding.Check >= 4, "LDAP finding has a DNS check number")
	invariant.Require(finding.Check <= 7, "LDAP finding has an unknown check number")
	finding.Object = entry.First("sAMAccountName")
	if finding.Object == "" {
		finding.Object = entry.Name
	}
	if finding.Object == "" {
		finding.Object = entry.DN
	}
	if disable {
		flags, err := strconv.ParseUint(entry.First("userAccountControl"), 10, 32)
		if err == nil && entry.Revision != "" && len(entry.Attributes["useraccountcontrol"]) == 1 {
			finding.Fix = "ldap_disable_account"
			finding.Entry = entry
			finding.Flags = uint32(flags)
		}
	}
	return finding
}

func olderThan(reference, now time.Time, days int32) bool {
	invariant.Require(days > 0, "age threshold must be positive")
	invariant.Require(days <= 100000, "age threshold exceeds duration safety limit")
	if reference.IsZero() {
		return false
	}
	return reference.Before(now.Add(-time.Duration(days) * 24 * time.Hour))
}

// Whole elapsed days are rounded down. Future timestamps are not stale.
func ageDays(reference, now time.Time) int {
	if reference.IsZero() {
		return 0
	}
	return max(0, int(now.Sub(reference)/(24*time.Hour)))
}
