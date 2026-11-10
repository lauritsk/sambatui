package tui

import (
	"context"
	"errors"
	"fmt"

	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/lauritsk/sambatui/internal/health"
	"github.com/lauritsk/sambatui/internal/invariant"
	"github.com/lauritsk/sambatui/internal/lifecycle"
	"github.com/miekg/dns"
)

// readRequest contains only immutable values. Workers never access Model state.
type readRequest struct {
	snapshot                                                  lifecycle.Snapshot
	requestID                                                 uint64
	kind, zone, base, searchKind, query, queryType, queryName string
	check                                                     int
}

func runRead(
	operationContext context.Context,
	service backend.Service,
	request readRequest,
) readResult {
	invariant.Require(request.snapshot.Generation > 0, "read requires a connection generation")
	invariant.Require(request.requestID > 0, "read requires a request ID")
	result := readResult{
		generation: request.snapshot.Generation, requestID: request.requestID,
		kind: request.kind, zone: request.zone,
	}
	settings := request.snapshot.Settings
	switch request.kind {
	case "zones", "setup":
		result.zones, result.err = service.Zones(operationContext, settings)
		if request.kind == "setup" && result.err == nil {
			result.err = service.CheckLDAP(operationContext, settings)
		}
	case "dns":
		result.records, result.err = service.Records(
			operationContext,
			settings,
			request.zone,
			"@",
			dns.TypeANY,
		)
	case "query":
		recordType, err := backend.ParseQueryType(request.queryType)
		if err != nil {
			result.err = err
		} else {
			name := request.queryName
			if name == "" {
				name = "@"
			}
			result.records, result.err = service.Records(
				operationContext,
				settings,
				request.zone,
				name,
				recordType,
			)
		}
	case "ldap":
		result.entries, result.err = service.Search(
			operationContext, settings, request.base, request.searchKind,
			request.query, settings.LDAPMaxRows,
		)
		if result.err == nil {
			result.folders, result.err = service.Search(
				operationContext, settings, request.base, "containers", "", settings.LDAPMaxRows,
			)
		}
	case "health":
		result.findings = readHealth(operationContext, service, settings, request.check)
	default:
		panic("unknown read kind")
	}
	return result
}

func readHealth(
	operationContext context.Context, service backend.Service, settings config.Settings, check int,
) []health.Finding {
	findings := []health.Finding{}
	completed := map[int]bool{}
	if check <= 3 || check == 8 {
		dnsFindings, complete := readHealthDNS(operationContext, service, settings, check)
		findings = append(findings, dnsFindings...)
		for number := 1; number <= 3; number++ {
			completed[number] = complete
		}
	}
	if check >= 4 {
		ldapFindings, complete := readHealthLDAP(operationContext, service, settings, check)
		findings = append(findings, ldapFindings...)
		for number := 4; number <= 7; number++ {
			completed[number] = complete
		}
	}
	if check == 8 {
		findings = health.Dashboard(findings, completed)
	}
	if len(findings) == 0 {
		findings = append(findings, health.Finding{
			Severity: "info", Finding: "No findings in completed checks",
			Evidence: "This is hygiene evidence, not an authorization or security audit.",
		})
	}
	return findings
}

const (
	healthDNSRowsMax  = 100000
	healthDNSBytesMax = 16 << 20
	healthDNSZonesMax = 10000
)

func readHealthDNS(
	operationContext context.Context, service backend.Service, settings config.Settings, check int,
) ([]health.Finding, bool) {
	zones, err := service.Zones(operationContext, settings)
	if err != nil {
		return []health.Finding{{
			Severity: "error", Finding: "DNS checks failed", Evidence: err.Error(),
		}}, false
	}
	records := map[string][]dnsrpc.Row{}
	findings := []health.Finding{}
	complete := true
	rowCount, sizeBytes := 0, 0
	if len(zones) > healthDNSZonesMax {
		return []health.Finding{{
			Severity: "error", Finding: "DNS checks failed",
			Evidence: "DNS health check exceeds zone safety limit",
		}}, false
	}
	for _, zone := range zones {
		rows, err := service.Records(operationContext, settings, zone, "@", dns.TypeANY)
		if err == nil {
			var readBytes int
			readBytes, err = readHealthDNSBudget(
				rows,
				healthDNSRowsMax-rowCount,
				healthDNSBytesMax-sizeBytes,
			)
			if err != nil {
				return append(findings, health.Finding{
					Severity: "error", Object: zone, Finding: "DNS zone check failed",
					Evidence: err.Error(),
				}), false
			}
			rowCount += len(rows)
			sizeBytes += readBytes
		}
		if err != nil {
			findings = append(findings, health.Finding{
				Severity: "error", Object: zone, Finding: "DNS zone check failed",
				Evidence: err.Error(),
			})
			complete = false
		} else {
			records[zone] = rows
		}
	}
	// Cross-zone negative findings are misleading after any failed zone read.
	if complete {
		findings = append(findings, filterFindings(health.DNS(records), check)...)
	}
	return findings, complete
}

func readHealthDNSBudget(rows []dnsrpc.Row, remainingRows, remainingBytes int) (int, error) {
	if len(rows) > remainingRows {
		return 0, errors.New(
			"DNS health check exceeds record safety limit; no clean " + "result claimed",
		)
	}
	sizeBytes := 0
	for _, row := range rows {
		for _, value := range []string{row.Name, row.Type, row.Value} {
			if len(value) > remainingBytes-sizeBytes {
				return 0, errors.New(
					"DNS health check exceeds byte safety limit; no clean result claimed",
				)
			}
			sizeBytes += len(value)
		}
	}
	return sizeBytes, nil
}

func readHealthLDAP(
	operationContext context.Context, service backend.Service, settings config.Settings, check int,
) ([]health.Finding, bool) {
	entries, err := service.Search(
		operationContext,
		settings,
		settings.BaseDN,
		"all",
		"",
		settings.MaxRows,
	)
	if err != nil {
		return []health.Finding{{
			Severity: "error", Finding: "LDAP checks failed", Evidence: err.Error(),
		}}, false
	}
	findings := filterFindings(health.LDAP(entries, health.Options{
		Days: settings.Days, DisabledDays: settings.DisabledDays,
		NeverLoggedDays: settings.NeverLoggedDays,
	}), check)
	complete := len(entries) < settings.MaxRows
	if !complete {
		findings = append(findings, health.Finding{
			Severity: "info", Finding: "LDAP check limited",
			Evidence: fmt.Sprintf(
				"Only first %d entries checked; load more before concluding clean.",
				settings.MaxRows,
			),
		})
	}
	return findings, complete
}

func filterFindings(findings []health.Finding, check int) []health.Finding {
	filtered := make([]health.Finding, 0, len(findings))
	for _, finding := range findings {
		if check == 8 || finding.Check == check {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}
