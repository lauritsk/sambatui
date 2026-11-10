package tui

import (
	"context"

	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/invariant"
	"github.com/lauritsk/sambatui/internal/lifecycle"
	"github.com/miekg/dns"
)

// readRequest contains only immutable values. Workers never access Model state.
type readRequest struct {
	snapshot                                                  lifecycle.Snapshot
	requestID                                                 uint64
	kind, zone, base, searchKind, query, queryType, queryName string
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
	case "zones":
		result.zones, result.err = service.Zones(operationContext, settings)
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
	default:
		panic("unknown read kind")
	}
	return result
}
