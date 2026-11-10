package tui

import (
	"context"
	"time"

	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/invariant"
	"github.com/lauritsk/sambatui/internal/lifecycle"
	"github.com/miekg/dns"
)

// One event-loop owner cancels and supersedes reads, including discovery and
// reconciliation. Workers capture the resulting context and identity by value.
func (model *Model) startRead(timeout time.Duration) (context.Context, context.CancelFunc) {
	invariant.Require(timeout > 0, "read requires a positive timeout")
	invariant.Require(timeout <= 300*time.Second, "read timeout exceeds settings limit")
	if model.readCancel != nil {
		model.readCancel()
	}
	model.readID = invariant.Next(model.readID)
	operationContext, cancel := context.WithTimeout(context.Background(), timeout)
	model.readCancel = cancel
	return operationContext, cancel
}

func (model *Model) readCurrent(generation, requestID uint64) bool {
	return model.state.Current(generation) && requestID == model.readID
}

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
