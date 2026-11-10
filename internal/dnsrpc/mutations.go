package dnsrpc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
	"github.com/oiweiwei/go-msrpc/ndr"
)

// Replace matches the old RDATA on this DC and preserves its existing TTL,
// rank/flags and aging metadata, as Samba's management update does. The only
// write is a single add+delete request; reads are not a write retry or rollback.
func (client *Client) Replace(
	operationContext context.Context,
	zone, name string,
	old, new *record.Record,
) error {
	if old == nil || new == nil {
		return errors.New("replace requires old and new records")
	}
	resource, err := decodeRecord(old)
	if err != nil {
		return err
	}
	resource.Header().Name = "."
	rows, err := client.Records(operationContext, zone, name, uint16(old.Type))
	if err != nil {
		return err
	}
	for _, row := range rows {
		candidate, err := dns.NewRR(fmt.Sprintf(". %d IN %s %s", row.TTL, row.Type, row.Value))
		if err != nil {
			return fmt.Errorf("DNS update parse observed record: %w", err)
		}
		if !strings.EqualFold(row.Name, name) {
			continue
		}
		if dns.IsDuplicate(resource, candidate) {
			original := *old
			replacement := *new
			original.TTLSeconds = row.TTL
			original.Flags = row.Flags
			original.Serial = row.Serial
			original.Timestamp = row.Timestamp
			replacement.TTLSeconds = row.TTL
			replacement.Flags = row.Flags
			replacement.Serial = row.Serial
			replacement.Timestamp = row.Timestamp
			return client.Mutate(operationContext, zone, name, &original, &replacement)
		}
	}
	return &StatusError{Operation: "update old record no longer matches; refresh", Code: 9714}
}

// Mutate performs exactly one RPC request. old/new nil mean add/delete. An
// exchange sends both records in the same server operation, not delete+add.
// Transport failures after dispatch have uncertain outcomes, not rollback.
func (client *Client) Mutate(
	operationContext context.Context,
	zone, name string,
	old, new *record.Record,
) error {
	if !dnsdata.ValidName(zone, false) || !dnsdata.ValidName(name, true) {
		return errors.New("invalid DNS mutation target")
	}
	if old == nil && new == nil {
		return errors.New("empty DNS mutation")
	}
	nodeName := qualifiedNodeName(zone, name, name)
	if len(strings.TrimSuffix(nodeName, ".")) > 253 {
		return errors.New("fully qualified DNS mutation name exceeds 253 bytes")
	}
	convert := func(currentRecord *record.Record) (*dnsp.Record, error) {
		if currentRecord == nil {
			return nil, nil
		}
		data, currentErr := ndr.Marshal(currentRecord, ndr.Opaque)
		if currentErr != nil {
			return nil, currentErr
		}
		var out dnsp.Record
		if currentErr = ndr.Unmarshal(data, &out, ndr.Opaque); currentErr != nil {
			return nil, currentErr
		}
		return &out, nil
	}
	add, currentErr := convert(new)
	if currentErr != nil {
		return currentErr
	}
	del, currentErr := convert(old)
	if currentErr != nil {
		return currentErr
	}
	stop := context.AfterFunc(operationContext, client.sockets.close)
	defer stop()
	if err := operationContext.Err(); err != nil {
		return err
	}
	r, currentErr := client.rpc.UpdateRecord2(
		operationContext,
		&dnsserver.UpdateRecord2Request{
			ServerName:   client.server,
			Zone:         zone,
			NodeName:     nodeName,
			AddRecord:    add,
			DeleteRecord: del,
		},
	)
	if currentErr != nil {
		return &UncertainError{Cause: currentErr}
	}
	if r == nil {
		return &UncertainError{Cause: errors.New("DNS write returned no acknowledgement")}
	}
	if r.Return != 0 {
		return statusError("write", r.Return)
	}
	return nil
}
