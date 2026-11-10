package dnsrpc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
)

type recordBranch struct {
	name        string
	includeSelf bool
}

// Records enumerates the management interface, not ordinary DNS answers. A
// partial/overflow response is an error, never a successful partial zone.
func (client *Client) Records(
	operationContext context.Context,
	zone, node string,
	recordType uint16,
) ([]Row, error) {
	if !dnsdata.ValidName(zone, false) {
		return nil, errors.New("invalid DNS enumeration zone")
	}
	if node == "" {
		node = "@"
	}
	if !dnsdata.ValidName(node, true) {
		return nil, errors.New("invalid DNS enumeration node")
	}
	if recordType == 0 {
		recordType = dns.TypeANY
	}
	stop := context.AfterFunc(operationContext, client.sockets.close)
	defer stop()

	queue := []recordBranch{{name: node, includeSelf: true}}
	scheduled := map[string]bool{strings.ToLower(node): true}
	rows := []Row{}
	sizeBytes := 0
	for index := 0; index < len(queue); index++ {
		if err := operationContext.Err(); err != nil {
			return nil, err
		}
		parent := queue[index]
		nodes, readBytes, err := client.recordsRead(
			operationContext,
			zone,
			qualifiedNodeName(zone, parent.name, node),
			recordType,
			recordBytesMax-sizeBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("DNS zone %q node %q: %w", zone, parent.name, err)
		}
		sizeBytes += readBytes
		pageRows, children, err := recordsRows(nodes, parent)
		if err != nil {
			return nil, err
		}
		rows = append(rows, pageRows...)
		for _, child := range children {
			key := strings.ToLower(child.name)
			if scheduled[key] {
				continue
			}
			// Bound pending work before enqueue, not just after visiting nodes.
			if len(queue) == recordNodesMax {
				return nil, errors.New("DNS enumeration exceeds 10000 nodes")
			}
			scheduled[key] = true
			queue = append(queue, child)
		}
	}
	return rows, nil
}

func (client *Client) recordsRead(
	operationContext context.Context, zone, parent string, recordType uint16, remainingBytes int,
) (record.NodeList, int, error) {
	if len(strings.TrimSuffix(parent, ".")) > 253 {
		return record.NodeList{}, 0, errors.New(
			"fully qualified DNS enumeration name exceeds 253 bytes",
		)
	}
	response, err := client.rpc.EnumRecords2(operationContext, &dnsserver.EnumRecords2Request{
		ClientVersion: 0x70000, ServerName: client.server, Zone: zone,
		NodeName: parent, RecordType: recordType, SelectFlag: 1,
	})
	if err != nil {
		return record.NodeList{}, 0, fmt.Errorf("DNS enumerate records: %w", err)
	}
	if response == nil {
		return record.NodeList{}, 0, errors.New("DNS enumerate records: missing result")
	}
	if response.Return != 0 {
		return record.NodeList{}, 0, statusError("enumerate records", response.Return)
	}
	if len(response.Buffer) > remainingBytes {
		return record.NodeList{}, 0, errors.New(
			"DNS record response exceeds 16 MiB (no partial results accepted)",
		)
	}
	nodes, err := decodeNodes(response.Buffer)
	if err != nil {
		return record.NodeList{}, 0, fmt.Errorf("DNS record decoding: %w", err)
	}
	return nodes, len(response.Buffer), nil
}

// Fully qualify relative owners: Samba can strip even a partial zone suffix
// from an undotted name, selecting a different subtree or returning status 9714.
func qualifiedNodeName(zone, parent, root string) string {
	if parent == "@" {
		return parent
	}
	zone = strings.TrimSuffix(zone, ".")
	absolute := strings.HasSuffix(root, ".") || strings.EqualFold(root, zone) ||
		strings.HasSuffix(strings.ToLower(root), "."+strings.ToLower(zone))
	if absolute {
		return dns.Fqdn(parent)
	}
	return dns.Fqdn(parent + "." + zone)
}

func recordsRows(nodes record.NodeList, parent recordBranch) ([]Row, []recordBranch, error) {
	rows := []Row{}
	children := []recordBranch{}
	for _, node := range nodes.DNSNodes {
		if node == nil || node.DNSNodeName == nil {
			return nil, nil, errors.New("DNS record decoding: missing node")
		}
		label := strings.TrimRight(string(node.DNSNodeName.DNSName), "\x00")
		name := label
		if label == "" {
			name = parent.name
		} else if parent.name != "@" {
			name = label + "." + parent.name
		}
		if label != "" && node.ChildCount > 0 {
			children = append(children, recordBranch{
				name: name, includeSelf: len(node.DNSRecords) == 0,
			})
		}
		for _, resource := range node.DNSRecords {
			row, err := recordsRow(resource, name)
			if err != nil {
				return nil, nil, err
			}
			// Samba omits branch records from the parent's response, unlike
			// servers that return both records and a nonzero child count.
			if parent.includeSelf || label != "" {
				rows = append(rows, row)
			}
		}
	}
	return rows, children, nil
}

func recordsRow(resource *record.Record, name string) (Row, error) {
	decoded, err := decodeRecord(resource)
	if err != nil {
		return Row{}, err
	}
	return resourceRow(decoded, name, resource.Flags, resource.Serial, resource.Timestamp)
}

func resourceRow(decoded dns.RR, name string, flags, serial, timestamp uint32) (Row, error) {
	decoded.Header().Name = "."
	parts := strings.SplitN(decoded.String(), "\t", 5)
	if len(parts) != 5 {
		return Row{}, errors.New("DNS record decoding: invalid resource record")
	}
	return Row{
		Name: name, Type: dns.TypeToString[decoded.Header().Rrtype], Value: parts[4],
		TTL: decoded.Header().Ttl, Flags: flags,
		Serial: serial, Timestamp: timestamp,
	}, nil
}
