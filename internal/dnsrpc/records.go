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

	queue := []string{node}
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
			parent,
			recordType,
			recordBytesMax-sizeBytes,
		)
		if err != nil {
			return nil, err
		}
		sizeBytes += readBytes
		pageRows, children, err := recordsRows(nodes, parent, node)
		if err != nil {
			return nil, err
		}
		rows = append(rows, pageRows...)
		for _, child := range children {
			key := strings.ToLower(child)
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

func recordsRows(nodes record.NodeList, parent, root string) ([]Row, []string, error) {
	rows := []Row{}
	children := []string{}
	for _, node := range nodes.DNSNodes {
		if node == nil || node.DNSNodeName == nil {
			return nil, nil, errors.New("DNS record decoding: missing node")
		}
		label := strings.TrimRight(string(node.DNSNodeName.DNSName), "\x00")
		name := label
		if label == "" {
			name = parent
		} else if parent != "@" {
			name = label + "." + parent
		}
		if label != "" && node.ChildCount > 0 {
			children = append(children, name)
		}
		for _, resource := range node.DNSRecords {
			row, err := recordsRow(resource, name)
			if err != nil {
				return nil, nil, err
			}
			// A parent's response already includes immediate children's records.
			// A descendant response's self node must not duplicate those records.
			if parent == root || label != "" {
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
	decoded.Header().Name = "."
	parts := strings.SplitN(decoded.String(), "\t", 5)
	if len(parts) != 5 {
		return Row{}, errors.New("DNS record decoding: invalid resource record")
	}
	return Row{
		Name: name, Type: dns.TypeToString[decoded.Header().Rrtype], Value: parts[4],
		TTL: decoded.Header().Ttl, Flags: resource.Flags,
		Serial: resource.Serial, Timestamp: resource.Timestamp,
	}, nil
}
