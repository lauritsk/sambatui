package dnsrpc

import (
	"context"
	"fmt"
	"testing"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
	"github.com/oiweiwei/go-msrpc/ndr"
)

func nodeBuffer(t *testing.T, nodes ...*record.Node) []byte {
	t.Helper()
	data, err := ndr.Marshal(&record.NodeList{DNSNodes: nodes}, ndr.Opaque)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEnumerationBoundsPendingNodesBeforeMoreRequests(t *testing.T) {
	nodes := make([]*record.Node, recordNodesMax)
	for index := range nodes {
		nodes[index] = &record.Node{DNSNodeName: record.NewNodeName(fmt.Sprintf("host%d", index)), ChildCount: 1}
	}
	data := nodeBuffer(t, nodes...)
	calls := 0
	client := &Client{sockets: &trackedDialer{}, rpc: fakeRPC{enum: func(*dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error) {
		calls++
		return &dnsserver.EnumRecords2Response{Buffer: data}, nil
	}}}
	rows, err := client.Records(context.Background(), "lab.invalid", "@", 0)
	if err == nil || rows != nil || calls != 1 {
		t.Fatalf("rows %d, calls %d, error %v", len(rows), calls, err)
	}
}

func TestEnumerationSchedulesDuplicateChildrenOnce(t *testing.T) {
	child := &record.Node{DNSNodeName: record.NewNodeName("child"), ChildCount: 1}
	root := nodeBuffer(t, child, child)
	leaf := nodeBuffer(t, &record.Node{DNSNodeName: record.NewNodeName("")})
	calls := 0
	client := &Client{sockets: &trackedDialer{}, rpc: fakeRPC{enum: func(request *dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error) {
		calls++
		if request.NodeName == "@" {
			return &dnsserver.EnumRecords2Response{Buffer: root}, nil
		}
		return &dnsserver.EnumRecords2Response{Buffer: leaf}, nil
	}}}
	if _, err := client.Records(context.Background(), "lab.invalid", "@", 0); err != nil || calls != 2 {
		t.Fatalf("calls %d, error %v", calls, err)
	}
}

func TestEnumerationRejectsMissingAndOversizeResponses(t *testing.T) {
	for _, response := range []*dnsserver.EnumRecords2Response{
		nil, {Buffer: make([]byte, recordBytesMax+1)},
	} {
		client := &Client{sockets: &trackedDialer{}, rpc: fakeRPC{enum: func(*dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error) {
			return response, nil
		}}}
		if rows, err := client.Records(context.Background(), "lab.invalid", "@", 0); err == nil || rows != nil {
			t.Fatalf("rows %d, error %v", len(rows), err)
		}
	}
}

type fakeZoneRPC struct {
	dnsserver.DNSServerClient
	response *dnsserver.ComplexOperation2Response
}

func (f fakeZoneRPC) ComplexOperation2(
	context.Context, *dnsserver.ComplexOperation2Request, ...dcerpc.CallOption,
) (*dnsserver.ComplexOperation2Response, error) {
	return f.response, nil
}

func TestZoneEnumerationBoundsAndMissingResults(t *testing.T) {
	for _, count := range []int{0, 1, zonesMax, zonesMax + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			list := &dnsp.ZoneListW2K{ZoneArray: make([]*dnsp.ZoneW2K, count)}
			for index := range list.ZoneArray {
				list.ZoneArray[index] = &dnsp.ZoneW2K{ZoneName: fmt.Sprintf("zone%d.invalid", index)}
			}
			response := &dnsserver.ComplexOperation2Response{
				DataOut: &dnsp.Union{Value: &dnsp.Union_ZoneListW2K{ZoneListW2K: list}},
			}
			client := &Client{sockets: &trackedDialer{}, rpc: fakeZoneRPC{response: response}}
			zones, err := client.Zones(context.Background())
			if count <= zonesMax {
				if err != nil || len(zones) != count {
					t.Fatalf("zones %d, error %v", len(zones), err)
				}
			} else if err == nil || zones != nil {
				t.Fatalf("oversized enumeration: zones %d, error %v", len(zones), err)
			}
		})
	}
	for _, response := range []*dnsserver.ComplexOperation2Response{
		nil, {}, {DataOut: &dnsp.Union{Value: &dnsp.Union_ZoneListW2K{}}},
	} {
		client := &Client{sockets: &trackedDialer{}, rpc: fakeZoneRPC{response: response}}
		if _, err := client.Zones(context.Background()); err == nil {
			t.Fatal("missing zone result accepted")
		}
	}
}
