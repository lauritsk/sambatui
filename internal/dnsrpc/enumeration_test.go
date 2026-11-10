package dnsrpc

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
)

func TestEnumerationOwnerQualification(t *testing.T) {
	for _, test := range []struct{ root, parent, expected string }{
		{"@", "@", "@"},
		{"@", "ee", "ee.colleduc.ee."},
		{"@", "api.ee", "api.ee.colleduc.ee."},
		{"@", "colleduc.ee", "colleduc.ee.colleduc.ee."},
		{"host", "leaf.host", "leaf.host.colleduc.ee."},
		{"host.colleduc.ee", "host.colleduc.ee", "host.colleduc.ee."},
		{"HOST.COLLEDUC.EE", "leaf.HOST.COLLEDUC.EE", "leaf.HOST.COLLEDUC.EE."},
		{"host.colleduc.ee.", "leaf.host.colleduc.ee.", "leaf.host.colleduc.ee."},
		{"colleduc.ee", "colleduc.ee", "colleduc.ee."},
	} {
		if actual := qualifiedNodeName("colleduc.ee", test.parent, test.root); actual != test.expected {
			t.Fatalf("root %q parent %q: got %q, want %q", test.root, test.parent, actual, test.expected)
		}
	}
}

func TestEnumerationQualifiesNestedNamesSharingTheZoneSuffix(t *testing.T) {
	resource, err := record.NewRecordFromString(dns.TypeA, 900, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string][]byte{
		"@": nodeBuffer(t, &record.Node{DNSNodeName: record.NewNodeName("ee"), ChildCount: 1}),
		"ee.colleduc.ee.": nodeBuffer(t,
			&record.Node{DNSNodeName: record.NewNodeName("")},
			&record.Node{DNSNodeName: record.NewNodeName("api"), ChildCount: 1}),
		"api.ee.colleduc.ee.": nodeBuffer(t,
			&record.Node{DNSNodeName: record.NewNodeName("")},
			&record.Node{DNSNodeName: record.NewNodeName("leaf"), DNSRecords: []*record.Record{resource}}),
	}
	var calls []string
	client := &Client{sockets: &trackedDialer{}, rpc: fakeRPC{
		enum: func(request *dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error) {
			calls = append(calls, request.NodeName)
			data, exists := pages[request.NodeName]
			if !exists {
				return &dnsserver.EnumRecords2Response{Return: 9714}, nil
			}
			return &dnsserver.EnumRecords2Response{Buffer: data}, nil
		},
	}}
	rows, err := client.Records(context.Background(), "colleduc.ee", "@", 0)
	if err != nil || len(rows) != 1 || rows[0].Name != "leaf.api.ee" {
		t.Fatalf("nested enumeration: rows=%v error=%v", rows, err)
	}
	if !reflect.DeepEqual(calls, []string{"@", "ee.colleduc.ee.", "api.ee.colleduc.ee."}) {
		t.Fatal("unexpected subtree requests", calls)
	}
}

func TestEnumerationIncludesBranchRecordsExactlyOnce(t *testing.T) {
	resource, err := record.NewRecordFromString(dns.TypeA, 900, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, parentIncludesRecords := range []bool{false, true} {
		branch := &record.Node{DNSNodeName: record.NewNodeName("branch"), ChildCount: 1}
		if parentIncludesRecords {
			branch.DNSRecords = []*record.Record{resource}
		}
		root := nodeBuffer(t, branch)
		children := nodeBuffer(t,
			&record.Node{DNSNodeName: record.NewNodeName(""), DNSRecords: []*record.Record{resource}},
			&record.Node{DNSNodeName: record.NewNodeName("leaf"), DNSRecords: []*record.Record{resource}})
		client := &Client{sockets: &trackedDialer{}, rpc: fakeRPC{
			enum: func(request *dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error) {
				if request.NodeName == "@" {
					return &dnsserver.EnumRecords2Response{Buffer: root}, nil
				}
				return &dnsserver.EnumRecords2Response{Buffer: children}, nil
			},
		}}
		rows, err := client.Records(context.Background(), "lab.invalid", "@", 0)
		if err != nil || len(rows) != 2 || rows[0].Name != "branch" || rows[1].Name != "leaf.branch" {
			t.Fatalf("parent includes records=%v: rows=%v error=%v", parentIncludesRecords, rows, err)
		}
	}
}

func TestEnumerationRejectsOversizeQualifiedNamesBeforeRPC(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	client := &Client{sockets: &trackedDialer{}, rpc: fakeRPC{
		enum: func(*dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error) {
			t.Fatal("oversized owner reached the server")
			return nil, nil
		},
	}}
	rows, err := client.Records(context.Background(), "colleduc.ee", name, 0)
	if rows != nil || err == nil || !strings.Contains(err.Error(), "253 bytes") {
		t.Fatalf("oversized owner accepted: rows=%v error=%v", rows, err)
	}
}

func TestEnumerationErrorsIdentifyTheSubtreeWithoutReturningPartialResults(t *testing.T) {
	for _, failAtRoot := range []bool{false, true} {
		root := nodeBuffer(t, &record.Node{DNSNodeName: record.NewNodeName("branch"), ChildCount: 1})
		client := &Client{sockets: &trackedDialer{}, rpc: fakeRPC{
			enum: func(request *dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error) {
				if !failAtRoot && request.NodeName == "@" {
					return &dnsserver.EnumRecords2Response{Buffer: root}, nil
				}
				return &dnsserver.EnumRecords2Response{Return: 9714}, nil
			},
		}}
		rows, err := client.Records(context.Background(), "colleduc.ee", "@", 0)
		var status *StatusError
		if rows != nil || !errors.As(err, &status) || status.Code != 9714 {
			t.Fatalf("missing node accepted: rows=%v error=%v", rows, err)
		}
		node := "branch"
		if failAtRoot {
			node = "@"
		}
		if !strings.Contains(err.Error(), `zone "colleduc.ee" node "`+node+`"`) {
			t.Fatal("failure lost its target", err)
		}
	}
}
