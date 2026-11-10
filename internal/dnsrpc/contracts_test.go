package dnsrpc

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
)

func TestMissingWriteAcknowledgementIsUncertainAndNeverRetried(t *testing.T) {
	calls := 0
	client := &Client{sockets: &trackedDialer{}, rpc: fakeRPC{
		update: func(*dnsserver.UpdateRecord2Request) (*dnsserver.UpdateRecord2Response, error) {
			calls++
			return nil, nil
		},
	}}
	resource, err := record.NewRecordFromString(dns.TypeA, 900, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	err = client.Mutate(context.Background(), "lab.invalid", "host", nil, resource)
	var uncertain *UncertainError
	if !errors.As(err, &uncertain) || calls != 1 {
		t.Fatalf("outcome %v, calls %d", err, calls)
	}
}

func TestRPCConnectionBudgetAndCloseAreEnforcedBeforeDial(t *testing.T) {
	calls := 0
	dialer := &trackedDialer{dial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		conn, peer := net.Pipe()
		t.Cleanup(func() { peer.Close() })
		return conn, nil
	}}
	defer dialer.close()
	for index := 0; index < socketsMax; index++ {
		if _, err := dialer.DialContext(context.Background(), "tcp", "unused"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "unused"); err == nil {
		t.Fatal("connection budget exceeded")
	}
	dialer.close()
	dialer.close()
	if _, err := dialer.DialContext(context.Background(), "tcp", "unused"); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed dialer reused", err)
	}
	if calls != socketsMax || len(dialer.conns) != 0 {
		t.Fatalf("calls %d, retained sockets %d", calls, len(dialer.conns))
	}
}

func TestReplaceCannotMatchDescendantRDATA(t *testing.T) {
	resource, err := record.NewRecordFromString(dns.TypeA, 900, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	data := nodeBuffer(t, &record.Node{
		DNSNodeName: record.NewNodeName("child"), DNSRecords: []*record.Record{resource},
	})
	client := &Client{sockets: &trackedDialer{}, rpc: fakeRPC{
		enum: func(*dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error) {
			return &dnsserver.EnumRecords2Response{Buffer: data}, nil
		},
		update: func(*dnsserver.UpdateRecord2Request) (*dnsserver.UpdateRecord2Response, error) {
			t.Fatal("descendant record matched parent update")
			return nil, nil
		},
	}}
	err = client.Replace(context.Background(), "lab.invalid", "parent", resource, resource)
	var status *StatusError
	if !errors.As(err, &status) || status.Code != 9714 {
		t.Fatal("missing parent record not reported", err)
	}
}
