package dnsrpc

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
	"github.com/oiweiwei/go-msrpc/ndr"
)

type fakeRPC struct {
	dnsserver.DNSServerClient
	update func(*dnsserver.UpdateRecord2Request) (*dnsserver.UpdateRecord2Response, error)
	enum   func(*dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error)
}

func (f fakeRPC) EnumRecords2(_ context.Context, r *dnsserver.EnumRecords2Request, _ ...dcerpc.CallOption) (*dnsserver.EnumRecords2Response, error) {
	return f.enum(r)
}

func (f fakeRPC) UpdateRecord2(_ context.Context, r *dnsserver.UpdateRecord2Request, _ ...dcerpc.CallOption) (*dnsserver.UpdateRecord2Response, error) {
	return f.update(r)
}

func TestMutationIsOneExchangeAndNeverRetried(t *testing.T) {
	a, e := record.NewRecordFromString(dns.TypeA, 900, "192.0.2.1")
	if e != nil {
		t.Fatal(e)
	}
	b, e := record.NewRecordFromString(dns.TypeA, 900, "192.0.2.2")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	c := &Client{server: "selected-dc", sockets: &trackedDialer{}, rpc: fakeRPC{update: func(req *dnsserver.UpdateRecord2Request) (*dnsserver.UpdateRecord2Response, error) {
		calls++
		if req.ServerName != "selected-dc" || req.Zone != "lab.invalid" || req.NodeName != "host" {
			t.Fatalf("wrong target %+v", req)
		}
		if req.AddRecord == nil || req.DeleteRecord == nil {
			t.Fatal("update split into non-atomic operations")
		}
		if string(req.AddRecord.Buffer) != string([]byte{192, 0, 2, 2}) || string(req.DeleteRecord.Buffer) != string([]byte{192, 0, 2, 1}) {
			t.Fatal("bad NDR data")
		}
		return nil, io.ErrUnexpectedEOF
	}}}
	e = c.Mutate(context.Background(), "lab.invalid", "host", a, b)
	if e == nil || !strings.Contains(e.Error(), "uncertain") || calls != 1 {
		t.Fatalf("lost response: %v calls=%d", e, calls)
	}
}

func TestNativeRPCHandshakeTimeoutAndCancellationCloseSockets(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "cancel"}[cancelled], func(t *testing.T) {
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			accepted := make(chan net.Conn, 1)
			go func() {
				c, e := listener.Accept()
				if e == nil {
					accepted <- c
					if cancelled {
						cancel()
					}
				}
			}()
			sockets := &trackedDialer{dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
			}}
			start := time.Now()
			c, e := dial(ctx, Config{Server: "127.0.0.1", User: `LAB\Admin`, Password: NewPassword("synthetic"), Timeout: 300 * time.Millisecond}, sockets)
			if e == nil {
				defer c.Close()

				_, e = c.Zones(ctx)
			}
			if e == nil {
				t.Fatal("blackhole handshake succeeded")
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("unbounded RPC timeout")
			}
			// Close at owner boundary, even where upstream returned before its IO worker.
			sockets.close()
			select {
			case remote := <-accepted:
				defer remote.Close()
				remote.SetReadDeadline(time.Now().Add(time.Second))
				_, e = io.Copy(io.Discard, remote)
				if ne, ok := e.(net.Error); ok && ne.Timeout() {
					t.Fatal("RPC socket retained after cancellation")
				}
			case <-time.After(time.Second):
				t.Fatal("handshake never reached fake")
			}
		})
	}
}

func TestReplacementPreservesMetadataAndDoesNotSplitWrite(t *testing.T) {
	old, _ := record.NewRecordFromString(dns.TypeCNAME, 900, "TARGET.LAB.INVALID.")
	next, _ := record.NewRecordFromString(dns.TypeCNAME, 900, "next.lab.invalid.")
	actual, _ := record.NewRecordFromString(dns.TypeCNAME, 1234, "target.lab.invalid.")
	actual.Flags = 0xf0
	actual.Timestamp = 777
	actual.Serial = 81
	b, e := ndr.Marshal(&record.NodeList{DNSNodes: []*record.Node{{DNSNodeName: record.NewNodeName(""), DNSRecords: []*record.Record{actual}}}}, ndr.Opaque)
	if e != nil {
		t.Fatal(e)
	}
	reads, writes := 0, 0
	c := &Client{server: "selected-dc", sockets: &trackedDialer{}, rpc: fakeRPC{
		enum: func(r *dnsserver.EnumRecords2Request) (*dnsserver.EnumRecords2Response, error) {
			reads++
			return &dnsserver.EnumRecords2Response{Buffer: b}, nil
		},
		update: func(r *dnsserver.UpdateRecord2Request) (*dnsserver.UpdateRecord2Response, error) {
			writes++
			if r.AddRecord.TTLSeconds != 1234 || r.AddRecord.Timestamp != 777 || r.AddRecord.Flags != 0xf0 || r.AddRecord.Serial != 81 {
				t.Fatalf("metadata lost %+v", r.AddRecord)
			}
			if r.DeleteRecord == nil {
				t.Fatal("replace split")
			}
			return &dnsserver.UpdateRecord2Response{}, nil
		},
	}}
	if e = c.Replace(context.Background(), "lab.invalid", "host", old, next); e != nil {
		t.Fatal(e)
	}
	if reads != 1 || writes != 1 || next.TTLSeconds != 900 {
		t.Fatal("replacement retried or mutated caller record")
	}
}

func TestEncodingUsesExactMappedAAAAAndTXTWireOctets(t *testing.T) {
	for _, data := range []string{`. 900 IN AAAA ::ffff:192.0.2.10`, `. 900 IN TXT "a\\\\b \\"quote\\" café"`, `. 900 IN TXT "\\000edge\\000"`, `. 900 IN TXT "one" "two"`} {
		rr, e := dns.NewRR(data)
		if e != nil {
			t.Fatal(e)
		}
		expected, e := wireData(rr)
		if e != nil {
			t.Fatal(e)
		}
		encoded, e := Encode(rr)
		if e != nil {
			t.Fatal(e)
		}
		if string(encoded.Buffer) != string(expected) {
			t.Fatalf("RPC octets differ from DNS RDATA: got %x want %x", encoded.Buffer, expected)
		}
		if rr.Header().Rrtype == dns.TypeAAAA && (encoded.DataLength != 16 || len(encoded.Buffer) != 16) {
			t.Fatal("mapped IPv6 shortened to IPv4")
		}
		b, e := ndr.Marshal(encoded, ndr.Opaque)
		if e != nil {
			t.Fatal(e)
		}
		var wireRecord record.Record
		if e = ndr.Unmarshal(b, &wireRecord, ndr.Opaque); e != nil {
			t.Fatal(e)
		}
		decoded, e := decodeRecord(&wireRecord)
		if e != nil {
			t.Fatal(e)
		}
		actual, e := wireData(decoded)
		if e != nil || string(actual) != string(expected) {
			t.Fatalf("RPC decode lost TXT/mapped data: %x %x %v", actual, expected, e)
		}
	}
}

func TestSelectedCacheNeverFallsBack(t *testing.T) {
	t.Setenv("KRB5CCNAME", "FILE:/some/other/cache")
	t.Setenv("KRB5_CCACHE", "/some/other/cache")
	_, e := Dial(context.Background(), Config{Server: "127.0.0.1", Auth: "kerberos", Cache: "FILE:" + t.TempDir() + "/missing"})
	if e == nil || !strings.Contains(e.Error(), "selected Kerberos cache") {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = Dial(ctx, Config{})
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
