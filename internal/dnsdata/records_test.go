package dnsdata

import (
	"testing"

	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
	"github.com/oiweiwei/go-msrpc/ndr"
)

func TestSupportedDNSRecordsRoundTripThroughMSDNSP(t *testing.T) {
	for _, v := range []struct{ typ, value string }{{"A", "192.0.2.10"}, {"AAAA", "2001:db8::10"}, {"AAAA", "::ffff:192.0.2.10"}, {"CNAME", "alias.example.com."}, {"PTR", "host.example.com."}, {"NS", "dc.example.com."}, {"MX", "mail.example.com. 10"}, {"SRV", "0 100 389 dc.example.com."}, {"TXT", "--help literal [red] text"}, {"TXT", `"part one" "part two"`}} {
		t.Run(v.typ+v.value, func(t *testing.T) {
			rr, e := Parse("_test", v.typ, v.value)
			if e != nil {
				t.Fatal(e)
			}
			rpc, e := dnsrpc.Encode(rr)
			if e != nil {
				t.Fatal(e)
			}
			b, e := ndr.Marshal(rpc, ndr.Opaque)
			if e != nil {
				t.Fatal(e)
			}
			var got record.Record
			if e = ndr.Unmarshal(b, &got, ndr.Opaque); e != nil {
				t.Fatal(e)
			}
			decoded := got.RR()
			decoded.Header().Name = rr.Header().Name
			if decoded.String() != rr.String() {
				t.Fatalf("got %s want %s", decoded, rr)
			}
		})
	}
}

func TestPTRTargetsRespectQualifiedNamesAndRelativeDescendants(t *testing.T) {
	for _, c := range []struct{ name, want string }{{"@", "lab.invalid"}, {"host", "host.lab.invalid"}, {"leaf.branch", "leaf.branch.lab.invalid"}, {"host.lab.invalid", "host.lab.invalid"}, {"host.other.invalid.", "host.other.invalid"}} {
		if got := FQDN(c.name, "lab.invalid"); got != c.want {
			t.Fatalf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestValidationAndPTR(t *testing.T) {
	for _, v := range []struct{ name, typ, value string }{{"-bad", "A", "192.0.2.1"}, {"x", "A", "2001:db8::1"}, {"x", "AAAA", "192.0.2.1"}, {"x", "CNAME", "192.0.2.1"}, {"x", "SRV", "0 1 65536 dc.example.com."}, {"x", "MX", "-1 mail.example.com."}, {"x", "BOGUS", "value"}, {"x", "PTR", "bad name"}} {
		if _, e := Parse(v.name, v.typ, v.value); e == nil {
			t.Fatalf("invalid record accepted %+v", v)
		}
	}
	z, n, ok := Reverse("192.0.2.10", []string{"0.192.in-addr.arpa", "2.0.192.in-addr.arpa"})
	if !ok || z != "2.0.192.in-addr.arpa" || n != "10" {
		t.Fatal(z, n, ok)
	}
	if ip := ReverseIP(n, z); ip != "192.0.2.10" {
		t.Fatal(ip)
	}
}
