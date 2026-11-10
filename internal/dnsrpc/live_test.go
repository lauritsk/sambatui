package dnsrpc

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/dnsdata"
	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
)

// This test may mutate ONLY the isolated loopback lab created by integration/server.sh.
func TestDisposableSamba(t *testing.T) {
	if os.Getenv("SAMBATUI_DISPOSABLE_TEST") != "YES" {
		t.Skip("opt-in disposable lab only")
	}
	marker, e := os.ReadFile("/tmp/native-ad/disposable.marker")
	if e != nil || string(marker) != "sambatui isolated disposable lab\n" {
		t.Fatal("not the authorized disposable fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := Config{Server: "127.0.0.1", User: `LAB\Administrator`, Password: NewPassword("Disposable-test-only_42!"), Timeout: 5 * time.Second}
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	zones, err := c.Zones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("zones:", zones)
	if len(zones) != 3 || !slices.Contains(zones, "lab.invalid") || !slices.Contains(zones, "2.0.192.in-addr.arpa") {
		t.Fatalf("want disposable lab forward/reverse zones, got %v", zones)
	}
	rows, err := c.Records(ctx, "lab.invalid", "@", dns.TypeANY)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("records:", rows)
	a, err := record.NewRecordFromString(dns.TypeA, 900, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	b, err := record.NewRecordFromString(dns.TypeA, 900, "192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		old, new *record.Record
		value    string
	}{{nil, a, "192.0.2.10"}, {a, b, "192.0.2.11"}, {b, nil, ""}} {
		if err = c.Mutate(ctx, "lab.invalid", "native-proof", step.old, step.new); err != nil {
			t.Fatal(err)
		}
		if step.value != "" {
			r, e := c.Records(ctx, "lab.invalid", "native-proof", dns.TypeA)
			if e != nil {
				t.Fatal(e)
			}
			if len(r) != 1 || r[0].Value != step.value {
				t.Fatalf("read after write: %+v", r)
			}
		}
	}
	t.Run("all supported record types", func(t *testing.T) {
		for _, v := range []struct{ typ, a, b string }{{"A", "192.0.2.100", "192.0.2.101"}, {"AAAA", "2001:db8::100", "2001:db8::101"}, {"AAAA", "::ffff:192.0.2.100", "::ffff:192.0.2.101"}, {"CNAME", "first.lab.invalid.", "second.lab.invalid."}, {"PTR", "first.lab.invalid.", "second.lab.invalid."}, {"NS", "dc.lab.invalid.", "other.lab.invalid."}, {"MX", "10 dc.lab.invalid.", "20 other.lab.invalid."}, {"SRV", "0 100 389 dc.lab.invalid.", "10 50 636 dc.lab.invalid."}, {"TXT", "--help [red] literal text", "  surrounding whitespace  "}, {"TXT", `"a\\\\b \\"quoted\\" café"`, `"back\\\\slash" "multi-string"`}} {
			t.Run(v.typ, func(t *testing.T) {
				rr, e := dnsdata.Parse("native-types", v.typ, v.a)
				if e != nil {
					t.Fatal(e)
				}
				old, e := Encode(rr)
				if e != nil {
					t.Fatal(e)
				}
				next, e := dnsdata.Parse("native-types", v.typ, v.b)
				if e != nil {
					t.Fatal(e)
				}
				new, e := Encode(next)
				if e != nil {
					t.Fatal(e)
				}
				name := "native-types-" + v.typ
				old.TTLSeconds = 1234
				old.Flags = 0xf0
				if e = c.Mutate(ctx, "lab.invalid", name, nil, old); e != nil {
					t.Fatal(e)
				}
				if e = c.Replace(ctx, "lab.invalid", name, old, new); e != nil {
					t.Fatal(e)
				}
				rows, e := c.Records(ctx, "lab.invalid", name, next.Header().Rrtype)
				if e != nil || len(rows) != 1 {
					t.Fatalf("read update: %v %v", rows, e)
				}
				next.Header().Name = "."
				want := strings.SplitN(next.String(), "\t", 5)[4]
				if rows[0].Value != want || rows[0].TTL != 1234 {
					t.Fatalf("update value/metadata not preserved: got %+v want value=%s TTL=1234", rows[0], want)
				}
				if e = c.Mutate(ctx, "lab.invalid", name, new, nil); e != nil {
					t.Fatal(e)
				}
			})
		}
	})
	t.Run("qualified owner name", func(t *testing.T) {
		if e := c.Mutate(ctx, "lab.invalid", "native-qualified.lab.invalid", nil, a); e != nil {
			t.Fatal(e)
		}
		defer c.Mutate(ctx, "lab.invalid", "native-qualified.lab.invalid", a, nil)
		m := new(dns.Msg)
		m.SetQuestion("native-qualified.lab.invalid.", dns.TypeA)
		reply, _, e := (&dns.Client{}).ExchangeContext(ctx, m, "127.0.0.1:53")
		if e != nil || reply == nil || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) == 0 {
			t.Fatalf("qualified node name was not interpreted as absolute: %v %v", reply, e)
		}
	})
	t.Run("password Kerberos without downgrade", func(t *testing.T) {
		kcfg := cfg
		kcfg.User = "Administrator@LAB.INVALID"
		kcfg.Server = "dc.lab.invalid"
		kcfg.PasswordAuth = "kerberos"
		kcfg.KerberosConfig = "/tmp/native-ad/krb5.conf"
		k, e := Dial(ctx, kcfg)
		if e != nil {
			t.Fatal(e)
		}
		defer k.Close()
		zones, e := k.Zones(ctx)
		if e != nil || len(zones) != 3 {
			t.Fatal(zones, e)
		}
		if e = k.Mutate(ctx, "lab.invalid", "native-kerberos-password", nil, a); e != nil {
			t.Fatal(e)
		}
		if e = k.Mutate(ctx, "lab.invalid", "native-kerberos-password", a, nil); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		bad := cfg
		bad.Password = NewPassword("wrong")
		badClient, e := Dial(ctx, bad)
		if badClient != nil {
			defer badClient.Close()
		}
		if e == nil {
			_, e = badClient.Zones(ctx)
		}
		if e == nil {
			t.Fatal("bad credentials accepted")
		}
		t.Log(e)
	})
	t.Run("permission denial", func(t *testing.T) {
		reader := cfg
		reader.User = `LAB\Reader`
		rc, e := Dial(ctx, reader)
		if e != nil {
			t.Fatal(e)
		}
		defer rc.Close()
		e = rc.Mutate(ctx, "lab.invalid", "unauthorized", nil, a)
		if e == nil {
			t.Fatal("unauthorized DNS write accepted")
		}
		t.Log(e)
	})
	t.Run("protocol error", func(t *testing.T) {
		_, e := c.Records(ctx, "missing.invalid", "@", dns.TypeA)
		if e == nil {
			t.Fatal("nonexistent zone succeeded")
		}
		t.Log(e)
	})
	t.Run("nested enumeration", func(t *testing.T) {
		for _, name := range []string{"branch", "leaf.branch", "leaf.suffix.invalid"} {
			if e := c.Mutate(ctx, "lab.invalid", name, nil, a); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				if e := c.Mutate(ctx, "lab.invalid", name, a, nil); e != nil {
					t.Error("nested enumeration cleanup:", e)
				}
			})
		}
		r, e := c.Records(ctx, "lab.invalid", "@", dns.TypeANY)
		if e != nil {
			t.Fatal(e)
		}
		legacy, legacyErr := c.rpc.EnumRecords2(ctx, &dnsserver.EnumRecords2Request{
			ClientVersion: 0x70000, ServerName: cfg.Server, Zone: "lab.invalid",
			NodeName: "suffix.invalid", RecordType: dns.TypeANY, SelectFlag: 1,
		})
		if legacyErr != nil || legacy == nil {
			t.Fatalf("relative-name comparison failed: %v", legacyErr)
		}
		t.Logf("relative subtree status: %d; qualified enumeration succeeded", legacy.Return)
		for _, name := range []string{"branch", "leaf.branch", "leaf.suffix.invalid"} {
			count := 0
			for _, row := range r {
				if row.Name == name {
					count++
				}
			}
			if count != 1 {
				t.Errorf("zone enumeration returned %d copies of %s; want one", count, name)
			}
		}
	})
	t.Run("kerberos selected cache", func(t *testing.T) {
		kc := cfg
		kc.Auth = "kerberos"
		kc.Server = "dc.lab.invalid"
		kc.User = "this-must-not-select-the-identity"
		kc.Password = NewPassword("")
		kc.Cache = "FILE:/tmp/native-ad/reader.ccache"
		blob, _, e := auth.CacheSnapshot(kc.Cache)
		if e != nil {
			t.Fatal(e)
		}
		kc.CacheContents = blob
		kc.Cache = "FILE:/tmp/native-ad/snapshot-source-no-longer-present"
		kc.KerberosConfig = "/tmp/native-ad/krb5.conf"
		k, e := Dial(ctx, kc)
		if e != nil {
			t.Fatal(e)
		}
		defer k.Close()
		_, e = k.Records(ctx, "lab.invalid", "@", dns.TypeANY)
		if e != nil {
			t.Fatal(e)
		}
		if e = k.Mutate(ctx, "lab.invalid", "wrong-identity", nil, a); e == nil {
			t.Fatal("Reader cache used Administrator identity")
		}
		t.Log(e)
		kc.Cache = "FILE:/tmp/native-ad/missing"
		kc.CacheContents = auth.Secret{}
		if _, e = Dial(ctx, kc); e == nil {
			t.Fatal("missing cache did not fail")
		}
	})
}
