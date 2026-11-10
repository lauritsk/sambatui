package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/backend"
	"github.com/lauritsk/sambatui/internal/config"
	"github.com/lauritsk/sambatui/internal/dnsrpc"
	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
)

func TestDisposableShadowedDNSZone(t *testing.T) {
	if os.Getenv("SAMBATUI_DISPOSABLE_TEST") != "YES" {
		t.Skip("opt-in isolated Samba fixture only")
	}
	marker, err := os.ReadFile("/tmp/native-ad/disposable.marker")
	if err != nil || string(marker) != "sambatui isolated disposable lab\n" {
		t.Fatal("not the authorized disposable fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	settings := config.Defaults()
	settings.Server, settings.Domain = "dc.lab.invalid", "lab.invalid"
	settings.User, settings.BaseDN = "Administrator@lab.invalid", "DC=lab,DC=invalid"
	settings.Password = auth.NewSecret("Disposable-test-only_42!")
	settings.CAFile = "/tmp/native-ad/cert.pem"
	client, err := dnsrpc.Dial(ctx, settings.DNS())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, item := range []struct{ name, kind, value string }{
		{"leaf.1", "A", "192.0.2.1"},
		{"shadow.lab.invalid.lab.invalid.", "A", "192.0.2.2"},
		{"directory-text", "TXT", `"one" "two\\000three"`},
		{"directory-v6", "AAAA", "2001:db8::1"},
		{"directory-alias", "CNAME", "dc.lab.invalid."},
		{"directory-mail", "MX", "10 dc.lab.invalid."},
		{"directory-pointer", "PTR", "dc.lab.invalid."},
	} {
		resource, err := record.NewRecordFromString(dns.StringToType[item.kind], 1234, item.value)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Mutate(ctx, "lab.invalid", item.name, nil, resource); err != nil {
			t.Fatal(err)
		}
		defer func(name string, resource *record.Record) {
			if err := client.Mutate(ctx, "lab.invalid", name, resource, nil); err != nil {
				t.Error("shadow fixture cleanup:", err)
			}
		}(item.name, resource)
	}
	rows, err := (backend.Native{}).Records(ctx, settings, "lab.invalid", "@", dns.TypeANY)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]dnsrpc.Row{}
	for _, row := range rows {
		found[row.Name+"/"+row.Type] = row
	}
	for _, key := range []string{
		"leaf.1/A", "shadow.lab.invalid.lab.invalid./A", "@/SOA", "@/NS",
		"_ldap._tcp/SRV", "directory-text/TXT", "directory-v6/AAAA", "directory-alias/CNAME",
		"directory-mail/MX", "directory-pointer/PTR",
	} {
		if _, exists := found[key]; !exists {
			t.Fatalf("complete zone omitted %s", key)
		}
	}
	if row := found["shadow.lab.invalid.lab.invalid./A"]; row.Value != "192.0.2.2" || row.TTL != 1234 {
		t.Fatal("shadowed owner lost its identity, value or TTL", row)
	}
	settings.CAFile = ""
	if rows, err := (backend.Native{}).Records(ctx, settings, "lab.invalid", "@", dns.TypeANY); err == nil || rows != nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatal("directory fallback bypassed certificate verification", err)
	}
}
