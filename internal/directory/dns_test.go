package directory

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/miekg/dns"
)

const testDNSZoneDN = "DC=lab.invalid,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=invalid"

func dnsTestBlob() string {
	data := make([]byte, 28)
	binary.LittleEndian.PutUint16(data[:2], 4)
	binary.LittleEndian.PutUint16(data[2:4], dns.TypeA)
	data[4], data[5] = 5, 0xf0
	binary.BigEndian.PutUint32(data[12:16], 600)
	copy(data[24:], []byte{192, 0, 2, 1})
	return string(data)
}

func dnsTestSession(t *testing.T, nodes []*ldap.Entry) *fakeSession {
	t.Helper()
	return &fakeSession{search: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.DerefAliases != ldap.NeverDerefAliases {
			t.Fatal("DNS lookup followed an alias")
		}
		switch {
		case request.BaseDN == "":
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{
				"namingContexts":       {"DC=lab,DC=invalid", "DC=DomainDnsZones,DC=lab,DC=invalid"},
				"defaultNamingContext": {"DC=lab,DC=invalid"},
			})}}, nil
		case request.BaseDN == testDNSZoneDN && request.Scope == ldap.ScopeBaseObject:
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry(testDNSZoneDN, map[string][]string{"objectClass": {"dnsZone"}}),
			}}, nil
		case request.BaseDN == testDNSZoneDN && request.Scope == ldap.ScopeSingleLevel:
			if !strings.Contains(request.Filter, "(!(dNSTombstoned=TRUE))") {
				t.Fatal("DNS lookup included tombstoned nodes")
			}
			return &ldap.SearchResult{Entries: nodes}, nil
		default:
			return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such zone"))
		}
	}}
}

func TestDirectoryDNSReadIsScopedToTheDiscoveredZone(t *testing.T) {
	session := dnsTestSession(t, []*ldap.Entry{
		ldap.NewEntry("DC=host,"+testDNSZoneDN, map[string][]string{
			"name": {"host"}, "dnsRecord": {dnsTestBlob()},
		}),
	})
	rows, err := fakeClient(session).DNSRecords(context.Background(), "lab.invalid", "@", dns.TypeANY)
	if err != nil || len(rows) != 1 || rows[0].Name != "host" || rows[0].Value != "192.0.2.1" {
		t.Fatalf("zone read: rows=%v error=%v", rows, err)
	}
	if session.closed != 1 {
		t.Fatal("directory DNS session retained after enumeration")
	}
}

func TestDirectoryDNSRejectsWrongScopesAndMalformedNodes(t *testing.T) {
	for _, entry := range []*ldap.Entry{
		ldap.NewEntry("DC=host,DC=other,DC=invalid", map[string][]string{
			"name": {"host"}, "dnsRecord": {dnsTestBlob()},
		}),
		ldap.NewEntry("DC=host,"+testDNSZoneDN, map[string][]string{
			"name": {"host"}, "dnsRecord": {"broken"},
		}),
		ldap.NewEntry("DC=host,"+testDNSZoneDN, map[string][]string{
			"name": {"host"}, "dnsRecord": {dnsTestBlob()}, "dNSTombstoned": {"TRUE"},
		}),
	} {
		session := dnsTestSession(t, []*ldap.Entry{entry})
		rows, err := fakeClient(session).DNSRecords(context.Background(), "lab.invalid", "@", dns.TypeANY)
		if err == nil || rows != nil {
			t.Fatalf("invalid directory node accepted: rows=%v error=%v", rows, err)
		}
	}
}

func TestDirectoryDNSDoesNotFollowReferralsOrContinueAfterAccessDenial(t *testing.T) {
	for _, denied := range []bool{false, true} {
		calls := 0
		session := &fakeSession{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			if denied {
				return nil, ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
			}
			return &ldap.SearchResult{Referrals: []string{"ldaps://other.invalid"}}, nil
		}}
		rows, err := fakeClient(session).DNSRecords(context.Background(), "lab.invalid", "@", dns.TypeANY)
		if err == nil || rows != nil || calls != 1 {
			t.Fatalf("directory failure retried or accepted: calls=%d rows=%v error=%v", calls, rows, err)
		}
	}
}

func TestDirectoryDNSNodeBudgetIncludesBothSidesOfTheLimit(t *testing.T) {
	for _, count := range []int{dnsNodesMax, dnsNodesMax + 1} {
		nodes := make([]*ldap.Entry, count)
		for index := range nodes {
			nodes[index] = ldap.NewEntry("DC=host,"+testDNSZoneDN,
				map[string][]string{"name": {"host"}})
		}
		rows, err := fakeClient(dnsTestSession(t, nodes)).DNSRecords(
			context.Background(), "lab.invalid", "@", dns.TypeANY)
		if count == dnsNodesMax && (err != nil || len(rows) != 0) {
			t.Fatalf("node budget rejected its boundary: %v", err)
		}
		if count > dnsNodesMax && (err == nil || rows != nil) {
			t.Fatal("oversized zone was accepted or returned partial rows")
		}
	}
}

func TestDirectoryDNSSubtreeFilteringAndAbsoluteOwners(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"@", "@"},
		{"host", "host"},
		{"host.lab.invalid.", "host"},
		{"shadow.lab.invalid.lab.invalid.", "shadow.lab.invalid"},
	} {
		actual, err := dnsRelativeNode("lab.invalid", test.input)
		if err != nil || actual != test.want {
			t.Fatal("incorrect DNS subtree", test, actual, err)
		}
	}
	if _, err := dnsRelativeNode("lab.invalid", "host.other.invalid."); err == nil {
		t.Fatal("foreign absolute owner accepted")
	}
	session := dnsTestSession(t, []*ldap.Entry{ldap.NewEntry("DC=unrelated,"+testDNSZoneDN,
		map[string][]string{"name": {"unrelated"}, "dnsRecord": {dnsTestBlob()}})})
	if rows, err := fakeClient(session).DNSRecords(context.Background(), "lab.invalid", "branch", dns.TypeA); err == nil || rows != nil {
		t.Fatal("server returned a record outside the requested subtree", err)
	}
}
