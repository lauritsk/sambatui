package directory

import (
	"context"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestRangedMembershipIsCompletedOnPinnedSession(t *testing.T) {
	calls := 0
	dn := "CN=Alice,DC=lab,DC=invalid"
	f := &fakeSession{search: func(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
		calls++
		if calls == 1 {
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(dn, map[string][]string{"name": {"Alice"}, "objectClass": {"user"}, "uSNChanged": {"42"}, "memberOf;range=0-1": {"CN=One", "CN=Two"}})}}, nil
		}
		if r.BaseDN != dn || r.Scope != ldap.ScopeBaseObject || len(r.Attributes) != 1 || r.Attributes[0] != "memberof;range=2-*" {
			t.Fatal("range escaped pinned DN/session", r)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(dn, map[string][]string{"memberOf;range=2-*": {"CN=Three"}})}}, nil
	}}
	rows, e := fakeClient(f).Search(context.Background(), "", "users", "", 10)
	if e != nil || len(rows) != 1 || len(rows[0].Attributes["memberof"]) != 3 || calls != 2 || f.closed != 1 {
		t.Fatalf("range read lost values: %+v %v calls=%d", rows, e, calls)
	}
	if rows[0].Revision != "42" {
		t.Fatal("range read replaced selected revision")
	}
}

func TestMalformedOrMissingRangeNeverLooksLikeEmptyMembership(t *testing.T) {
	for _, spec := range []string{"1-*", "0-5", "0-bad", "0-0"} {
		calls := 0
		dn := "CN=x,DC=lab,DC=invalid"
		f := &fakeSession{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			if calls == 1 {
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(dn, map[string][]string{"memberOf;range=" + spec: {"CN=Group"}})}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(dn, map[string][]string{})}}, nil
		}}
		rows, e := fakeClient(f).Search(context.Background(), "", "users", "", 10)
		if e == nil || len(rows) != 0 || !strings.Contains(e.Error(), "range") {
			t.Fatalf("partial membership silently accepted: %+v %v", rows, e)
		}
	}
}
