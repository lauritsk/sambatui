package directory

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestSearchRejectsInvalidLimitsBeforeConnecting(t *testing.T) {
	client := NewWithFactory(Config{BaseDN: "DC=lab,DC=invalid"}, func(context.Context, Config) (Session, error) {
		t.Fatal("invalid limit connected")
		return nil, nil
	})
	for _, limit := range []int{-1, searchRowsMax + 1} {
		if _, err := client.Search(context.Background(), "", "users", "", limit); err == nil {
			t.Fatalf("accepted limit %d", limit)
		}
	}
}

func TestCompleteSearchIsBoundedWithoutReturningPartialRows(t *testing.T) {
	for _, count := range []int{searchRowsMax, searchRowsMax + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			entries := make([]*ldap.Entry, count)
			for index := range entries {
				entries[index] = ldap.NewEntry("CN=x,DC=lab,DC=invalid", nil)
			}
			session := &fakeSession{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: entries}, nil
			}}
			rows, err := fakeClient(session).Search(context.Background(), "", "users", "", 0)
			if count == searchRowsMax {
				if err != nil || len(rows) != count {
					t.Fatalf("%d rows, %v", len(rows), err)
				}
			} else if err == nil || rows != nil {
				t.Fatalf("oversize returned %d rows, %v", len(rows), err)
			}
		})
	}
}

func TestEmptyPagingCannotRunForever(t *testing.T) {
	calls := 0
	session := &fakeSession{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		calls++
		control := ldap.NewControlPaging(1)
		control.SetCookie([]byte("same-handle"))
		return &ldap.SearchResult{Controls: []ldap.Control{control}}, nil
	}}
	rows, err := fakeClient(session).Search(context.Background(), "", "users", "", 0)
	if err == nil || rows != nil || calls != searchPagesMax {
		t.Fatalf("rows %d, calls %d, error %v", len(rows), calls, err)
	}
}

func TestMalformedSearchResultsFailClosed(t *testing.T) {
	for _, result := range []*ldap.SearchResult{nil, {Entries: []*ldap.Entry{nil}}} {
		session := &fakeSession{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return result, nil
		}}
		if rows, err := fakeClient(session).Search(context.Background(), "", "users", "", 1); err == nil || rows != nil {
			t.Fatalf("malformed search: %v, %v", rows, err)
		}
	}
}

func TestRangedAttributeBoundariesAndAmbiguity(t *testing.T) {
	// Oversized initial pages must fail before copying, and failures must not
	// publish partially normalized attributes to the caller.
	for _, attributes := range [][]*ldap.EntryAttribute{
		{ldap.NewEntryAttribute("member;range=0-*", []string{strings.Repeat("x", rangeBytesMax+1)})},
		{ldap.NewEntryAttribute("member", []string{"plain"}), ldap.NewEntryAttribute("member;range=0-*", []string{"ranged"})},
		{nil},
	} {
		entry := &ldap.Entry{DN: "CN=x,DC=lab,DC=invalid", Attributes: attributes}
		if err := expandRanges(context.Background(), nil, entry); err == nil {
			t.Fatal("invalid ranged entry accepted")
		}
		if entry.Attributes[0] != attributes[0] {
			t.Fatal("failure published a partial entry")
		}
	}
}
