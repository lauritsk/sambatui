package directory

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

type fakeSession struct {
	search func(*ldap.SearchRequest) (*ldap.SearchResult, error)
	modify func(*ldap.ModifyRequest) error
	del    func(*ldap.DelRequest) error
	add    func(*ldap.AddRequest) error
	closed int
}

func (f *fakeSession) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) { return f.search(r) }

func (f *fakeSession) Modify(r *ldap.ModifyRequest) error { return f.modify(r) }
func (f *fakeSession) Del(r *ldap.DelRequest) error       { return f.del(r) }
func (f *fakeSession) Add(r *ldap.AddRequest) error       { return f.add(r) }
func (f *fakeSession) Close() error                       { f.closed++; return nil }

func fakeClient(f *fakeSession) *Client {
	return NewWithFactory(Config{BaseDN: "DC=lab,DC=invalid", PageSize: 1}, func(context.Context, Config) (Session, error) { return f, nil })
}

func advertised(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{"supportedControl": {AssertionOID}})}}, nil
}

func asserted(t *testing.T, controls []ldap.Control, want string) {
	t.Helper()
	if len(controls) != 1 {
		t.Fatalf("controls %v", controls)
	}
	c, ok := controls[0].(*ldap.ControlString)
	if !ok || c.ControlType != AssertionOID || !c.Criticality {
		t.Fatal("assertion not critical")
	}
	p, e := ber.DecodePacketErr([]byte(c.ControlValue))
	if e != nil {
		t.Fatal(e)
	}
	got, e := ldap.DecompileFilter(p)
	if e != nil || got != want {
		t.Fatalf("assertion got %s want %s error %v", got, want, e)
	}
	wire := c.Encode()
	if len(wire.Children) != 3 || wire.Children[1].Value != true {
		t.Fatal("criticality not encoded")
	}
}

func TestConditionalWritesAndPreservedFlags(t *testing.T) {
	writes := 0
	f := &fakeSession{search: advertised}
	c := fakeClient(f)
	f.modify = func(r *ldap.ModifyRequest) error {
		writes++
		if r.DN != "CN=Alice,DC=lab,DC=invalid" {
			t.Fatal("wrong DN")
		}
		if writes == 1 {
			asserted(t, r.Controls, "(&(uSNChanged=42))")
			if r.Changes[0].Operation != ldap.ReplaceAttribute {
				t.Fatal("modify operation")
			}
		} else {
			asserted(t, r.Controls, "(&(uSNChanged=43)(userAccountControl=66048))")
			if !reflect.DeepEqual(r.Changes[0].Modification.Vals, []string{"66050"}) {
				t.Fatal("unrelated UAC flags lost")
			}
		}
		return nil
	}
	if e := c.Modify(context.Background(), "CN=Alice,DC=lab,DC=invalid", "user", "42", map[string]string{"mail": "alice@lab.invalid"}); e != nil {
		t.Fatal(e)
	}
	if e := c.Disable(context.Background(), "CN=Alice,DC=lab,DC=invalid", "43", 66048); e != nil {
		t.Fatal(e)
	}
	f.del = func(r *ldap.DelRequest) error { writes++; asserted(t, r.Controls, "(&(uSNChanged=44))"); return nil }
	if e := c.Delete(context.Background(), "CN=Alice,DC=lab,DC=invalid", "44"); e != nil {
		t.Fatal(e)
	}
	if writes != 3 || f.closed != 3 {
		t.Fatalf("writes %d closes %d", writes, f.closed)
	}
}

func TestUnsupportedAssertionsFailBeforeWrite(t *testing.T) {
	f := &fakeSession{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) { return &ldap.SearchResult{}, nil }, modify: func(*ldap.ModifyRequest) error { t.Fatal("unadvertised assertion write dispatched"); return nil }}
	if e := fakeClient(f).Modify(context.Background(), "CN=x,DC=lab,DC=invalid", "group", "1", map[string]string{"description": "unsafe"}); e == nil || !strings.Contains(e.Error(), "without unsafe fallback") {
		t.Fatal(e)
	}
}

func TestServerRejectsCriticalControlNoRetry(t *testing.T) {
	for _, code := range []uint16{12, 122, 50} {
		calls := 0
		f := &fakeSession{search: advertised, modify: func(r *ldap.ModifyRequest) error {
			calls++
			asserted(t, r.Controls, "(&(uSNChanged=1))")
			return ldap.NewError(code, errors.New("synthetic refusal"))
		}}
		e := fakeClient(f).Modify(context.Background(), "CN=x,DC=lab,DC=invalid", "group", "1", map[string]string{"description": "value"})
		if e == nil || calls != 1 {
			t.Fatalf("%d: %v calls=%d", code, e, calls)
		}
	}
}

func TestPagingUsesOpaqueCookiesAndPinnedSession(t *testing.T) {
	calls := 0
	connects := 0
	f := &fakeSession{search: func(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
		calls++
		if r.BaseDN != "DC=lab,DC=invalid" || r.DerefAliases != ldap.NeverDerefAliases {
			t.Fatal("search redirected")
		}
		domain := r.Controls[1].(*ldap.ControlString)
		if domain.ControlType != ldap.ControlTypeMicrosoftDomainScope || !domain.Criticality {
			t.Fatal("search lost critical naming-context scope")
		}
		pc := r.Controls[0].(*ldap.ControlPaging)
		if calls == 1 && len(pc.Cookie) != 0 {
			t.Fatal("unexpected initial cookie")
		}
		if calls > 1 && string(pc.Cookie) != "same-handle" {
			t.Fatal("cookie not echoed")
		}
		next := ldap.NewControlPaging(1)
		if calls < 3 {
			next.SetCookie([]byte("same-handle"))
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("CN=x,DC=lab,DC=invalid", map[string][]string{"name": {"x"}, "objectClass": {"user"}, "uSNChanged": {"1"}})}, Controls: []ldap.Control{next}}, nil
	}}
	c := NewWithFactory(Config{BaseDN: "DC=lab,DC=invalid", PageSize: 1}, func(context.Context, Config) (Session, error) { connects++; return f, nil })
	rows, e := c.Search(context.Background(), "", "users", `a*)(objectClass=*)`, 0)
	if e != nil || len(rows) != 3 || connects != 1 || calls != 3 || f.closed != 1 {
		t.Fatalf("rows=%d calls=%d connects=%d err=%v", len(rows), calls, connects, e)
	}
	filter, _ := Filter("users", `*)(objectClass=*)`)
	if !strings.Contains(filter, `\2a\29\28objectClass=\2a\29`) {
		t.Fatal("filter injection")
	}
}

func TestScopedTargetsAndRevisionsFailBeforeConnect(t *testing.T) {
	c := NewWithFactory(Config{BaseDN: "DC=lab,DC=invalid"}, func(context.Context, Config) (Session, error) { t.Fatal("invalid request connected"); return nil, nil })
	for _, op := range []func() error{
		func() error { return c.Delete(context.Background(), "DC=lab,DC=invalid", "1") },
		func() error { return c.Delete(context.Background(), "CN=x,DC=other", "1") },
		func() error {
			return c.Modify(context.Background(), "CN=x,DC=lab,DC=invalid", "user", "", map[string]string{"mail": "x"})
		},
		func() error {
			return c.Modify(context.Background(), "CN=x,DC=lab,DC=invalid", "user", "1", map[string]string{"userAccountControl": "0"})
		},
	} {
		if e := op(); e == nil {
			t.Fatal("invalid request succeeded")
		}
	}
	if !InScope(`CN=Lastname\, Firstname, DC=lab, DC=invalid`, `dc=LAB,dc=invalid`) {
		t.Fatal("escaped DN scope")
	}
}

func TestReferralsAreNotFollowedOrReportedAsCleanPartialSearch(t *testing.T) {
	f := &fakeSession{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Referrals: []string{"ldaps://other-dc/DC=other"}}, nil
	}}
	rows, e := fakeClient(f).Search(context.Background(), "", "users", "", 10)
	if e == nil || len(rows) != 0 || !strings.Contains(e.Error(), "referrals") {
		t.Fatal(rows, e)
	}
}

func TestLostAddReplyUncertainAndNotRetried(t *testing.T) {
	calls := 0
	f := &fakeSession{add: func(r *ldap.AddRequest) error { calls++; return io.ErrUnexpectedEOF }}
	_, e := fakeClient(f).Add(context.Background(), "computer", "DC=lab,DC=invalid", "machine", nil)
	var uncertain *UncertainError
	if !errors.As(e, &uncertain) || calls != 1 {
		t.Fatalf("%v calls=%d", e, calls)
	}
}

func TestLDAPHandshakeTimeoutAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "cancel"}[cancelled], func(t *testing.T) {
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				c, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				if cancelled {
					cancel()
				}
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, e = io.Copy(io.Discard, c)
				done <- e
			}()
			start := time.Now()
			_, e = Dial(ctx, Config{Server: listener.Addr().String(), Encryption: "ldaps", Timeout: 100 * time.Millisecond})
			if e == nil || time.Since(start) > time.Second {
				t.Fatalf("unbounded/accepted LDAP blackhole: %v", e)
			}
			if e = <-done; e != nil {
				if ne, ok := e.(net.Error); ok && ne.Timeout() {
					t.Fatal("LDAP connection survived cancellation/timeout")
				}
			}
		})
	}
}

func TestTLSOnlyEndpointValidation(t *testing.T) {
	for _, c := range []Config{{Server: "dc", Encryption: "off"}, {Server: "ldap://dc", Encryption: "ldaps"}, {Server: "ldaps://dc", Encryption: "starttls"}, {Server: "ldaps://user:password@dc", Encryption: "ldaps"}} {
		if _, _, e := Endpoint(c); e == nil {
			t.Fatalf("insecure endpoint accepted %+v", c)
		}
	}
}
