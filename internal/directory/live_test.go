package directory

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/lauritsk/sambatui/internal/auth"
)

type lostReplySession struct {
	Session
	attempts *int
}

func (s *lostReplySession) Add(r *ldap.AddRequest) error {
	*s.attempts++
	if e := s.Session.Add(r); e != nil {
		return e
	}
	return io.ErrUnexpectedEOF
}

func TestDisposableSamba(t *testing.T) {
	if os.Getenv("SAMBATUI_DISPOSABLE_TEST") != "YES" {
		t.Skip("opt-in isolated lab only")
	}
	marker, e := os.ReadFile("/tmp/native-ad/disposable.marker")
	if e != nil || string(marker) != "sambatui isolated disposable lab\n" {
		t.Fatal("not the authorized disposable fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cfg := Config{Server: "dc.lab.invalid", BaseDN: "DC=lab,DC=invalid", User: "Administrator@lab.invalid", Password: auth.NewSecret("Disposable-test-only_42!"), Encryption: "ldaps", CAFile: "/tmp/native-ad/cert.pem", Timeout: 5 * time.Second, PageSize: 1}
	for _, mode := range []string{"ldaps", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			c := cfg
			c.Encryption = mode
			if e := New(c).Check(ctx); e != nil {
				t.Fatal(e)
			}
		})
	}
	t.Run("untrusted certificate", func(t *testing.T) {
		c := cfg
		c.CAFile = ""
		if e := New(c).Check(ctx); e == nil {
			t.Fatal("untrusted certificate accepted")
		}
	})
	t.Run("hostname verification", func(t *testing.T) {
		c := cfg
		c.Server = "localhost"
		if e := New(c).Check(ctx); e == nil {
			t.Fatal("wrong hostname accepted")
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		c := cfg
		c.Password = auth.NewSecret("wrong")
		if e := New(c).Check(ctx); e == nil {
			t.Fatal("wrong password accepted")
		}
	})
	t.Run("password whitespace preserved", func(t *testing.T) {
		c := cfg
		c.User = "Whitespace@lab.invalid"
		c.Password = auth.NewSecret("  Disposable-test-only_42!  ")
		if e := New(c).Check(ctx); e != nil {
			t.Fatal(e)
		}
		c.Password = auth.NewSecret("Disposable-test-only_42!")
		if e := New(c).Check(ctx); e == nil {
			t.Fatal("trimmed password accepted")
		}
	})
	t.Run("NTLM with channel binding", func(t *testing.T) {
		c := cfg
		c.User = `LAB\Administrator`
		if e := New(c).Check(ctx); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("Kerberos selected Reader identity", func(t *testing.T) {
		c := cfg
		c.Auth = "kerberos"
		c.Cache = "FILE:/tmp/native-ad/reader.ccache"
		blob, _, e := auth.CacheSnapshot(c.Cache)
		if e != nil {
			t.Fatal(e)
		}
		c.CacheContents = blob
		c.Cache = "FILE:/tmp/native-ad/snapshot-source-no-longer-present"
		c.KerberosConfig = "/tmp/native-ad/krb5.conf"
		c.User = "Administrator@lab.invalid"
		c.Password = auth.NewSecret("")
		if e := New(c).Check(ctx); e != nil {
			t.Fatal(e)
		}
		_, e = New(c).Add(ctx, "group", cfg.BaseDN, "NoPermission", nil)
		if e == nil {
			t.Fatal("Reader cache used administrator identity")
		}
		t.Log(e)
		c.Cache = "FILE:/tmp/native-ad/missing"
		c.CacheContents = auth.Secret{}
		if e = New(c).Check(ctx); e == nil {
			t.Fatal("missing selected cache accepted")
		}
	})
	cl := New(cfg)
	t.Run("all entry add kinds", func(t *testing.T) {
		for _, item := range []struct{ kind, search, name string }{{"user", "users", "NativeUser"}, {"group", "groups", "NativeGroup"}, {"computer", "computers", "NativeComputer"}, {"ou", "ous", "NativeOU"}} {
			t.Run(item.kind, func(t *testing.T) {
				dn, e := cl.Add(ctx, item.kind, cfg.BaseDN, item.name, map[string]string{"description": "native add proof"})
				if e != nil {
					t.Fatal(e)
				}
				rows, e := cl.Search(ctx, "", item.search, item.name, 10)
				if e != nil || len(rows) != 1 || !EqualDN(rows[0].DN, dn) {
					t.Fatalf("add/read: %v %v", rows, e)
				}
			})
		}
	})
	t.Run("lost committed add reply", func(t *testing.T) {
		attempts := 0
		c := NewWithFactory(cfg, func(ctx context.Context, cfg Config) (Session, error) {
			s, e := Dial(ctx, cfg)
			if e != nil {
				return nil, e
			}
			return &lostReplySession{s, &attempts}, nil
		})
		_, e := c.Add(ctx, "group", cfg.BaseDN, "NativeLostReply", nil)
		var unknown *UncertainError
		if !errors.As(e, &unknown) || attempts != 1 {
			t.Fatalf("lost reply was not uncertain/one-shot: %v attempts=%d", e, attempts)
		}
		rows, e := cl.Search(ctx, "", "groups", "NativeLostReply", 10)
		if e != nil || len(rows) != 1 {
			t.Fatal("committed add not visible after lost reply", e)
		}
	})
	rows, e := cl.Search(ctx, "", "users", "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) < 3 {
		t.Fatalf("paging: got %d users", len(rows))
	}
	t.Log("paged users", len(rows))
	name := "NativeProof" + time.Now().Format("150405.000000")
	dn, e := cl.Add(ctx, "group", cfg.BaseDN, name, map[string]string{"description": "before"})
	if e != nil {
		t.Fatal(e)
	}
	groups, e := cl.Search(ctx, "", "groups", name, 10)
	if e != nil || len(groups) != 1 {
		t.Fatalf("read added group: %v %v", groups, e)
	}
	if e = cl.Modify(ctx, dn, "group", groups[0].Revision, map[string]string{"description": "after"}); e == nil {
		t.Fatal("Samba unexpectedly supports assertion; update test expectation after verification")
	} else {
		t.Log("conditional modify:", e)
	}
	if e = cl.Delete(ctx, dn, groups[0].Revision); e == nil {
		t.Fatal("Samba unexpectedly supports assertion delete")
	} else {
		t.Log("conditional delete:", e)
	}
	if e = cl.Disable(ctx, dn, groups[0].Revision, 512); e == nil {
		t.Fatal("unsupported conditional disable succeeded")
	}
	groups, e = cl.Search(ctx, "", "groups", name, 10)
	if e != nil || len(groups) != 1 || groups[0].First("description") != "before" {
		t.Fatalf("refused writes changed entry: %v %v", groups, e)
	}
}
