package discovery

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
)

type resolverFunc func(context.Context, string, string, string) (string, []*net.SRV, error)

func (f resolverFunc) LookupSRV(c context.Context, s, p, n string) (string, []*net.SRV, error) {
	return f(c, s, p, n)
}

func TestADQueriesAndDeterministicDCChoice(t *testing.T) {
	queries := []string{}
	r := resolverFunc(func(_ context.Context, s, p, name string) (string, []*net.SRV, error) {
		queries = append(queries, name)
		if s != "" || p != "" {
			t.Fatal("lookup name rewritten")
		}
		if name == "_ldap._tcp.dc._msdcs.lab.invalid" {
			return "", []*net.SRV{{Target: "b.lab.invalid.", Port: 389, Priority: 1, Weight: 10}, {Target: "a.lab.invalid.", Port: 389, Priority: 1, Weight: 20}, {Target: ".", Port: 389}}, nil
		}
		return "", []*net.SRV{{Target: "kdc.lab.invalid.", Port: 88, Priority: 1}}, nil
	})
	services, e := Discover(context.Background(), " lab.invalid. ", r)
	if e != nil {
		t.Fatal(e)
	}
	if services[0].Target != "a.lab.invalid" || !reflect.DeepEqual(queries, []string{"_ldap._tcp.dc._msdcs.lab.invalid", "_kerberos._tcp.lab.invalid"}) {
		t.Fatal(services, queries)
	}
}

func TestPreferredControllerSelectsLDAPBeforeLowerPriorityKDC(t *testing.T) {
	services := []Service{{Kind: "kerberos", Target: "kdc-only.lab.invalid", Priority: 0}, {Kind: "ldap", Target: "dc.lab.invalid", Priority: 1}}
	preferred, ok := Preferred(services)
	if !ok || preferred.Target != "dc.lab.invalid" {
		t.Fatal("non-DC Kerberos endpoint selected", preferred)
	}
	if _, ok = Preferred(nil); ok {
		t.Fatal("empty discovery succeeded")
	}
}

func TestDiscoveryFailuresAndCancellation(t *testing.T) {
	r := resolverFunc(func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, errors.New("no records")
	})
	if _, e := Discover(context.Background(), "lab.invalid", r); e == nil {
		t.Fatal("missing services succeeded")
	}
	if _, e := Discover(context.Background(), "bad domain", r); e == nil {
		t.Fatal("invalid domain accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Discover(ctx, "lab.invalid", r); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
