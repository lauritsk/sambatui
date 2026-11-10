package discovery

import (
	"context"
	"net"
	"testing"
)

func TestDiscoveryBoundsUntrustedResults(t *testing.T) {
	for _, rows := range [][]*net.SRV{
		{nil}, make([]*net.SRV, servicesMax+1),
	} {
		resolver := resolverFunc(func(context.Context, string, string, string) (string, []*net.SRV, error) {
			return "", rows, nil
		})
		if services, err := Discover(context.Background(), "lab.invalid", resolver); err == nil || services != nil {
			t.Fatalf("malformed services accepted: %d %v", len(services), err)
		}
	}
}

func TestDiscoveryTieBreakIncludesPort(t *testing.T) {
	services := []Service{
		{Kind: "ldap", Target: "dc.lab.invalid", Port: 636},
		{Kind: "ldap", Target: "dc.lab.invalid", Port: 389},
	}
	sortServices(services)
	if services[0].Port != 389 {
		t.Fatal("equal targets have nondeterministic port order")
	}
}
