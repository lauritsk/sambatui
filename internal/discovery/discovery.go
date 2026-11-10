package discovery

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/lauritsk/sambatui/internal/dnsdata"
)

type Service struct {
	Kind, Target           string
	Port, Priority, Weight uint16
}
type Resolver interface {
	LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error)
}

func NormalizeDomain(domain string) (string, error) {
	domain = strings.TrimRight(strings.TrimSpace(domain), ".")
	if !dnsdata.ValidName(domain, false) {
		return "", errors.New("invalid AD DNS domain")
	}
	return domain, nil
}

func Preferred(services []Service) (Service, bool) {
	for _, s := range services {
		if s.Kind == "ldap" {
			return s, true
		}
	}
	if len(services) > 0 {
		return services[0], true
	}
	return Service{}, false
}

func Discover(ctx context.Context, domain string, resolver Resolver) ([]Service, error) {
	var err error
	domain, err = NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	services := []Service{}
	for _, q := range []struct{ kind, name string }{{"ldap", "_ldap._tcp.dc._msdcs." + domain}, {"kerberos", "_kerberos._tcp." + domain}} {
		_, rows, e := resolver.LookupSRV(ctx, "", "", q.name)
		if e != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		for _, r := range rows {
			target := strings.TrimSuffix(r.Target, ".")
			if target != "" && dnsdata.ValidName(target, false) && r.Port > 0 {
				services = append(services, Service{q.kind, target, r.Port, r.Priority, r.Weight})
			}
		}
	}
	sort.Slice(services, func(i, j int) bool {
		a, b := services[i], services[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Kind != b.Kind {
			return a.Kind == "ldap"
		}
		if a.Weight != b.Weight {
			return a.Weight > b.Weight
		}
		return a.Target < b.Target
	})
	if len(services) == 0 {
		return nil, errors.New("no AD SRV records found; check AD DNS domain or enter individual DC hostname")
	}
	return services, nil
}
