package discovery

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/lauritsk/sambatui/internal/dnsdata"
)

const servicesMax = 4096

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
	for _, service := range services {
		if service.Kind == "ldap" {
			return service, true
		}
	}
	if len(services) > 0 {
		return services[0], true
	}
	return Service{}, false
}

func Discover(
	operationContext context.Context,
	domain string,
	resolver Resolver,
) ([]Service, error) {
	if err := operationContext.Err(); err != nil {
		return nil, err
	}
	var err error
	domain, err = NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	services := make([]Service, 0, 16)
	var lookupErrors error
	for _, query := range []struct{ kind, name string }{
		{"ldap", "_ldap._tcp.dc._msdcs." + domain},
		{"kerberos", "_kerberos._tcp." + domain},
	} {
		_, rows, currentErr := resolver.LookupSRV(operationContext, "", "", query.name)
		if currentErr != nil {
			if operationContext.Err() != nil {
				return nil, operationContext.Err()
			}
			lookupErrors = errors.Join(lookupErrors, currentErr)
			continue
		}
		if len(rows) > servicesMax-len(services) {
			return nil, errors.New("AD discovery exceeds service safety limit")
		}
		for _, record := range rows {
			if record == nil {
				return nil, errors.New("AD discovery returned a missing service")
			}
			target := strings.TrimSuffix(record.Target, ".")
			if target != "" && dnsdata.ValidName(target, false) && record.Port > 0 {
				services = append(services, Service{
					query.kind, target, record.Port, record.Priority, record.Weight,
				})
			}
		}
	}
	if err := operationContext.Err(); err != nil {
		return nil, err
	}
	sortServices(services)
	if len(services) == 0 {
		return nil, errors.Join(
			errors.New("no AD SRV records found; check domain or enter a DC"),
			lookupErrors,
		)
	}
	return services, nil
}

func sortServices(services []Service) {
	sort.Slice(services, func(index, rightIndex int) bool {
		leftService, rightService := services[index], services[rightIndex]
		if leftService.Priority != rightService.Priority {
			return leftService.Priority < rightService.Priority
		}
		if leftService.Kind != rightService.Kind {
			return leftService.Kind == "ldap"
		}
		if leftService.Weight != rightService.Weight {
			return leftService.Weight > rightService.Weight
		}
		if leftService.Target != rightService.Target {
			return leftService.Target < rightService.Target
		}
		return leftService.Port < rightService.Port
	})
}
