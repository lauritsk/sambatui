package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/discovery"
	"github.com/lauritsk/sambatui/internal/invariant"
)

const discoveryTimeout = 10 * time.Second

type discovered struct {
	generation, requestID uint64
	domain                string
	services              []discovery.Service
	err                   error
}

// Discovery is an explicit user action, never silent failover for an active write.
func (model *Model) startDiscovery(domain string, resolver discovery.Resolver) tea.Cmd {
	normalized, err := discovery.NormalizeDomain(domain)
	invariant.Require(err == nil, "discovery requires a valid domain")
	invariant.Require(domain == normalized, "discovery requires a normalized domain")
	operationContext, cancel := model.startRead(discoveryTimeout)
	generation, requestID := model.state.Snapshot().Generation, model.readID
	return func() tea.Msg {
		defer cancel()
		services, err := discovery.Discover(operationContext, domain, resolver)
		return discovered{
			generation: generation, requestID: requestID,
			domain: domain, services: services, err: err,
		}
	}
}

func (model *Model) updateDiscovered(result discovered) tea.Cmd {
	if !model.readCurrent(result.generation, result.requestID) {
		return nil
	}
	// A read must not replace a newer user interaction or orphan a write reservation.
	if model.form != nil || model.flow != nil || model.detail != "" {
		return nil
	}
	if result.err != nil {
		model.error(result.err)
		return nil
	}
	preferred, ok := discovery.Preferred(result.services)
	if !ok {
		model.status = "No AD service endpoints discovered"
		return nil
	}
	model.openForm(
		"Select discovered DC",
		discoveryPreview(result.services),
		[]field{{"DC hostname", preferred.Target, false}},
		false,
		func(values []string) tea.Cmd {
			if !model.readCurrent(result.generation, result.requestID) || model.flow != nil {
				model.status = "Stale discovery ignored; discover services again."
				return nil
			}
			settings := model.settings
			settings.Server = values[0]
			settings.Domain = result.domain
			settings.BaseDN = "DC=" + strings.ReplaceAll(result.domain, ".", ",DC=")
			model.setConnection(settings)
			model.connectionForm()
			return nil
		},
	)
	return nil
}

func discoveryPreview(services []discovery.Service) string {
	var text strings.Builder
	text.WriteString("Discovered services (review before selecting):\n")
	for _, service := range services {
		fmt.Fprintf(&text, "%s %s:%d priority=%d weight=%d\n",
			service.Kind, Literal(service.Target), service.Port, service.Priority, service.Weight,
		)
	}
	return text.String()
}
