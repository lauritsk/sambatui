from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

import dns.exception
import dns.resolver

from sambatui.dns.validation import valid_dns_name


class SrvResolver(Protocol):
    def resolve(self, qname: str, rdtype: str) -> Iterable[object]: ...


@dataclass(frozen=True)
class DiscoveredService:
    service: str
    domain: str
    target: str
    port: int
    priority: int
    weight: int


AD_SRV_QUERIES = (
    ("ldap", "_ldap._tcp.dc._msdcs.{domain}"),
    ("kerberos", "_kerberos._tcp.{domain}"),
)


def normalize_domain(domain: str) -> str:
    normalized = domain.strip().rstrip(".")
    if not valid_dns_name(normalized):
        raise ValueError("Bad AD domain. Use DNS labels like example.com.")
    return normalized


def ad_srv_query_names(domain: str) -> list[tuple[str, str]]:
    normalized = normalize_domain(domain)
    return [
        (service, template.format(domain=normalized))
        for service, template in AD_SRV_QUERIES
    ]


def discover_ad_services(
    domain: str, resolver: SrvResolver | None = None
) -> list[DiscoveredService]:
    normalized = normalize_domain(domain)
    srv_resolver = resolver or dns.resolver.Resolver()
    services: list[DiscoveredService] = []
    for service, qname in ad_srv_query_names(normalized):
        try:
            answer = srv_resolver.resolve(qname, "SRV")
        except dns.exception.DNSException:
            continue
        services.extend(_services_from_answer(service, normalized, answer))
    return sort_discovered_services(services)


def _services_from_answer(
    service: str, domain: str, answer: Iterable[object]
) -> list[DiscoveredService]:
    services: list[DiscoveredService] = []
    for record in answer:
        target = str(getattr(record, "target", "")).rstrip(".")
        if not target or target == ".":
            continue
        try:
            port = int(getattr(record, "port"))
            priority = int(getattr(record, "priority"))
            weight = int(getattr(record, "weight"))
        except TypeError, ValueError:
            continue
        services.append(
            DiscoveredService(
                service=service,
                domain=domain,
                target=target,
                port=port,
                priority=priority,
                weight=weight,
            )
        )
    return services


def sort_discovered_services(
    services: Iterable[DiscoveredService],
) -> list[DiscoveredService]:
    return sorted(
        services,
        key=lambda service: (
            service.priority,
            0 if service.service == "ldap" else 1,
            -service.weight,
            service.target.casefold(),
            service.port,
        ),
    )


def preferred_domain_controller(
    services: Iterable[DiscoveredService],
) -> DiscoveredService | None:
    sorted_services = sort_discovered_services(services)
    for service in sorted_services:
        if service.service == "ldap":
            return service
    return sorted_services[0] if sorted_services else None
