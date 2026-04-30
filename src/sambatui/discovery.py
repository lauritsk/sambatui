from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol

import dns.exception
import dns.resolver

from .dns import valid_dns_name


class SrvResolver(Protocol):
    def resolve(self, qname: str, rdtype: str) -> Iterable[Any]: ...


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
    service: str, domain: str, answer: Iterable[Any]
) -> list[DiscoveredService]:
    services: list[DiscoveredService] = []
    for record in answer:
        target = str(record.target).rstrip(".")
        if not target or target == ".":
            continue
        services.append(
            DiscoveredService(
                service=service,
                domain=domain,
                target=target,
                port=int(record.port),
                priority=int(record.priority),
                weight=int(record.weight),
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
    for service in sort_discovered_services(services):
        if service.service == "ldap":
            return service
    return next(iter(sort_discovered_services(services)), None)
