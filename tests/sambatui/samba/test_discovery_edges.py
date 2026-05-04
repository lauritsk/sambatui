from __future__ import annotations

from dataclasses import dataclass

from sambatui.samba.discovery import (
    DiscoveredService,
    _services_from_answer,
    preferred_domain_controller,
)


@dataclass(frozen=True)
class FakeSrvRecord:
    target: str
    port: int = 389
    priority: int = 0
    weight: int = 0


class BadSrvRecord:
    target = "bad.example.com"
    port = object()
    priority = 0
    weight = 0


def test_discovery_empty_target_bad_port_and_non_ldap_preference() -> None:
    services = _services_from_answer(
        "ldap",
        "example.com",
        [FakeSrvRecord("."), BadSrvRecord(), FakeSrvRecord("dc.example.com.")],
    )
    assert [service.target for service in services] == ["dc.example.com"]
    preferred = preferred_domain_controller(
        [DiscoveredService("kerberos", "example.com", "kdc.example.com", 88, 0, 0)]
    )
    assert preferred is not None
    assert preferred.target == "kdc.example.com"
    assert preferred_domain_controller([]) is None
