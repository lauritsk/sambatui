from collections.abc import Iterable

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from sambatui.discovery import (
    ad_srv_query_names,
    discover_ad_services,
    normalize_domain,
    preferred_domain_controller,
)


class FakeResolver:
    def __init__(self, answers: dict[str, list[object]]) -> None:
        self.answers = answers

    def resolve(self, qname: str, rdtype: str) -> Iterable[object]:
        assert rdtype == "SRV"
        try:
            return self.answers[qname]
        except KeyError as exc:
            raise dns.resolver.NXDOMAIN from exc


def srv(text: str) -> object:
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SRV, text)


def test_ad_srv_query_names_targets_ldap_and_kerberos() -> None:
    assert ad_srv_query_names("example.com.") == [
        ("ldap", "_ldap._tcp.dc._msdcs.example.com"),
        ("kerberos", "_kerberos._tcp.example.com"),
    ]


def test_normalize_domain_rejects_bad_names() -> None:
    with pytest.raises(ValueError, match="Bad AD domain"):
        normalize_domain("bad space.example.com")


def test_discover_ad_services_sorts_ldap_records_first_by_priority() -> None:
    resolver = FakeResolver(
        {
            "_ldap._tcp.dc._msdcs.example.com": [
                srv("1 100 389 dc02.example.com."),
                srv("0 50 389 dc01.example.com."),
            ],
            "_kerberos._tcp.example.com": [srv("0 100 88 dc01.example.com.")],
        }
    )

    services = discover_ad_services("example.com", resolver)

    assert [
        (service.service, service.target, service.port) for service in services
    ] == [
        ("ldap", "dc01.example.com", 389),
        ("kerberos", "dc01.example.com", 88),
        ("ldap", "dc02.example.com", 389),
    ]
    assert preferred_domain_controller(services) == services[0]


def test_discover_ad_services_ignores_missing_srv_records() -> None:
    assert discover_ad_services("example.com", FakeResolver({})) == []
