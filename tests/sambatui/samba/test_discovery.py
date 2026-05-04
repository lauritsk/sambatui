from collections.abc import Iterable

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest
from hypothesis import given
from hypothesis import strategies as st

from sambatui.samba.discovery import (
    DiscoveredService,
    ad_srv_query_names,
    discover_ad_services,
    normalize_domain,
    preferred_domain_controller,
    sort_discovered_services,
)

DNS_LABEL = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"))
    | st.sampled_from("-"),
    min_size=1,
    max_size=20,
).filter(lambda value: value[0].isalnum() and value[-1].isalnum() and value.isascii())
DNS_NAME = st.lists(DNS_LABEL, min_size=2, max_size=5).map(".".join)
SERVICES = st.builds(
    DiscoveredService,
    service=st.sampled_from(["ldap", "kerberos"]),
    domain=DNS_NAME,
    target=DNS_NAME,
    port=st.integers(min_value=1, max_value=65535),
    priority=st.integers(min_value=0, max_value=10),
    weight=st.integers(min_value=0, max_value=100),
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


@given(DNS_NAME)
def test_ad_srv_query_names_targets_ldap_and_kerberos(domain: str) -> None:
    normalized = normalize_domain(f" {domain}. ")

    assert ad_srv_query_names(f" {domain}. ") == [
        ("ldap", f"_ldap._tcp.dc._msdcs.{normalized}"),
        ("kerberos", f"_kerberos._tcp.{normalized}"),
    ]


BAD_DOMAIN = st.one_of(
    st.just("bad space.example.com"),
    st.text(alphabet=" .", max_size=8).filter(lambda value: not value.strip(".")),
)


@given(BAD_DOMAIN)
def test_normalize_domain_rejects_bad_names(domain: str) -> None:
    with pytest.raises(ValueError, match="Bad AD domain"):
        normalize_domain(domain)


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


@given(st.lists(SERVICES, max_size=12))
def test_sort_discovered_services_matches_preferred_controller(
    services: list[DiscoveredService],
) -> None:
    sorted_services = sort_discovered_services(services)
    preferred = preferred_domain_controller(services)

    assert sorted_services == sorted(
        services,
        key=lambda service: (
            service.priority,
            0 if service.service == "ldap" else 1,
            -service.weight,
            service.target.casefold(),
            service.port,
        ),
    )
    if any(service.service == "ldap" for service in services):
        assert preferred is not None
        assert preferred.service == "ldap"
    else:
        assert preferred == (sorted_services[0] if sorted_services else None)
