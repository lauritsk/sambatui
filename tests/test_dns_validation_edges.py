from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sambatui.dns import validation as validation_module
from sambatui.dns.ptr import ptr_target_for_name, reverse_record_for_ipv4
from sambatui.dns.validation import valid_dns_name, validate_record

DNS_LABEL = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"))
    | st.sampled_from("_-"),
    min_size=1,
    max_size=20,
).filter(lambda value: value[0].isalnum() and value[-1].isalnum() and value.isascii())
DNS_NAME = st.lists(DNS_LABEL, min_size=1, max_size=5).map(".".join)


def test_dns_value_error_path_and_mx_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    assert validate_record("@", "MX", "10 bad space") is not None
    assert validate_record("@", "MX", "mail.example.com bad") is not None

    def raise_value_error(_rtype: str, _value: str) -> str | None:
        raise ValueError("bad rdata")

    monkeypatch.setattr(validation_module, "_record_value_error", raise_value_error)
    assert validate_record("www", "A", "192.0.2.1") == "bad rdata"


@given(DNS_NAME, DNS_NAME)
def test_ptr_target_for_valid_names_is_well_formed(name: str, zone: str) -> None:
    target = ptr_target_for_name(name, zone)

    assert target == target.rstrip(".")
    assert ".." not in target
    assert valid_dns_name(target)


@given(st.ip_addresses(v=4), st.lists(st.just("0.0.127.in-addr.arpa"), max_size=1))
def test_reverse_record_for_ipv4_returns_valid_reverse_name(
    address: ipaddress.IPv4Address, zones: list[str]
) -> None:
    result = reverse_record_for_ipv4(str(address), zones)

    assert result is not None
    zone, name = result
    assert zone.endswith(".in-addr.arpa")
    assert name == "@" or valid_dns_name(name)
    assert valid_dns_name(zone)
