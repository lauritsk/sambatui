from __future__ import annotations

from typing import ClassVar

import pytest
from hypothesis import given
from hypothesis import strategies as st
from ldap3.core.exceptions import LDAPException

from sambatui.ldap.client import LdapDirectoryClient
from sambatui.ldap.connection import ldap_result_message as _ldap_result_message
from sambatui.ldap.connection import paged_search_cookie as _paged_search_cookie
from sambatui.ldap.dn import (
    build_add_entry,
    ldap_dn_equal,
    ldap_dn_in_scope,
    normalized_ldap_dn_parts,
)
from sambatui.ldap.entries import infer_kind
from sambatui.ldap.errors import LdapOperationError
from sambatui.ldap.types import LdapSearchConfig


def test_ldap_helpers() -> None:
    normalized_ldap_dn_parts(r"CN=Doe\, Jane,DC=example,DC=com")
    assert ldap_dn_in_scope("bad dn", "DC=example,DC=com") is False
    assert ldap_dn_equal("bad dn", "DC=example,DC=com") is False
    assert infer_kind({"objectClass": ("computer",)}, "all") == "computer"
    assert (
        LdapSearchConfig(
            "dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
            encryption="off",
        ).validation_error()
        == "LDAP encryption must be ldaps or starttls."
    )
    assert _paged_search_cookie(None) is None
    assert _paged_search_cookie({"controls": {}}) is None
    assert _paged_search_cookie({"controls": {"1.2.840.113556.1.4.319": "bad"}}) is None
    assert _paged_search_cookie({"controls": {"1.2.840.113556.1.4.319": {}}}) is None
    assert _ldap_result_message(None, "fallback") == "fallback"


@given(
    st.text(min_size=1).filter(
        lambda kind: kind.casefold() not in {"user", "group", "computer", "ou"}
    )
)
def test_build_add_entry_rejects_generated_bad_kinds(kind: str) -> None:
    with pytest.raises(ValueError, match="LDAP add type must be one of"):
        build_add_entry(kind, "DC=example,DC=com", "Alice", {})


@given(
    st.sampled_from(["user", "group", "computer", "ou"]),
    st.text(alphabet=" \t\n", max_size=20),
)
def test_build_add_entry_rejects_generated_blank_names(kind: str, blank: str) -> None:
    with pytest.raises(ValueError, match="LDAP add needs a name"):
        build_add_entry(kind, "DC=example,DC=com", blank, {})


@given(
    st.sampled_from(["user", "group", "computer", "ou"]),
    st.text(alphabet=" \t\n", max_size=20),
)
def test_build_add_entry_rejects_generated_blank_parents(kind: str, blank: str) -> None:
    with pytest.raises(ValueError, match="LDAP add needs a parent DN"):
        build_add_entry(kind, blank, "Alice", {})


def test_build_add_entry_group_and_computer_defaults() -> None:
    assert build_add_entry("group", "DC=example,DC=com", "Ops", {})[2] == {
        "cn": "Ops",
        "sAMAccountName": "Ops",
        "groupType": -2147483646,
    }
    assert build_add_entry(
        "computer", "DC=example,DC=com", "HOST", {"sAMAccountName": "CUSTOM"}
    )[2] == {"cn": "HOST", "sAMAccountName": "CUSTOM$", "userAccountControl": 4128}


def test_ldap_write_delete_modify_and_exception_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = LdapDirectoryClient(
        LdapSearchConfig(
            "dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
        )
    )

    with pytest.raises(ValueError, match="LDAP delete needs a DN"):
        client.delete_entry(" ", expected_revision="17")
    client.modify_attributes("CN=Alice,DC=example,DC=com", {}, expected_revision="17")

    class FailedConnection:
        result: ClassVar[dict[str, object]] = {
            "description": "constraintViolation",
            "message": "denied",
        }

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def bind(self) -> bool:
            return True

        def add(self, *_args: object) -> bool:
            return False

        def unbind(self) -> bool:
            return True

    monkeypatch.setattr("ldap3.Connection", FailedConnection)
    monkeypatch.setattr("ldap3.Server", lambda *_args, **_kwargs: object())
    with pytest.raises(
        LdapOperationError, match="LDAP add failed: constraintViolation: denied"
    ):
        client.add_entry("ou", "DC=example,DC=com", "Ops", {})

    class ExceptionConnection(FailedConnection):
        result: ClassVar[dict[str, object]] = {}

        def add(self, *_args: object) -> bool:
            raise LDAPException("boom")

    monkeypatch.setattr("ldap3.Connection", ExceptionConnection)
    with pytest.raises(LdapOperationError, match="LDAP add failed: boom"):
        client.add_entry("ou", "DC=example,DC=com", "Ops", {})


def test_ldap_starttls_and_search_exception_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StartTlsExceptionConnection:
        result: ClassVar[dict[str, object]] = {}
        entries: ClassVar[list[object]] = []

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def start_tls(self) -> bool:
            raise LDAPException("tls exploded")

        def unbind(self) -> bool:
            return True

    monkeypatch.setattr("ldap3.Connection", StartTlsExceptionConnection)
    monkeypatch.setattr("ldap3.Server", lambda *_args, **_kwargs: object())
    cfg = LdapSearchConfig(
        "ldap://dc01.example.com",
        user="EXAMPLE\\admin",
        password="secret",
        base_dn="DC=example,DC=com",
        encryption="starttls",
    )
    with pytest.raises(LdapOperationError, match="LDAP StartTLS failed: tls exploded"):
        LdapDirectoryClient(cfg).search("users")

    class SearchExceptionConnection(StartTlsExceptionConnection):
        def start_tls(self) -> bool:
            return True

        def bind(self) -> bool:
            return True

        def search(self, *_args: object, **_kwargs: object) -> bool:
            raise LDAPException("search exploded")

    monkeypatch.setattr("ldap3.Connection", SearchExceptionConnection)
    with pytest.raises(LdapOperationError, match="LDAP search failed: search exploded"):
        LdapDirectoryClient(cfg).search("users")
