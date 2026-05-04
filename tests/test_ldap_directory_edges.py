from __future__ import annotations

from typing import Any

import pytest
from ldap3.core.exceptions import LDAPException

from sambatui import ldap_directory as ldap_module
from sambatui.ldap_directory import (
    LdapCompatibilityTls,
    LdapDirectoryClient,
    LdapSearchConfig,
    _ldap_result_message,
    _paged_search_cookie,
    build_add_entry,
    infer_kind,
    ldap_dn_equal,
    ldap_dn_in_scope,
    normalized_ldap_dn_parts,
)


def test_ldap_tls_wrap_socket_and_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    contexts: list[Any] = []

    class FakeContext:
        def __init__(self, _protocol: object) -> None:
            self.check_hostname = True
            self.verify_mode = None
            self.options = 0xFFFF
            contexts.append(self)

        def set_ciphers(self, ciphers: str) -> None:
            self.ciphers = ciphers

        def wrap_socket(
            self, socket: object, **kwargs: object
        ) -> tuple[object, dict[str, object]]:
            return socket, kwargs

    monkeypatch.setattr(ldap_module.ssl, "SSLContext", FakeContext)
    monkeypatch.setattr(ldap_module.ssl, "OP_NO_TLSv1", 0x1, raising=False)
    monkeypatch.setattr(ldap_module.ssl, "OP_NO_TLSv1_1", 0x2, raising=False)

    class Connection:
        socket: Any = object()

    connection = Connection()
    LdapCompatibilityTls().wrap_socket(connection, do_handshake=True)

    assert contexts[0].check_hostname is False
    assert contexts[0].verify_mode == ldap_module.ssl.CERT_NONE
    assert contexts[0].options & 0x3 == 0
    assert connection.socket[1]["do_handshake_on_connect"] is True

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
        == "LDAP password bind requires ldaps or starttls."
    )
    assert _paged_search_cookie(None) is None
    assert _ldap_result_message(None, "fallback") == "fallback"


@pytest.mark.parametrize(
    ("kind", "attrs", "expected"),
    [
        ("bad", {}, "LDAP add type must be one of"),
        ("user", {}, "LDAP add needs a name"),
        ("user", {}, "LDAP add needs a parent DN"),
    ],
)
def test_build_add_entry_rejects_bad_inputs(
    kind: str, attrs: dict[str, str], expected: str
) -> None:
    parent = "DC=example,DC=com" if expected != "LDAP add needs a parent DN" else ""
    name = "Alice" if expected == "LDAP add needs a parent DN" else ""
    with pytest.raises(ValueError, match=expected):
        build_add_entry(kind, parent, name, attrs)


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
        client.delete_entry(" ")
    client.modify_attributes("CN=Alice,DC=example,DC=com", {})

    class FailedConnection:
        result = {"description": "constraintViolation", "message": "denied"}

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
        ValueError, match="LDAP add failed: constraintViolation: denied"
    ):
        client.add_entry("ou", "DC=example,DC=com", "Ops", {})

    class ExceptionConnection(FailedConnection):
        result = {}

        def add(self, *_args: object) -> bool:
            raise LDAPException("boom")

    monkeypatch.setattr("ldap3.Connection", ExceptionConnection)
    with pytest.raises(ValueError, match="LDAP add failed: boom"):
        client.add_entry("ou", "DC=example,DC=com", "Ops", {})


def test_ldap_starttls_and_search_exception_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StartTlsExceptionConnection:
        result = {}
        entries: list[object] = []

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
    with pytest.raises(ValueError, match="LDAP StartTLS failed: tls exploded"):
        LdapDirectoryClient(cfg).search("users")

    class SearchExceptionConnection(StartTlsExceptionConnection):
        def start_tls(self) -> bool:
            return True

        def bind(self) -> bool:
            return True

        def search(self, *_args: object, **_kwargs: object) -> bool:
            raise LDAPException("search exploded")

    monkeypatch.setattr("ldap3.Connection", SearchExceptionConnection)
    with pytest.raises(ValueError, match="LDAP search failed: search exploded"):
        LdapDirectoryClient(cfg).search("users")
