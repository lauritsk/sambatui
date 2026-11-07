from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import pytest
from ldap3.core.exceptions import LDAPException

from sambatui.ldap.client import LdapDirectoryClient
from sambatui.ldap.connection import LdapConnection
from sambatui.ldap.types import (
    LdapAttributes,
    LdapChanges,
    LdapCookie,
    LdapEntry,
    LdapResult,
    LdapSearchConfig,
    LdapServerSettings,
)


@dataclass
class Entry:
    entry_dn: str = "CN=Alice,DC=example,DC=com"
    entry_attributes_as_dict: Mapping[str, object] = field(
        default_factory=lambda: {"cn": ["Alice"], "objectClass": ["person", "user"]}
    )


class Connection:
    """A structurally checked fake, not an untyped ldap3 replacement."""

    def __init__(self, fail_at: str = "", *, cleanup_error: bool = False) -> None:
        self.calls: list[str] = []
        self.entries: Sequence[LdapEntry] = [Entry()]
        self.result: LdapResult = {}
        self.fail_at = fail_at
        self.cleanup_error = cleanup_error
        self.attributes: LdapAttributes = {}
        self.changes: LdapChanges = {}

    def _step(self, name: str) -> bool:
        self.calls.append(name)
        if self.fail_at == name:
            raise LDAPException(f"{name} failed")
        return True

    def start_tls(self) -> bool:
        return self._step("tls")

    def bind(self) -> bool:
        return self._step("bind")

    def search(
        self,
        search_base: str,
        search_filter: str,
        *,
        search_scope: str,
        attributes: list[str],
        paged_size: int,
        paged_cookie: LdapCookie,
    ) -> bool:
        return self._step("search")

    def add(
        self, dn: str, object_class: tuple[str, ...], attributes: LdapAttributes
    ) -> bool:
        self.attributes = attributes
        return self._step("add")

    def delete(self, dn: str) -> bool:
        return self._step("delete")

    def modify(self, dn: str, changes: LdapChanges) -> bool:
        self.changes = changes
        return self._step("modify")

    def unbind(self) -> None:
        self.calls.append("unbind")
        if self.cleanup_error:
            raise LDAPException("cleanup failed")


def make_client(connection: Connection) -> tuple[LdapDirectoryClient, list[bool]]:
    read_only_values: list[bool] = []

    def factory(
        config: LdapSearchConfig, *, read_only: bool = True
    ) -> tuple[LdapConnection, LdapServerSettings]:
        read_only_values.append(read_only)
        return connection, LdapServerSettings("dc.example.com", 389, False)

    config = LdapSearchConfig(
        "ldap://dc.example.com",
        user="alice",
        password="secret",
        base_dn="DC=example,DC=com",
        encryption="starttls",
    )
    return LdapDirectoryClient(config, connection_factory=factory), read_only_values


@pytest.mark.parametrize("operation", ["check", "search", "add", "modify", "delete"])
def test_injected_connection_owns_tls_bind_and_cleanup(operation: str) -> None:
    connection = Connection()
    client, read_only_values = make_client(connection)
    dn = "CN=Alice,DC=example,DC=com"
    if operation == "check":
        client.check_connection()
        expected = []
    elif operation == "search":
        rows = client.search("users")
        assert rows[0].dn == dn
        assert rows[0].attributes["cn"] == ("Alice",)
        expected = ["search"]
    elif operation == "add":
        client.add_entry("group", "DC=example,DC=com", "Ops", {})
        assert connection.attributes["groupType"] == -2147483646
        expected = ["add"]
    elif operation == "modify":
        client.modify_attributes(dn, {"description": "", "mail": "alice@example.com"})
        assert connection.changes == {
            "description": [("MODIFY_DELETE", [])],
            "mail": [("MODIFY_REPLACE", ["alice@example.com"])],
        }
        expected = ["modify"]
    else:
        client.delete_entry(dn)
        expected = ["delete"]
    assert read_only_values == [operation in {"check", "search"}]
    assert connection.calls == ["tls", "bind", *expected, "unbind"]


@pytest.mark.parametrize("failure", ["tls", "bind", "search", "add"])
@pytest.mark.parametrize("cleanup_error", [False, True])
def test_failed_sessions_always_unbind_without_masking_errors(
    failure: str, cleanup_error: bool
) -> None:
    connection = Connection(failure, cleanup_error=cleanup_error)
    client, _ = make_client(connection)
    with pytest.raises(ValueError, match=f"{failure} failed"):
        if failure == "add":
            client.add_entry("ou", "DC=example,DC=com", "Ops", {})
        else:
            client.search("users")
    assert connection.calls[-1] == "unbind"
    assert connection.calls.count("unbind") == 1


def test_invalid_config_does_not_open_a_session() -> None:
    connection = Connection()
    client, read_only_values = make_client(connection)
    client.config = LdapSearchConfig("dc.example.com")
    with pytest.raises(ValueError, match="username"):
        client.check_connection()
    assert read_only_values == []
    assert connection.calls == []
