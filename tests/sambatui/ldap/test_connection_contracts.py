from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import pytest
from gssapi.exceptions import GSSError
from ldap3.core.exceptions import LDAPException
from ldap3.protocol.rfc4511 import And
from pyasn1.codec.ber.decoder import decode

from sambatui.ldap.client import LdapDirectoryClient
from sambatui.ldap.connection import LdapConnection, ldap_connection_kwargs
from sambatui.ldap.errors import LdapConflictError, LdapOperationError
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
        self.controls: Sequence[tuple[str, bool, bytes]] | None = None
        self.search_result = True
        self.modify_result = True

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
        return self._step("search") and self.search_result

    def add(
        self, dn: str, object_class: tuple[str, ...], attributes: LdapAttributes
    ) -> bool:
        self.attributes = attributes
        return self._step("add")

    def delete(
        self, dn: str, *, controls: Sequence[tuple[str, bool, bytes]] | None = None
    ) -> bool:
        self.controls = controls
        return self._step("delete") and self.modify_result

    def modify(
        self,
        dn: str,
        changes: LdapChanges,
        *,
        controls: Sequence[tuple[str, bool, bytes]] | None = None,
    ) -> bool:
        self.changes = changes
        self.controls = controls
        return self._step("modify") and self.modify_result

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
        client.modify_attributes(
            dn, {"description": "", "mail": "alice@example.com"}, expected_revision="17"
        )
        assert connection.changes == {
            "description": [("MODIFY_DELETE", [])],
            "mail": [("MODIFY_REPLACE", ["alice@example.com"])],
        }
        expected = ["modify"]
    else:
        client.delete_entry(dn, expected_revision="17")
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
    with pytest.raises(LdapOperationError, match=f"{failure} failed"):
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


@pytest.mark.parametrize("operation", ["modify", "delete", "disable"])
def test_conditional_writes_send_critical_revision_assertions(operation: str) -> None:
    connection = Connection()
    client, read_only_values = make_client(connection)
    dn = Entry().entry_dn
    if operation == "modify":
        client.modify_attributes(
            dn, {"mail": "new@example.com"}, expected_revision="17"
        )
    elif operation == "delete":
        client.delete_entry(dn, expected_revision="17")
    else:
        client.disable_account(dn, 66048, expected_revision="17")
        assert connection.changes == {
            "userAccountControl": [("MODIFY_REPLACE", ["66050"])]
        }
    assert read_only_values == [False]
    assert connection.calls == [
        "tls",
        "bind",
        "delete" if operation == "delete" else "modify",
        "unbind",
    ]
    assert connection.controls is not None
    oid, critical, value = connection.controls[0]
    assert oid == "1.3.6.1.1.12" and critical is True
    assertion, rest = decode(value, asn1Spec=And())
    assert rest == b""
    conditions = {
        str(item["equalityMatch"]["attributeDesc"]): str(
            item["equalityMatch"]["assertionValue"]
        )
        for item in assertion
    }
    assert conditions == (
        {"uSNChanged": "17", "userAccountControl": "66048"}
        if operation == "disable"
        else {"uSNChanged": "17"}
    )


@pytest.mark.parametrize("operation", ["modify", "delete", "disable"])
@pytest.mark.parametrize(
    ("result", "error"), [(122, LdapConflictError), (12, LdapOperationError)]
)
def test_conditional_writes_fail_closed_without_retry(
    operation: str, result: int, error: type[LdapOperationError]
) -> None:
    connection = Connection()
    connection.modify_result = False
    connection.result = {"result": result, "description": "assertion rejected"}
    client, _ = make_client(connection)
    with pytest.raises(error):
        if operation == "modify":
            client.modify_attributes(
                Entry().entry_dn, {"description": "new"}, expected_revision="17"
            )
        elif operation == "delete":
            client.delete_entry(Entry().entry_dn, expected_revision="17")
        else:
            client.disable_account(Entry().entry_dn, 512, expected_revision="17")
    assert len([call for call in connection.calls if call in {"modify", "delete"}]) == 1
    assert connection.calls[-1] == "unbind"


@pytest.mark.parametrize("revision", ["", "-1", "bad", "１２", "1.5"])
@pytest.mark.parametrize("operation", ["modify", "delete", "disable"])
def test_invalid_revisions_never_open_a_connection(
    revision: str, operation: str
) -> None:
    connection = Connection()
    client, opened = make_client(connection)
    with pytest.raises(ValueError, match="revision"):
        if operation == "modify":
            client.modify_attributes(
                Entry().entry_dn, {"description": "new"}, expected_revision=revision
            )
        elif operation == "delete":
            client.delete_entry(Entry().entry_dn, expected_revision=revision)
        else:
            client.disable_account(Entry().entry_dn, 512, expected_revision=revision)
    assert opened == []


def test_empty_successful_search_is_not_a_failure() -> None:
    connection = Connection()
    connection.search_result = False
    connection.entries = []
    connection.result = {"result": 0}
    client, _ = make_client(connection)
    assert client.search("users") == []
    assert connection.calls == ["tls", "bind", "search", "unbind"]


def test_opaque_paging_cookie_may_remain_unchanged() -> None:
    connection = Connection()
    connection.result = {
        "controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b"opaque-cursor"}}}
    }
    client, _ = make_client(connection)
    assert len(client.search("users", max_entries=3)) == 3
    assert connection.calls[-1] == "unbind"


def test_kerberos_cache_acquisition_errors_are_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(**kwargs: object) -> None:
        raise GSSError(458752, 0)

    monkeypatch.setattr("sambatui.ldap.connection.Credentials", unavailable)
    with pytest.raises(LdapOperationError, match="Cannot load Kerberos credentials"):
        ldap_connection_kwargs(LdapSearchConfig("dc", auth_mode="kerberos"))


def test_native_kerberos_bind_errors_are_cleaned_up() -> None:
    class NativeFailure(Connection):
        def bind(self) -> bool:
            raise GSSError(458752, 0)

    connection = NativeFailure()
    client, _ = make_client(connection)
    with pytest.raises(LdapOperationError, match="LDAP bind failed"):
        client.check_connection()
    assert connection.calls == ["tls", "unbind"]


def test_disable_rejects_invalid_flags() -> None:
    client, opened = make_client(Connection())
    with pytest.raises(ValueError, match="userAccountControl"):
        client.disable_account(Entry().entry_dn, -1, expected_revision="17")
    assert opened == []
