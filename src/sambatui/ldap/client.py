from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import suppress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sambatui.ldap.rows import DirectoryRow


def _install_pyasn1_ber_legacy_aliases() -> None:
    with suppress(ImportError, AttributeError):
        from pyasn1.codec.ber import encoder

        encoder.tagMap = encoder.TAG_MAP
        encoder.typeMap = encoder.TYPE_MAP


_install_pyasn1_ber_legacy_aliases()

from sambatui.ldap.config import (  # noqa: E402
    domain_to_base_dn as domain_to_base_dn,
    gssapi_cred_store as gssapi_cred_store,
    ldap_compatibility_enabled as ldap_compatibility_enabled,
    ldap_server_get_info as ldap_server_get_info,
    ldap_server_scheme as ldap_server_scheme,
    parse_ldap_server as parse_ldap_server,
)
from sambatui.ldap.connection import (  # noqa: E402
    LdapConnection,
    bind_connection,
    ldap_connection_kwargs as ldap_connection_kwargs,
    ldap_exception_message,
    ldap_result_message,
    new_ldap_connection,
    paged_search_cookie,
    search_connection,
    start_tls_if_needed,
    unbind_suppressing_ldap_error,
)
from sambatui.ldap.dn import (  # noqa: E402
    build_add_entry as build_add_entry,
    ldap_dn_equal,
    ldap_dn_in_scope as ldap_dn_in_scope,
    normalized_ldap_dn_parts as normalized_ldap_dn_parts,
)
from sambatui.ldap.entries import (  # noqa: E402
    directory_summary as directory_summary,
    entry_to_directory_row,
    first_attr as first_attr,
    infer_kind as infer_kind,
    normalize_attribute_values as normalize_attribute_values,
    normalize_entry_attributes as normalize_entry_attributes,
)
from sambatui.ldap.filters import (  # noqa: E402
    CHILD_CONTAINER_FILTER,
    build_directory_filter as build_directory_filter,
)
from sambatui.ldap.tls import (  # noqa: E402
    LdapCompatibilityTls as LdapCompatibilityTls,
    ldap_server_tls as ldap_server_tls,
    ssl as ssl,
)
from sambatui.ldap.types import (  # noqa: E402
    ALL_LDAP_EDITABLE_ATTRIBUTES,
    LDAP_ADD_KINDS as LDAP_ADD_KINDS,
    LDAP_AUTH_MODES as LDAP_AUTH_MODES,
    LDAP_COMPATIBILITY_OFF as LDAP_COMPATIBILITY_OFF,
    LDAP_COMPATIBILITY_ON as LDAP_COMPATIBILITY_ON,
    LDAP_EDITABLE_ATTRIBUTES as LDAP_EDITABLE_ATTRIBUTES,
    LDAP_ENCRYPTION_MODES as LDAP_ENCRYPTION_MODES,
    LDAP_SEARCH_KINDS as LDAP_SEARCH_KINDS,
    DirectoryAddKind as DirectoryAddKind,
    DirectorySearchKind as DirectorySearchKind,
    LdapAuthMode as LdapAuthMode,
    LdapSearchConfig,
    LdapServerSettings as LdapServerSettings,
)


class LdapDirectoryClient:
    def __init__(self, config: LdapSearchConfig) -> None:
        self.config = config

    def validation_error(self) -> str | None:
        return self.config.validation_error()

    def _raise_validation_error(self) -> None:
        error = self.validation_error()
        if error:
            raise ValueError(error)

    def check_connection(self) -> None:
        self._raise_validation_error()

        connection, settings = new_ldap_connection(self.config)
        try:
            start_tls_if_needed(connection, self.config, settings)
            bind_connection(connection)
        finally:
            unbind_suppressing_ldap_error(connection)

    def search(
        self, kind: str, text: str = "", max_entries: int | None = None
    ) -> list[DirectoryRow]:
        return self._search_rows(
            build_directory_filter(kind, text), kind, max_entries=max_entries
        )

    def child_containers(self, max_entries: int | None = None) -> list[DirectoryRow]:
        return self._search_rows(
            CHILD_CONTAINER_FILTER,
            "all",
            max_entries=max_entries,
            one_level=True,
        )

    def add_entry(
        self,
        kind: str,
        parent_dn: str,
        name: str,
        attributes: Mapping[str, str],
    ) -> str:
        self._raise_validation_error()
        dn, object_class, ldap_attributes = build_add_entry(
            kind, parent_dn, name, attributes
        )
        self._write(
            lambda connection: connection.add(dn, object_class, ldap_attributes),
            "LDAP add failed",
        )
        return dn

    def delete_entry(self, dn: str) -> None:
        if not dn.strip():
            raise ValueError("LDAP delete needs a DN.")
        if ldap_dn_equal(dn, self.config.base_dn):
            raise ValueError("Refusing to delete LDAP base DN.")
        self._raise_validation_error()
        self._write(lambda connection: connection.delete(dn), "LDAP delete failed")

    def modify_attributes(self, dn: str, changes: Mapping[str, str]) -> None:
        self._raise_validation_error()
        invalid = sorted(set(changes) - ALL_LDAP_EDITABLE_ATTRIBUTES)
        if invalid:
            raise ValueError(f"LDAP attribute is not editable: {', '.join(invalid)}")
        self._modify_attributes(dn, changes, "LDAP modify failed")

    def disable_account(self, dn: str, user_account_control: int) -> None:
        if not dn.strip():
            raise ValueError("LDAP disable needs a DN.")
        self._raise_validation_error()
        self._modify_attributes(
            dn,
            {"userAccountControl": str(user_account_control | 0x0002)},
            "LDAP disable failed",
        )

    def _modify_attributes(
        self, dn: str, changes: Mapping[str, str], failure_message: str
    ) -> None:
        if not changes:
            return

        from ldap3 import MODIFY_DELETE, MODIFY_REPLACE

        ldap_changes = {
            attr: [(MODIFY_DELETE, [])] if value == "" else [(MODIFY_REPLACE, [value])]
            for attr, value in changes.items()
        }
        self._write(
            lambda connection: connection.modify(dn, ldap_changes), failure_message
        )

    def _write(
        self, operation: Callable[[LdapConnection], bool], failure_message: str
    ) -> None:
        from ldap3.core.exceptions import LDAPException

        connection, settings = new_ldap_connection(self.config, read_only=False)
        try:
            start_tls_if_needed(connection, self.config, settings)
            bind_connection(connection)
            try:
                ok = operation(connection)
            except LDAPException as exc:
                raise ValueError(ldap_exception_message(exc, failure_message)) from exc
            if not ok:
                raise ValueError(
                    ldap_result_message(connection.result, failure_message)
                )
        finally:
            unbind_suppressing_ldap_error(connection)

    def _search_rows(
        self,
        search_filter: str,
        kind: str,
        *,
        max_entries: int | None = None,
        one_level: bool = False,
    ) -> list[DirectoryRow]:
        self._raise_validation_error()

        connection, settings = new_ldap_connection(self.config)
        try:
            start_tls_if_needed(connection, self.config, settings)
            bind_connection(connection)
            entries = search_connection(
                connection,
                self.config,
                search_filter,
                max_entries,
                one_level=one_level,
            )
            return [entry_to_directory_row(entry, kind) for entry in entries]
        finally:
            unbind_suppressing_ldap_error(connection)


# Backwards-compatible private aliases for tests and downstream users that imported them.
_new_ldap_connection = new_ldap_connection
_start_tls_if_needed = start_tls_if_needed
_bind_connection = bind_connection
_search_connection = search_connection
_paged_search_cookie = paged_search_cookie
_ldap_result_message = ldap_result_message
_ldap_exception_message = ldap_exception_message
