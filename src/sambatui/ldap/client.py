from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sambatui.ldap.rows import DirectoryRow


from sambatui.ldap.connection import (
    LdapConnection,
    LdapConnectionFactory,
    ldap_exception_message,
    ldap_result_message,
    ldap_session,
    new_ldap_connection,
    search_connection,
)
from sambatui.ldap.controls import entry_assertion
from sambatui.ldap.dn import (
    build_add_entry,
    ldap_dn_equal,
    ldap_dn_in_scope,
)
from sambatui.ldap.entries import (
    entry_to_directory_row,
)
from sambatui.ldap.errors import LdapConflictError, LdapOperationError
from sambatui.ldap.filters import (
    CHILD_CONTAINER_FILTER,
    build_directory_filter,
)
from sambatui.ldap.types import (
    ALL_LDAP_EDITABLE_ATTRIBUTES,
    LdapChanges,
    LdapSearchConfig,
)


class LdapDirectoryClient:
    def __init__(
        self,
        config: LdapSearchConfig,
        *,
        connection_factory: LdapConnectionFactory = new_ldap_connection,
    ) -> None:
        self.config = config
        self._connection_factory = connection_factory

    def validation_error(self) -> str | None:
        return self.config.validation_error()

    def _raise_validation_error(self) -> None:
        error = self.validation_error()
        if error:
            raise ValueError(error)

    def check_connection(self) -> None:
        self._raise_validation_error()

        with ldap_session(self.config, factory=self._connection_factory):
            pass

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
        self._raise_out_of_scope(parent_dn, "LDAP add parent")
        dn, object_class, ldap_attributes = build_add_entry(
            kind, parent_dn, name, attributes
        )
        self._write(
            lambda connection: connection.add(dn, object_class, ldap_attributes),
            "LDAP add failed",
        )
        return dn

    def delete_entry(self, dn: str, *, expected_revision: str) -> None:
        if not dn.strip():
            raise ValueError("LDAP delete needs a DN.")
        if ldap_dn_equal(dn, self.config.base_dn):
            raise ValueError("Refusing to delete LDAP base DN.")
        self._raise_validation_error()
        self._raise_out_of_scope(dn, "LDAP delete target")
        control = entry_assertion(expected_revision)
        self._write(
            lambda connection: connection.delete(dn, controls=[control]),
            "LDAP delete failed",
        )

    def modify_attributes(
        self, dn: str, changes: Mapping[str, str], *, expected_revision: str
    ) -> None:
        self._raise_validation_error()
        self._raise_out_of_scope(dn, "LDAP modify target")
        invalid = sorted(set(changes) - ALL_LDAP_EDITABLE_ATTRIBUTES)
        if invalid:
            raise ValueError(f"LDAP attribute is not editable: {', '.join(invalid)}")
        if not changes:
            return
        from ldap3 import MODIFY_DELETE, MODIFY_REPLACE

        control = entry_assertion(expected_revision)
        ldap_changes: LdapChanges = {
            attr: [(MODIFY_DELETE, [])] if value == "" else [(MODIFY_REPLACE, [value])]
            for attr, value in changes.items()
        }
        self._write(
            lambda connection: connection.modify(dn, ldap_changes, controls=[control]),
            "LDAP modify failed",
        )

    def disable_account(
        self, dn: str, user_account_control: int, *, expected_revision: str
    ) -> None:
        from ldap3 import MODIFY_REPLACE

        if not dn.strip():
            raise ValueError("LDAP disable needs a DN.")
        self._raise_validation_error()
        self._raise_out_of_scope(dn, "LDAP disable target")
        if user_account_control < 0:
            raise ValueError("Invalid userAccountControl.")
        control = entry_assertion(expected_revision, user_account_control)
        self._write(
            lambda connection: connection.modify(
                dn,
                {
                    "userAccountControl": [
                        (MODIFY_REPLACE, [str(user_account_control | 0x0002)])
                    ]
                },
                controls=[control],
            ),
            "LDAP disable failed",
        )

    def _raise_out_of_scope(self, dn: str, label: str) -> None:
        if not ldap_dn_in_scope(dn, self.config.base_dn):
            raise ValueError(f"{label} must be at or below LDAP base DN.")

    def _write(
        self, operation: Callable[[LdapConnection], bool], failure_message: str
    ) -> None:
        from ldap3.core.exceptions import LDAPException

        with ldap_session(
            self.config, factory=self._connection_factory, read_only=False
        ) as connection:
            try:
                ok = operation(connection)
            except LDAPException as exc:
                raise LdapOperationError(
                    ldap_exception_message(exc, failure_message)
                ) from exc
            if not ok:
                if connection.result.get("result") == 122:
                    raise LdapConflictError(
                        "LDAP entry changed; refresh before retrying."
                    )
                if connection.result.get("result") == 12:
                    raise LdapOperationError(
                        "Server does not support conditional LDAP writes; "
                        "the operation was refused without an unsafe fallback."
                    )
                raise LdapOperationError(
                    ldap_result_message(connection.result, failure_message)
                )

    def _search_rows(
        self,
        search_filter: str,
        kind: str,
        *,
        max_entries: int | None = None,
        one_level: bool = False,
    ) -> list[DirectoryRow]:
        self._raise_validation_error()

        with ldap_session(self.config, factory=self._connection_factory) as connection:
            entries = search_connection(
                connection,
                self.config,
                search_filter,
                max_entries,
                one_level=one_level,
            )
            return [entry_to_directory_row(entry, kind) for entry in entries]
