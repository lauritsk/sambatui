from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING

from textual import work

from sambatui.app_constants import (
    LDAP_DEFAULT_MAX_ROWS,
    LDAP_LOAD_MORE_ROWS,
    LDAP_MAX_ROWS,
)
from sambatui.core.config import DEFAULT_LDAP_ENCRYPTION, DEFAULT_SMART_MAX_ROWS
from sambatui.ldap.client import LdapDirectoryClient
from sambatui.ldap.config import domain_to_base_dn
from sambatui.ldap.dn import ldap_dn_in_scope
from sambatui.ldap.types import LDAP_ADD_KINDS, LDAP_EDITABLE_ATTRIBUTES

from ..core.mutations import mutation_action
from ..core.operations import LdapAddOperation
from ..core.remediation import bounded_int
from ..ldap.errors import LdapOperationError
from ..ldap.rows import DirectoryRow
from ..smart_view_catalog import SMART_ROW_LIMIT_DEFAULT
from ..ui.screens import (
    FormField,
)

if TYPE_CHECKING:
    from ..app import SambatuiApp
from .helpers import (
    ldap_limit_suffix,
)


class AppLdapActionsMixin:
    def ldap_base_default(self: SambatuiApp) -> str:
        return self.val("ldap_base") or domain_to_base_dn(
            self.connection_domain_default() or self.val("zone")
        )

    def ldap_connection_fields(self: SambatuiApp, base_dn: str) -> list[FormField]:
        return [
            ("Base DN", "base_dn", "DC=example,DC=com", base_dn),
            (
                "LDAP encryption",
                "ldap_encryption",
                "ldaps | starttls",
                self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            ),
        ]

    def smart_max_rows_field(self: SambatuiApp) -> FormField:
        return (
            "Max rows",
            "max_rows",
            str(SMART_ROW_LIMIT_DEFAULT),
            self.val("smart_max_rows") or DEFAULT_SMART_MAX_ROWS,
        )

    def ldap_search_fields(
        self: SambatuiApp, default_kind: str = "users"
    ) -> list[FormField]:
        return [
            (
                "Search type",
                "kind",
                "users | groups | computers | ous | all",
                default_kind,
            ),
            ("Search text", "text", "name, login, mail, DN fragment", ""),
            *self.ldap_connection_fields(self.ldap_base_default()),
            (
                "Max rows",
                "max_rows",
                str(LDAP_DEFAULT_MAX_ROWS),
                str(self.views.directory.max_rows),
            ),
        ]

    def apply_ldap_connection_values(
        self: SambatuiApp, values: dict[str, str], *, refresh_sidebar: bool = True
    ) -> None:
        if values["base_dn"].casefold() != self.val("ldap_base").casefold():
            self.ldap_structure_rows = []
        updates = {"ldap_base": values["base_dn"]}
        updates.update(
            (key, values[key]) for key in ("ldap_encryption",) if key in values
        )
        self.set_connection_values(updates)
        if refresh_sidebar:
            self.populate_ldap_structure(self.ldap_structure_rows)
        self.save_preferences()

    async def ldap_thread_result[Result](
        self: SambatuiApp,
        operation: Callable[[], Result],
        *,
        report_error: bool = True,
        write: bool = False,
    ) -> tuple[Result | None, str]:
        async with self.busy():
            try:
                if write:
                    return await self.mutations.run_thread(operation), ""
                return await asyncio.to_thread(operation), ""
            except (ValueError, LdapOperationError) as exc:
                error = str(exc)
                if report_error:
                    self.report_error(error)
                return None, error

    async def directory_search_rows(
        self: SambatuiApp,
        client: LdapDirectoryClient,
        kind: str,
        text: str,
        max_entries: int | None = None,
    ) -> list[DirectoryRow] | None:
        rows, _error = await self.ldap_thread_result(
            lambda: client.search(kind, text, max_entries)
        )
        return rows

    async def directory_container_rows(
        self: SambatuiApp, client: LdapDirectoryClient
    ) -> list[DirectoryRow]:
        rows, _error = await self.ldap_thread_result(
            lambda: client.child_containers(LDAP_MAX_ROWS), report_error=False
        )
        return rows or []

    def ldap_search_max_rows(self: SambatuiApp, values: dict[str, str]) -> int:
        return bounded_int(
            values.get("max_rows", ""), LDAP_DEFAULT_MAX_ROWS, maximum=LDAP_MAX_ROWS
        )

    async def run_directory_search(
        self: SambatuiApp,
        values: dict[str, str],
        *,
        default_kind: str = "users",
        max_rows: int | None = None,
        action: str = "Loaded",
    ) -> bool:
        self.apply_ldap_connection_values(values, refresh_sidebar=False)
        limit = max_rows if max_rows is not None else self.ldap_search_max_rows(values)
        client = self.ldap_client(values.get("search_base_dn") or values["base_dn"])
        error = client.validation_error()
        if error:
            self.report_error(error)
            return False

        kind = values["kind"] or default_kind
        revision, mode = self.connection_revision, self.views.mode
        rows = await self.directory_search_rows(client, kind, values["text"], limit)
        if rows is None:
            return False
        container_rows = await self.directory_container_rows(client)
        if revision != self.connection_revision or mode != self.views.mode:
            return False
        self.views.directory.values = {**values, "kind": kind, "max_rows": str(limit)}
        self.views.directory.max_rows = limit
        self.set_search_text("", refresh=False)
        self.remember_ldap_structure_rows(container_rows)
        self.populate_directory(rows)
        self.set_status(
            f"{action} {len(rows)} LDAP entries "
            f"(limit {limit}){ldap_limit_suffix(len(rows), limit)}"
        )
        self.notify(f"{action} {len(rows)} LDAP entries")
        return True

    async def open_ldap_search(self: SambatuiApp, default_kind: str = "users") -> None:
        values = await self.form(
            "Search AD directory",
            "LDAP via ldap3. Password bind requires LDAPS/StartTLS; UPN usernames work best.",
            self.ldap_search_fields(default_kind),
            "Search",
        )
        if not values:
            return
        await self.run_directory_search(values, default_kind=default_kind)

    async def refresh_current_directory_search(self: SambatuiApp) -> bool:
        if not self.connection_is_current():
            return False
        if not self.views.directory.values:
            self.set_status("No LDAP search to refresh. Press L to search directory.")
            return False
        return await self.run_directory_search(
            self.views.directory.values,
            max_rows=self.views.directory.max_rows,
            action="Refreshed",
        )

    async def load_more_current_view(self: SambatuiApp) -> bool:
        match self.views.mode:
            case "directory":
                return await self.load_more_directory()
            case "smart":
                return await self.load_more_smart_view()
            case "dns":
                self.set_status("Load more is unavailable for DNS records.")
                return False
            case _:
                self.set_status("No active view to load more rows for.")
                return False

    async def load_more_directory(self: SambatuiApp) -> bool:
        if not self.views.directory.values:
            self.set_status("No LDAP search to extend. Press L to search directory.")
            return False
        max_rows = min(
            self.views.directory.max_rows + LDAP_LOAD_MORE_ROWS, LDAP_MAX_ROWS
        )
        if max_rows == self.views.directory.max_rows:
            self.set_status(f"LDAP row limit already at {LDAP_MAX_ROWS}.")
            return False
        return await self.run_directory_search(
            self.views.directory.values,
            max_rows=max_rows,
            action="Loaded",
        )

    @work
    async def action_ldap_search(self: SambatuiApp) -> None:
        await self.open_ldap_search()

    @work
    async def action_ldap_search_kind(self: SambatuiApp, kind: str) -> None:
        await self.open_ldap_search(kind)

    @work
    async def action_load_more_directory(self: SambatuiApp) -> None:
        await self.load_more_current_view()

    def selected_directory_entries(self: SambatuiApp) -> list[DirectoryRow]:
        rows = self.visible_directory()
        if self.views.directory.selected_rows:
            row_indices = sorted(self.views.directory.selected_rows)
            if any(
                row_index < 0 or row_index >= len(rows) for row_index in row_indices
            ):
                self.notify(
                    "LDAP selection is stale; clear selection and select entries again.",
                    severity="error",
                )
                return []
            return [rows[row_index] for row_index in row_indices]

        row = self.visible_row_at(rows, self.records_cursor_row())
        if row is None:
            self.notify("Select an LDAP entry first.", severity="error")
            return []
        return [row]

    def selected_directory_row(self: SambatuiApp) -> DirectoryRow | None:
        rows = self.selected_directory_entries()
        if len(rows) > 1:
            self.notify(
                "LDAP update works on one entry only. Select one row.",
                severity="error",
            )
            return None
        return rows[0] if rows else None

    def ldap_editable_attributes(
        self: SambatuiApp, row: DirectoryRow
    ) -> tuple[str, ...]:
        return LDAP_EDITABLE_ATTRIBUTES.get(row.kind, ())

    def ldap_attribute_value(self: SambatuiApp, row: DirectoryRow, attr: str) -> str:
        values = row.attributes.get(attr, ())
        return values[0] if values else ""

    def ldap_edit_fields(self: SambatuiApp, row: DirectoryRow) -> list[FormField]:
        return [
            (
                attr,
                attr,
                "new value; leave blank to delete attribute",
                self.ldap_attribute_value(row, attr),
            )
            for attr in self.ldap_editable_attributes(row)
        ]

    def ldap_attribute_changes(
        self: SambatuiApp, row: DirectoryRow, values: dict[str, str]
    ) -> dict[str, str]:
        return {
            attr: values[attr]
            for attr in self.ldap_editable_attributes(row)
            if values[attr] != self.ldap_attribute_value(row, attr)
        }

    def ldap_edit_preview(
        self: SambatuiApp, row: DirectoryRow, changes: Mapping[str, str]
    ) -> str:
        lines = [
            f"{attr}: {self.ldap_attribute_value(row, attr) or '<empty>'} -> "
            f"{value or '<delete>'}"
            for attr, value in changes.items()
        ]
        return "\n".join(["Edit LDAP entry?", "", f"DN: {row.dn}", *lines])

    @mutation_action
    async def update_ldap_entry(self: SambatuiApp) -> None:
        row = self.selected_directory_row()
        if row is None:
            return
        fields = self.ldap_edit_fields(row)
        if not fields:
            self.notify(
                f"No editable LDAP attributes for object type: {row.kind}.",
                severity="error",
            )
            return
        values = await self.form("Edit LDAP entry", row.dn, fields, "Preview")
        if not values:
            return
        changes = self.ldap_attribute_changes(row, values)
        if not changes:
            self.notify("No LDAP attribute changes.")
            return
        if not await self.confirm(
            self.ldap_edit_preview(row, changes), default_confirm=True
        ):
            self.notify("LDAP edit cancelled")
            return
        client = self.ldap_client()
        _result, error = await self.ldap_thread_result(
            lambda: client.modify_attributes(
                row.dn, changes, expected_revision=row.revision
            ),
            write=True,
        )
        if error:
            return
        self.notify("LDAP entry updated")
        await self.refresh_current_directory_search()

    def ldap_add_parent_dn(self: SambatuiApp) -> str:
        return (
            self.views.directory.values.get("search_base_dn")
            or self.views.directory.values.get("base_dn")
            or self.ldap_base_default()
        )

    def ldap_add_fields(self: SambatuiApp) -> list[FormField]:
        return [
            ("Object type", "kind", "user | group | computer | ou", "user"),
            (
                "Parent DN",
                "parent_dn",
                "container/OU DN for new object",
                self.ldap_add_parent_dn(),
            ),
            ("Name", "name", "CN/OU name", ""),
            (
                "sAMAccountName",
                "sAMAccountName",
                "users/groups/computers; blank uses name",
                "",
            ),
            ("UPN", "userPrincipalName", "optional user@domain", ""),
            ("Mail", "mail", "optional", ""),
            ("Description", "description", "optional", ""),
        ]

    def ldap_add_error(self: SambatuiApp, values: dict[str, str]) -> str | None:
        kind = values.get("kind", "").casefold()
        if kind not in LDAP_ADD_KINDS:
            return f"Choose LDAP type: {', '.join(LDAP_ADD_KINDS)}."
        parent_dn = values.get("parent_dn", "").strip()
        if not parent_dn:
            return "Enter LDAP parent DN."
        configured_base_dn = (
            self.views.directory.values.get("base_dn") or self.ldap_base_default()
        ).strip()
        if configured_base_dn and not ldap_dn_in_scope(parent_dn, configured_base_dn):
            return f"Parent DN must be at or below LDAP base: {configured_base_dn}."
        search_base_dn = self.views.directory.values.get("search_base_dn", "").strip()
        if search_base_dn and not ldap_dn_in_scope(parent_dn, search_base_dn):
            return f"Parent DN must be at or below LDAP search base: {search_base_dn}."
        if not values.get("name", "").strip():
            return "Enter LDAP object name."
        return None

    def ldap_add_attributes(
        self: SambatuiApp, values: dict[str, str]
    ) -> dict[str, str]:
        return {
            attr: values.get(attr, "").strip()
            for attr in ("sAMAccountName", "userPrincipalName", "mail", "description")
        }

    def ldap_add_operation(
        self: SambatuiApp, values: dict[str, str]
    ) -> LdapAddOperation:
        return LdapAddOperation.create(
            values["kind"].casefold(),
            values["parent_dn"],
            values["name"],
            self.ldap_add_attributes(values),
        )

    def ldap_add_operation_preview(
        self: SambatuiApp, operation: LdapAddOperation
    ) -> str:
        lines = [f"{attr}: {value}" for attr, value in operation.attributes if value]
        return "\n".join(
            [
                "Add LDAP entry?",
                "",
                f"Type: {operation.kind}",
                f"Parent DN: {operation.parent_dn}",
                f"Name: {operation.name}",
                *lines,
            ]
        )

    @mutation_action
    async def add_ldap_entry(self: SambatuiApp) -> None:
        values = await self.form(
            "Add LDAP entry",
            "Create a user, group, computer, or OU under the chosen parent DN.",
            self.ldap_add_fields(),
            "Preview",
            self.ldap_add_error,
        )
        if not values:
            return
        operation = self.ldap_add_operation(values)
        if not await self.confirm(
            self.ldap_add_operation_preview(operation), default_confirm=True
        ):
            self.notify("LDAP add cancelled")
            return
        client = self.ldap_client()
        dn, error = await self.ldap_thread_result(
            lambda: client.add_entry(
                operation.kind,
                operation.parent_dn,
                operation.name,
                operation.attribute_values,
            ),
            write=True,
        )
        if error:
            return
        self.notify(f"LDAP entry added: {dn}")
        await self.refresh_current_directory_search()

    def ldap_entry_count_label(self: SambatuiApp, count: int) -> str:
        label = "LDAP entry" if count == 1 else "LDAP entries"
        return f"{count} {label}"

    def ldap_delete_preview(
        self: SambatuiApp, rows: Sequence[DirectoryRow], *, preview_limit: int = 12
    ) -> str:
        preview_rows = rows[:preview_limit]
        lines = [
            f"- Name: {row.name}\n  Kind: {row.kind}\n  DN: {row.dn}"
            for row in preview_rows
        ]
        if len(rows) > preview_limit:
            lines.append(f"... and {len(rows) - preview_limit} more")
        return "\n".join(
            [
                f"DELETE {self.ldap_entry_count_label(len(rows))}?",
                "",
                *lines,
                "",
                "This is irreversible from this app.",
                "Non-empty containers may fail; recursive delete is not performed.",
            ]
        )

    @mutation_action
    async def delete_ldap_entry(self: SambatuiApp) -> None:
        rows = self.selected_directory_entries()
        if not rows:
            return
        if not await self.confirm(self.ldap_delete_preview(rows)):
            self.notify("LDAP delete cancelled")
            return

        failed = 0
        client = self.ldap_client()
        for row in rows:
            _result, error = await self.ldap_thread_result(
                lambda row=row: client.delete_entry(
                    row.dn, expected_revision=row.revision
                ),
                write=True,
            )
            if error:
                failed += 1
        self.clear_directory_selection()
        deleted = len(rows) - failed
        if failed:
            self.notify(
                f"Deleted {self.ldap_entry_count_label(deleted)}; {failed} failure(s)",
                severity="error",
            )
        else:
            self.notify(f"Deleted {self.ldap_entry_count_label(deleted)}")
        await self.refresh_current_directory_search()
