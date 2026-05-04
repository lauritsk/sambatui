from __future__ import annotations

import asyncio

from textual import work

from ..ldap_directory import (
    LDAP_ADD_KINDS,
    LDAP_EDITABLE_ATTRIBUTES,
    DirectoryRow,
    LdapDirectoryClient,
    domain_to_base_dn,
    ldap_dn_in_scope,
)
from ..remediation import bounded_int
from ..screens import (
    FormField,
)
from ..app_constants import (
    DEFAULT_LDAP_COMPATIBILITY,
    DEFAULT_LDAP_ENCRYPTION,
    DEFAULT_SMART_MAX_ROWS,
    LDAP_DEFAULT_MAX_ROWS,
    LDAP_LOAD_MORE_ROWS,
    LDAP_MAX_ROWS,
)
from .base import AppControllerBase
from .helpers import (
    ldap_limit_suffix,
)


class AppLdapActionsMixin(AppControllerBase):
    def ldap_base_default(self) -> str:
        return self.val("ldap_base") or domain_to_base_dn(
            self.connection_domain_default() or self.val("zone")
        )

    def ldap_connection_fields(self, base_dn: str) -> list[FormField]:
        return [
            ("Base DN", "base_dn", "DC=example,DC=com", base_dn),
            (
                "LDAP encryption",
                "ldap_encryption",
                "off | ldaps | starttls",
                self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            ),
            (
                "LDAP compatibility — only if DC needs relaxed TLS/schema; with password auth prefer UPN user",
                "ldap_compatibility",
                "on | off",
                self.val("ldap_compatibility") or DEFAULT_LDAP_COMPATIBILITY,
            ),
        ]

    def smart_max_rows_field(self) -> FormField:
        return (
            "Max rows",
            "max_rows",
            "500",
            self.val("smart_max_rows") or DEFAULT_SMART_MAX_ROWS,
        )

    def ldap_search_fields(self, default_kind: str = "users") -> list[FormField]:
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
                str(self.current_directory_max_rows),
            ),
        ]

    def apply_ldap_connection_values(
        self, values: dict[str, str], *, refresh_sidebar: bool = True
    ) -> None:
        if values["base_dn"].casefold() != self.val("ldap_base").casefold():
            self.ldap_structure_rows = []
        self.set_val("ldap_base", values["base_dn"])
        self.set_val("ldap_encryption", values["ldap_encryption"])
        self.set_val("ldap_compatibility", values["ldap_compatibility"])
        if refresh_sidebar:
            self.populate_ldap_structure(self.ldap_structure_rows)
        self.save_preferences()

    async def directory_search_rows(
        self,
        client: LdapDirectoryClient,
        kind: str,
        text: str,
        max_entries: int | None = None,
    ) -> list[DirectoryRow] | None:
        async with self.busy():
            try:
                return await asyncio.to_thread(client.search, kind, text, max_entries)
            except ValueError as exc:
                self.report_error(str(exc))
                return None

    async def directory_container_rows(
        self, client: LdapDirectoryClient
    ) -> list[DirectoryRow]:
        async with self.busy():
            try:
                return await asyncio.to_thread(client.child_containers, LDAP_MAX_ROWS)
            except ValueError:
                return []

    def ldap_search_max_rows(self, values: dict[str, str]) -> int:
        return bounded_int(
            values.get("max_rows", ""), LDAP_DEFAULT_MAX_ROWS, maximum=LDAP_MAX_ROWS
        )

    async def run_directory_search(
        self,
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
        rows = await self.directory_search_rows(client, kind, values["text"], limit)
        if rows is None:
            return False
        container_rows = await self.directory_container_rows(client)
        self.current_directory_values = {**values, "kind": kind, "max_rows": str(limit)}
        self.current_directory_max_rows = limit
        self.set_search_text("", refresh=False)
        self.remember_ldap_structure_rows(container_rows)
        self.populate_directory(rows)
        self.set_status(
            f"{action} {len(rows)} LDAP entries "
            f"(limit {limit}){ldap_limit_suffix(len(rows), limit)}"
        )
        self.notify(f"{action} {len(rows)} LDAP entries")
        return True

    async def open_ldap_search(self, default_kind: str = "users") -> None:
        values = await self.form(
            "Search AD directory",
            "LDAP via ldap3. Password bind requires LDAPS/StartTLS; UPN usernames work best.",
            self.ldap_search_fields(default_kind),
            "Search",
        )
        if not values:
            return
        await self.run_directory_search(values, default_kind=default_kind)

    async def refresh_current_directory_search(self) -> bool:
        if not self.current_directory_values:
            self.set_status("No LDAP search to refresh. Press L to search directory.")
            return False
        return await self.run_directory_search(
            self.current_directory_values,
            max_rows=self.current_directory_max_rows,
            action="Refreshed",
        )

    async def load_more_directory(self) -> bool:
        if not self.current_directory_values:
            self.set_status("No LDAP search to extend. Press L to search directory.")
            return False
        max_rows = min(
            self.current_directory_max_rows + LDAP_LOAD_MORE_ROWS, LDAP_MAX_ROWS
        )
        if max_rows == self.current_directory_max_rows:
            self.set_status(f"LDAP row limit already at {LDAP_MAX_ROWS}.")
            return False
        return await self.run_directory_search(
            self.current_directory_values,
            max_rows=max_rows,
            action="Loaded",
        )

    @work
    async def action_ldap_search(self) -> None:
        await self.open_ldap_search()

    @work
    async def action_ldap_search_kind(self, kind: str) -> None:
        await self.open_ldap_search(kind)

    @work
    async def action_load_more_directory(self) -> None:
        await self.load_more_directory()

    def selected_directory_row(self) -> DirectoryRow | None:
        row = self.visible_row_at(self.visible_directory(), self.records_cursor_row())
        if row is None:
            self.notify("Select an LDAP entry first.", severity="error")
        return row

    def ldap_editable_attributes(self, row: DirectoryRow) -> tuple[str, ...]:
        return LDAP_EDITABLE_ATTRIBUTES.get(row.kind, ())

    def ldap_attribute_value(self, row: DirectoryRow, attr: str) -> str:
        values = row.attributes.get(attr, ())
        return values[0] if values else ""

    def ldap_edit_fields(self, row: DirectoryRow) -> list[FormField]:
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
        self, row: DirectoryRow, values: dict[str, str]
    ) -> dict[str, str]:
        return {
            attr: values[attr]
            for attr in self.ldap_editable_attributes(row)
            if values[attr] != self.ldap_attribute_value(row, attr)
        }

    def ldap_edit_preview(self, row: DirectoryRow, changes: dict[str, str]) -> str:
        lines = [
            f"{attr}: {self.ldap_attribute_value(row, attr) or '<empty>'} -> "
            f"{value or '<delete>'}"
            for attr, value in changes.items()
        ]
        return "\n".join(["Edit LDAP entry?", "", f"DN: {row.dn}", *lines])

    async def update_ldap_entry(self) -> None:
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
        async with self.busy():
            try:
                await asyncio.to_thread(
                    self.ldap_client().modify_attributes, row.dn, changes
                )
            except ValueError as exc:
                self.report_error(str(exc))
                return
        self.notify("LDAP entry updated")
        await self.refresh_current_directory_search()

    def ldap_add_parent_dn(self) -> str:
        return (
            self.current_directory_values.get("search_base_dn")
            or self.current_directory_values.get("base_dn")
            or self.ldap_base_default()
        )

    def ldap_add_fields(self) -> list[FormField]:
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

    def ldap_add_error(self, values: dict[str, str]) -> str | None:
        kind = values.get("kind", "").casefold()
        if kind not in LDAP_ADD_KINDS:
            return f"Choose LDAP type: {', '.join(LDAP_ADD_KINDS)}."
        parent_dn = values.get("parent_dn", "").strip()
        if not parent_dn:
            return "Enter LDAP parent DN."
        configured_base_dn = (
            self.current_directory_values.get("base_dn") or self.ldap_base_default()
        ).strip()
        if configured_base_dn and not ldap_dn_in_scope(parent_dn, configured_base_dn):
            return f"Parent DN must be at or below LDAP base: {configured_base_dn}."
        search_base_dn = self.current_directory_values.get("search_base_dn", "").strip()
        if search_base_dn and not ldap_dn_in_scope(parent_dn, search_base_dn):
            return f"Parent DN must be at or below LDAP search base: {search_base_dn}."
        if not values.get("name", "").strip():
            return "Enter LDAP object name."
        return None

    def ldap_add_attributes(self, values: dict[str, str]) -> dict[str, str]:
        return {
            attr: values.get(attr, "").strip()
            for attr in ("sAMAccountName", "userPrincipalName", "mail", "description")
        }

    def ldap_add_preview(self, values: dict[str, str]) -> str:
        attrs = self.ldap_add_attributes(values)
        lines = [f"{attr}: {value}" for attr, value in attrs.items() if value]
        return "\n".join(
            [
                "Add LDAP entry?",
                "",
                f"Type: {values['kind'].casefold()}",
                f"Parent DN: {values['parent_dn']}",
                f"Name: {values['name']}",
                *lines,
            ]
        )

    async def add_ldap_entry(self) -> None:
        values = await self.form(
            "Add LDAP entry",
            "Create a user, group, computer, or OU under the chosen parent DN.",
            self.ldap_add_fields(),
            "Preview",
            self.ldap_add_error,
        )
        if not values:
            return
        if not await self.confirm(self.ldap_add_preview(values), default_confirm=True):
            self.notify("LDAP add cancelled")
            return
        async with self.busy():
            try:
                dn = await asyncio.to_thread(
                    self.ldap_client().add_entry,
                    values["kind"],
                    values["parent_dn"],
                    values["name"],
                    self.ldap_add_attributes(values),
                )
            except ValueError as exc:
                self.report_error(str(exc))
                return
        self.notify(f"LDAP entry added: {dn}")
        await self.refresh_current_directory_search()

    def ldap_delete_preview(self, row: DirectoryRow) -> str:
        return (
            "DELETE selected LDAP entry?\n\n"
            f"Name: {row.name}\nKind: {row.kind}\nDN: {row.dn}\n\n"
            "This cannot be undone from this app. Non-empty containers may fail."
        )

    async def delete_ldap_entry(self) -> None:
        row = self.selected_directory_row()
        if row is None:
            return
        if not await self.confirm(self.ldap_delete_preview(row)):
            self.notify("LDAP delete cancelled")
            return
        async with self.busy():
            try:
                await asyncio.to_thread(self.ldap_client().delete_entry, row.dn)
            except ValueError as exc:
                self.report_error(str(exc))
                return
        self.notify("LDAP entry deleted")
        await self.refresh_current_directory_search()
