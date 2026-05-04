import asyncio
from contextlib import suppress
from typing import Any, cast


from sambatui.app import (
    SambatuiApp,
)
from textual.widgets import DataTable, Input

from sambatui.ldap.client import DirectoryRow, LdapDirectoryClient
from sambatui.ui.screens import (
    FormField,
    FormValidator,
)


def test_update_ldap_entry_edits_changed_allowlisted_attributes() -> None:
    class FakeLdapClient:
        def __init__(self, app: Any) -> None:
            self.app = app

        def modify_attributes(self, dn: str, changes: dict[str, str]) -> None:
            self.app.modified = (dn, changes)

    class LdapEditApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.modified: tuple[str, dict[str, str]] | None = None
            self.confirm_message = ""
            self.refreshed = False

        async def form(
            self,
            title: str,
            hint: str,
            fields: list[FormField],
            submit_label: str = "Continue",
            validator: FormValidator | None = None,
        ) -> dict[str, str] | None:
            assert title == "Edit LDAP entry"
            assert hint == "CN=Alice,DC=example,DC=com"
            assert fields == [
                (
                    "displayName",
                    "displayName",
                    "new value; leave blank to delete attribute",
                    "Alice",
                ),
                (
                    "mail",
                    "mail",
                    "new value; leave blank to delete attribute",
                    "alice@example.com",
                ),
                (
                    "description",
                    "description",
                    "new value; leave blank to delete attribute",
                    "same",
                ),
            ]
            return {"displayName": "Alice Admin", "mail": "", "description": "same"}

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            self.confirm_message = message
            assert default_confirm is True
            return True

        def ldap_client(self, base_dn: str = "") -> Any:
            return FakeLdapClient(self)

        async def refresh_current_directory_search(self) -> bool:
            self.refreshed = True
            return True

    async def run_app() -> None:
        app = LdapEditApp()
        async with app.run_test():
            app.populate_directory(
                [
                    DirectoryRow(
                        dn="CN=Alice,DC=example,DC=com",
                        kind="user",
                        name="Alice",
                        summary="alice@example.com",
                        attributes={
                            "displayName": ("Alice",),
                            "mail": ("alice@example.com",),
                            "description": ("same",),
                        },
                    )
                ]
            )

            await app.update_ldap_entry()

            assert app.modified == (
                "CN=Alice,DC=example,DC=com",
                {"displayName": "Alice Admin", "mail": ""},
            )
            assert "displayName: Alice -> Alice Admin" in app.confirm_message
            assert "mail: alice@example.com -> <delete>" in app.confirm_message
            assert app.refreshed

    asyncio.run(run_app())


def test_add_ldap_entry_creates_entry_and_refreshes() -> None:
    class FakeLdapClient:
        def __init__(self, app: Any) -> None:
            self.app = app

        def add_entry(
            self, kind: str, parent_dn: str, name: str, attributes: dict[str, str]
        ) -> str:
            self.app.added = (kind, parent_dn, name, attributes)
            return f"CN={name},{parent_dn}"

    class LdapAddApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.added: tuple[str, str, str, dict[str, str]] | None = None
            self.confirm_message = ""
            self.refreshed = False

        async def form(
            self,
            title: str,
            hint: str,
            fields: list[FormField],
            submit_label: str = "Continue",
            validator: FormValidator | None = None,
        ) -> dict[str, str] | None:
            assert title == "Add LDAP entry"
            assert submit_label == "Preview"
            assert validator is not None
            values = {
                "kind": "user",
                "parent_dn": "CN=Users,DC=example,DC=com",
                "name": "Alice",
                "sAMAccountName": "alice",
                "userPrincipalName": "alice@example.com",
                "mail": "",
                "description": "Admin",
            }
            assert validator(values) is None
            return values

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            self.confirm_message = message
            assert default_confirm is True
            return True

        def ldap_client(self, base_dn: str = "") -> Any:
            assert base_dn == ""
            return FakeLdapClient(self)

        async def refresh_current_directory_search(self) -> bool:
            self.refreshed = True
            return True

    async def run_app() -> None:
        app = LdapAddApp()
        async with app.run_test():
            app.current_directory_values = {"base_dn": "DC=example,DC=com"}
            await app.add_ldap_entry()

            assert app.added == (
                "user",
                "CN=Users,DC=example,DC=com",
                "Alice",
                {
                    "sAMAccountName": "alice",
                    "userPrincipalName": "alice@example.com",
                    "mail": "",
                    "description": "Admin",
                },
            )
            assert "Add LDAP entry?" in app.confirm_message
            assert app.refreshed

    asyncio.run(run_app())


def test_ldap_add_error_rejects_parent_outside_current_search_base() -> None:
    app = SambatuiApp()
    app.current_directory_values = {
        "base_dn": "DC=example,DC=com",
        "search_base_dn": "OU=Users,DC=example,DC=com",
    }

    error = app.ldap_add_error(
        {"kind": "user", "parent_dn": "OU=Other,DC=example,DC=com", "name": "Alice"}
    )

    assert (
        error
        == "Parent DN must be at or below LDAP search base: OU=Users,DC=example,DC=com."
    )
    assert (
        app.ldap_add_error(
            {"kind": "user", "parent_dn": "OU=Other,DC=evil,DC=com", "name": "Alice"}
        )
        == "Parent DN must be at or below LDAP base: DC=example,DC=com."
    )
    assert (
        app.ldap_add_error(
            {
                "kind": "user",
                "parent_dn": "CN=Staff, OU=Users, DC=example,DC=com",
                "name": "Alice",
            }
        )
        is None
    )


def test_delete_ldap_entry_deletes_selected_dn() -> None:
    class FakeLdapClient:
        def __init__(self, app: Any) -> None:
            self.app = app

        def delete_entry(self, dn: str) -> None:
            self.app.deleted = dn

    class LdapDeleteApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.deleted = ""
            self.confirm_message = ""
            self.refreshed = False

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            self.confirm_message = message
            return True

        def ldap_client(self, base_dn: str = "") -> Any:
            return FakeLdapClient(self)

        async def refresh_current_directory_search(self) -> bool:
            self.refreshed = True
            return True

    async def run_app() -> None:
        app = LdapDeleteApp()
        async with app.run_test():
            app.populate_directory(
                [
                    DirectoryRow(
                        dn="CN=Alice,DC=example,DC=com",
                        kind="user",
                        name="Alice",
                        summary="alice@example.com",
                        attributes={},
                    )
                ]
            )

            await app.delete_ldap_entry()

            assert app.deleted == "CN=Alice,DC=example,DC=com"
            assert "DELETE selected LDAP entry?" in app.confirm_message
            assert app.refreshed

    asyncio.run(run_app())


def test_ldap_container_expansion_failure_does_not_report_error() -> None:
    class FailingContainerClient:
        def child_containers(
            self, max_entries: int | None = None
        ) -> list[DirectoryRow]:
            raise ValueError("LDAP search failed: insufficientAccessRights")

    class ContainerApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.errors: list[str] = []

        def report_error(self, message: str) -> None:
            self.errors.append(message)

    async def run_app() -> None:
        app = ContainerApp()
        async with app.run_test():
            app.errors.clear()
            rows = await app.directory_container_rows(
                cast(LdapDirectoryClient, FailingContainerClient())
            )

            assert rows == []
            assert app.errors == []

    asyncio.run(run_app())


def test_ldap_sidebar_uses_root_and_discovered_tree_rows() -> None:
    class SidebarApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.searches: list[tuple[str, str, int | None]] = []
            self.search_bases: list[str] = []
            self.sidebar_cursor_rows: list[int] = []

        def save_preferences(self) -> None:
            return

        def populate_ldap_structure(self, rows) -> None:
            super().populate_ldap_structure(rows)
            with suppress(Exception):
                self.sidebar_cursor_rows.append(
                    self.query_one("#ldap_structure", DataTable).cursor_row
                )

        async def directory_search_rows(
            self,
            client,
            kind: str,
            text: str,
            max_entries: int | None = None,
        ) -> list[DirectoryRow] | None:
            self.searches.append((kind, text, max_entries))
            self.search_bases.append(client.config.base_dn)
            if client.config.base_dn in {
                "CN=Users,DC=example,DC=com",
                "OU=Departments,DC=example,DC=com",
            }:
                return []
            return [
                DirectoryRow(
                    dn="CN=Ops,CN=Users,DC=example,DC=com",
                    kind="group",
                    name="Ops",
                    summary="",
                    attributes={},
                )
            ]

        async def directory_container_rows(self, client) -> list[DirectoryRow]:
            containers = {
                "DC=example,DC=com": [
                    DirectoryRow(
                        dn="CN=Users,DC=example,DC=com",
                        kind="container",
                        name="Users",
                        summary="",
                        attributes={},
                    ),
                    DirectoryRow(
                        dn="OU=Departments,DC=example,DC=com",
                        kind="ou",
                        name="Departments",
                        summary="",
                        attributes={},
                    ),
                ],
                "OU=Departments,DC=example,DC=com": [
                    DirectoryRow(
                        dn="OU=Engineering,OU=Departments,DC=example,DC=com",
                        kind="ou",
                        name="Engineering",
                        summary="",
                        attributes={},
                    )
                ],
            }
            return containers.get(client.config.base_dn, [])

    async def run_app() -> None:
        app = SidebarApp()
        async with app.run_test():
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#user", Input).value = "admin@example.com"
            app.query_one("#password", Input).value = "secret"
            app.query_one("#ldap_base", Input).value = "DC=example,DC=com"
            app.populate_ldap_structure([])
            structure = app.query_one("#ldap_structure", DataTable)

            # Root is preloaded and acts as the all-entries load/refresh action.
            assert str(structure.get_row_at(0)[0]) == "DC=example,DC=com"
            assert await app.activate_sidebar_selection(structure)
            assert app.searches == [("all", "", 200)]
            assert app.search_bases == ["DC=example,DC=com"]

            records = app.query_one("#records", DataTable)
            assert app.view_mode == "directory"
            assert str(records.get_row_at(0)[1]) == "Ops"
            assert structure.row_count == 3
            assert str(structure.get_row_at(1)[0]) == "  CN=Users"
            assert str(structure.get_row_at(2)[0]) == "  OU=Departments"

            # Discovered structure rows remain actionable; no synthetic Users/Groups rows.
            app.sidebar_cursor_rows.clear()
            structure.move_cursor(row=1)
            assert await app.activate_sidebar_selection(structure)
            assert app.searches[-1] == ("all", "", 200)
            assert app.search_bases[-1] == "CN=Users,DC=example,DC=com"
            assert app.query_one("#records", DataTable).row_count == 1
            assert str(app.query_one("#records", DataTable).get_row_at(0)[1]) == (
                "No LDAP entries shown"
            )
            assert structure.row_count == 3
            assert structure.cursor_row == 1
            assert app.sidebar_cursor_rows == [1]

            app.sidebar_cursor_rows.clear()
            structure.move_cursor(row=2)
            assert await app.activate_sidebar_selection(structure)
            assert app.search_bases[-1] == "OU=Departments,DC=example,DC=com"
            assert str(structure.get_row_at(3)[0]) == "    OU=Engineering"
            assert structure.cursor_row == 2
            assert app.sidebar_cursor_rows == [2]

    asyncio.run(run_app())
