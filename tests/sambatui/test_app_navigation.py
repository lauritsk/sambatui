import asyncio


from sambatui.app import (
    SambatuiApp,
    actionable_error,
    ldap_structure_labels,
)
from textual.widgets import Button, DataTable, Input

from sambatui.ldap.client import DirectoryRow
from sambatui.ui.screens import (
    CommandPaletteScreen,
    command_palette_choice_matches,
)


def test_key_hints_change_by_side_tab() -> None:
    app = SambatuiApp()

    assert app.keys_hint_for_tab("dns_tab").startswith("DNS:")
    assert app.keys_hint_for_tab("ldap_tab").startswith("LDAP:")
    assert app.keys_hint_for_tab("smart_tab").startswith("Smart:")


def test_actionable_error_adds_concise_remediation() -> None:
    assert actionable_error("LDAP bind failed: invalidCredentials").endswith(
        "Action: check credentials, UPN username format, encryption, or Kerberos ticket."
    )
    assert "run kinit" in actionable_error("Kerberos ticket expired")
    assert actionable_error("") == ""


def test_report_error_disables_markup_for_raw_command_output() -> None:
    class ErrorApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.notifications = []

        def notify(
            self,
            message: str,
            *,
            title: str = "",
            severity: str = "information",
            timeout: float | None = None,
            markup: bool = True,
        ) -> None:
            self.notifications.append(
                {
                    "message": message,
                    "title": title,
                    "severity": severity,
                    "timeout": timeout,
                    "markup": markup,
                }
            )

    app = ErrorApp()

    app.report_error(
        "Failed to bind to uuid 50abc2a4-574d-40b3-9d66-ee4fd5fba076 "
        "[ncalrpc:=50abc2a4-574d-40b3-9d66-ee4fd5fba076/0x00000005,lo]"
    )

    assert app.notifications[0]["severity"] == "error"
    assert app.notifications[0]["markup"] is False


def test_command_palette_search_matches_label_shortcut_and_description() -> None:
    choice = (
        "ldap_search_users",
        "Search LDAP users",
        "",
        "Open LDAP search prefilled for users.",
    )

    assert command_palette_choice_matches(choice, "ldap users")
    assert command_palette_choice_matches(choice, "prefilled")
    assert not command_palette_choice_matches(choice, "dns zone")


def test_command_palette_filters_choices() -> None:
    screen = CommandPaletteScreen(
        [
            ("add_record", "Add DNS record", "a", "Create a DNS record."),
            ("ldap_search", "Search LDAP directory", "L", "Search AD entries."),
        ]
    )

    assert [choice[0] for choice in screen.matching_choices("dns")] == ["add_record"]
    assert [choice[0] for choice in screen.matching_choices("search")] == [
        "ldap_search"
    ]


def test_sidebar_uses_current_list_widgets() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            assert list(app.query(Button)) == []
            assert app.query_one("#zones", DataTable).row_count == 1
            app.query_one("#ldap_base", Input).value = "DC=example,DC=com"
            app.populate_ldap_structure([])
            assert app.query_one("#ldap_structure", DataTable).row_count == 1

    asyncio.run(run_app())


def test_ldap_structure_labels_show_base_and_containers() -> None:
    rows = [
        DirectoryRow(
            dn="CN=Alice,OU=Engineering,OU=Users,DC=example,DC=com",
            kind="user",
            name="Alice",
            summary="",
            attributes={},
        ),
        DirectoryRow(
            dn="OU=Servers,DC=example,DC=com",
            kind="ou",
            name="Servers",
            summary="",
            attributes={},
        ),
    ]

    assert ldap_structure_labels(rows, "DC=example,DC=com") == [
        "DC=example,DC=com",
        "  OU=Servers",
        "  OU=Users",
        "    OU=Engineering",
    ]


def test_command_palette_routes_to_existing_actions() -> None:
    class PaletteApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.actions: list[str] = []

        async def action_setup_wizard(self) -> None:
            self.actions.append("setup")

        async def action_connection(self) -> None:
            self.actions.append("connection")

        async def action_add(self) -> None:
            self.actions.append("add")

        async def action_ldap_search_kind(self, kind: str) -> None:
            self.actions.append(f"ldap:{kind}")

        async def action_smart_view_shortcut(self, shortcut: str) -> None:
            self.actions.append(f"smart:{shortcut}")

    async def run_app() -> None:
        app = PaletteApp()
        assert await app.run_command_palette_action("setup_wizard")
        assert await app.run_command_palette_action("connection")
        assert await app.run_command_palette_action("add_record")
        assert await app.run_command_palette_action("ldap_search_users")
        assert await app.run_command_palette_action("smart_view_1")
        assert not await app.run_command_palette_action("missing")
        assert app.actions == ["setup", "connection", "add", "ldap:users", "smart:1"]

    asyncio.run(run_app())


def test_ldap_search_fields_accept_default_kind() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            assert app.ldap_search_fields("groups")[0][3] == "groups"

    asyncio.run(run_app())


def test_ldap_search_load_more_and_refresh_reuse_last_search() -> None:
    class DirectoryApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.search_limits: list[int | None] = []

        def save_preferences(self) -> None:
            return

        async def directory_search_rows(
            self,
            client,
            kind: str,
            text: str,
            max_entries: int | None = None,
        ) -> list[DirectoryRow] | None:
            self.search_limits.append(max_entries)
            count = max_entries or 0
            return [
                DirectoryRow(
                    dn=f"CN=User {index},DC=example,DC=com",
                    kind="user",
                    name=f"User {index}",
                    summary="",
                    attributes={},
                )
                for index in range(count)
            ]

        async def directory_container_rows(self, client) -> list[DirectoryRow]:
            return []

    async def run_app() -> None:
        app = DirectoryApp()
        async with app.run_test():
            values = {
                "kind": "users",
                "text": "",
                "base_dn": "DC=example,DC=com",
                "ldap_encryption": "ldaps",
                "ldap_compatibility": "off",
                "max_rows": "200",
            }
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#user", Input).value = "admin@example.com"
            app.query_one("#password", Input).value = "secret"

            assert await app.run_directory_search(values)
            assert app.query_one("#records", DataTable).row_count == 200

            assert await app.load_more_directory()
            assert app.query_one("#records", DataTable).row_count == 400

            await app.action_refresh()

            assert app.search_limits == [200, 400, 400]
            assert app.current_directory_max_rows == 400

    asyncio.run(run_app())
