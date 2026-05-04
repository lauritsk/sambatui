import asyncio

from hypothesis import given
from hypothesis import strategies as st

from sambatui.app import (
    SambatuiApp,
    actionable_error,
    ldap_structure_labels,
)
from textual.widgets import Button, DataTable, Input

from sambatui.ldap.client import DirectoryRow
from sambatui.smart_views import SmartViewRow
from sambatui.ui.screens import (
    CommandPaletteScreen,
    command_palette_choice_matches,
)


@given(
    st.sampled_from(
        [("dns_tab", "DNS:"), ("ldap_tab", "LDAP:"), ("smart_tab", "Smart:")]
    )
)
def test_key_hints_change_by_side_tab(case: tuple[str, str]) -> None:
    tab, prefix = case
    app = SambatuiApp()

    assert app.keys_hint_for_tab(tab).startswith(prefix)


@given(
    st.sampled_from(
        [
            (
                "LDAP bind failed: invalidCredentials",
                "Action: check credentials, UPN username format, encryption, or Kerberos ticket.",
            ),
            ("Kerberos ticket expired", "run kinit"),
            ("", ""),
        ]
    )
)
def test_actionable_error_adds_concise_remediation(case: tuple[str, str]) -> None:
    message, expected = case

    assert expected in actionable_error(message)


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


@given(
    st.sampled_from(
        [("ldap users", True), ("prefilled", True), ("dns zone", False), ("", True)]
    )
)
def test_command_palette_search_matches_label_shortcut_and_description(
    case: tuple[str, bool],
) -> None:
    query, expected = case
    choice = (
        "ldap_search_users",
        "Search LDAP users",
        "",
        "Open LDAP search prefilled for users.",
    )

    assert command_palette_choice_matches(choice, query) is expected


@given(st.sampled_from([("dns", ["add_record"]), ("search", ["ldap_search"])]))
def test_command_palette_filters_choices(case: tuple[str, list[str]]) -> None:
    query, expected_ids = case
    screen = CommandPaletteScreen(
        [
            ("add_record", "Add DNS record", "a", "Create a DNS record."),
            ("ldap_search", "Search LDAP directory", "L", "Search AD entries."),
        ]
    )

    assert [choice[0] for choice in screen.matching_choices(query)] == expected_ids


def test_sidebar_uses_current_list_widgets() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            assert list(app.query(Button)) == []
            assert app.query_one("#zones", DataTable).row_count == 1
            assert app.query_one("#smart_views", DataTable).row_count == 8
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


def test_smart_view_load_more_preserves_active_smart_view() -> None:
    class SmartLoadMoreApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.search_limits: list[int | None] = []
            self.return_no_rows = False

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
            if self.return_no_rows:
                return None
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

        def ldap_smart_rows(
            self, view_id, directory_rows, options
        ) -> list[SmartViewRow]:
            return [
                SmartViewRow(
                    severity="info",
                    source="ldap",
                    object=row.name,
                    finding=f"Finding {index}",
                    evidence=row.dn,
                    suggested_action="Review user.",
                )
                for index, row in enumerate(directory_rows)
            ]

    async def run_app() -> None:
        app = SmartLoadMoreApp()
        async with app.run_test():
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#user", Input).value = "admin@example.com"
            app.query_one("#password", Input).value = "secret"
            app.current_smart_view_id = "ldap_inactive_users"
            app.current_smart_max_rows = 200
            app.current_smart_values = {
                "days": "90",
                "base_dn": "DC=example,DC=com",
                "ldap_encryption": "ldaps",
                "ldap_compatibility": "off",
                "max_rows": "200",
            }
            app.populate_smart_view("LDAP inactive enabled users", [])

            assert await app.load_more_current_view()

            assert app.view_mode == "smart"
            assert app.current_smart_view_id == "ldap_inactive_users"
            assert app.current_smart_max_rows == 400
            assert app.current_smart_values["max_rows"] == "400"
            assert app.query_one("#records", DataTable).row_count == 400
            assert app.search_limits == [400]
            assert not app.current_directory_values

            app.return_no_rows = True
            await app.refresh_current_smart_view()
            assert app.search_limits == [400, 400]

            app.current_smart_values = {}
            app.current_smart_view_id = "ldap_inactive_users"
            await app.refresh_current_smart_view()

            app.current_smart_view_id = ""
            assert not await app.load_more_current_view()

            app.current_smart_values = {"max_rows": "5000"}
            app.current_smart_view_id = "ldap_inactive_users"
            app.current_smart_max_rows = 5000
            assert not await app.load_more_current_view()

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
