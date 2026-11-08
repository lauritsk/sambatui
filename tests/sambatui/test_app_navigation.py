import asyncio

from hypothesis import given
from hypothesis import strategies as st
from textual.widgets import Button, DataTable

from sambatui.app import SambatuiApp
from sambatui.app_actions import (
    ACTIONS,
    APP_BINDINGS,
    PALETTE_ACTION_MAP,
    PALETTE_ACTIONS,
)
from sambatui.core.models import DnsRow
from sambatui.core.remediation import actionable_error
from sambatui.ldap.rows import DirectoryRow
from sambatui.ldap.sidebar import ldap_structure_labels
from sambatui.smart_views import SmartViewRow
from sambatui.ui.screens import (
    CommandPaletteScreen,
    command_palette_choice_matches,
)


def test_action_registry_derives_bindings_and_palette_routes() -> None:
    assert SambatuiApp.BINDINGS == list(APP_BINDINGS)
    assert len({action.action_id for action in ACTIONS}) == len(ACTIONS)
    assert len({action.binding for action in ACTIONS if action.binding}) == len(
        APP_BINDINGS
    )
    assert {choice[0] for choice in PALETTE_ACTIONS} == set(PALETTE_ACTION_MAP)


@given(st.sampled_from([("dns_tab", "DNS:"), ("ldap_tab", "LDAP:")]))
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
            ("Kerberos ticket expired", "renew the Kerberos ticket"),
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
            dns_findings = app.query_one("#dns_findings", DataTable)
            ldap_findings = app.query_one("#ldap_findings", DataTable)
            assert dns_findings.row_count == 3
            assert ldap_findings.row_count == 4
            assert len(dns_findings.get_row_at(0)) == 1
            assert len(ldap_findings.get_row_at(0)) == 1
            app.set_val("ldap_base", "DC=example,DC=com")
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
            attributes={"uSNChanged": ("17",)},
        ),
        DirectoryRow(
            dn="OU=Servers,DC=example,DC=com",
            kind="ou",
            name="Servers",
            summary="",
            attributes={"uSNChanged": ("17",)},
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


def test_ldap_directory_rows_support_multi_select_and_escape_clear() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.populate_directory(
                [
                    DirectoryRow(
                        dn="CN=Alice,DC=example,DC=com",
                        kind="user",
                        name="Alice",
                        summary="alice@example.com",
                        attributes={"uSNChanged": ("17",)},
                    ),
                    DirectoryRow(
                        dn="CN=Bob,DC=example,DC=com",
                        kind="user",
                        name="Bob",
                        summary="bob@example.com",
                        attributes={"uSNChanged": ("17",)},
                    ),
                    DirectoryRow(
                        dn="CN=Ops,DC=example,DC=com",
                        kind="group",
                        name="Ops",
                        summary="ops@example.com",
                        attributes={"uSNChanged": ("17",)},
                    ),
                ]
            )
            records = app.query_one("#records", DataTable)
            records.focus()

            severity = str(records.get_row_at(0)[1])
            await pilot.press("space")
            assert app.views.directory.selected_rows == {0}
            assert str(records.get_row_at(0)[0]) == "✓"
            assert str(records.get_row_at(0)[1]) == severity
            indicator = app.query_one("#selection_state")
            assert indicator.display
            assert "1 selected" in str(indicator.render())

            await pilot.press("j")
            await pilot.press("V")
            assert app.views.directory.selected_rows == {0, 1}
            assert str(records.get_row_at(1)[0]) == "✓"

            app.views.dns.selected_rows.add(42)
            await pilot.press("escape")
            assert app.views.directory.selected_rows == set()
            assert app.views.directory.selection_anchor is None
            assert app.views.dns.selected_rows == {42}
            assert not indicator.display

    asyncio.run(run_app())


def smart_row(name: str, *, source: str = "dns") -> SmartViewRow:
    return SmartViewRow(
        severity="medium",
        object=name,
        finding="Finding",
        evidence="Evidence",
        suggested_action="Fix it",
        source=source,
        fix_action="dns_add_ptr",
    )


def test_ldap_directory_selection_clears_on_sort() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            app.populate_directory(
                [
                    DirectoryRow(
                        dn="CN=Bob,DC=example,DC=com",
                        kind="user",
                        name="Bob",
                        summary="bob@example.com",
                        attributes={"uSNChanged": ("17",)},
                    ),
                    DirectoryRow(
                        dn="CN=Alice,DC=example,DC=com",
                        kind="user",
                        name="Alice",
                        summary="alice@example.com",
                        attributes={"uSNChanged": ("17",)},
                    ),
                ]
            )
            app.set_directory_selected(0, True)
            app.set_directory_selected(1, True)

            app.sort_directory("name")

            assert app.views.directory.selected_rows == set()
            records = app.query_one("#records", DataTable)
            assert [str(records.get_row_at(index)[2]) for index in range(2)] == [
                "Alice",
                "Bob",
            ]
            assert str(records.get_row_at(0)[0]) != "✓"

    asyncio.run(run_app())


def test_dns_multi_select_still_works() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.populate_records(
                [
                    DnsRow("www", "1", "0", "A", "192.0.2.10", "3600", "raw"),
                    DnsRow("db", "1", "0", "A", "192.0.2.20", "3600", "raw"),
                ]
            )
            records = app.query_one("#records", DataTable)
            records.focus()

            await pilot.press("space")
            await pilot.press("j")
            await pilot.press("V")

            assert app.views.dns.selected_rows == {0, 1}
            assert app.views.directory.selected_rows == set()
            assert [str(records.get_row_at(index)[0]) for index in range(2)] == [
                "✓",
                "✓",
            ]

            await pilot.press("escape")
            assert app.views.dns.selected_rows == set()

    asyncio.run(run_app())


def test_smart_view_multi_select_works_for_dns_and_ldap_findings() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.populate_smart_view(
                "Findings",
                [smart_row("dns-a", source="dns"), smart_row("ldap-a", source="ldap")],
            )
            records = app.query_one("#records", DataTable)
            records.focus()

            await pilot.press("space")
            await pilot.press("j")
            await pilot.press("V")

            assert app.views.smart.selected_rows == {0, 1}
            assert app.views.dns.selected_rows == set()
            assert app.views.directory.selected_rows == set()
            assert app.selection_count_label() == "2 smart findings"
            assert [row.object for row in app.selected_smart_rows_for_fix()] == [
                "dns-a",
                "ldap-a",
            ]
            assert [str(records.get_row_at(index)[0]) for index in range(2)] == [
                "✓",
                "✓",
            ]

            await pilot.press("escape")
            assert app.views.smart.selected_rows == set()

    asyncio.run(run_app())


def test_selection_helpers_cover_smart_and_invalid_directory_edges() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            app.populate_directory(
                [
                    DirectoryRow(
                        dn="CN=Alice,DC=example,DC=com",
                        kind="user",
                        name="Alice",
                        summary="alice@example.com",
                        attributes={"uSNChanged": ("17",)},
                    )
                ]
            )
            views = app.views
            app.set_directory_selected(99, True)
            assert views.directory.selected_rows == set()

            views.mode = "dns"
            views.directory.selected_rows.add(0)
            app.clear_directory_selection()
            assert views.directory.selected_rows == set()

            views.mode = "smart"
            views.visual_selecting = True
            views.dns.selection_anchor = 1
            views.directory.selection_anchor = 2
            views.smart.selection_anchor = 3
            views.smart.selected_rows.add(0)
            app.clear_current_selection()
            assert views.visual_selecting is False
            assert views.dns.selection_anchor == 1
            assert views.directory.selection_anchor == 2
            assert views.smart.selection_anchor is None
            assert views.smart.selected_rows == set()

            views.mode = "other"
            views.visual_selecting = True
            views.smart.selection_anchor = 3
            app.clear_current_selection()
            assert views.visual_selecting is False
            assert views.dns.selection_anchor is None
            assert views.directory.selection_anchor is None
            assert views.smart.selection_anchor is None

            records = app.query_one("#records", DataTable)
            records.clear()
            views.mode = "directory"
            app.select_directory_range(0, 1)
            assert views.directory.selected_rows == set()
            views.mode = "smart"
            app.set_smart_selected(99, True)
            app.select_smart_range(0, 1)
            assert views.smart.selected_rows == set()
            views.mode = "dns"
            views.smart.selected_rows.add(0)
            app.clear_smart_selection()
            assert views.smart.selected_rows == set()
            assert app.selected_smart_rows_for_fix() == []

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
                    attributes={"uSNChanged": ("17",)},
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
            app.set_val("server", "dc01.example.com")
            app.set_val("user", "admin@example.com")
            app.set_val("password", "secret")
            app.views.smart.view_id = "ldap_inactive_users"
            app.views.smart.max_rows = 200
            app.views.smart.values = {
                "days": "90",
                "base_dn": "DC=example,DC=com",
                "ldap_encryption": "ldaps",
                "max_rows": "200",
            }
            app.populate_smart_view("LDAP inactive enabled users", [])

            assert await app.load_more_current_view()

            assert app.views.mode == "smart"
            assert app.views.smart.view_id == "ldap_inactive_users"
            assert app.views.smart.max_rows == 400
            assert app.views.smart.values["max_rows"] == "400"
            assert app.query_one("#records", DataTable).row_count == 400
            assert app.search_limits == [400]
            assert not app.views.directory.values

            app.return_no_rows = True
            await app.refresh_current_smart_view()
            assert app.search_limits == [400, 400]

            app.views.smart.values = {}
            app.views.smart.view_id = "ldap_inactive_users"
            await app.refresh_current_smart_view()

            app.views.smart.view_id = ""
            assert not await app.load_more_current_view()

            app.views.smart.values = {"max_rows": "5000"}
            app.views.smart.view_id = "ldap_inactive_users"
            app.views.smart.max_rows = 5000
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
                    attributes={"uSNChanged": ("17",)},
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
                "max_rows": "200",
            }
            app.set_val("server", "dc01.example.com")
            app.set_val("user", "admin@example.com")
            app.set_val("password", "secret")

            assert await app.run_directory_search(values)
            assert app.query_one("#records", DataTable).row_count == 200

            assert await app.load_more_directory()
            assert app.query_one("#records", DataTable).row_count == 400

            await app.action_refresh()

            assert app.search_limits == [200, 400, 400]
            assert app.views.directory.max_rows == 400

    asyncio.run(run_app())
