import asyncio
from contextlib import suppress

from rich.text import Text

from sambatui.app import (
    DnsRow,
    SambatuiApp,
    actionable_error,
    ldap_structure_labels,
    parse_records,
    parse_zones,
    validate_record,
)
from textual.widgets import Button, DataTable, Input, Static

from sambatui.discovery import DiscoveredService
from sambatui.dns import ptr_target_for_name, reverse_record_for_ipv4, valid_dns_name
from sambatui.ldap_directory import DirectoryRow
from sambatui.screens import (
    CommandPaletteScreen,
    ConfirmScreen,
    FormScreen,
    SmartViewPickerScreen,
    command_palette_choice_matches,
)
from sambatui.smart_view_catalog import SmartViewOptions
from sambatui.smart_views import SmartViewRow


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


def test_empty_states_explain_next_actions() -> None:
    class EmptyStateApp(SambatuiApp):
        def connection_domain_default(self) -> str:
            return ""

    async def run_app() -> None:
        app = EmptyStateApp()
        async with app.run_test():
            records = app.query_one("#records", DataTable)
            details = app.query_one("#record_details", Static)
            assert str(records.get_row_at(0)[1]) == "No DNS records shown"
            assert "select zone" in str(records.get_row_at(0)[3])
            assert "No DNS records shown" in str(details.render())

            zones = app.query_one("#zones", DataTable)
            app.populate_zones([])
            assert "press z" in str(zones.get_row_at(0)[0])

            app.populate_directory([])
            assert str(records.get_row_at(0)[1]) == "No LDAP entries shown"
            assert "Press L" in str(records.get_row_at(0)[3])
            assert "No LDAP entries shown" in str(details.render())
            ldap_structure = app.query_one("#ldap_structure", DataTable)
            assert "LDAP base DN" in str(ldap_structure.get_row_at(0)[0])

            app.populate_smart_view("DNS duplicates/conflicts", [])
            assert str(records.get_row_at(0)[1]) == "No smart-view findings shown"
            assert "Press S" in str(records.get_row_at(0)[3])
            assert "No smart-view findings shown" in str(details.render())

    asyncio.run(run_app())


def test_setup_wizard_discovers_checks_and_loads_zones() -> None:
    class SetupApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.saved_preferences = 0
            self.ldap_checked = False

        async def discover_setup_services(self, domain: str) -> list[DiscoveredService]:
            assert domain == "example.com"
            return [
                DiscoveredService(
                    "ldap", "example.com", "dc01.example.com", 389, 0, 100
                )
            ]

        async def run_zonelist(self) -> tuple[int, str]:
            return (
                0,
                """
                pszZoneName : example.com
                pszZoneName : 2.0.192.in-addr.arpa
                """,
            )

        async def check_ldap_connectivity(self) -> str | None:
            self.ldap_checked = True
            return None

        async def run_samba(self, action: str, args: list[str]) -> tuple[int, str]:
            assert (action, args) == ("query", ["@", "ALL"])
            return (
                0,
                """
                Name=www, Records=1, Children=0
                  A: 192.0.2.10 (flags=f0, serial=1, ttl=3600)
                """,
            )

        def save_preferences(self) -> None:
            self.saved_preferences += 1

    async def run_app() -> None:
        app = SetupApp()
        async with app.run_test():
            values = {
                "domain": "Example.COM.",
                "user": r"EXAMPLE\admin",
                "password": "secret",
                "auth": "password",
                "kerberos": "off",
                "ldap_encryption": "ldaps",
                "ldap_compatibility": "off",
            }

            assert await app.run_setup_wizard(values)

            records = app.query_one("#records", DataTable)
            assert app.query_one("#server", Input).value == "dc01.example.com"
            assert app.query_one("#domain", Input).value == "example.com"
            assert app.query_one("#zone", Input).value == "example.com"
            assert app.query_one("#ldap_base", Input).value == "DC=example,DC=com"
            assert app.zones == ["example.com", "2.0.192.in-addr.arpa"]
            assert app.ldap_checked
            assert app.saved_preferences == 1
            assert str(records.get_row_at(0)[1]) == "www"

    asyncio.run(run_app())


def test_setup_wizard_failed_check_explains_next_action() -> None:
    class FailedSetupApp(SambatuiApp):
        async def discover_setup_services(self, domain: str) -> list[DiscoveredService]:
            return [DiscoveredService("ldap", domain, "dc01.example.com", 389, 0, 100)]

        async def run_zonelist(self) -> tuple[int, str]:
            return 1, "NT_STATUS_ACCESS_DENIED"

    async def run_app() -> None:
        app = FailedSetupApp()
        async with app.run_test():
            values = {
                "domain": "example.com",
                "user": r"EXAMPLE\admin",
                "password": "secret",
                "auth": "password",
                "kerberos": "off",
                "ldap_encryption": "ldaps",
                "ldap_compatibility": "off",
            }

            assert not await app.run_setup_wizard(values)

            status = app.query_one("#status", Static)
            assert "Setup DNS check failed" in str(status.render())
            assert "Action: check credentials" in str(status.render())

    asyncio.run(run_app())


def test_reverse_zone_does_not_become_setup_domain_default() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            app.query_one("#domain", Input).value = ""
            app.query_one("#zone", Input).value = "2.0.192.in-addr.arpa"
            app.query_one("#server", Input).value = "dc01.example.com"

            assert app.connection_domain_default() == "example.com"

            app.query_one("#domain", Input).value = "ad.example.com"
            prefs = app.preference_values()

            assert prefs["domain"] == "ad.example.com"
            assert prefs["zone"] == "ad.example.com"
            assert prefs["last_zone"] == "2.0.192.in-addr.arpa"
            assert app.ldap_base_default() == "DC=ad,DC=example,DC=com"

    asyncio.run(run_app())


def test_zone_activation_restores_saved_zone_and_updates_title() -> None:
    class ZoneApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.commands: list[tuple[str, str, list[str]]] = []
            self.saved_preferences = 0

        async def run_zonelist(self) -> tuple[int, str]:
            return (
                0,
                """
                pszZoneName : example.com
                pszZoneName : other.example
                """,
            )

        async def run_samba(self, action: str, args: list[str]) -> tuple[int, str]:
            self.commands.append((self.val("zone"), action, args))
            return (
                0,
                """
                Name=www, Records=1, Children=0
                  A: 192.0.2.10 (flags=f0, serial=1, ttl=3600)
                """,
            )

        def save_preferences(self) -> None:
            self.saved_preferences += 1

    async def run_app() -> None:
        app = ZoneApp()
        async with app.run_test():
            title = app.query_one("#records_title", Static)
            status = app.query_one("#status", Static)
            zone = app.query_one("#zone", Input)

            zone.value = "example.com"
            await app.load_zones()
            assert app.commands[-1] == ("example.com", "query", ["@", "ALL"])
            assert str(title.render()) == "Records — example.com"
            assert "Loaded 1 records from example.com" in str(status.render())
            assert app.saved_preferences == 0

            assert await app.activate_zone("other.example")
            assert zone.value == "other.example"
            assert app.commands[-1] == ("other.example", "query", ["@", "ALL"])
            assert str(title.render()) == "Records — other.example"
            assert app.saved_preferences == 1

    asyncio.run(run_app())


def test_load_password_can_fix_open_permissions(tmp_path) -> None:
    class PasswordApp(SambatuiApp):
        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            self.confirm_message = message
            return True

    async def run_app() -> None:
        path = tmp_path / "password"
        path.write_text("secret\n", encoding="utf-8")
        path.chmod(0o644)
        app = PasswordApp()
        async with app.run_test():
            app.query_one("#password_file", Input).value = str(path)

            await app.load_password()

            assert app.query_one("#password", Input).value == "secret"
            assert "chmod 600" in app.confirm_message
            assert path.stat().st_mode & 0o077 == 0

    asyncio.run(run_app())


def test_preferences_snapshot_excludes_secrets_and_tracks_smart_defaults() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#domain", Input).value = "example.com"
            app.query_one("#zone", Input).value = "2.0.192.in-addr.arpa"
            app.query_one("#user", Input).value = "admin"
            app.query_one("#password", Input).value = "secret"
            app.query_one("#auth", Input).value = "kerberos"
            app.query_one("#ldap_base", Input).value = "DC=example,DC=com"
            app.query_one("#auto_ptr", Input).value = "off"
            app.query_one("#smart_days", Input).value = "120"

            prefs = app.preference_values()

            assert prefs["server"] == "dc01.example.com"
            assert prefs["domain"] == "example.com"
            assert prefs["zone"] == "example.com"
            assert prefs["last_zone"] == "2.0.192.in-addr.arpa"
            assert prefs["auto_ptr"] == "off"
            assert prefs["smart_days"] == "120"
            assert "password" not in prefs
            assert "user" not in prefs

    asyncio.run(run_app())


def test_details_pane_updates_for_dns_ldap_and_smart_rows() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.query_one("#zone", Input).value = "example.com"
            app.zones = ["example.com", "2.0.192.in-addr.arpa"]
            app.populate_records(
                [
                    DnsRow("www", "1", "0", "A", "192.0.2.10", "3600", "raw"),
                    DnsRow("alias", "1", "0", "CNAME", "www.example.com.", "", "raw"),
                ]
            )
            details = app.query_one("#record_details", Static)
            assert "DNS details" in str(details.render())
            assert "Name: alias" in str(details.render())
            assert "PTR status: not applicable" in str(details.render())

            app.query_one("#records", DataTable).focus()
            await pilot.press("j")
            assert "Name: www" in str(details.render())
            assert "PTR status: expected 10.2.0.192.in-addr.arpa" in str(
                details.render()
            )

            app.populate_directory(
                [
                    DirectoryRow(
                        dn="CN=Alice,CN=Users,DC=example,DC=com",
                        kind="user",
                        name="Alice",
                        summary="alice@example.com",
                        attributes={
                            "sAMAccountName": ("alice",),
                            "memberOf": ("CN=Staff,DC=example,DC=com",),
                        },
                    )
                ]
            )
            assert "LDAP details" in str(details.render())
            assert "sAMAccountName: alice" in str(details.render())
            ldap_structure = app.query_one("#ldap_structure", DataTable)
            assert str(ldap_structure.get_row_at(0)[0]) == "DC=example,DC=com"
            assert str(ldap_structure.get_row_at(1)[0]) == "  CN=Users"

            app.populate_smart_view(
                "DNS duplicates/conflicts",
                [
                    SmartViewRow(
                        severity="high",
                        object="example.com:www",
                        finding="Duplicate DNS record",
                        evidence="2 identical records",
                        suggested_action="Remove duplicate copies.",
                        source="dns",
                    )
                ],
            )
            assert "Smart-view details" in str(details.render())
            assert "Suggested action: Remove duplicate copies." in str(details.render())

    asyncio.run(run_app())


def test_full_health_dashboard_renders_summary_and_partial_failures() -> None:
    class DashboardApp(SambatuiApp):
        def save_preferences(self) -> None:
            return

        async def run_samba_zone(
            self, action: str, zone: str, args: list[str]
        ) -> tuple[int, str]:
            if zone == "bad.example":
                return 1, "access denied"
            return (
                0,
                """
  Name=www, Records=1, Children=0
    A: 192.0.2.10 (flags=f0, serial=1, ttl=900)
  Name=www, Records=1, Children=0
    A: 192.0.2.10 (flags=f0, serial=1, ttl=900)
""",
            )

        async def dashboard_ldap_rows(
            self, client, kind: str
        ) -> tuple[list[DirectoryRow] | None, str]:
            if kind == "computers":
                return None, "LDAP timeout"
            return [
                DirectoryRow(
                    dn="CN=Solo,CN=Users,DC=example,DC=com",
                    kind="user",
                    name="Solo",
                    summary="",
                    attributes={
                        "sAMAccountName": ("solo",),
                        "userAccountControl": ("512",),
                    },
                )
            ], ""

    async def run_app() -> None:
        app = DashboardApp()
        async with app.run_test():
            app.zones = ["example.com", "bad.example"]
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#user", Input).value = "admin"
            app.query_one("#password", Input).value = "secret"
            values = {
                "days": "90",
                "disabled_days": "180",
                "never_logged_days": "30",
                "max_rows": "20",
                "base_dn": "DC=example,DC=com",
                "ldap_encryption": "ldaps",
                "ldap_compatibility": "off",
            }

            await app.load_full_health_dashboard(
                values, SmartViewOptions.from_values(values)
            )

            records = app.query_one("#records", DataTable)
            assert str(records.get_row_at(0)[3]) == "Full health dashboard"
            assert "check(s) failed" in str(records.get_row_at(0)[4])
            findings = [
                str(records.get_row_at(index)[3]) for index in range(records.row_count)
            ]
            assert any("DNS zone queries" in finding for finding in findings)
            assert any(
                "LDAP stale computer accounts" in finding for finding in findings
            )
            assert any(
                "DNS duplicates/conflicts: Duplicate DNS record" in finding
                for finding in findings
            )
            assert all(
                "Full health dashboard" in str(records.get_row_at(index)[3])
                or str(records.get_row_at(index)[1]) in {"summary", "error"}
                for index in range(4)
            )

    asyncio.run(run_app())


def test_smart_fix_adds_ptr_and_refreshes_findings() -> None:
    class FixApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.commands: list[tuple[str, str, list[str]]] = []

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            assert "ADD DNS record" in message
            assert "Zone: 2.0.192.in-addr.arpa" in message
            assert "10 PTR host.example.com" in message
            return True

        async def run_samba_zone(
            self, action: str, zone: str, args: list[str]
        ) -> tuple[int, str]:
            self.commands.append((action, zone, args))
            if action == "add":
                return 0, "OK"
            if zone == "example.com":
                return (
                    0,
                    """
  Name=host, Records=1, Children=0
    A: 192.0.2.10 (flags=f0, serial=1, ttl=900)
""",
                )
            return (
                0,
                """
  Name=10, Records=1, Children=0
    PTR: host.example.com (flags=f0, serial=1, ttl=900)
""",
            )

    async def run_app() -> None:
        app = FixApp()
        async with app.run_test():
            app.zones = ["example.com", "2.0.192.in-addr.arpa"]
            app.current_smart_view_id = "dns_a_without_ptr"
            app.current_smart_max_rows = 500
            row = SmartViewRow(
                severity="medium",
                object="host.example.com A 192.0.2.10",
                finding="A record missing PTR",
                evidence="Expected 10.2.0.192.in-addr.arpa PTR host.example.com.",
                suggested_action="Add PTR or confirm host should not have reverse DNS.",
                source="dns",
                fix_action="dns_add_ptr",
                fix_label="add PTR 10.2.0.192.in-addr.arpa -> host.example.com",
                fix_zone="2.0.192.in-addr.arpa",
                fix_name="10",
                fix_rtype="PTR",
                fix_value="host.example.com",
            )
            app.populate_smart_view("DNS A records without matching PTR", [row])

            await app.apply_smart_fix(row)

            assert app.commands[0] == (
                "add",
                "2.0.192.in-addr.arpa",
                ["10", "PTR", "host.example.com"],
            )
            assert ("query", "example.com", ["@", "ALL"]) in app.commands
            assert (
                "query",
                "2.0.192.in-addr.arpa",
                ["@", "ALL"],
            ) in app.commands
            assert app.smart_view_rows == []

    asyncio.run(run_app())


def test_inline_search_ldap_queries_directory_not_loaded_rows() -> None:
    class DirectorySearchApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.searches: list[tuple[str, str, int | None]] = []

        def save_preferences(self) -> None:
            return

        async def directory_search_rows(
            self,
            client,
            kind: str,
            text: str,
            max_entries: int | None = None,
        ) -> list[DirectoryRow] | None:
            self.searches.append((kind, text, max_entries))
            if text == "alice":
                return [
                    DirectoryRow(
                        dn="CN=Alice,CN=Users,DC=example,DC=com",
                        kind="user",
                        name="Alice",
                        summary="alice@example.com",
                        attributes={},
                    )
                ]
            return [
                DirectoryRow(
                    dn="CN=Bob,CN=Users,DC=example,DC=com",
                    kind="user",
                    name="Bob",
                    summary="bob@example.com",
                    attributes={},
                )
            ]

        async def directory_container_rows(self, client) -> list[DirectoryRow]:
            return []

    async def run_app() -> None:
        app = DirectorySearchApp()
        async with app.run_test() as pilot:
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#user", Input).value = "admin@example.com"
            app.query_one("#password", Input).value = "secret"
            values = {
                "kind": "users",
                "text": "",
                "base_dn": "DC=example,DC=com",
                "ldap_encryption": "ldaps",
                "ldap_compatibility": "off",
                "max_rows": "200",
            }

            assert await app.run_directory_search(values)
            search = app.query_one("#inline_search", Input)
            records = app.query_one("#records", DataTable)

            search.value = "alice"
            await pilot.pause(0.6)

            assert app.searches == [("users", "", 200), ("users", "alice", 200)]
            assert records.row_count == 1
            assert str(records.get_row_at(0)[1]) == "Alice"

    asyncio.run(run_app())


def test_inline_search_dns_reloads_full_zone_before_filtering() -> None:
    class DnsSearchApp(SambatuiApp):
        def __init__(self) -> None:
            super().__init__()
            self.commands: list[tuple[str, list[str]]] = []

        async def run_samba(self, action: str, args: list[str]) -> tuple[int, str]:
            self.commands.append((action, args))
            return 0, (
                "Name=www, Records=1, Children=0\n"
                "    A: 192.0.2.10 (flags=f0, serial=1, ttl=3600)\n"
                "Name=db, Records=1, Children=0\n"
                "    A: 192.0.2.20 (flags=f0, serial=1, ttl=3600)\n"
            )

    async def run_app() -> None:
        app = DnsSearchApp()
        async with app.run_test() as pilot:
            app.query_one("#zone", Input).value = "example.com"
            app.zones = ["example.com"]
            app.populate_records(
                [DnsRow("db", "1", "0", "A", "192.0.2.20", "3600", "raw")]
            )
            search = app.query_one("#inline_search", Input)
            records = app.query_one("#records", DataTable)

            search.value = "www"
            await pilot.pause(0.6)

            assert app.commands == [("query", ["@", "ALL"])]
            assert records.row_count == 1
            assert str(records.get_row_at(0)[1]) == "www"

    asyncio.run(run_app())


def test_inline_search_filters_dns_directory_and_smart_views() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.populate_records(
                [
                    DnsRow("www", "1", "0", "A", "192.0.2.10", "3600", "raw"),
                    DnsRow("db", "1", "0", "A", "192.0.2.20", "3600", "raw"),
                ]
            )

            await pilot.press("/")
            search = app.query_one("#inline_search", Input)
            records = app.query_one("#records", DataTable)
            assert app.focused is search

            search.value = "www"
            await pilot.pause()
            assert app.search_text == "www"
            assert records.row_count == 1
            assert str(records.get_row_at(0)[1]) == "www"

            await pilot.press("escape")
            await pilot.pause()
            assert search.value == ""
            assert app.search_text == ""
            assert app.focused is records
            assert records.row_count == 2

            app.populate_directory(
                [
                    DirectoryRow(
                        dn="CN=Alice,CN=Users,DC=example,DC=com",
                        kind="user",
                        name="Alice",
                        summary="alice@example.com",
                        attributes={},
                    ),
                    DirectoryRow(
                        dn="CN=Ops,CN=Users,DC=example,DC=com",
                        kind="group",
                        name="Ops",
                        summary="ops@example.com",
                        attributes={},
                    ),
                ]
            )
            search.value = "alice"
            await pilot.pause()
            assert records.row_count == 1
            assert str(records.get_row_at(0)[1]) == "Alice"

            app.populate_smart_view(
                "DNS duplicates/conflicts",
                [
                    SmartViewRow(
                        severity="high",
                        object="example.com:www",
                        finding="Duplicate DNS record",
                        evidence="2 identical records",
                        suggested_action="Remove duplicate copies.",
                        source="dns",
                    ),
                    SmartViewRow(
                        severity="medium",
                        object="example.com:db",
                        finding="Missing PTR",
                        evidence="No reverse record",
                        suggested_action="Add PTR.",
                        source="dns",
                    ),
                ],
            )
            search.value = "duplicate"
            await pilot.pause()
            assert records.row_count == 1
            assert str(records.get_row_at(0)[3]) == "Duplicate DNS record"

    asyncio.run(run_app())


def test_ldap_kind_header_sorts_directory_rows() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            app.populate_directory(
                [
                    DirectoryRow(
                        dn="CN=Bob,CN=Users,DC=example,DC=com",
                        kind="user",
                        name="Bob",
                        summary="bob@example.com",
                        attributes={},
                    ),
                    DirectoryRow(
                        dn="CN=Ops,CN=Users,DC=example,DC=com",
                        kind="group",
                        name="Ops",
                        summary="ops@example.com",
                        attributes={},
                    ),
                ]
            )
            records = app.query_one("#records", DataTable)
            column = records.ordered_columns[2]

            app.on_data_table_header_selected(
                DataTable.HeaderSelected(records, column.key, 2, Text("Kind"))
            )

            assert [str(records.get_row_at(index)[2]) for index in range(2)] == [
                "group",
                "user",
            ]
            assert str(app.query_one("#status", Static).render()).startswith(
                "Sorted LDAP by kind"
            )

    asyncio.run(run_app())


def test_modal_key_shortcuts_open_without_key_handler_crash() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            for key, screen_type in [
                ("ctrl+o", FormScreen),
                ("w", FormScreen),
                ("c", FormScreen),
                ("L", FormScreen),
                ("S", SmartViewPickerScreen),
                ("1", FormScreen),
                ("q", FormScreen),
                ("a", FormScreen),
            ]:
                await pilot.press(key)
                for _ in range(10):
                    await pilot.pause()
                    if isinstance(app.screen, screen_type):
                        break
                assert isinstance(app.screen, screen_type), key
                await pilot.press("escape")
                for _ in range(10):
                    await pilot.pause()
                    if not isinstance(app.screen, screen_type):
                        break

            app.query_one("#password", Input).value = "secret"
            await pilot.press("P")
            for _ in range(10):
                await pilot.pause()
                if isinstance(app.screen, ConfirmScreen):
                    break
            assert isinstance(app.screen, ConfirmScreen)
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(run_app())


def test_modal_tab_stays_inside_foreground_popup() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.query_one("#records", DataTable).focus()
            await pilot.press("w")
            for _ in range(10):
                await pilot.pause()
                if isinstance(app.screen, FormScreen):
                    break

            assert isinstance(app.screen, FormScreen)
            focused = app.screen.focused
            assert focused is not None
            assert str(focused.id) == "domain"

            await pilot.press("tab")
            await pilot.pause()

            focused = app.screen.focused
            assert focused is not None
            assert str(focused.id) == "user"
            assert not app.query_one("#zones", DataTable).has_focus

    asyncio.run(run_app())


def test_parse_zones_deduplicates_zone_names() -> None:
    output = """
        pszZoneName                 : example.com
        ZoneName                    : 2.0.192.in-addr.arpa
        pszZoneName                 : example.com
    """

    assert parse_zones(output) == ["example.com", "2.0.192.in-addr.arpa"]


def test_parse_records_reads_records_and_empty_nodes() -> None:
    output = """
  Name=www, Records=1, Children=0
    A: 192.0.2.10 (flags=f0, serial=1, ttl=3600)
  Name=empty, Records=0, Children=1
    """

    assert parse_records(output) == [
        DnsRow(
            "www",
            "1",
            "0",
            "A",
            "192.0.2.10",
            "3600",
            "A: 192.0.2.10 (flags=f0, serial=1, ttl=3600)",
        ),
        DnsRow("empty", "0", "1", "-", "", "", "Name=empty, Records=0, Children=1"),
    ]


def test_validate_record_accepts_documentation_examples() -> None:
    assert validate_record("www", "A", "192.0.2.10") is None
    assert validate_record("alias", "CNAME", "www.example.com.") is None
    assert validate_record("@", "MX", "10 mail.example.com.") is None


def test_guided_add_record_fields_are_type_specific() -> None:
    app = SambatuiApp()

    a_fields = {field_id for _, field_id, _, _ in app.add_record_type_fields("A")}
    srv_fields = {field_id for _, field_id, _, _ in app.add_record_type_fields("SRV")}

    assert a_fields == {"name", "address", "ttl"}
    assert srv_fields == {"name", "priority", "weight", "port", "target", "ttl"}


def test_guided_add_record_error_validates_ttl_and_duplicates() -> None:
    app = SambatuiApp()
    app.record_rows = [DnsRow("www", "1", "0", "A", "192.0.2.10", "3600", "raw")]

    assert (
        app.guided_add_record_error(
            "A", {"name": "www", "address": "192.0.2.10", "ttl": ""}
        )
        == "Duplicate record already exists in the loaded zone view."
    )
    assert (
        app.guided_add_record_error(
            "A", {"name": "www", "address": "192.0.2.11", "ttl": "bad"}
        )
        == "TTL must be whole seconds, e.g. 3600."
    )
    assert (
        app.guided_add_record_error(
            "MX",
            {"name": "@", "priority": "10", "target": "mail.example.com.", "ttl": ""},
        )
        is None
    )


def test_guided_add_preview_includes_command_and_ptr_suggestion() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#zone", Input).value = "example.com"
            app.query_one("#user", Input).value = "admin"
            app.query_one("#password", Input).value = "secret"
            app.zones = ["example.com", "2.0.192.in-addr.arpa"]

            preview = app.add_record_preview("www", "A", "192.0.2.10", "300")

            assert "Record: www A 192.0.2.10" in preview
            assert "2.0.192.in-addr.arpa: 10 PTR www.example.com" in preview
            assert "Command preview: samba-tool dns add dc01.example.com" in preview
            assert "admin%******" in preview

    asyncio.run(run_app())


def test_form_screen_live_validation_disables_submit() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.push_screen(
                FormScreen(
                    "Validate",
                    "",
                    [("Value", "value", "ok", "bad")],
                    "Save",
                    lambda values: "Bad value" if values["value"] == "bad" else None,
                )
            )
            await pilot.pause()
            submit = app.screen.query_one("#submit", Button)
            error = app.screen.query_one("#form_error", Static)
            value = app.screen.query_one("#value", Input)

            assert submit.disabled
            assert str(error.render()) == "Bad value"

            value.value = "ok"
            await pilot.pause()

            assert not submit.disabled
            assert str(error.render()) == ""

    asyncio.run(run_app())


def test_setup_form_suggests_upn_domain_suffix() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.push_screen(
                FormScreen(
                    "First-run setup wizard",
                    "",
                    [
                        ("Domain", "domain", "example.com", "example.com"),
                        ("User", "user", "admin@example.com", ""),
                    ],
                    "Run checks",
                )
            )
            await pilot.pause()
            form = app.screen
            assert isinstance(form, FormScreen)
            domain = form.query_one("#domain", Input)
            user = form.query_one("#user", Input)
            user.focus()

            user.value = "alice"
            await pilot.pause()
            assert getattr(user, "_suggestion") == "alice@example.com"
            assert form.form_values()["user"] == "alice@example.com"

            await pilot.press("tab")
            await pilot.pause()
            assert user.value == "alice@example.com"
            assert getattr(user, "_suggestion") == ""

            user.focus()
            user.value = "alice"
            domain.value = "ad.example."
            await pilot.pause()
            assert getattr(user, "_suggestion") == "alice@ad.example"
            assert form.form_values()["user"] == "alice@ad.example"

            user.value = "alice@other.example"
            await pilot.pause()
            assert form.form_values()["user"] == "alice@other.example"

            user.value = r"EXAMPLE\alice"
            await pilot.pause()
            assert form.form_values()["user"] == r"EXAMPLE\alice"

    asyncio.run(run_app())


def test_validate_record_rejects_bad_cname_ip() -> None:
    assert validate_record("alias", "CNAME", "192.0.2.10") == (
        "CNAME value must be a hostname, not an IP address. Use A/AAAA for IPs."
    )


def test_validate_record_uses_dns_parser_for_supported_types() -> None:
    assert validate_record("_ldap._tcp", "SRV", "0 100 389 dc.example.com.") is None
    assert validate_record("@", "MX", "mail.example.com. 10") is None
    assert validate_record("www", "A", "999.0.2.10") is not None


def test_valid_dns_name_keeps_sambatui_label_policy() -> None:
    assert valid_dns_name("_ldap._tcp.example.com.")
    assert not valid_dns_name("-bad.example.com")
    assert not valid_dns_name("bad space.example.com")


def test_ptr_target_for_name_uses_zone_for_relative_names() -> None:
    assert ptr_target_for_name("www", "example.com") == "www.example.com"
    assert ptr_target_for_name("@", "example.com") == "example.com"
    assert ptr_target_for_name("host.example.net.", "example.com") == "host.example.net"


def test_reverse_record_for_ipv4_prefers_longest_matching_zone() -> None:
    zones = ["2.0.192.in-addr.arpa", "0.192.in-addr.arpa", "example.com"]

    assert reverse_record_for_ipv4("192.0.2.10", zones) == (
        "2.0.192.in-addr.arpa",
        "10",
    )


def test_reverse_record_for_ipv4_falls_back_to_24_zone() -> None:
    assert reverse_record_for_ipv4("192.0.2.10", []) == (
        "2.0.192.in-addr.arpa",
        "10",
    )


def test_reverse_record_for_ipv4_rejects_non_ipv4_values() -> None:
    assert reverse_record_for_ipv4("not-an-ip", []) is None
