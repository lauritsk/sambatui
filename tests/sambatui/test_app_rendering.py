import asyncio

from rich.text import Text

from sambatui.app import (
    DnsRow,
    SambatuiApp,
)
from textual.widgets import DataTable, Input, Static

from sambatui.ldap.client import DirectoryRow
from sambatui.smart_view_catalog import SmartViewOptions
from sambatui.smart_views import SmartViewRow


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
