import asyncio

from sambatui.app import (
    DnsRow,
    SambatuiApp,
    actionable_error,
    parse_records,
    parse_zones,
    validate_record,
)
from textual.widgets import DataTable, Input, Static

from sambatui.dns import ptr_target_for_name, reverse_record_for_ipv4, valid_dns_name
from sambatui.ldap_directory import DirectoryRow
from sambatui.screens import ConfirmScreen, FormScreen, SmartViewPickerScreen
from sambatui.smart_views import SmartViewRow


def test_key_hints_change_by_side_tab() -> None:
    app = SambatuiApp()

    assert app.keys_hint_for_tab("dns_tab").startswith("DNS:")
    assert app.keys_hint_for_tab("ldap_tab").startswith("LDAP:")
    assert app.keys_hint_for_tab("smart_tab").startswith("Smart:")


def test_actionable_error_adds_concise_remediation() -> None:
    assert actionable_error("LDAP bind failed: invalidCredentials").endswith(
        "Action: check credentials, domain format, encryption, or Kerberos ticket."
    )
    assert "run kinit" in actionable_error("Kerberos ticket expired")
    assert actionable_error("") == ""


def test_empty_states_explain_next_actions() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
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

            app.populate_smart_view("DNS duplicates/conflicts", [])
            assert str(records.get_row_at(0)[1]) == "No smart-view findings shown"
            assert "Press S" in str(records.get_row_at(0)[3])
            assert "No smart-view findings shown" in str(details.render())

    asyncio.run(run_app())


def test_preferences_snapshot_excludes_secrets_and_tracks_smart_defaults() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#zone", Input).value = "example.com"
            app.query_one("#user", Input).value = "admin"
            app.query_one("#password", Input).value = "secret"
            app.query_one("#auth", Input).value = "kerberos"
            app.query_one("#ldap_base", Input).value = "DC=example,DC=com"
            app.query_one("#auto_ptr", Input).value = "off"
            app.query_one("#smart_days", Input).value = "120"

            prefs = app.preference_values()

            assert prefs["server"] == "dc01.example.com"
            assert prefs["last_zone"] == "example.com"
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


def test_modal_key_shortcuts_open_without_key_handler_crash() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            for key, screen_type in [
                ("ctrl+o", FormScreen),
                ("c", FormScreen),
                ("L", FormScreen),
                ("S", SmartViewPickerScreen),
                ("1", FormScreen),
                ("q", FormScreen),
                ("a", FormScreen),
                ("slash", FormScreen),
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
