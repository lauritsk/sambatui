import asyncio


from sambatui.app import (
    SambatuiApp,
)
from textual.widgets import DataTable, Input, Static

from sambatui.samba.discovery import DiscoveredService


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
            assert str(records.get_row_at(0)[1]) == "No findings shown"
            assert "Press S" in str(records.get_row_at(0)[3])
            assert "No findings shown" in str(details.render())

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
