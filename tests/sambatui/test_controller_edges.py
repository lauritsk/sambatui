from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from textual.widgets import DataTable, Input, Static

from sambatui.app import DnsRow, SambatuiApp
from sambatui.controllers.core import AppCoreMixin
from sambatui.controllers.helpers import (
    directory_sort_label,
    ldap_limit_suffix,
    next_sort_state,
    setup_auth_values,
    sort_direction,
)
from sambatui.ldap.client import DirectoryRow
from sambatui.ldap.sidebar import SidebarItem
from sambatui.samba.discovery import DiscoveredService
from sambatui.smart_view_catalog import (
    FULL_HEALTH_VIEW_ID,
    SMART_VIEW_BY_ID,
    SMART_VIEW_BY_SHORTCUT,
    SmartViewOptions,
)
from sambatui.smart_views import SmartViewRow


class NotificationApp(SambatuiApp):
    def __init__(self) -> None:
        super().__init__()
        self.notifications: list[tuple[str, str]] = []

    def notify(
        self,
        message: str,
        *,
        title: str = "",
        severity: str = "information",
        timeout: float | None = None,
        markup: bool = True,
    ) -> None:
        self.notifications.append((message, severity))

    def save_preferences(self) -> None:
        return


def row(name: str = "www", rtype: str = "A", value: str = "192.0.2.10") -> DnsRow:
    return DnsRow(name, "1", "0", rtype, value, "3600", "raw")


def directory_row(kind: str = "user", name: str = "Alice") -> DirectoryRow:
    return DirectoryRow(
        dn=f"CN={name},CN=Users,DC=example,DC=com",
        kind=kind,
        name=name,
        summary=f"{name.lower()}@example.com",
        attributes={
            "displayName": (name,),
            "mail": (f"{name.lower()}@example.com",),
            "description": ("old",),
            "sAMAccountName": (name.lower(),),
            "userAccountControl": ("512",),
        },
    )


def smart_row(**overrides: Any) -> SmartViewRow:
    values = {
        "severity": "medium",
        "object": "host.example.com A 192.0.2.10",
        "finding": "A record missing PTR",
        "evidence": "Expected PTR.",
        "suggested_action": "Add PTR.",
        "source": "dns",
        "fix_action": "dns_add_ptr",
        "fix_label": "add PTR",
        "fix_zone": "2.0.192.in-addr.arpa",
        "fix_name": "10",
        "fix_rtype": "PTR",
        "fix_value": "host.example.com",
    }
    values.update(overrides)
    return SmartViewRow(**values)


def test_controller_helper_edges() -> None:
    assert setup_auth_values("kerberos", "off") == ("kerberos", "required")
    assert directory_sort_label("type") == "kind"
    assert directory_sort_label("name") == "name"
    assert ldap_limit_suffix(1, 2) == ""
    assert "limit reached" in ldap_limit_suffix(2, 2)
    assert next_sort_state("name", False, "name") == ("name", True)
    assert next_sort_state("name", True, "type") == ("type", False)
    assert sort_direction(True) == "desc"
    assert sort_direction(False) == "asc"


def test_dns_action_query_and_add_form_edges() -> None:
    class DnsApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.forms: list[dict[str, str] | None] = []
            self.commands: list[tuple[str, list[str], bool]] = []
            self.errors: list[str] = []

        async def form(self, *args: Any, **kwargs: Any) -> dict[str, str] | None:
            return self.forms.pop(0)

        async def do_command(
            self, action: str, args: list[str], update_table: bool = False
        ) -> int:
            self.commands.append((action, args, update_table))
            return 0

        def report_error(self, message: str) -> None:
            self.errors.append(message)

    async def run_app() -> None:
        app = DnsApp()
        async with app.run_test():
            app.forms = [None]
            await app.action_query.__wrapped__(app)
            assert app.commands == []

            app.forms = [{"name": "", "rtype": ""}]
            await app.action_query.__wrapped__(app)
            assert app.commands == [("query", ["@", "ALL"], True)]

            app.forms = [None]
            assert await app.add_record_form_values() is None
            app.forms = [{"rtype": "A"}, None]
            assert await app.add_record_form_values() is None
            app.forms = [{"rtype": "A"}, {"name": "www", "address": "bad", "ttl": ""}]
            assert await app.add_record_form_values() is None
            assert app.errors[-1]
            app.forms = [
                {"rtype": "txt"},
                {"name": "txt", "text": "hello world", "ttl": ""},
            ]
            assert await app.add_record_form_values() == (
                "txt",
                "TXT",
                "hello world",
                "",
            )

    asyncio.run(run_app())


def test_dns_record_validation_and_ptr_edges() -> None:
    async def run_app() -> None:
        app = NotificationApp()
        async with app.run_test():
            app.query_one("#zone", Input).value = "example.com"
            assert app.record_type_selection_error({"rtype": "bad"}) is not None
            assert (
                app.add_record_value_from_fields("UNKNOWN", {"value": "raw"}) == "raw"
            )
            assert app.ttl_error("0") == "TTL must be greater than zero."
            assert app.duplicate_record_error("x", "A", "192.0.2.1") is None
            assert app.existing_reverse_record_for_ipv4("not-ip") is None
            assert (
                app.ptr_preview_text("www", "CNAME", "alias")
                == "PTR suggestion: not applicable."
            )
            assert "no loaded reverse zone" in app.ptr_preview_text(
                "www", "A", "192.0.2.10"
            )

            app.zones = ["2.0.192.in-addr.arpa"]
            app.notifications.clear()
            app.query_one("#auto_ptr", Input).value = "off"
            await app.maybe_add_matching_ptr("www", "A", "192.0.2.10")
            assert app.notifications == []

    asyncio.run(run_app())


def test_dns_action_add_update_delete_edges() -> None:
    class DnsApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.record_values: tuple[str, str, str, str] | None = None
            self.confirms: list[bool] = []
            self.commands: list[tuple[str, list[str]]] = []
            self.refreshed = 0
            self.ldap_actions: list[str] = []
            self.forms: list[dict[str, str] | None] = []
            self.selected: list[dict[str, str]] = []
            self.errors: list[str] = []

        async def add_record_form_values(self) -> tuple[str, str, str, str] | None:
            return self.record_values

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            return self.confirms.pop(0)

        async def do_command(
            self, action: str, args: list[str], update_table: bool = False
        ) -> int:
            self.commands.append((action, args))
            return 1 if "fail" in args else 0

        async def refresh_current_zone(self) -> None:
            self.refreshed += 1

        async def add_ldap_entry(self) -> None:
            self.ldap_actions.append("add")

        async def update_ldap_entry(self) -> None:
            self.ldap_actions.append("update")

        async def delete_ldap_entry(self) -> None:
            self.ldap_actions.append("delete")

        def selected_records(self) -> list[dict[str, str]]:
            return self.selected

        async def form(self, *args: Any, **kwargs: Any) -> dict[str, str] | None:
            return self.forms.pop(0)

        def report_error(self, message: str) -> None:
            self.errors.append(message)

    async def run_app() -> None:
        app = DnsApp()
        async with app.run_test():
            app.view_mode = "directory"
            await app.action_add.__wrapped__(app)
            await app.action_update.__wrapped__(app)
            await app.action_delete.__wrapped__(app)
            assert app.ldap_actions == ["add", "update", "delete"]

            app.view_mode = "dns"
            app.query_one("#auto_ptr", Input).value = "off"
            app.record_values = None
            await app.action_add.__wrapped__(app)
            app.record_values = ("www", "A", "192.0.2.10", "")
            app.confirms = [False]
            await app.action_add.__wrapped__(app)
            assert app.notifications[-1] == ("Add cancelled", "information")
            app.confirms = [True]
            await app.action_add.__wrapped__(app)
            assert ("add", ["www", "A", "192.0.2.10"]) in app.commands
            assert app.refreshed == 1

            assert app.selected_record_for_update() is None
            app.selected = [
                {"name": "a", "rtype": "A", "value": "1.1.1.1"},
                {"name": "b", "rtype": "A", "value": "1.1.1.2"},
            ]
            assert app.selected_record_for_update() is None
            app.selected = [{"name": "a", "rtype": "A", "value": "1.1.1.1"}]
            assert app.update_record_fields(app.selected[0])[-1][1] == "value"

            app.confirms = [False]
            await app.change_record_type("a", "A", "1.1.1.1", "CNAME", "b.example.com.")
            app.confirms = [True]
            await app.change_record_type("a", "A", "1.1.1.1", "CNAME", "b.example.com.")
            assert ("delete", ["a", "A", "1.1.1.1"]) in app.commands

            app.confirms = [False]
            await app.update_record_value("a", "A", "1.1.1.1", "1.1.1.2")
            app.confirms = [True]
            await app.update_record_value("a", "A", "1.1.1.1", "1.1.1.2")
            assert ("update", ["a", "A", "1.1.1.1", "1.1.1.2"]) in app.commands

            app.forms = [None]
            await app.action_update.__wrapped__(app)
            app.forms = [
                {
                    "name": "bad space",
                    "old_rtype": "A",
                    "rtype": "A",
                    "old_value": "1.1.1.1",
                    "value": "1.1.1.2",
                }
            ]
            await app.action_update.__wrapped__(app)
            assert app.errors[-1]
            app.forms = [
                {
                    "name": "a",
                    "old_rtype": "A",
                    "rtype": "CNAME",
                    "old_value": "1.1.1.1",
                    "value": "b.example.com.",
                }
            ]
            app.confirms = [True]
            await app.action_update.__wrapped__(app)
            app.forms = [
                {
                    "name": "a",
                    "old_rtype": "A",
                    "rtype": "A",
                    "old_value": "1.1.1.1",
                    "value": "1.1.1.2",
                }
            ]
            app.confirms = [True]
            await app.action_update.__wrapped__(app)

            app.selected = []
            await app.action_delete.__wrapped__(app)
            app.selected = [{"name": "a", "rtype": "A", "value": "1.1.1.1"}]
            app.confirms = [False]
            await app.action_delete.__wrapped__(app)
            app.selected = [
                {
                    "name": f"r{i}",
                    "rtype": "A",
                    "value": "fail" if i == 0 else "1.1.1.1",
                }
                for i in range(13)
            ]
            app.confirms = [True]
            await app.action_delete.__wrapped__(app)
            assert any("failure" in note[0] for note in app.notifications)

    asyncio.run(run_app())


def test_setup_validation_connectivity_and_wizard_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SetupApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.forms: list[dict[str, str] | None] = []
            self.zonelist: tuple[int, str] = (0, "pszZoneName : example.com")
            self.ldap_error: str | None = None
            self.services: list[DiscoveredService] = []
            self.discovery_error: Exception | None = None
            self.loaded = 0

        async def form(self, *args: Any, **kwargs: Any) -> dict[str, str] | None:
            return self.forms.pop(0)

        async def run_zonelist(self) -> tuple[int, str]:
            return self.zonelist

        async def check_ldap_connectivity(self) -> str | None:
            return self.ldap_error

        async def discover_setup_services(self, domain: str) -> list[DiscoveredService]:
            if self.discovery_error:
                raise self.discovery_error
            return self.services

        async def activate_zone(self, zone: str, *, save: bool = True) -> bool:
            return False

        async def load_zones(self, *, restore_active_zone: bool = True) -> None:
            self.loaded += 1

    async def run_app() -> None:
        app = SetupApp()
        async with app.run_test():
            app.query_one("#password_file", Input).value = str(tmp_path / "missing")
            assert app.setup_wizard_validation_error({"domain": "bad..domain"})
            assert (
                app.setup_wizard_validation_error(
                    {
                        "domain": "example.com",
                        "auth": "password",
                        "user": "",
                        "password": "",
                    }
                )
                == "Enter username or switch auth to kerberos."
            )
            assert (
                app.setup_wizard_validation_error(
                    {"domain": "example.com", "auth": "kerberos"}
                )
                is None
            )
            password_file = tmp_path / "password"
            password_file.write_text("secret\n", encoding="utf-8")
            password_file.chmod(0o600)
            app.query_one("#password_file", Input).value = str(password_file)
            assert (
                app.setup_wizard_validation_error(
                    {
                        "domain": "example.com",
                        "auth": "password",
                        "user": "admin",
                        "password": "",
                    }
                )
                is None
            )
            assert app.setup_wizard_fields()[0][1] == "domain"

            app.query_one("#auth", Input).value = "kerberos"
            app.query_one("#kerberos", Input).value = "off"
            assert app.setup_wizard_auth_defaults() == ("kerberos", "required")
            app.apply_setup_wizard_values(
                "example.com",
                "dc01.example.com",
                {"auth": "kerberos", "kerberos": "off"},
            )
            assert app.query_one("#server", Input).value == "dc01.example.com"
            assert app.query_one("#password", Input).value == "secret"

            app.zonelist = (0, "")
            assert await app.setup_dns_zones() is None
            assert await app.setup_ldap_connectivity_ok()
            app.ldap_error = "bind failed\nmore"
            assert not await app.setup_ldap_connectivity_ok()

            app.discovery_error = ValueError("bad srv")
            assert not await app.run_setup_wizard({"domain": "example.com"})
            app.discovery_error = None
            app.services = []
            assert not await app.run_setup_wizard({"domain": "example.com"})
            app.services = [
                DiscoveredService(
                    "ldap", "example.com", "dc01.example.com", 389, 0, 100
                )
            ]
            app.zonelist = (1, "denied")
            assert not await app.run_setup_wizard({"domain": "example.com"})
            app.zonelist = (0, "pszZoneName : other.example")
            app.ldap_error = None
            assert await app.run_setup_wizard({"domain": "example.com"})
            assert "Setup complete" in str(app.query_one("#status", Static).render())

            app.forms = [None]
            assert not await app.open_setup_wizard()
            app.forms = [{"domain": "example.com"}]
            assert await app.open_setup_wizard()
            app.forms = [{"domain": "example.com"}]
            await app.action_setup_wizard.__wrapped__(app)

            app.forms = [None]
            assert not await app.open_connection_settings()
            app.forms = [
                {
                    "server": "dc01.example.com",
                    "domain": "example.com",
                    "zone": "example.com",
                    "user": "admin",
                    "password": "",
                    "auth": "password",
                    "kerberos": "off",
                    "ldap_base": "DC=example,DC=com",
                    "ldap_encryption": "ldaps",
                    "ldap_compatibility": "off",
                    "auto_ptr": "ask",
                    "password_file": str(password_file),
                    "smart_days": "90",
                    "smart_disabled_days": "180",
                    "smart_never_logged_days": "30",
                    "smart_max_rows": "500",
                }
            ]
            assert await app.open_connection_settings()
            assert app.loaded >= 1
            app.forms = [
                {
                    "server": "dc01.example.com",
                    "domain": "example.com",
                    "zone": "example.com",
                    "user": "admin",
                    "password": "",
                    "auth": "password",
                    "kerberos": "off",
                    "ldap_base": "DC=example,DC=com",
                    "ldap_encryption": "ldaps",
                    "ldap_compatibility": "off",
                    "auto_ptr": "ask",
                    "password_file": str(password_file),
                    "smart_days": "90",
                    "smart_disabled_days": "180",
                    "smart_never_logged_days": "30",
                    "smart_max_rows": "500",
                }
            ]
            await app.action_connection.__wrapped__(app)

    async def fake_to_thread(func: Any, *args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    monkeypatch.setattr("sambatui.controllers.setup.asyncio.to_thread", fake_to_thread)
    asyncio.run(run_app())


def test_setup_discover_ad_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    class DiscoverApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.forms: list[dict[str, str] | None] = []

        async def form(self, *args: Any, **kwargs: Any) -> dict[str, str] | None:
            return self.forms.pop(0)

    services = [
        DiscoveredService("ldap", "example.com", "dc01.example.com", 389, 0, 100)
    ]

    async def run_app() -> None:
        app = DiscoverApp()
        async with app.run_test():
            app.forms = [None]
            assert not await app.open_discover_ad()

            async def ok_to_thread(func: Any, domain: str) -> list[DiscoveredService]:
                return services

            monkeypatch.setattr(
                "sambatui.controllers.setup.asyncio.to_thread", ok_to_thread
            )
            result = await app.discover_ad_controller("example.com")
            assert result is not None
            app.apply_discovered_ad_controller(services[0])
            assert app.query_one("#server", Input).value == "dc01.example.com"

            app.forms = [{"domain": ""}]
            assert await app.open_discover_ad("example.com")
            app.forms = [{"domain": "example.com"}]
            await app.action_discover_ad.__wrapped__(app)

            async def empty_to_thread(
                func: Any, domain: str
            ) -> list[DiscoveredService]:
                return []

            monkeypatch.setattr(
                "sambatui.controllers.setup.asyncio.to_thread", empty_to_thread
            )
            assert await app.discover_ad_controller("example.com") is None

            async def bad_to_thread(func: Any, domain: str) -> list[DiscoveredService]:
                raise ValueError("bad domain")

            monkeypatch.setattr(
                "sambatui.controllers.setup.asyncio.to_thread", bad_to_thread
            )
            assert await app.discover_ad_controller("bad") is None

    asyncio.run(run_app())


def test_core_status_password_command_and_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class CoreApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.confirm_values: list[bool] = []
            self.screen_values: list[Any] = []
            self.loaded_password = 0
            self.loaded_zones = 0
            self.refreshed_modes: list[str] = []
            self.commands: list[list[str]] = []

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            return self.confirm_values.pop(0)

        async def push_screen_wait(
            self, screen: Any, *, mode: str | None = None
        ) -> Any:
            return self.screen_values.pop(0)

        async def load_password(self) -> None:
            self.loaded_password += 1

        async def load_zones(self, *, restore_active_zone: bool = True) -> None:
            self.loaded_zones += 1

        async def refresh_current_smart_view(self) -> None:
            self.refreshed_modes.append("smart")

        async def refresh_current_directory_search(self) -> bool:
            self.refreshed_modes.append("directory")
            return True

        async def refresh_current_zone(self) -> None:
            self.refreshed_modes.append("dns")

        async def invoke_action(self, action_name: str, *args: Any) -> None:
            self.commands.append([action_name, *args])

    async def run_app() -> None:
        app = CoreApp()
        async with app.run_test():
            app.query_one("#auth", Input).value = "kerberos"
            app.set_initial_connection_status()
            assert "Kerberos" in str(app.query_one("#status", Static).render())
            app.query_one("#auth", Input).value = "password"
            app.query_one("#password", Input).value = "secret"
            app.set_initial_connection_status()
            assert "Password loaded" in str(app.query_one("#status", Static).render())
            assert app.normalized_domain_candidate("bad domain") == ""

            app.screen_values = [None]
            await app.action_open_command_palette()
            app.screen_values = ["setup_wizard"]
            await app.action_open_command_palette()
            assert app.commands[-1][0] == "action_setup_wizard"
            await app.action_load_password_file()
            assert app.loaded_password == 1
            app.query_one("#password", Input).value = ""
            app.action_save_password_file()

            for mode in ("smart", "directory", "dns"):
                app.view_mode = mode
                await app.action_refresh()
            assert app.refreshed_modes == ["smart", "directory", "dns"]

        parent = tmp_path / "new"
        app = CoreApp()
        async with app.run_test():
            app.query_one("#password_file", Input).value = str(parent / "password")
            app.query_one("#password", Input).value = ""
            await app.save_password.__wrapped__(app)
            app.query_one("#password", Input).value = "secret"
            app.confirm_values = [False]
            await app.save_password.__wrapped__(app)
            app.confirm_values = [True]
            await app.save_password.__wrapped__(app)
            assert (parent / "password").read_text(encoding="utf-8") == "secret\n"
            assert parent.stat().st_mode & 0o077 == 0

    class FakeButton:
        disabled = False

    class FakeBusy:
        def __init__(self) -> None:
            self.button = FakeButton()
            self.states: list[bool] = []

        def query(self, widget: Any) -> list[FakeButton]:
            return [self.button]

        def set_busy(self, busy: bool) -> None:
            self.states.append(busy)
            AppCoreMixin.set_busy(cast(AppCoreMixin, self), busy)

    class FakeHelp:
        pushed = False

        def push_screen(self, screen: Any) -> None:
            self.pushed = True

    fake_help = FakeHelp()
    AppCoreMixin.action_help(cast(AppCoreMixin, fake_help))
    assert fake_help.pushed

    fake_busy = FakeBusy()
    AppCoreMixin.set_busy(cast(AppCoreMixin, fake_busy), True)
    assert fake_busy.button.disabled

    async def use_busy() -> None:
        async with AppCoreMixin.busy(cast(AppCoreMixin, fake_busy)):
            assert fake_busy.states[-1]
        assert fake_busy.states[-1] is False

    asyncio.run(use_busy())

    asyncio.run(run_app())


def test_core_load_password_error_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class PasswordApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.confirms: list[bool] = []

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            return self.confirms.pop(0)

    async def run_app() -> None:
        missing = tmp_path / "missing"
        app = PasswordApp()
        async with app.run_test():
            app.query_one("#password_file", Input).value = str(missing)
            await app.load_password()
            assert "No password" in str(app.query_one("#status", Static).render())

        path = tmp_path / "password"
        path.write_text("secret\n", encoding="utf-8")
        path.chmod(0o644)
        app = PasswordApp()
        async with app.run_test():
            app.query_one("#password_file", Input).value = str(path)
            app.confirms = [False]
            await app.load_password()
            assert "permissions" in str(app.query_one("#status", Static).render())

        app = PasswordApp()
        async with app.run_test():
            app.query_one("#password_file", Input).value = str(path)
            app.confirms = [True]
            monkeypatch.setattr(
                "sambatui.controllers.core.fix_password_file_permissions",
                lambda p: (_ for _ in ()).throw(OSError("no chmod")),
            )
            await app.load_password()
            assert "Cannot fix" in str(app.query_one("#status", Static).render())

    asyncio.run(run_app())


def test_core_run_command_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    class CommandApp(NotificationApp):
        pass

    class FakeClient:
        def __init__(self, error: str = "") -> None:
            self.error = error

        def authentication_error(self) -> str:
            return self.error

        def status_command(self, cmd: list[str]) -> str:
            return " ".join(cmd)

    class FakeProc:
        def __init__(self, code: int, output: bytes) -> None:
            self.returncode = code
            self.output = output

        async def communicate(self) -> tuple[bytes, bytes]:
            return self.output, b""

    async def run_app() -> None:
        app = CommandApp()
        async with app.run_test():
            assert await app.run_command(
                cast(Any, FakeClient("auth bad")), ["cmd"]
            ) == (2, "auth bad")

            async def ok_exec(*cmd: str, **kwargs: Any) -> FakeProc:
                return FakeProc(0, b"ok")

            monkeypatch.setattr(
                "sambatui.controllers.core.asyncio.create_subprocess_exec", ok_exec
            )
            assert await app.run_command(cast(Any, FakeClient()), ["cmd"]) == (0, "ok")

            async def bad_exec(*cmd: str, **kwargs: Any) -> FakeProc:
                return FakeProc(4, b"first\nsecond")

            monkeypatch.setattr(
                "sambatui.controllers.core.asyncio.create_subprocess_exec", bad_exec
            )
            code, output = await app.run_command(cast(Any, FakeClient()), ["cmd"])
            assert (code, output) == (4, "first\nsecond")

    asyncio.run(run_app())


def test_views_sidebar_load_sort_selection_edges() -> None:
    class ViewApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.zonelist: tuple[int, str] = (0, "")
            self.commands: list[tuple[str, str, list[str]]] = []
            self.directory_searches: list[dict[str, str]] = []
            self.smart_runs: list[str] = []
            self.fail_ptr = False

        async def run_zonelist(self) -> tuple[int, str]:
            return self.zonelist

        async def run_samba_zone(
            self, action: str, zone: str, args: list[str]
        ) -> tuple[int, str]:
            self.commands.append((action, zone, args))
            return (1, "bad") if self.fail_ptr else (0, "ok")

        async def run_directory_search(
            self,
            values: dict[str, str],
            *,
            default_kind: str = "users",
            max_rows: int | None = None,
            action: str = "Loaded",
        ) -> bool:
            self.directory_searches.append(values)
            return True

        async def refresh_current_zone(self) -> None:
            self.commands.append(("query", self.val("zone"), []))

        def action_smart_view_shortcut(self, shortcut: str) -> None:
            view_id = SMART_VIEW_BY_SHORTCUT[shortcut].view_id
            self.smart_runs.append(view_id)
            self.current_smart_view_id = view_id

    async def run_app() -> None:
        app = ViewApp()
        async with app.run_test():
            app.query_one("#zone", Input).value = "example.com"
            assert await app.add_ptr("www", "bad") == 0
            app.zones = ["2.0.192.in-addr.arpa"]
            assert await app.add_ptr("www", "192.0.2.10") == 0
            app.commands.clear()
            app.fail_ptr = True
            assert await app.add_ptr("www", "192.0.2.10") == 1
            app.fail_ptr = False

            app.zonelist = (1, "denied")
            await app.load_zones()
            app.zonelist = (0, "")
            await app.load_zones()
            assert "select zone" in str(app.query_one("#status", Static).render())
            app.query_one("#zone", Input).value = "missing.example"
            app.zonelist = (0, "pszZoneName : example.com")
            await app.load_zones(restore_active_zone=False)
            assert "saved zone missing" in str(
                app.query_one("#status", Static).render()
            )
            app.query_one("#zone", Input).value = ""
            await app.load_zones(restore_active_zone=False)
            assert "select a zone" in str(app.query_one("#status", Static).render())

            assert app.sidebar_item_at("zones", -1) is None
            assert app.sidebar_item_at("zones", 99) is None
            assert not app.select_sidebar_cursor(
                "zones", SidebarItem("Nope", "nope", "dns_zone")
            )
            assert not await app.activate_sidebar_item(None)
            assert not await app.activate_sidebar_item(
                SidebarItem("Empty", "", "empty")
            )
            assert not await app.activate_sidebar_item(
                SidebarItem("Unknown", "", "unknown")
            )
            app.zones = ["example.com"]
            assert await app.activate_sidebar_item(
                SidebarItem("example.com", "example.com", "dns_zone")
            )
            assert await app.activate_sidebar_item(SidebarItem("LDAP", "", "ldap_root"))
            assert await app.activate_sidebar_item(
                SidebarItem("OU", "OU=Users,DC=example,DC=com", "ldap_dn")
            )
            assert await app.activate_sidebar_item(
                SidebarItem("Run 1", "dns_duplicates", "smart_view")
            )
            assert app.smart_runs == ["dns_duplicates"]
            app.query_one("#smart_views", DataTable).move_cursor(row=1)
            assert await app.activate_sidebar_selection(
                app.query_one("#smart_views", DataTable)
            )
            assert app.smart_runs[-1] == "dns_duplicates"
            table = app.query_one("#zones", DataTable)
            assert await app.activate_sidebar_selection(table)

            app.remember_ldap_structure_rows(
                [directory_row(), directory_row(name="Bob")]
            )
            app.remember_ldap_structure_rows([directory_row()])
            assert len(app.ldap_structure_rows) == 2

            assert app.visible_row_at([], 0) is None
            app.view_mode = "dns"
            assert "No DNS" in app.dns_details_text(99)
            app.view_mode = "directory"
            assert "No LDAP" in app.directory_details_text(99)
            app.view_mode = "smart"
            assert "No smart" in app.smart_details_text(99)

            app.set_visible_status(0, 1, "records", "dns")
            app.search_text = "www"
            app.set_visible_status(1, 2, "records", "dns")
            assert "/www/" in str(app.query_one("#status", Static).render())

            app.populate_records([row("b"), row("a")])
            app.sort_records("type")
            app.populate_smart_view("x", [smart_row()])
            app.sort_records("name")
            assert "Sorted smart view" in str(app.query_one("#status", Static).render())
            app.sort_smart_view("missing")
            app.view_mode = "unknown"
            app.sort_records("name")
            app.populate_directory(
                [directory_row(name="Bob"), directory_row(name="Alice")]
            )
            app.sort_records("name")
            app.sort_directory("missing")

            records = app.query_one("#records", DataTable)
            app.set_record_selected(-1, True)
            app.select_record_range(0, 99)
            assert app.selected_record_rows
            app.clear_record_selection()
            assert not app.selected_record_rows
            app.view_mode = "directory"
            assert app.row_to_record(0) is None
            app.view_mode = "dns"
            app.populate_records([row("www")])
            assert app.row_to_record(0) == {
                "name": "www",
                "rtype": "A",
                "value": "192.0.2.10",
                "ttl": "3600",
            }
            assert app.row_to_record(99) is None
            app.populate_records([])
            assert app.row_to_record(0) is None
            app.search_text = ""
            app.populate_records([row("www"), row("db")])
            app.selected_record_rows = {0, 1}
            assert app.selected_record() is None
            app.selected_record_rows = {0}
            selected = app.selected_record()
            assert selected is not None
            assert selected["name"] == "www"
            records.clear()
            app.select_record_range(0, 1)

            for mode in ("directory", "smart", "dns"):
                app.view_mode = mode
                app.refresh_current_view()
            await app.action_load_zones()

    asyncio.run(run_app())


def test_smart_view_default_sort_and_user_override() -> None:
    async def run_app() -> None:
        app = NotificationApp()
        async with app.run_test():
            rows = [
                smart_row(object="recent", evidence="lastLogonTimestamp 100 days ago"),
                smart_row(object="oldest", evidence="lastLogonTimestamp 300 days ago"),
                smart_row(object="older", evidence="lastLogonTimestamp 200 days ago"),
            ]
            app.current_smart_view_id = "ldap_inactive_users"
            app.populate_smart_view("LDAP inactive enabled users", rows)
            assert [row.object for row in app.smart_view_rows] == [
                "oldest",
                "older",
                "recent",
            ]

            app.sort_records("name")
            assert [row.object for row in app.smart_view_rows] == [
                "older",
                "oldest",
                "recent",
            ]
            app.populate_smart_view("LDAP inactive enabled users", rows)
            assert [row.object for row in app.smart_view_rows] == [
                "older",
                "oldest",
                "recent",
            ]

    asyncio.run(run_app())


def test_view_inline_search_scope_edges() -> None:
    class SearchApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.search_rows: list[DirectoryRow] | None = []
            self.samba_result: tuple[int, str] = (
                0,
                "Name=www, Records=1, Children=0\n  A: 192.0.2.10 (flags=f0, serial=1, ttl=1)",
            )

        async def directory_search_rows(
            self, client: Any, kind: str, text: str, max_entries: int | None = None
        ) -> list[DirectoryRow] | None:
            return self.search_rows

        async def run_samba(self, action: str, args: list[str]) -> tuple[int, str]:
            return self.samba_result

    async def run_app() -> None:
        app = SearchApp()
        async with app.run_test():
            assert not await app.refresh_directory_search_scope("alice")
            app.current_directory_values = {
                "kind": "",
                "text": "",
                "base_dn": "",
                "search_base_dn": "",
                "ldap_encryption": "ldaps",
                "ldap_compatibility": "off",
                "max_rows": "10",
            }
            assert not await app.refresh_directory_search_scope("alice")
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#user", Input).value = "admin@example.com"
            app.query_one("#password", Input).value = "secret"
            app.current_directory_values["base_dn"] = "DC=example,DC=com"
            app.current_directory_values["search_base_dn"] = "DC=example,DC=com"
            app.search_rows = None
            assert not await app.refresh_directory_search_scope("alice")
            app.search_rows = [directory_row()]
            app.search_text = "bob"
            app.view_mode = "directory"
            assert not await app.refresh_directory_search_scope("alice")
            app.search_text = "alice"
            assert await app.refresh_directory_search_scope("alice")

            app.query_one("#zone", Input).value = ""
            assert not await app.refresh_dns_search_scope("www")
            app.query_one("#zone", Input).value = "example.com"
            app._last_dns_search_zone = "example.com"
            assert not await app.refresh_dns_search_scope("www")
            app._last_dns_search_zone = ""
            app.samba_result = (1, "bad")
            assert not await app.refresh_dns_search_scope("www")
            app.samba_result = (
                0,
                "Name=www, Records=1, Children=0\n  A: 192.0.2.10 (flags=f0, serial=1, ttl=1)",
            )
            app.search_text = "other"
            app.view_mode = "dns"
            assert not await app.refresh_dns_search_scope("www")
            app.search_text = "www"
            assert await app.refresh_dns_search_scope("www")

            app.search_text = "x"
            app.view_mode = "dns"
            refresh_scope = cast(Any, app.refresh_inline_search_scope).__wrapped__
            await refresh_scope(app, "no", "dns")
            await refresh_scope(app, "x", "dns")
            app.view_mode = "directory"
            await refresh_scope(app, "x", "directory")

    asyncio.run(run_app())


def test_ldap_action_edges() -> None:
    class FakeLdapClient:
        def __init__(self) -> None:
            self.error = ""
            self.modified: list[tuple[str, dict[str, str]]] = []
            self.added: list[tuple[str, str, str, dict[str, str]]] = []
            self.deleted: list[str] = []

        def validation_error(self) -> str:
            return self.error

        def search(
            self, kind: str, text: str, max_entries: int | None = None
        ) -> list[DirectoryRow]:
            if kind == "bad":
                raise ValueError("bad search")
            return [directory_row(kind="computer" if kind == "computers" else "user")]

        def child_containers(self, max_entries: int) -> list[DirectoryRow]:
            return [directory_row(kind="ou", name="Engineering")]

        def modify_attributes(self, dn: str, changes: dict[str, str]) -> None:
            if changes.get("description") == "bad":
                raise ValueError("bad modify")
            self.modified.append((dn, changes))

        def add_entry(
            self, kind: str, parent_dn: str, name: str, attrs: dict[str, str]
        ) -> str:
            if name == "bad":
                raise ValueError("bad add")
            self.added.append((kind, parent_dn, name, attrs))
            return f"CN={name},{parent_dn}"

        def delete_entry(self, dn: str) -> None:
            if "Bad" in dn:
                raise ValueError("bad delete")
            self.deleted.append(dn)

    class LdapApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.client = FakeLdapClient()
            self.forms: list[dict[str, str] | None] = []
            self.confirms: list[bool] = []

        def ldap_client(self, base_dn: str = "") -> Any:
            return self.client

        async def form(self, *args: Any, **kwargs: Any) -> dict[str, str] | None:
            return self.forms.pop(0)

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            return self.confirms.pop(0)

    async def run_app() -> None:
        app = LdapApp()
        async with app.run_test():
            app.query_one("#domain", Input).value = "example.com"
            app.query_one("#ldap_base", Input).value = ""
            assert app.ldap_base_default() == "DC=example,DC=com"
            assert (
                app.ldap_connection_fields("DC=example,DC=com")[0][3]
                == "DC=example,DC=com"
            )
            assert app.smart_max_rows_field()[1] == "max_rows"
            assert app.ldap_search_max_rows({"max_rows": "bad"}) == 200

            values = {
                "kind": "",
                "text": "",
                "base_dn": "DC=example,DC=com",
                "search_base_dn": "",
                "ldap_encryption": "ldaps",
                "ldap_compatibility": "off",
                "max_rows": "1",
            }
            app.client.error = "missing server"
            assert not await app.run_directory_search(values)
            app.client.error = ""
            assert not await app.run_directory_search({**values, "kind": "bad"})
            assert await app.run_directory_search(values, default_kind="users")
            assert app.current_directory_max_rows == 1

            app.forms = [None]
            await app.open_ldap_search()
            app.forms = [values]
            await app.open_ldap_search("groups")
            app.forms = [values]
            await app.action_ldap_search.__wrapped__(app)
            app.forms = [values]
            await app.action_ldap_search_kind.__wrapped__(app, "computers")

            app.current_directory_values = {}
            assert not await app.refresh_current_directory_search()
            assert not await app.load_more_directory()
            app.current_directory_values = values
            app.current_directory_max_rows = 5000
            assert not await app.load_more_directory()
            await app.action_load_more_directory.__wrapped__(app)

            app.populate_directory([])
            assert app.selected_directory_row() is None
            app.populate_directory([directory_row(kind="other")])
            await app.update_ldap_entry()
            app.populate_directory([directory_row()])
            app.forms = [None]
            await app.update_ldap_entry()
            app.forms = [
                {
                    "displayName": "Alice",
                    "mail": "alice@example.com",
                    "description": "old",
                }
            ]
            await app.update_ldap_entry()
            app.forms = [
                {
                    "displayName": "Alicia",
                    "mail": "alice@example.com",
                    "description": "old",
                }
            ]
            app.confirms = [False]
            await app.update_ldap_entry()
            app.forms = [
                {
                    "displayName": "Alicia",
                    "mail": "alice@example.com",
                    "description": "bad",
                }
            ]
            app.confirms = [True]
            await app.update_ldap_entry()
            app.forms = [
                {
                    "displayName": "Alicia",
                    "mail": "alice@example.com",
                    "description": "new",
                }
            ]
            app.confirms = [True]
            await app.update_ldap_entry()
            assert app.client.modified

            add_values = {
                "kind": "user",
                "parent_dn": "CN=Users,DC=example,DC=com",
                "name": "Bob",
                "sAMAccountName": "",
                "userPrincipalName": "",
                "mail": "",
                "description": "",
            }
            assert app.ldap_add_error({"kind": "bad"})
            assert app.ldap_add_error({"kind": "user", "parent_dn": ""})
            app.current_directory_values = {
                "base_dn": "DC=example,DC=com",
                "search_base_dn": "OU=Sales,DC=example,DC=com",
            }
            assert app.ldap_add_error(
                {
                    "kind": "user",
                    "parent_dn": "CN=Users,DC=example,DC=com",
                    "name": "Bob",
                }
            )
            app.current_directory_values = {
                "base_dn": "DC=example,DC=com",
                "search_base_dn": "",
            }
            assert (
                app.ldap_add_error({**add_values, "name": ""})
                == "Enter LDAP object name."
            )
            assert app.ldap_add_error(add_values) is None
            assert "Type: user" in app.ldap_add_preview(add_values)
            app.current_directory_values = values
            app.forms = [None]
            await app.add_ldap_entry()
            app.forms = [add_values]
            app.confirms = [False]
            await app.add_ldap_entry()
            app.forms = [{**add_values, "name": "bad"}]
            app.confirms = [True]
            await app.add_ldap_entry()
            app.forms = [add_values]
            app.confirms = [True]
            await app.add_ldap_entry()
            assert app.client.added

            app.populate_directory([])
            await app.delete_ldap_entry()
            app.populate_directory([directory_row()])
            app.confirms = [False]
            await app.delete_ldap_entry()
            app.populate_directory([directory_row(name="Bad")])
            app.confirms = [True]
            await app.delete_ldap_entry()
            app.populate_directory([directory_row()])
            app.confirms = [True]
            await app.delete_ldap_entry()
            assert app.client.deleted

    asyncio.run(run_app())


def test_smart_action_edges() -> None:
    class SmartApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.forms: list[dict[str, str] | None] = []
            self.screen_values: list[str | None] = []
            self.loaded_full: list[bool] = []
            self.records_result: dict[str, list[DnsRow]] | None = {
                "example.com": [row()]
            }
            self.directory_result: list[DirectoryRow] | None = [directory_row()]
            self.fix_codes: list[int] = []
            self.confirms: list[bool] = []

        async def form(self, *args: Any, **kwargs: Any) -> dict[str, str] | None:
            return self.forms.pop(0)

        async def push_screen_wait(
            self, screen: Any, *, mode: str | None = None
        ) -> Any:
            return self.screen_values.pop(0)

        async def load_full_health_dashboard(
            self,
            values: dict[str, str],
            options: SmartViewOptions,
            *,
            refreshed: bool = False,
        ) -> None:
            self.loaded_full.append(refreshed)

        async def dns_records_for_smart_view(self) -> dict[str, list[DnsRow]] | None:
            return self.records_result

        async def ldap_directory_for_smart_view(
            self, view: Any, values: dict[str, str]
        ) -> list[DirectoryRow] | None:
            return self.directory_result

        async def run_samba_zone(
            self, action: str, zone: str, args: list[str]
        ) -> tuple[int, str]:
            return self.fix_codes.pop(0), ""

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            return self.confirms.pop(0)

    async def run_app() -> None:
        app = SmartApp()
        async with app.run_test():
            assert app.smart_view_choices()
            full = SMART_VIEW_BY_ID[FULL_HEALTH_VIEW_ID]
            fields = app.smart_view_fields(full)
            assert any(field[1] == "base_dn" for field in fields)
            assert app.dns_smart_rows("missing", {}) == []
            app.view_mode = "dns"
            assert app.selected_smart_row() is None
            app.current_smart_view_id = "missing"
            await app.refresh_current_smart_view()
            app.current_smart_view_id = FULL_HEALTH_VIEW_ID
            app.current_smart_values = {}
            await app.refresh_current_smart_view()
            app.current_smart_values = {"max_rows": "5", "base_dn": "DC=example,DC=com"}
            await app.refresh_current_smart_view()
            assert app.loaded_full[-1]
            app.current_smart_view_id = "ldap_inactive_users"
            await app.refresh_current_smart_view()
            app.current_smart_view_id = "dns_duplicates"
            app.records_result = None
            await app.refresh_current_smart_view()

            app.screen_values = [None]
            await app.action_smart_view.__wrapped__(app)
            app.screen_values = ["dns_duplicates"]
            app.forms = [{"max_rows": "5"}]
            await app.action_smart_view.__wrapped__(app)
            await app.action_smart_view_shortcut.__wrapped__(app, "missing")
            app.forms = [{"max_rows": "5"}]
            await app.action_smart_view_shortcut.__wrapped__(app, "1")

            app.forms = [None]
            await app.run_smart_view("dns_duplicates")
            app.forms = [{"max_rows": "5"}]
            app.records_result = {"example.com": [row(), row()]}
            await app.run_smart_view("dns_duplicates")
            assert app.view_mode == "smart"
            app.forms = [
                {
                    "max_rows": "5",
                    "base_dn": "DC=example,DC=com",
                    "ldap_encryption": "ldaps",
                    "ldap_compatibility": "off",
                }
            ]
            app.directory_result = None
            await app.run_smart_view("ldap_users_without_groups")
            app.directory_result = [directory_row()]
            app.forms = [
                {
                    "max_rows": "5",
                    "base_dn": "DC=example,DC=com",
                    "ldap_encryption": "ldaps",
                    "ldap_compatibility": "off",
                }
            ]
            await app.run_smart_view("ldap_users_without_groups")
            app.forms = [
                {
                    "max_rows": "5",
                    "base_dn": "DC=example,DC=com",
                    "ldap_encryption": "ldaps",
                    "ldap_compatibility": "off",
                }
            ]
            await app.run_smart_view(FULL_HEALTH_VIEW_ID)
            assert app.loaded_full

            await app.apply_smart_fix(smart_row(source="ldap"))
            await app.apply_smart_fix(smart_row(fix_action=""))
            await app.apply_smart_fix(smart_row(fix_name="bad space"))
            app.confirms = [False]
            await app.apply_smart_fix(smart_row())
            app.confirms = [True]
            app.fix_codes = [1]
            await app.apply_smart_fix(smart_row())
            app.populate_smart_view("x", [smart_row()])
            app.confirms = [True]
            app.fix_codes = [0]
            await app.action_fix_smart.__wrapped__(app)
            app.populate_records([row()])
            await app.action_fix_smart.__wrapped__(app)

    asyncio.run(run_app())


def test_smart_dns_ldap_dashboard_and_directory_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        def __init__(self, error: str = "") -> None:
            self.error = error

        def validation_error(self) -> str:
            return self.error

        def search(self, kind: str, text: str) -> list[DirectoryRow]:
            if kind == "computers":
                raise ValueError("computer error")
            return [directory_row()]

    class DashboardApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.loaded = 0
            self.zone_results: dict[str, tuple[int, str]] = {}
            self.client = FakeClient()

        async def load_zones(self, *, restore_active_zone: bool = True) -> None:
            self.loaded += 1

        async def run_samba_zone(
            self, action: str, zone: str, args: list[str]
        ) -> tuple[int, str]:
            return self.zone_results.get(
                zone,
                (
                    0,
                    "Name=www, Records=1, Children=0\n  A: 192.0.2.10 (flags=f0, serial=1, ttl=1)",
                ),
            )

        def ldap_client(self, base_dn: str = "") -> Any:
            return self.client

    async def fake_to_thread(func: Any, *args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    async def run_app() -> None:
        app = DashboardApp()
        async with app.run_test():
            assert await app.dns_records_with_failures_for_smart_view() is None
            app.zones = ["example.com", "bad.example"]
            app.zone_results = {"bad.example": (1, "")}
            result = await app.dns_records_with_failures_for_smart_view()
            assert result is not None
            records_by_zone, failures = result
            assert records_by_zone.keys() == {"example.com"}
            assert failures == ["bad.example: query failed"]
            records = await app.dns_records_for_smart_view()
            assert records is not None
            assert app.notifications[-1][1] == "error"

            unloaded = app.dns_dashboard_unloaded_results()
            assert all(item.error for item in unloaded)
            app.zones = []
            checks = await app.dns_dashboard_check_results()
            assert all(item.error for item in checks)
            app.zones = ["example.com"]
            checks = await app.dns_dashboard_check_results()
            assert checks

            options = SmartViewOptions.from_values(
                {
                    "days": "90",
                    "disabled_days": "180",
                    "never_logged_days": "30",
                    "max_rows": "5",
                }
            )
            ldap_results = app.ldap_dashboard_results(
                [directory_row()], "", None, "computer error", options
            )
            assert any(result.error == "computer error" for result in ldap_results)
            validation_results = app.ldap_dashboard_validation_results("missing server")
            assert all(
                result.error == "missing server" for result in validation_results
            )
            app.client = FakeClient("missing server")
            assert all(
                result.error
                for result in await app.ldap_dashboard_check_results(
                    {
                        "base_dn": "DC=example,DC=com",
                        "ldap_encryption": "ldaps",
                        "ldap_compatibility": "off",
                    },
                    options,
                )
            )
            app.client = FakeClient()
            dashboard = await app.ldap_dashboard_check_results(
                {
                    "base_dn": "DC=example,DC=com",
                    "ldap_encryption": "ldaps",
                    "ldap_compatibility": "off",
                },
                options,
            )
            assert dashboard

            assert app.ldap_smart_rows("missing", [], options) == []
            assert (
                app.ldap_smart_rows("ldap_inactive_users", [directory_row()], options)
                == []
            )
            assert (
                app.ldap_smart_rows(
                    "ldap_delete_candidates", [directory_row()], options
                )
                == []
            )
            assert (
                app.ldap_smart_rows(
                    "ldap_stale_computers", [directory_row(kind="computer")], options
                )
                == []
            )
            assert app.ldap_smart_rows(
                "ldap_users_without_groups", [directory_row()], options
            )

            assert await app.dashboard_ldap_rows(cast(Any, FakeClient()), "users")
            rows, error = await app.dashboard_ldap_rows(
                cast(Any, FakeClient()), "computers"
            )
            assert rows is None and error == "computer error"

    monkeypatch.setattr(
        "sambatui.controllers.smart_actions.asyncio.to_thread", fake_to_thread
    )
    asyncio.run(run_app())


def test_core_on_mount_and_config_constructor_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MountApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.after: list[Any] = []
            self.needs_setup = True

        def call_after_refresh(self, callback: Any, *args: Any, **kwargs: Any) -> bool:
            self.after.append(callback)
            return True

        def connection_needs_setup(self) -> bool:
            return self.needs_setup

        async def load_zones(self, *, restore_active_zone: bool = True) -> None:
            return

    async def run_app() -> None:
        app = MountApp()
        async with app.run_test():
            monkeypatch.setattr(
                "sambatui.controllers.core.shutil.which", lambda name: None
            )
            app.on_mount()
            assert app.notifications[-1][0].startswith("samba-tool not found")

            monkeypatch.setattr(
                "sambatui.controllers.core.shutil.which",
                lambda name: "/usr/bin/samba-tool",
            )
            app.on_mount()
            assert "Connection incomplete" in str(
                app.query_one("#status", Static).render()
            )
            app.needs_setup = False
            app.on_mount()
            assert app.after
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#domain", Input).value = "example.com"
            app.query_one("#zone", Input).value = "example.com"
            assert app.connection_settings()
            assert app.connection_summary()
            assert app.connection_fields()
            assert app.password_file()
            assert app.samba_config()
            assert app.samba_client()
            assert app.ldap_config("DC=example,DC=com")
            assert app.ldap_client("DC=example,DC=com")

    asyncio.run(run_app())


def test_remaining_controller_coverage_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class MiscApp(NotificationApp):
        def __init__(self) -> None:
            super().__init__()
            self.confirm_values: list[bool] = []
            self.commands_run: list[tuple[Any, list[str]]] = []
            self.forms: list[dict[str, str] | None] = []
            self.selected: list[dict[str, str]] | None = None

        async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
            return self.confirm_values.pop(0)

        async def add_ptr(self, name: str, ip_value: str) -> int:
            self.commands_run.append(("ptr", [name, ip_value]))
            return 0

        async def run_command(self, client: Any, cmd: list[str]) -> tuple[int, str]:
            self.commands_run.append((client, cmd))
            return 0, "ok"

        async def form(self, *args: Any, **kwargs: Any) -> dict[str, str] | None:
            return self.forms.pop(0)

        def selected_records(self) -> list[dict[str, str]]:
            return [] if self.selected is None else self.selected

    async def run_app() -> None:
        app = MiscApp()
        async with app.run_test():
            app.query_one("#zone", Input).value = "example.com"
            app.query_one("#auto_ptr", Input).value = "ask"
            app.zones = ["2.0.192.in-addr.arpa"]
            await app.maybe_add_matching_ptr("www", "CNAME", "alias.example.com.")
            app.confirm_values = [True]
            await app.maybe_add_matching_ptr("www", "A", "192.0.2.10")
            app.query_one("#auto_ptr", Input).value = "on"
            await app.maybe_add_matching_ptr("db", "A", "192.0.2.11")
            assert ("ptr", ["www", "192.0.2.10"]) in app.commands_run
            assert app.ttl_error("1") is None

            await app.action_update.__wrapped__(app)
            assert any("Select a real record" in note[0] for note in app.notifications)

            monkeypatch.setattr(
                "sambatui.controllers.core.save_user_config",
                lambda values: (_ for _ in ()).throw(OSError("readonly")),
            )
            AppCoreMixin.save_preferences(app)
            assert "Cannot save" in str(app.query_one("#status", Static).render())

            path = tmp_path / "blocked"
            path.write_text("secret\n", encoding="utf-8")
            path.chmod(0o000)
            monkeypatch.setattr(
                "sambatui.controllers.core.password_file_warning",
                lambda p: "cannot read",
            )
            app.set_initial_connection_status()
            assert "cannot read" in str(app.query_one("#status", Static).render())
            monkeypatch.setattr(
                "sambatui.controllers.core.password_file_permissions_too_open",
                lambda p: False,
            )
            app.query_one("#password_file", Input).value = str(path)
            await app.load_password()
            assert "cannot read" in str(app.query_one("#status", Static).render())

            app.commands_run.clear()
            await app.run_samba("query", ["@", "ALL"])
            await app.run_samba_zone("query", "example.com", ["@", "ALL"])
            await app.run_zonelist()
            assert len(app.commands_run) == 3

            assert not await app.activate_zone("missing.example")
            assert "select zone" in str(app.query_one("#status", Static).render())

            original_query_one = app.query_one
            setattr(
                app,
                "query_one",
                lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no table")),
            )
            assert app.records_cursor_row() == 0
            setattr(app, "query_one", original_query_one)

            app.populate_records([row("www")])
            original_query_one = app.query_one
            setattr(
                app,
                "query_one",
                lambda *args, **kwargs: SimpleNamespace(
                    get_row_at=lambda row_index: []
                ),
            )
            assert app.row_to_record(0) is None
            setattr(app, "query_one", original_query_one)

            app.query_one("#password_file", Input).value = str(tmp_path / "missing")
            password_values = {
                "domain": "example.com",
                "auth": "password",
                "user": "admin",
                "password": "",
                "server": "dc01.example.com",
                "ldap_encryption": "off",
            }
            assert (
                app.setup_wizard_validation_error(
                    {"domain": "example.com", "auth": "bad"}
                )
                == "Auth must be password or kerberos."
            )
            assert app.setup_wizard_validation_error(password_values)
            assert app.setup_wizard_validation_error({**password_values, "server": ""})

            class FakeCheckClient:
                def __init__(self, error: str = "") -> None:
                    self.error = error

                def check_connection(self) -> None:
                    if self.error:
                        raise ValueError(self.error)

            setattr(app, "ldap_client", lambda base_dn="": FakeCheckClient())
            assert await app.check_ldap_connectivity() is None
            setattr(
                app, "ldap_client", lambda base_dn="": FakeCheckClient("bind failed")
            )
            assert await app.check_ldap_connectivity() == "bind failed"

            monkeypatch.setattr(
                "sambatui.controllers.setup.password_file_warning",
                lambda p: "bad password file",
            )
            app.forms = [
                {
                    "auth": "password",
                    "password": "",
                    "password_file": str(tmp_path / "missing"),
                }
            ]
            assert await app.open_connection_settings()
            assert any("bad password file" in note[0] for note in app.notifications)

            app.forms = [{"domain": "example.com"}]

            async def no_discovery(
                domain: str,
            ) -> tuple[list[DiscoveredService], DiscoveredService] | None:
                return None

            setattr(app, "discover_ad_controller", no_discovery)
            assert not await app.open_discover_ad()

            async def no_dns_records() -> (
                tuple[dict[str, list[DnsRow]], list[str]] | None
            ):
                return None

            setattr(app, "dns_records_with_failures_for_smart_view", no_dns_records)
            assert await app.dns_records_for_smart_view() is None

            values = {
                "base_dn": "",
                "ldap_encryption": "ldaps",
                "ldap_compatibility": "off",
            }
            setattr(
                app,
                "ldap_client",
                lambda base_dn="": SimpleNamespace(
                    validation_error=lambda: "missing base"
                ),
            )
            assert (
                await app.ldap_directory_for_smart_view(
                    SMART_VIEW_BY_ID["ldap_users_without_groups"], values
                )
                is None
            )
            values["base_dn"] = "DC=example,DC=com"
            setattr(
                app,
                "ldap_client",
                lambda base_dn="": SimpleNamespace(validation_error=lambda: ""),
            )

            async def directory_rows(
                client: Any,
                kind: str,
                text: str,
                max_entries: int | None = None,
            ) -> list[DirectoryRow]:
                return [
                    directory_row(kind="computer" if kind == "computers" else "user")
                ]

            setattr(app, "directory_search_rows", directory_rows)
            assert await app.ldap_directory_for_smart_view(
                SMART_VIEW_BY_ID["ldap_users_without_groups"], values
            )
            assert await app.ldap_directory_for_smart_view(
                SMART_VIEW_BY_ID["ldap_stale_computers"], values
            )

            app.populate_directory([])
            await app.update_ldap_entry()

    asyncio.run(run_app())


def test_setup_thread_wrappers(monkeypatch: pytest.MonkeyPatch) -> None:
    app = SambatuiApp()
    services = [
        DiscoveredService("ldap", "example.com", "dc01.example.com", 389, 0, 100)
    ]

    async def fake_to_thread(func: Any, *args: Any, **kwargs: Any) -> Any:
        return services

    monkeypatch.setattr("sambatui.controllers.setup.asyncio.to_thread", fake_to_thread)
    assert asyncio.run(app.discover_setup_services("example.com")) == services
