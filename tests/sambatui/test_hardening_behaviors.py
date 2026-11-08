from __future__ import annotations

import asyncio
import threading
from collections.abc import Mapping
from pathlib import Path

import pytest
from rich.text import Text
from textual.content import Content
from textual.widgets import DataTable, Input, Label, Static

from sambatui.app import SambatuiApp
from sambatui.core.config import AppConfig, read_password_file
from sambatui.core.models import DnsRow
from sambatui.core.mutations import MutationHost
from sambatui.core.settings import ConnectionSettings
from sambatui.ldap.client import LdapDirectoryClient
from sambatui.ldap.rows import DirectoryRow
from sambatui.ldap.sidebar import SidebarItem
from sambatui.ui.screens import ConfirmScreen, FormScreen


class LocalApp(SambatuiApp):
    def on_mount(self) -> None:
        self.initialize_view()

    def save_preferences(self) -> None:
        pass


def test_settings_are_immutable_normalized_and_secret_safe(tmp_path: Path) -> None:
    secret = "  secret with spaces  "
    config = AppConfig.load(
        env={"SAMBATUI_PASSWORD": secret}, preferences={}, ticket_checker=lambda: False
    )
    settings = ConnectionSettings(server=" dc.example.com ", password=secret)
    assert config.password == settings.password == secret
    assert secret not in repr(config)
    assert secret not in repr(settings)
    updated = settings.updated({"server": " new.example.com ", "password": secret})
    assert settings.server == "dc.example.com"
    assert updated.server == "new.example.com"
    assert updated.password == secret
    with pytest.raises(KeyError):
        settings.updated({"misspelled": "value"})
    path = tmp_path / "password"
    path.write_text(secret + "\r\n", encoding="utf-8")
    path.chmod(0o600)
    assert read_password_file(path) == secret


def test_model_replaces_hidden_inputs_and_implements_controller_contracts() -> None:
    async def scenario() -> None:
        app = LocalApp()
        mutation_host: MutationHost = app
        assert mutation_host is app
        app.set_val("server", " dc.example.com ")
        revision = app.connection_revision
        app.set_val("server", "dc.example.com")
        assert app.connection_revision == revision
        assert app.val("server") == "dc.example.com"
        async with app.run_test():
            assert [widget.id for widget in app.query(Input)] == ["inline_search"]
            assert not app.query("#connection_state")
            app.set_status("[not markup] raw output")
            assert (
                str(app.query_one("#status", Static).render())
                == "[not markup] raw output"
            )

    asyncio.run(scenario())


def test_password_form_preserves_whitespace() -> None:
    async def scenario() -> None:
        app = LocalApp()
        async with app.run_test():
            screen = FormScreen(
                "Credentials", "", [("Password", "password", "", "  secret  ")]
            )
            await app.push_screen(screen)
            assert screen.form_values()["password"] == "  secret  "

    asyncio.run(scenario())


def test_ldap_write_builds_client_on_ui_thread_and_freezes_confirmed_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        app = LocalApp()
        ui_thread = threading.get_ident()
        calls: list[tuple[str, str]] = []
        row = DirectoryRow(
            "CN=Alice,DC=example,DC=com", "user", "Alice", "", {"uSNChanged": ("17",)}
        )

        class Client(LdapDirectoryClient):
            def modify_attributes(
                self, dn: str, changes: Mapping[str, str], *, expected_revision: str
            ) -> None:
                assert threading.get_ident() != ui_thread
                calls.append((self.config.server, dn))

        def client(base_dn: str = "") -> Client:
            assert threading.get_ident() == ui_thread
            return Client(app.ldap_config(base_dn))

        async def form(*args: object, **kwargs: object) -> dict[str, str]:
            return {"displayName": "", "mail": "", "description": "new"}

        async def confirm(*args: object, **kwargs: object) -> bool:
            app.set_val("server", "new.example.com")
            return True

        monkeypatch.setattr(app, "selected_directory_row", lambda: row)
        monkeypatch.setattr(app, "form", form)
        monkeypatch.setattr(app, "confirm", confirm)
        monkeypatch.setattr(app, "ldap_client", client)
        app.set_val("server", "original.example.com")
        async with app.run_test():
            await app.update_ldap_entry()
        assert calls == [("original.example.com", row.dn)]
        assert app.val("server") == "new.example.com"
        assert not app.mutations.active

    asyncio.run(scenario())


def test_unexpected_ui_errors_are_not_silenced(monkeypatch: pytest.MonkeyPatch) -> None:
    app = LocalApp()

    def broken_query(*args: object, **kwargs: object) -> Static:
        raise RuntimeError("programming error")

    monkeypatch.setattr(app, "query_one", broken_query)
    with pytest.raises(RuntimeError, match="programming error"):
        app.set_status("message")


def test_connection_changes_discard_pending_dns_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        app = LocalApp()
        original = DnsRow("old", "1", "0", "A", "192.0.2.1", "60", "")

        async def query(action: str, args: list[str]) -> tuple[int, str]:
            app.set_val("server", "different.example.com")
            return 0, "Name=new, Records=1, Children=0\n  A: 192.0.2.2 (ttl=60)"

        monkeypatch.setattr(app, "run_samba", query)
        async with app.run_test():
            app.populate_records([original])
            await app.do_command("query", ["@", "ALL"], update_table=True)
            assert app.views.dns.rows == []

    asyncio.run(scenario())


def test_untrusted_directory_dns_and_confirmation_text_is_literal() -> None:
    async def scenario() -> None:
        app = LocalApp()
        payload = "[conceal]not hidden[/conceal]"

        def assert_literal(widget: Static) -> None:
            widget.update(payload)
            visual = widget.visual
            assert isinstance(visual, Content)
            assert visual.plain == payload
            assert not visual.spans

        async with app.run_test() as pilot:
            app.populate_records(
                [DnsRow("literal", "1", "0", "TXT", payload, "900", "")]
            )
            cells = app.query_one("#records", DataTable).get_row_at(0)
            literal = next(
                cell
                for cell in cells
                if isinstance(cell, Text) and cell.plain == payload
            )
            assert literal.spans == []
            app.populate_sidebar_table("zones", [SidebarItem(payload, payload, "zone")])
            sidebar = app.query_one("#zones", DataTable).get_row_at(0)[0]
            assert isinstance(sidebar, Text)
            assert sidebar.plain == payload and sidebar.spans == []
            assert_literal(app.query_one("#connection_summary", Static))
            assert_literal(app.query_one("#records_title", Label))
            await app.push_screen(ConfirmScreen(payload))
            assert_literal(app.screen.query_one("#confirm_message", Static))
            app.pop_screen()
            await pilot.pause()
            await app.push_screen(
                FormScreen(payload, payload, [(payload, "name", "", payload)])
            )
            for widget in app.screen.query(Static):
                assert_literal(widget)

    asyncio.run(scenario())
