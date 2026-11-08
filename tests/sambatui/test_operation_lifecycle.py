from __future__ import annotations

import asyncio

import pytest

from sambatui.app import SambatuiApp
from sambatui.ldap.client import LdapDirectoryClient
from sambatui.ldap.rows import DirectoryRow
from sambatui.samba.client import SambaCommandClient
from sambatui.smart_view_catalog import SmartViewOptions
from sambatui.smart_views import SmartViewCheckResult


class LocalApp(SambatuiApp):
    def on_mount(self) -> None:
        self.initialize_view()

    def save_preferences(self) -> None:
        pass


LDAP_VALUES = {
    "kind": "users",
    "text": "",
    "base_dn": "DC=example,DC=com",
    "ldap_encryption": "ldaps",
}


def test_dns_and_ldap_write_entrypoints_share_one_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        app = LocalApp()
        app.set_val("server", "original.example.com")
        started, release = asyncio.Event(), asyncio.Event()
        targets: list[str] = []

        async def execute(
            client: SambaCommandClient, command: list[str]
        ) -> tuple[int, str]:
            targets.append(command[command.index("--") + 1])
            started.set()
            await release.wait()
            return 0, "written"

        def unexpected_selection() -> list[DirectoryRow]:
            pytest.fail("overlapping LDAP action entered its body")

        monkeypatch.setattr(app, "run_command", execute)
        monkeypatch.setattr(app, "selected_directory_entries", unexpected_selection)
        async with app.run_test():
            task = asyncio.create_task(
                app.run_samba_zone("add", "example.com", ["a", "A", "192.0.2.1"])
            )
            try:
                await started.wait()
                assert app.mutations.active
                code, message = await app.run_samba_zone(
                    "delete", "example.com", ["a", "A", "192.0.2.1"]
                )
                assert code == 2
                assert "still in progress" in message
                await app.delete_ldap_entry()
                app.set_val("server", "new.example.com")
            finally:
                release.set()
                assert await task == (0, "written")
            assert not app.mutations.active
        assert targets == ["original.example.com"]

    asyncio.run(scenario())


def test_connection_change_discards_directory_search_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        app = LocalApp()
        app.set_connection_values(
            {"server": "original.example.com", "user": "alice", "password": "secret"}
        )
        row = DirectoryRow(
            "CN=Alice,DC=example,DC=com", "user", "Alice", "", {"uSNChanged": ("17",)}
        )

        async def search(*args: object, **kwargs: object) -> list[DirectoryRow]:
            app.set_val("server", "new.example.com")
            return [row]

        async def containers(*args: object, **kwargs: object) -> list[DirectoryRow]:
            return []

        monkeypatch.setattr(app, "directory_search_rows", search)
        monkeypatch.setattr(app, "directory_container_rows", containers)
        async with app.run_test():
            assert not await app.run_directory_search(LDAP_VALUES)
            assert app.views.directory.rows == []

    asyncio.run(scenario())


def test_write_refresh_does_not_switch_back_to_an_old_connection() -> None:
    async def scenario() -> None:
        app = LocalApp()
        async with app.run_test():
            with app.mutations.reserve(app.connection_settings()):
                app.set_val("server", "new.example.com")
                await app.refresh_current_zone()
                await app.refresh_current_smart_view()
                assert not await app.refresh_current_directory_search()
            assert app.val("server") == "new.example.com"

    asyncio.run(scenario())


def test_dashboard_discards_results_after_connection_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        app = LocalApp()

        async def dns() -> list[SmartViewCheckResult]:
            app.set_val("server", "new.example.com")
            return []

        async def ldap(*args: object, **kwargs: object) -> list[SmartViewCheckResult]:
            return []

        monkeypatch.setattr(app, "dns_dashboard_check_results", dns)
        monkeypatch.setattr(app, "ldap_dashboard_check_results", ldap)
        async with app.run_test():
            await app.load_full_health_dashboard(
                LDAP_VALUES, SmartViewOptions.from_values({})
            )
            assert app.views.smart.rows == []

    asyncio.run(scenario())


def test_setup_does_not_disguise_programming_errors_as_connection_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenClient(LdapDirectoryClient):
        def check_connection(self) -> None:
            raise RuntimeError("programming error")

    async def scenario() -> None:
        app = LocalApp()
        monkeypatch.setattr(app, "ldap_client", lambda: BrokenClient(app.ldap_config()))
        with pytest.raises(RuntimeError, match="programming error"):
            await app.check_ldap_connectivity()

    asyncio.run(scenario())
