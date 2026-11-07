from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from textual.widgets import DataTable, Static

from sambatui.app import SambatuiApp
from sambatui.core.models import DnsRow
from sambatui.core.view_state import ViewMode
from sambatui.ldap.rows import DirectoryRow
from sambatui.smart_views.models import SmartViewRow


class LocalApp(SambatuiApp):
    def save_preferences(self) -> None:
        pass


def populate(app: SambatuiApp, mode: ViewMode, count: int) -> None:
    if mode is ViewMode.DNS:
        app.populate_records(
            [
                DnsRow(f"host{i}", "1", "0", "A", f"192.0.2.{i + 1}", "", "")
                for i in range(count)
            ]
        )
    elif mode is ViewMode.DIRECTORY:
        app.populate_directory(
            [
                DirectoryRow(
                    f"CN=User{i},DC=example,DC=com", "user", f"User{i}", "", {}
                )
                for i in range(count)
            ]
        )
    else:
        app.populate_smart_view(
            "Findings",
            [
                SmartViewRow(
                    "info", f"Object{i}", "Finding", "Evidence", "Review", "dns"
                )
                for i in range(count)
            ],
        )


def test_state_exists_before_mount() -> None:
    app = LocalApp()
    assert app.views.mode is ViewMode.DNS
    assert not app.views.dns.rows
    assert not app.views.directory.values
    assert not app.views.smart.values


@pytest.mark.parametrize("mode", list(ViewMode))
def test_visual_range_keeps_anchor_and_visual_mode(mode: ViewMode) -> None:
    async def run_app() -> None:
        app = LocalApp()
        async with app.run_test() as pilot:
            populate(app, mode, 3)
            app.query_one("#records", DataTable).focus()
            await pilot.press("v", "j", "j")
            assert app.views.visual_selecting
            assert app.views.current.selection_anchor == 0
            assert app.views.current.selected_rows == {0, 1, 2}
            assert "VISUAL" in str(app.query_one("#selection_state", Static).render())

            await pilot.press("k")
            assert app.views.current.selected_rows == {0, 1}
            await pilot.press("escape")
            assert not app.views.visual_selecting
            assert app.views.current.selected_rows == {0, 1}
            await pilot.press("escape")
            assert not app.views.current.selected_rows
            assert app.views.current.selection_anchor is None

    asyncio.run(run_app())


@pytest.mark.parametrize("mode", list(ViewMode))
def test_empty_state_rows_cannot_be_selected(mode: ViewMode) -> None:
    async def run_app() -> None:
        app = LocalApp()
        async with app.run_test() as pilot:
            populate(app, mode, 0)
            table = app.query_one("#records", DataTable)
            table.focus()
            await pilot.press("space", "v", "V")
            app.set_current_row_selected(0, True)
            assert not app.views.current.selected_rows
            assert app.views.current.selection_anchor is None
            assert not app.views.visual_selecting
            assert str(table.get_row_at(0)[0]) == ""

    asyncio.run(run_app())


def test_additive_ranges_and_inactive_selection_do_not_corrupt_current_table() -> None:
    async def run_app() -> None:
        app = LocalApp()
        async with app.run_test():
            populate(app, ViewMode.DNS, 4)
            app.sort_records("unknown")
            assert app.views.dns.sort_field == "name"
            app.clear_view_selection("unknown")
            app.set_record_selected(0, True)
            app.select_record_range(2, 3, clear=False)
            assert app.views.dns.selected_rows == {0, 2, 3}
            app.select_record_range(1, 2)
            assert app.views.dns.selected_rows == {1, 2}

            populate(app, ViewMode.DIRECTORY, 1)
            app.set_record_selected(0, True)
            assert app.views.dns.selected_rows == {0}
            assert str(app.query_one("#records", DataTable).get_row_at(0)[0]) == ""
            app.clear_record_selection()
            assert not app.views.dns.selected_rows
            assert not app.views.directory.selected_rows

    asyncio.run(run_app())


def test_failed_smart_view_keeps_previous_findings_and_options() -> None:
    class FailedApp(LocalApp):
        async def smart_view_values(self, view):
            return {"max_rows": "20"}

        async def build_smart_view_rows(self, view, values, options):
            return None

    async def run_app() -> None:
        app = FailedApp()
        async with app.run_test():
            app.views.smart.view_id = "dns_duplicates"
            app.views.smart.values = {"max_rows": "10"}
            app.views.smart.max_rows = 10
            app.views.smart.sort_field = "object"
            populate(app, ViewMode.SMART, 1)
            rows = app.views.smart.rows.copy()
            await app.run_smart_view("dns_a_without_ptr")
            assert app.views.mode is ViewMode.SMART
            assert app.views.smart.view_id == "dns_duplicates"
            assert app.views.smart.values == {"max_rows": "10"}
            assert app.views.smart.max_rows == 10
            assert app.views.smart.sort_field == "object"
            assert app.views.smart.rows == rows

    asyncio.run(run_app())


def test_dns_inline_search_discards_results_after_zone_switch() -> None:
    async def run_app() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        class DelayedApp(LocalApp):
            async def run_samba(self, action, args):
                started.set()
                await release.wait()
                return (
                    0,
                    "Name=old, Records=1, Children=0\n  A: 192.0.2.1 (flags=f0, serial=1, ttl=1)",
                )

        app = DelayedApp()
        async with app.run_test():
            app.set_val("zone", "old.example.com")
            app.search_text = "host"
            task = asyncio.create_task(app.refresh_dns_search_scope("host"))
            await started.wait()
            app.set_val("zone", "new.example.com")
            populate(app, ViewMode.DNS, 1)
            release.set()
            assert not await task
            assert app.views.dns.rows[0].name == "host0"
            assert not app.views.dns.last_search_zone

    asyncio.run(run_app())


def test_smart_refresh_discards_results_after_leaving_findings() -> None:
    async def run_app() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        class DelayedApp(LocalApp):
            async def build_smart_view_rows(self, view, values, options):
                started.set()
                await release.wait()
                return []

        app = DelayedApp()
        async with app.run_test():
            app.views.smart.view_id = "dns_duplicates"
            app.views.smart.values = {"max_rows": "10"}
            populate(app, ViewMode.SMART, 1)
            task = asyncio.create_task(app.refresh_current_smart_view())
            await started.wait()
            populate(app, ViewMode.DIRECTORY, 1)
            release.set()
            await task
            assert app.views.mode is ViewMode.DIRECTORY
            assert app.views.smart.view_id == ""
            assert app.views.directory.rows[0].name == "User0"

    asyncio.run(run_app())


def test_nested_busy_scopes_stay_busy_until_outer_exit() -> None:
    class BusyApp(LocalApp):
        def __init__(self):
            super().__init__()
            self.busy_changes = []

        def set_busy(self, busy):
            self.busy_changes.append(busy)

    async def run_app() -> None:
        app = BusyApp()
        with pytest.raises(ValueError, match="failed"):
            async with app.busy():
                async with app.busy():
                    assert app._busy_depth == 2
                assert app._busy_depth == 1
                assert app.busy_changes == [True]
                raise ValueError("failed")
        assert app._busy_depth == 0
        assert app.busy_changes == [True, False]

    asyncio.run(run_app())


def test_cancelling_command_reaps_its_subprocess(monkeypatch) -> None:
    class CancelledProcess:
        calls = 0
        killed = False

        async def communicate(self):
            self.calls += 1
            if self.calls == 1:
                raise asyncio.CancelledError
            return b"", b""

        def kill(self):
            self.killed = True

    process = CancelledProcess()

    async def fake_exec(*args, **kwargs):
        return process

    monkeypatch.setattr(
        "sambatui.samba.execution.asyncio.create_subprocess_exec", fake_exec
    )

    async def run_app() -> None:
        app = LocalApp()
        client = SimpleNamespace(
            authentication_error=lambda: None,
            status_command=lambda cmd: "fake command",
            execution_env=lambda: None,
        )
        with pytest.raises(asyncio.CancelledError):
            await app.run_command(client, ["never-executed"])
        assert process.killed
        assert process.calls == 2

    asyncio.run(run_app())


def test_range_selection_filters_rows_once_per_batch() -> None:
    class CountingApp(LocalApp):
        def __init__(self):
            super().__init__()
            self.filter_calls = 0

        def visible_rows_for_mode(self, mode):
            self.filter_calls += 1
            return super().visible_rows_for_mode(mode)

    async def run_app() -> None:
        app = CountingApp()
        async with app.run_test():
            populate(app, ViewMode.DNS, 3)
            app.search_text = "host"
            app.set_record_selected(0, True)
            app.filter_calls = 0
            app.select_record_range(0, 2)
            assert app.views.dns.selected_rows == {0, 1, 2}
            assert app.filter_calls == 1

    asyncio.run(run_app())
