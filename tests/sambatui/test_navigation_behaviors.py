from __future__ import annotations

import asyncio
from types import SimpleNamespace

from textual.events import Key
from textual.widgets import DataTable, Input, TabbedContent

from sambatui.app import SambatuiApp
from sambatui.core.models import DnsRow


class NavigationApp(SambatuiApp):
    def __init__(self) -> None:
        super().__init__()
        self.actions = []
        self.searches = []

    def save_preferences(self) -> None:
        pass

    async def action_ldap_search(self) -> None:
        self.actions.append("ldap")

    def action_fix_smart(self) -> None:
        self.actions.append("fix")

    def action_smart_view_shortcut(self, shortcut: str) -> None:
        self.actions.append(shortcut)

    async def activate_sidebar_selection(self, table: DataTable) -> bool:
        self.actions.append(table.id)
        return True

    def refresh_inline_search_scope(self, text: str, mode: str) -> None:
        self.searches.append((text, mode))


def populate(app: SambatuiApp) -> DataTable:
    app.populate_records(
        [
            DnsRow(f"host{i}", "1", "0", "A", f"192.0.2.{i + 1}", "", "")
            for i in range(3)
        ]
    )
    return app.focus_records_table()


def test_focus_cycles_through_each_sidebar_and_records() -> None:
    async def run_app() -> None:
        app = NavigationApp()
        async with app.run_test() as pilot:
            populate(app)
            steps = [
                (app.action_focus_zones, "zones"),
                (app.action_next_table, "dns_findings"),
                (app.action_next_table, "records"),
                (app.action_next_table, "zones"),
                (app.action_previous_table, "records"),
                (app.action_previous_table, "zones"),
                (app.action_next_side_tab, "ldap_structure"),
                (app.action_next_table, "ldap_findings"),
                (app.action_next_table, "records"),
                (app.action_previous_side_tab, "zones"),
            ]
            for action, expected in steps:
                action()
                await pilot.pause()
                assert app.focused_table().id == expected
            assert app.query_one("#side_tabs", TabbedContent).active == "dns_tab"

    asyncio.run(run_app())


def test_cursor_paging_and_sort_shortcuts() -> None:
    async def run_app() -> None:
        app = NavigationApp()
        async with app.run_test():
            table = populate(app)
            assert app.page_rows(SimpleNamespace(size=SimpleNamespace(height=0))) == 10
            assert app.page_rows(SimpleNamespace(size=SimpleNamespace(height=4))) == 1
            app.action_cursor_bottom()
            assert table.cursor_row == 2
            app.action_cursor_top()
            assert table.cursor_row == 0
            app.action_cursor_page_down()
            assert table.cursor_row == 2
            app.action_cursor_page_up()
            assert table.cursor_row == 0
            app.action_cursor_half_page_down()
            assert table.cursor_row > 0
            app.action_cursor_half_page_up()
            assert table.cursor_row == 0
            app.action_sort_type()
            assert app.views.dns.sort_field == "type"
            app.action_sort_value()
            assert app.views.dns.sort_field == "value"
            app.action_sort_name()
            assert app.views.dns.sort_field == "name"
            table.clear()
            app.move_cursor_by(1)
            app.action_cursor_bottom()
            assert app.record_selection_table() is None
            app.action_extend_up()

    asyncio.run(run_app())


def test_key_dispatch_and_row_activation_remain_mode_specific() -> None:
    async def run_app() -> None:
        app = NavigationApp()
        async with app.run_test() as pilot:
            table = populate(app)
            assert await app.handle_key("L", "L")
            assert app.actions == ["ldap"]
            assert await app.handle_key("1", "1")
            assert app.actions[-1] == "1"
            assert await app.handle_key("G", "G")
            assert table.cursor_row == 2
            assert await app.handle_key("g", "g")
            assert app.pending_g
            assert await app.handle_key("g", "g")
            assert table.cursor_row == 0
            assert await app.handle_key("n", "n")
            assert not await app.handle_key("unknown", None)

            await app.action_activate_row()
            assert app.views.dns.selected_rows == {0}
            app.views.mode = "directory"
            await app.action_activate_row()
            app.views.mode = "smart"
            await app.action_activate_row()
            assert app.actions[-1] == "fix"
            app.views.mode = "unknown"
            await app.action_activate_row()
            assert not app.ensure_selectable_records_view()
            assert app.record_selection_table() is None
            assert app.header_sort_field(2) is None
            app.action_focus_zones()
            await pilot.pause()
            await app.action_activate_row()
            assert app.actions[-1] == "zones"
            assert app.record_selection_table(require_records_focus=True) is None
            assert not app.is_sidebar_table(None)

    asyncio.run(run_app())


def test_range_extension_and_visual_toggle() -> None:
    async def run_app() -> None:
        app = NavigationApp()
        async with app.run_test():
            table = populate(app)
            table.move_cursor(row=1)
            app.action_select_range()
            assert app.views.dns.selection_anchor == 1
            assert app.views.dns.selected_rows == {1}
            app.clear_current_selection()
            app.action_extend_up()
            assert app.views.dns.selected_rows == {0, 1}
            app.action_extend_down()
            assert app.views.dns.selected_rows == {1}
            app.action_visual_select()
            assert app.views.visual_selecting
            app.action_visual_select()
            assert not app.views.visual_selecting

    asyncio.run(run_app())


def test_inline_search_keyboard_events_and_escape_layers() -> None:
    async def run_app() -> None:
        app = NavigationApp()
        async with app.run_test() as pilot:
            table = populate(app)
            await pilot.press("/")
            search = app.query_one("#inline_search", Input)
            assert app.focused is search
            assert app.active_table() is table
            app.set_search_text("host")
            await pilot.pause()
            assert app.should_ignore_key_event(Key("x", "x"))
            await app.on_key(Key("x", "x"))
            await pilot.press("enter")
            assert app.focused is table
            assert app.search_text == "host"
            await pilot.press("escape")
            assert not app.search_text
            await pilot.press("escape")
            assert app.focused is table

            await pilot.press("/", "escape")
            assert app.focused is table
            app.set_search_text("host")
            await pilot.press("/", "escape")
            assert not app.search_text
            assert app.focused is table

            app.views.smart.view_id = "dns_duplicates"
            app.populate_smart_view("Findings", [])
            app.action_clear_navigation_state()
            assert app.views.mode == "dns"

    asyncio.run(run_app())


def test_table_events_ignore_other_widgets_and_sort_result_headers() -> None:
    async def run_app() -> None:
        app = NavigationApp()
        async with app.run_test():
            table = populate(app)
            zones = app.query_one("#zones", DataTable)
            app.on_data_table_header_selected(
                SimpleNamespace(data_table=zones, column_index=0)
            )
            app.on_data_table_header_selected(
                SimpleNamespace(data_table=table, column_index=3)
            )
            assert app.views.dns.sort_field == "type"
            app.on_data_table_header_selected(
                SimpleNamespace(data_table=table, column_index=99)
            )
            assert app.views.dns.sort_field == "type"
            await app.on_data_table_row_selected(SimpleNamespace(data_table=table))
            await app.on_data_table_row_selected(SimpleNamespace(data_table=zones))
            assert app.actions == ["zones"]
            app._syncing_search_input = True
            app.on_input_changed(
                Input.Changed(app.query_one("#inline_search", Input), "host")
            )
            assert app.searches == []

    asyncio.run(run_app())
