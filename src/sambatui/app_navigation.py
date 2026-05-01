from __future__ import annotations

import inspect
from contextlib import suppress
from typing import TYPE_CHECKING, Any

from textual.app import App
from textual.widgets import Button, DataTable, Input, TabbedContent

from .app_constants import (
    CASE_SENSITIVE_ACTION_NAMES,
    CHAR_ACTION_NAMES,
    KEY_ACTION_NAMES,
    SIDE_TAB_IDS,
)
from .smart_view_catalog import SMART_VIEW_BY_SHORTCUT


class AppNavigationMixin(App):
    if TYPE_CHECKING:
        _syncing_search_input: bool
        pending_g: bool
        search_text: str
        selected_record_rows: set[int]
        selection_anchor: int | None
        view_mode: str
        visual_selecting: bool
        zones: list[str]

        def action_fix_smart(self) -> Any: ...

        def action_smart_view_shortcut(self, shortcut: str) -> Any: ...

        async def activate_sidebar_selection(self, table: DataTable) -> bool: ...

        def clear_record_selection(self) -> None: ...

        def refresh_current_view(self) -> None: ...

        def refresh_key_hints(self) -> None: ...

        def refresh_inline_search_scope(
            self, search_text: str, view_mode: str
        ) -> Any: ...

        def select_record_range(self, start: int, end: int) -> None: ...

        def set_record_selected(self, row_index: int, selected: bool) -> None: ...

        def set_status(self, message: str) -> None: ...

        def sort_records(self, field: str) -> None: ...

        def update_details_pane(self) -> None: ...

    def sync_inline_search_input(self) -> None:
        with suppress(Exception):
            search = self.query_one("#inline_search", Input)
            if search.value == self.search_text:
                return
            self._syncing_search_input = True
            try:
                search.value = self.search_text
            finally:
                self._syncing_search_input = False

    def set_search_text(self, text: str, *, refresh: bool = True) -> None:
        self.search_text = text
        self.sync_inline_search_input()
        if refresh:
            self.refresh_current_view()

    def action_search(self) -> None:
        self.pending_g = False
        search = self.query_one("#inline_search", Input)
        search.focus()
        self.set_status(
            "Inline search: LDAP/DNS searches source data; smart views filter loaded findings"
        )

    def focused_table(self) -> DataTable | None:
        focused = self.focused
        return focused if isinstance(focused, DataTable) else None

    def sidebar_table_id(self) -> str:
        active = "dns_tab"
        with suppress(Exception):
            active = self.query_one("#side_tabs", TabbedContent).active or "dns_tab"
        if active == "ldap_tab":
            return "ldap_structure"
        return "zones"

    def action_focus_zones(self) -> None:
        self.pending_g = False
        self.query_one(f"#{self.sidebar_table_id()}", DataTable).focus()

    def action_focus_records(self) -> None:
        self.pending_g = False
        self.query_one("#records", DataTable).focus()

    def action_next_table(self) -> None:
        table = self.focused_table()
        if table and table.id in {"zones", "ldap_structure"}:
            self.action_focus_records()
        else:
            self.action_focus_zones()

    def action_previous_table(self) -> None:
        table = self.focused_table()
        if table and table.id == "records":
            self.action_focus_zones()
        else:
            self.action_focus_records()

    def action_next_side_tab(self) -> None:
        self.switch_side_tab(1)

    def action_previous_side_tab(self) -> None:
        self.switch_side_tab(-1)

    def switch_side_tab(self, delta: int) -> None:
        tabs = self.query_one("#side_tabs", TabbedContent)
        current = tabs.active if tabs.active in SIDE_TAB_IDS else "dns_tab"
        current_index = SIDE_TAB_IDS.index(current)
        tabs.active = SIDE_TAB_IDS[(current_index + delta) % len(SIDE_TAB_IDS)]
        self.refresh_key_hints()
        if tabs.active in {"dns_tab", "ldap_tab"}:
            self.action_focus_zones()
        else:
            self.action_focus_records()

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated
    ) -> None:
        if event.tabbed_content.id == "side_tabs":
            self.refresh_key_hints()

    def action_sort_name(self) -> None:
        self.sort_records("name")

    def action_sort_type(self) -> None:
        self.sort_records("type")

    def action_sort_value(self) -> None:
        self.sort_records("value")

    def update_visual_selection(self) -> None:
        if not self.visual_selecting or self.selection_anchor is None:
            return
        table = self.query_one("#records", DataTable)
        if self.focused_table() is table:
            self.select_record_range(self.selection_anchor, table.cursor_row)

    def active_table(self) -> DataTable:
        return self.focused_table() or self.query_one("#records", DataTable)

    def page_rows(self, table: DataTable) -> int:
        height = getattr(table.size, "height", 0)
        return max(1, height - 3) if height else 10

    def move_cursor_by(self, delta: int) -> None:
        table = self.active_table()
        if not table.row_count:
            return
        row = max(0, min(table.cursor_row + delta, table.row_count - 1))
        table.move_cursor(row=row)
        self.update_visual_selection()
        self.update_details_pane()

    def action_cursor_down(self) -> None:
        self.pending_g = False
        self.move_cursor_by(1)

    def action_cursor_up(self) -> None:
        self.pending_g = False
        self.move_cursor_by(-1)

    def action_cursor_page_down(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(self.page_rows(table))

    def action_cursor_page_up(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(-self.page_rows(table))

    def action_cursor_half_page_down(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(max(1, self.page_rows(table) // 2))

    def action_cursor_half_page_up(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(-max(1, self.page_rows(table) // 2))

    def action_cursor_top(self) -> None:
        self.pending_g = False
        table = self.active_table()
        table.move_cursor(row=0)
        self.update_visual_selection()
        self.update_details_pane()

    def action_cursor_bottom(self) -> None:
        self.pending_g = False
        table = self.active_table()
        if table.row_count:
            table.move_cursor(row=table.row_count - 1)
            self.update_visual_selection()
            self.update_details_pane()

    def ensure_dns_records_view(self) -> bool:
        if self.view_mode == "dns":
            return True
        self.set_status("Current view is read-only.")
        return False

    def action_toggle_select(self) -> None:
        self.pending_g = False
        table = self.focused_table() or self.query_one("#records", DataTable)
        if table.id != "records" or not table.row_count:
            return
        if not self.ensure_dns_records_view():
            return
        row_index = table.cursor_row
        self.selection_anchor = (
            row_index if self.selection_anchor is None else self.selection_anchor
        )
        self.set_record_selected(row_index, row_index not in self.selected_record_rows)
        self.set_status(f"Selected {len(self.selected_record_rows)} record(s)")

    def action_visual_select(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not table.row_count:
            return
        if not self.ensure_dns_records_view():
            return
        if self.visual_selecting:
            self.visual_selecting = False
            self.set_status(
                f"Visual selection off; selected {len(self.selected_record_rows)} record(s)"
            )
            return
        self.visual_selecting = True
        self.selection_anchor = table.cursor_row
        self.select_record_range(table.cursor_row, table.cursor_row)
        self.set_status("Visual selection on: use j/k, then d to delete selected")

    def action_select_range(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not table.row_count:
            return
        if not self.ensure_dns_records_view():
            return
        if self.selection_anchor is None:
            self.selection_anchor = table.cursor_row
        self.select_record_range(self.selection_anchor, table.cursor_row)

    def action_extend_up(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not self.ensure_dns_records_view():
            return
        if self.selection_anchor is None:
            self.selection_anchor = table.cursor_row
        self.move_cursor_by(-1)
        self.select_record_range(self.selection_anchor, table.cursor_row)

    def action_extend_down(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not self.ensure_dns_records_view():
            return
        if self.selection_anchor is None:
            self.selection_anchor = table.cursor_row
        self.move_cursor_by(1)
        self.select_record_range(self.selection_anchor, table.cursor_row)

    def action_clear_navigation_state(self) -> None:
        self.pending_g = False
        if self.focused_inline_search():
            if self.search_text:
                self.set_search_text("")
                self.action_focus_records()
                self.set_status("Search cleared")
                return
            self.action_focus_records()
            self.set_status("Search closed")
            return
        if self.visual_selecting:
            self.visual_selecting = False
            self.set_status(
                f"Visual selection off; selected {len(self.selected_record_rows)} record(s)"
            )
            return
        if self.selected_record_rows:
            self.clear_record_selection()
            self.set_status("Selection cleared")
            return
        if self.search_text:
            self.set_search_text("")
            self.set_status("Search cleared")
            return
        self.action_focus_records()

    async def action_activate_row(self) -> None:
        self.pending_g = False
        table = self.focused_table()
        if table and table.id == "records":
            if self.view_mode == "smart":
                self.action_fix_smart()
            else:
                self.action_toggle_select()
            return
        if table and table.id in {"zones", "ldap_structure"}:
            await self.activate_sidebar_selection(table)

    async def on_key(self, event: Any) -> None:
        if self.handle_inline_search_key(event):
            event.prevent_default()
            event.stop()
            return
        if self.should_ignore_key_event(event):
            return
        handled = await self.handle_key(event.key, getattr(event, "character", None))
        if handled:
            event.prevent_default()
            event.stop()

    def focused_inline_search(self) -> bool:
        return isinstance(self.focused, Input) and self.focused.id == "inline_search"

    def handle_inline_search_key(self, event: Any) -> bool:
        if not self.focused_inline_search():
            return False
        if event.key == "escape":
            self.action_clear_navigation_state()
            return True
        if event.key == "enter":
            self.action_focus_records()
            self.set_status("Search kept; press Esc to clear it")
            return True
        return False

    def should_ignore_key_event(self, event: Any) -> bool:
        if isinstance(self.focused, Input):
            return True
        return isinstance(self.focused, Button) and event.key in {"enter", "space"}

    async def handle_key(self, key: str, char: str | None) -> bool:
        char_lower = char.casefold() if char else ""
        if char_lower != "g":
            self.pending_g = False
        if await self.handle_case_sensitive_key(char):
            return True
        if self.handle_smart_view_shortcut(char_lower):
            return True
        if self.handle_g_key(char, char_lower):
            return True
        if await self.handle_mapped_key(key, char_lower):
            return True
        self.pending_g = False
        return False

    async def handle_case_sensitive_key(self, char: str | None) -> bool:
        action_name = CASE_SENSITIVE_ACTION_NAMES.get(char or "")
        if action_name is None:
            return False
        await self.invoke_action(action_name)
        return True

    def handle_smart_view_shortcut(self, char_lower: str) -> bool:
        if char_lower not in SMART_VIEW_BY_SHORTCUT:
            return False
        self.action_smart_view_shortcut(char_lower)
        return True

    def handle_g_key(self, char: str | None, char_lower: str) -> bool:
        if char_lower != "g":
            return False
        if char == "G":
            self.action_cursor_bottom()
        elif self.pending_g:
            self.action_cursor_top()
        else:
            self.pending_g = True
            self.set_status("g pressed: press g again for top; G goes bottom")
        return True

    async def handle_mapped_key(self, key: str, char_lower: str) -> bool:
        action_name = KEY_ACTION_NAMES.get(key) or CHAR_ACTION_NAMES.get(char_lower)
        if action_name is None:
            return False
        await self.invoke_action(action_name)
        return True

    async def invoke_action(self, action_name: str, *args: Any) -> None:
        result = getattr(self, action_name)(*args)
        if inspect.isawaitable(result):
            await result

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "inline_search":
            return
        event.stop()
        if getattr(self, "_syncing_search_input", False):
            return
        self.search_text = event.value
        self.refresh_current_view()
        self.refresh_inline_search_scope(event.value, self.view_mode)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "records":
            self.update_details_pane()

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id not in {"zones", "ldap_structure"}:
            return
        await self.activate_sidebar_selection(event.data_table)

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        if event.data_table.id != "records":
            return
        match event.column_index:
            case 1:
                self.sort_records("name")
            case 2:
                self.sort_records("type")
            case 3:
                self.sort_records("value")
