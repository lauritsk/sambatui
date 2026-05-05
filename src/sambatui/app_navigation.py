from __future__ import annotations

import inspect
from contextlib import suppress
from typing import TYPE_CHECKING

from textual.app import App
from textual.events import Key
from textual.widgets import Button, DataTable, Input, TabbedContent

from .app_constants import (
    CASE_SENSITIVE_ACTION_NAMES,
    CHAR_ACTION_NAMES,
    KEY_ACTION_NAMES,
    SIDE_TAB_IDS,
)
from .smart_view_catalog import SMART_VIEW_BY_SHORTCUT

DNS_HEADER_SORT_FIELDS = {1: "name", 2: "type", 3: "value"}
DIRECTORY_HEADER_SORT_FIELDS = {1: "name", 2: "type", 3: "value"}
SMART_HEADER_SORT_FIELDS = {
    1: "severity",
    2: "object",
    3: "finding",
    4: "evidence",
    5: "action",
    6: "source",
}
HEADER_SORT_FIELDS_BY_VIEW_MODE = {
    "dns": DNS_HEADER_SORT_FIELDS,
    "directory": DIRECTORY_HEADER_SORT_FIELDS,
    "smart": SMART_HEADER_SORT_FIELDS,
}
SIDEBAR_TABLE_IDS = frozenset(
    {"zones", "ldap_structure", "dns_findings", "ldap_findings"}
)
NEXT_TABLE_BY_ID = {
    "zones": "dns_findings",
    "dns_findings": "records",
    "ldap_structure": "ldap_findings",
    "ldap_findings": "records",
}
SELECTABLE_VIEW_MODES = {"dns", "directory"}


class AppNavigationMixin(App):
    if TYPE_CHECKING:
        _syncing_search_input: bool
        pending_g: bool
        search_text: str
        selected_record_rows: set[int]
        selected_directory_rows: set[int]
        selection_anchor: int | None
        directory_selection_anchor: int | None
        view_mode: str
        visual_selecting: bool
        zones: list[str]

        def action_fix_smart(self) -> object: ...

        def action_smart_view_shortcut(self, shortcut: str) -> object: ...

        async def activate_sidebar_selection(self, table: DataTable) -> bool: ...

        def clear_current_selection(self) -> None: ...

        def clear_current_smart_view(self) -> None: ...

        def refresh_current_view(self) -> None: ...

        def refresh_key_hints(self) -> None: ...

        def refresh_inline_search_scope(
            self, search_text: str, view_mode: str
        ) -> object: ...

        def current_selection_anchor(self) -> int | None: ...

        def select_current_range(self, start: int, end: int) -> None: ...

        def selected_rows_for_current_view(self) -> set[int]: ...

        def selection_count_label(self) -> str: ...

        def set_current_row_selected(self, row_index: int, selected: bool) -> None: ...

        def set_current_selection_anchor(self, row_index: int | None) -> None: ...

        def set_status(self, message: str) -> None: ...

        def sort_records(self, field: str) -> None: ...

        def update_details_pane(self) -> None: ...

        def visible_directory(self) -> list[object]: ...

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

    def records_table(self) -> DataTable:
        return self.query_one("#records", DataTable)

    def focus_records_table(self) -> DataTable:
        table = self.records_table()
        table.focus()
        return table

    def action_focus_records(self) -> None:
        self.pending_g = False
        self.focus_records_table()

    def focus_table(self, table_id: str) -> DataTable:
        table = self.query_one(f"#{table_id}", DataTable)
        table.focus()
        return table

    def next_table_id(self, table_id: str | None) -> str | None:
        return NEXT_TABLE_BY_ID.get(table_id or "")

    def action_next_table(self) -> None:
        table = self.focused_table()
        table_id = self.next_table_id(str(table.id)) if table is not None else None
        if table_id is None:
            self.action_focus_zones()
            return
        self.focus_table(table_id)

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
        self.clear_current_selection()
        self.refresh_key_hints()
        self.action_focus_zones()

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
        anchor = self.current_selection_anchor()
        if not self.visual_selecting or anchor is None:
            return
        table = self.records_table()
        if self.focused_table() is table:
            self.select_current_range(anchor, table.cursor_row)

    def active_table(self) -> DataTable:
        return self.focused_table() or self.records_table()

    def page_rows(self, table: DataTable) -> int:
        height = getattr(table.size, "height", 0)
        if not height:
            return 10
        return max(1, height - 3)

    def finish_cursor_move(self) -> None:
        self.update_visual_selection()
        self.update_details_pane()

    def move_cursor_by(self, delta: int) -> None:
        table = self.active_table()
        if not table.row_count:
            return
        row = max(0, min(table.cursor_row + delta, table.row_count - 1))
        table.move_cursor(row=row)
        self.finish_cursor_move()

    def action_cursor_down(self) -> None:
        self.pending_g = False
        self.move_cursor_by(1)

    def action_cursor_up(self) -> None:
        self.pending_g = False
        self.move_cursor_by(-1)

    def move_cursor_by_page(self, direction: int, *, half_page: bool = False) -> None:
        self.pending_g = False
        rows = self.page_rows(self.active_table())
        if half_page:
            rows = max(1, rows // 2)
        self.move_cursor_by(direction * rows)

    def action_cursor_page_down(self) -> None:
        self.move_cursor_by_page(1)

    def action_cursor_page_up(self) -> None:
        self.move_cursor_by_page(-1)

    def action_cursor_half_page_down(self) -> None:
        self.move_cursor_by_page(1, half_page=True)

    def action_cursor_half_page_up(self) -> None:
        self.move_cursor_by_page(-1, half_page=True)

    def action_cursor_top(self) -> None:
        self.pending_g = False
        table = self.active_table()
        table.move_cursor(row=0)
        self.finish_cursor_move()

    def action_cursor_bottom(self) -> None:
        self.pending_g = False
        table = self.active_table()
        if table.row_count:
            table.move_cursor(row=table.row_count - 1)
            self.finish_cursor_move()

    def ensure_selectable_records_view(self) -> bool:
        if self.view_mode in SELECTABLE_VIEW_MODES:
            return True
        self.set_status("Selection applies to DNS records and LDAP entries.")
        return False

    def record_selection_table(
        self, *, focus: bool = False, require_records_focus: bool = False
    ) -> DataTable | None:
        table = self.focus_records_table() if focus else self.active_table()
        if require_records_focus and table.id != "records":
            return None
        if not table.row_count:
            return None
        if not self.ensure_selectable_records_view():
            return None
        if self.view_mode == "directory" and not self.visible_directory():
            self.set_status("Select an LDAP entry first.")
            return None
        return table

    def action_toggle_select(self) -> None:
        self.pending_g = False
        table = self.record_selection_table(require_records_focus=True)
        if table is None:
            return
        row_index = table.cursor_row
        if self.current_selection_anchor() is None:
            self.set_current_selection_anchor(row_index)
        is_selected = row_index in self.selected_rows_for_current_view()
        self.set_current_row_selected(row_index, not is_selected)
        self.set_status(f"Selected {self.selection_count_label()}")

    def action_visual_select(self) -> None:
        self.pending_g = False
        table = self.record_selection_table(focus=True)
        if table is None:
            return
        if self.visual_selecting:
            self.visual_selecting = False
            self.set_visual_selection_off_status()
            return
        self.visual_selecting = True
        self.set_current_selection_anchor(table.cursor_row)
        self.select_current_range(table.cursor_row, table.cursor_row)
        self.set_status("Visual selection on: use j/k, then d to delete selected")

    def action_select_range(self) -> None:
        self.pending_g = False
        table = self.record_selection_table(focus=True)
        if table is None:
            return
        anchor = self.current_selection_anchor()
        if anchor is None:
            anchor = table.cursor_row
            self.set_current_selection_anchor(anchor)
        self.select_current_range(anchor, table.cursor_row)

    def extend_selection_by(self, delta: int) -> None:
        self.pending_g = False
        table = self.record_selection_table(focus=True)
        if table is None:
            return
        anchor = self.current_selection_anchor()
        if anchor is None:
            anchor = table.cursor_row
            self.set_current_selection_anchor(anchor)
        self.move_cursor_by(delta)
        self.select_current_range(anchor, table.cursor_row)

    def action_extend_up(self) -> None:
        self.extend_selection_by(-1)

    def action_extend_down(self) -> None:
        self.extend_selection_by(1)

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
            self.set_visual_selection_off_status()
            return
        if self.selected_rows_for_current_view():
            self.clear_current_selection()
            self.set_status("Selection cleared")
            return
        if self.view_mode == "smart":
            self.clear_current_smart_view()
            return
        if self.search_text:
            self.set_search_text("")
            self.set_status("Search cleared")
            return
        self.action_focus_records()

    def set_visual_selection_off_status(self) -> None:
        self.set_status(
            f"Visual selection off; selected {self.selection_count_label()}"
        )

    def is_sidebar_table(self, table: DataTable | None) -> bool:
        return table is not None and table.id in SIDEBAR_TABLE_IDS

    async def action_activate_row(self) -> None:
        self.pending_g = False
        table = self.focused_table()
        if table and table.id == "records":
            match self.view_mode:
                case "dns":
                    self.action_toggle_select()
                case "smart":
                    self.action_fix_smart()
                case "directory":
                    self.set_status(
                        "Space selects LDAP entries; u edits one, d deletes selected."
                    )
                case _:
                    self.set_status("No active records view.")
            return
        if table is not None and self.is_sidebar_table(table):
            await self.activate_sidebar_selection(table)

    async def on_key(self, event: Key) -> None:
        if self.handle_inline_search_key(event):
            event.prevent_default()
            event.stop()
            return
        if self.should_ignore_key_event(event):
            return
        handled = await self.handle_key(event.key, event.character)
        if handled:
            event.prevent_default()
            event.stop()

    def focused_inline_search(self) -> bool:
        return isinstance(self.focused, Input) and self.focused.id == "inline_search"

    def handle_inline_search_key(self, event: Key) -> bool:
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

    def should_ignore_key_event(self, event: Key) -> bool:
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

    async def invoke_action(self, action_name: str, *args: object) -> None:
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
        if not self.is_sidebar_table(event.data_table):
            return
        await self.activate_sidebar_selection(event.data_table)

    def header_sort_field(self, column_index: int) -> str | None:
        sort_fields = HEADER_SORT_FIELDS_BY_VIEW_MODE.get(self.view_mode)
        return None if sort_fields is None else sort_fields.get(column_index)

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        if event.data_table.id != "records":
            return

        field = self.header_sort_field(event.column_index)
        if field is not None:
            self.sort_records(field)
