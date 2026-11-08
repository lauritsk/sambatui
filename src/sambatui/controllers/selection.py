from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING

from textual.app import ScreenStackError
from textual.coordinate import Coordinate
from textual.css.query import NoMatches
from textual.widgets import DataTable, Static

from ..core.view_state import ViewMode

if TYPE_CHECKING:
    from ..app import SambatuiApp

SELECTION_LABELS = {
    ViewMode.DNS: ("record", "records"),
    ViewMode.DIRECTORY: ("LDAP entry", "LDAP entries"),
    ViewMode.SMART: ("smart finding", "smart findings"),
}


class AppSelectionMixin:
    def reset_render_state(self: SambatuiApp) -> None:
        self.views.reset_selection()
        self.refresh_selection_indicator()

    def selection_count_label(self: SambatuiApp) -> str:
        count = len(self.selected_rows_for_current_view())
        singular, plural = SELECTION_LABELS.get(
            self.views.mode, SELECTION_LABELS[ViewMode.DNS]
        )
        return f"{count} {singular if count == 1 else plural}"

    def selection_status_text(self: SambatuiApp) -> str:
        return f"{self.selection_count_label()} selected · Space toggles · Esc clears"

    def refresh_selection_indicator(self: SambatuiApp) -> None:
        with suppress(NoMatches, ScreenStackError):
            indicator = self.query_one("#selection_state", Static)
            count = len(self.selected_rows_for_current_view())
            indicator.display = bool(count or self.views.visual_selecting)
            mode = "VISUAL · " if self.views.visual_selecting else ""
            indicator.update(f"{mode}{count} selected")

    def selected_rows_for_current_view(self: SambatuiApp) -> set[int]:
        return self.views.current.selected_rows

    def current_selection_anchor(self: SambatuiApp) -> int | None:
        return self.views.current.selection_anchor

    def set_current_selection_anchor(self: SambatuiApp, row_index: int | None) -> None:
        self.views.current.selection_anchor = row_index

    def set_current_row_selected(
        self: SambatuiApp, row_index: int, selected: bool
    ) -> None:
        self.set_row_selected(self.views.mode, row_index, selected)

    def clear_current_selection(self: SambatuiApp) -> None:
        if self.views.table(self.views.mode) is None:
            self.views.reset_selection()
            self.refresh_selection_indicator()
        else:
            self.clear_view_selection(self.views.mode)

    def select_current_range(self: SambatuiApp, start: int, end: int) -> None:
        self.select_view_range(self.views.mode, start, end)

    def set_row_selected(
        self: SambatuiApp,
        mode: ViewMode | str,
        row_index: int,
        selected: bool,
        *,
        visible_count: int | None = None,
    ) -> None:
        state = self.views.table(mode)
        table = self.query_one("#records", DataTable)
        if visible_count is None:
            visible_count = len(self.visible_rows_for_mode(mode))
        if state is None or not 0 <= row_index < visible_count:
            return
        if selected:
            state.selected_rows.add(row_index)
        else:
            state.selected_rows.discard(row_index)
        if mode == self.views.mode and row_index < table.row_count:
            table.update_cell_at(Coordinate(row_index, 0), "✓" if selected else "")
            table.refresh_row(row_index)
        self.refresh_selection_indicator()

    def clear_view_selection(self: SambatuiApp, mode: ViewMode | str) -> None:
        state = self.views.table(mode)
        if state is None:
            return
        if mode == self.views.mode:
            count = len(self.visible_rows_for_mode(mode))
            for row_index in list(state.selected_rows):
                self.set_row_selected(mode, row_index, False, visible_count=count)
        state.clear_selection()
        self.views.visual_selecting = False
        self.refresh_selection_indicator()

    def select_view_range(
        self: SambatuiApp,
        mode: ViewMode | str,
        start: int,
        end: int,
        *,
        clear: bool = True,
    ) -> None:
        table = self.query_one("#records", DataTable)
        state = self.views.table(mode)
        count = min(table.row_count, len(self.visible_rows_for_mode(mode)))
        if not count or state is None:
            return
        start = max(0, min(start, count - 1))
        end = max(0, min(end, count - 1))
        if clear:
            for row_index in list(state.selected_rows):
                self.set_row_selected(mode, row_index, False, visible_count=count)
            state.selected_rows.clear()
        low, high = sorted((start, end))
        for row_index in range(low, high + 1):
            self.set_row_selected(mode, row_index, True, visible_count=count)
        self.refresh_selection_indicator()
        self.set_status(self.selection_status_text())

    def set_record_selected(self: SambatuiApp, row_index: int, selected: bool) -> None:
        self.set_row_selected(ViewMode.DNS, row_index, selected)

    def clear_record_selection(self: SambatuiApp) -> None:
        self.clear_view_selection(ViewMode.DNS)

    def set_directory_selected(
        self: SambatuiApp, row_index: int, selected: bool
    ) -> None:
        self.set_row_selected(ViewMode.DIRECTORY, row_index, selected)

    def clear_directory_selection(self: SambatuiApp) -> None:
        self.clear_view_selection(ViewMode.DIRECTORY)

    def set_smart_selected(self: SambatuiApp, row_index: int, selected: bool) -> None:
        self.set_row_selected(ViewMode.SMART, row_index, selected)

    def clear_smart_selection(self: SambatuiApp) -> None:
        self.clear_view_selection(ViewMode.SMART)

    def select_record_range(
        self: SambatuiApp, start: int, end: int, *, clear: bool = True
    ) -> None:
        self.select_view_range(ViewMode.DNS, start, end, clear=clear)

    def select_directory_range(
        self: SambatuiApp, start: int, end: int, *, clear: bool = True
    ) -> None:
        self.select_view_range(ViewMode.DIRECTORY, start, end, clear=clear)

    def select_smart_range(
        self: SambatuiApp, start: int, end: int, *, clear: bool = True
    ) -> None:
        self.select_view_range(ViewMode.SMART, start, end, clear=clear)
