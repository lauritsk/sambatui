from __future__ import annotations

from typing import Any, TypeAlias

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Static

from .base import FocusedModalScreen


SmartViewChoice: TypeAlias = tuple[str, str, str, str, str]


class SmartViewPickerScreen(FocusedModalScreen[str | None]):
    CSS = """
    SmartViewPickerScreen { align: center middle; }
    #smart_view_dialog {
        width: 104;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #smart_view_title { text-style: bold; color: $accent; margin-bottom: 1; }
    #smart_view_hint { color: $text-muted; margin-bottom: 1; }
    #smart_view_table { height: 16; margin-bottom: 1; }
    #smart_view_buttons { height: auto; align-horizontal: right; }
    #smart_view_buttons Button { width: 16; margin-left: 1; }
    """

    def __init__(self, choices: list[SmartViewChoice]) -> None:
        super().__init__()
        self.choices = choices

    def compose(self) -> ComposeResult:
        with Vertical(id="smart_view_dialog"):
            yield Static("Smart views", id="smart_view_title")
            yield Static(
                "Pick a read-only hygiene view. Keys 1-8 run views directly; Enter selects.",
                id="smart_view_hint",
            )
            table = DataTable(id="smart_view_table", cursor_type="row")
            table.add_columns("Key", "Source", "Smart view", "What it finds")
            for shortcut, view_id, source, label, description in self.choices:
                table.add_row(shortcut, source, label, description, key=view_id)
            yield table
            with Horizontal(id="smart_view_buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Run", id="run", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#smart_view_table", DataTable).focus()

    def selected_view_id(self) -> str | None:
        table = self.query_one("#smart_view_table", DataTable)
        if table.cursor_row < 0 or table.cursor_row >= len(self.choices):
            return None
        _, view_id, *_ = self.choices[table.cursor_row]
        return view_id

    def dismiss_selected(self) -> None:
        self.dismiss(self.selected_view_id())

    def on_key(self, event: Any) -> None:
        character = getattr(event, "character", None)
        if event.key == "escape":
            event.prevent_default()
            event.stop()
            self.dismiss(None)
            return
        if event.key == "enter":
            event.prevent_default()
            event.stop()
            self.dismiss_selected()
            return
        if character:
            for shortcut, view_id, *_ in self.choices:
                if character == shortcut:
                    event.prevent_default()
                    event.stop()
                    self.dismiss(view_id)
                    return

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "smart_view_table":
            self.dismiss_selected()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        self.dismiss_selected()
