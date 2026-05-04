from __future__ import annotations

from typing import TypeAlias

from textual.app import ComposeResult
from textual.events import Key
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Static

from .base import FocusedModalScreen


CommandPaletteChoice: TypeAlias = tuple[str, str, str, str]


def command_palette_choice_matches(choice: CommandPaletteChoice, query: str) -> bool:
    terms = [term.casefold() for term in query.split() if term]
    if not terms:
        return True
    haystack = " ".join(choice).casefold()
    return all(term in haystack for term in terms)


class CommandPaletteScreen(FocusedModalScreen[str | None]):
    CSS = """
    CommandPaletteScreen { align: center middle; }
    #command_palette_dialog {
        width: 104;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #command_palette_title { text-style: bold; color: $accent; margin-bottom: 1; }
    #command_palette_hint { color: $text-muted; margin-bottom: 1; }
    #command_palette_search { margin-bottom: 1; }
    #command_palette_table { height: 16; margin-bottom: 1; }
    #command_palette_buttons { height: auto; align-horizontal: right; }
    #command_palette_buttons Button { width: 16; margin-left: 1; }
    """

    def __init__(self, choices: list[CommandPaletteChoice]) -> None:
        super().__init__()
        self.choices = choices
        self.filtered_choices = choices

    def compose(self) -> ComposeResult:
        with Vertical(id="command_palette_dialog"):
            yield Static("Command palette", id="command_palette_title")
            yield Static(
                "Search actions by name, shortcut, or description. Enter runs selection.",
                id="command_palette_hint",
            )
            yield Input("", placeholder="Search actions", id="command_palette_search")
            table = DataTable(id="command_palette_table", cursor_type="row")
            table.add_columns("Action", "Shortcut", "Description")
            yield table
            with Horizontal(id="command_palette_buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Run", id="run", variant="primary")

    def matching_choices(self, query: str) -> list[CommandPaletteChoice]:
        return [
            choice
            for choice in self.choices
            if command_palette_choice_matches(choice, query)
        ]

    def render_choices(self, query: str = "") -> None:
        self.filtered_choices = self.matching_choices(query)
        table = self.query_one("#command_palette_table", DataTable)
        table.clear()
        for action_id, label, shortcut, description in self.filtered_choices:
            table.add_row(label, shortcut, description, key=action_id)
        if not self.filtered_choices:
            table.add_row("No matching actions", "", "Try a broader search.")
        table.move_cursor(row=0)

    def on_mount(self) -> None:
        self.render_choices()
        self.query_one("#command_palette_search", Input).focus()

    def selected_action_id(self) -> str | None:
        table = self.query_one("#command_palette_table", DataTable)
        if table.cursor_row < 0 or table.cursor_row >= len(self.filtered_choices):
            return None
        action_id, *_ = self.filtered_choices[table.cursor_row]
        return action_id

    def dismiss_selected(self) -> None:
        self.dismiss(self.selected_action_id())

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "command_palette_search":
            event.stop()
            self.render_choices(event.value)

    def on_key(self, event: Key) -> None:
        if event.key == "escape":
            event.prevent_default()
            event.stop()
            self.dismiss(None)
            return
        if event.key == "enter":
            event.prevent_default()
            event.stop()
            self.dismiss_selected()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "command_palette_table":
            self.dismiss_selected()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        self.dismiss_selected()
