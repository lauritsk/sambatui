from __future__ import annotations

from typing import TypeAlias

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class ConfirmScreen(ModalScreen[bool]):
    CSS = """
    ConfirmScreen { align: center middle; }
    #confirm_dialog {
        width: 76;
        height: auto;
        border: round $error;
        background: $surface;
        padding: 1 2;
    }
    #confirm_message { margin-bottom: 1; }
    #confirm_buttons { height: auto; align-horizontal: right; }
    #confirm_buttons Button { width: 16; margin-left: 1; }
    """

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm_dialog"):
            yield Static(self.message, id="confirm_message")
            with Horizontal(id="confirm_buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Confirm", id="confirm", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")


FormField: TypeAlias = tuple[str, str, str, str]


class FormScreen(ModalScreen[dict[str, str] | None]):
    CSS = """
    FormScreen { align: center middle; }
    #form_dialog {
        width: 78;
        height: auto;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #form_title { text-style: bold; color: $accent; margin-bottom: 1; }
    #form_hint { color: $text-muted; margin-bottom: 1; }
    .form_row { height: auto; margin-bottom: 1; }
    .form_row Input { width: 1fr; margin-right: 1; }
    #form_buttons { height: auto; align-horizontal: right; }
    #form_buttons Button { width: 16; margin-left: 1; }
    """

    def __init__(
        self,
        title: str,
        hint: str,
        fields: list[FormField],
        submit_label: str = "Continue",
    ) -> None:
        super().__init__()
        self.form_title = title
        self.hint = hint
        self.fields = fields
        self.submit_label = submit_label

    def compose(self) -> ComposeResult:
        with Vertical(id="form_dialog"):
            yield Static(self.form_title, id="form_title")
            if self.hint:
                yield Static(self.hint, id="form_hint")
            for label, field_id, placeholder, value in self.fields:
                yield Static(label, classes="hint")
                with Horizontal(classes="form_row"):
                    yield Input(value=value, placeholder=placeholder, id=field_id)
            with Horizontal(id="form_buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(self.submit_label, id="submit", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        values = {}
        for _, field_id, _, _ in self.fields:
            values[field_id] = self.query_one(f"#{field_id}", Input).value.strip()
        self.dismiss(values)
