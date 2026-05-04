from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from .base import FocusedModalScreen


class ConfirmScreen(FocusedModalScreen[bool]):
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
    #confirm_keys { color: $text-muted; margin-bottom: 1; }
    #confirm_buttons { height: auto; align-horizontal: right; }
    #confirm_buttons Button { width: 18; margin-left: 1; }
    """

    def __init__(self, message: str, *, default_confirm: bool = False) -> None:
        super().__init__()
        self.message = message
        self.default_confirm = default_confirm

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm_dialog"):
            yield Static(self.message, id="confirm_message")
            yield Static(
                f"Keys: y=yes  n=no  Esc=no  Enter={self.default_action_label}",
                id="confirm_keys",
            )
            with Horizontal(id="confirm_buttons"):
                yield Button(self.button_label(False), id="deny")
                yield Button(self.button_label(True), id="confirm", variant="error")

    @property
    def default_action_label(self) -> str:
        return "yes" if self.default_confirm else "no"

    def button_label(self, confirms: bool) -> str:
        label = "Yes" if confirms else "No"
        return f"{label} (Enter)" if confirms == self.default_confirm else label

    def key_decision(self, key: str, character: str | None = None) -> bool | None:
        if character and character.casefold() == "y":
            return True
        if character and character.casefold() == "n":
            return False
        if key == "escape":
            return False
        if key == "enter":
            return self.default_confirm
        return None

    def on_mount(self) -> None:
        button_id = "confirm" if self.default_confirm else "deny"
        self.query_one(f"#{button_id}", Button).focus()

    def on_key(self, event: Any) -> None:
        decision = self.key_decision(event.key, getattr(event, "character", None))
        if decision is None:
            return
        event.prevent_default()
        event.stop()
        self.dismiss(decision)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")
