from __future__ import annotations

from typing import Generic, TypeVar

from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input


ScreenResult = TypeVar("ScreenResult")


ScreenResult = TypeVar("ScreenResult")


class FocusedModalScreen(ModalScreen[ScreenResult], Generic[ScreenResult]):
    BINDINGS = [
        ("tab", "modal_focus_next", "Next field"),
        ("shift+tab", "modal_focus_previous", "Previous field"),
    ]

    def action_modal_focus_next(self) -> None:
        self.focus_next()

    def action_modal_focus_previous(self) -> None:
        self.focus_previous()

    def focus_first_control(self) -> None:
        for widget in self.walk_children():
            if isinstance(widget, (Input, DataTable, Button)) and not getattr(
                widget, "disabled", False
            ):
                widget.focus()
                return
