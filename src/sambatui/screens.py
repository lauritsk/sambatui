from __future__ import annotations

from ipaddress import ip_address
from typing import Any, TypeAlias
from urllib.parse import urlparse

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from .ldap_directory import domain_to_base_dn


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

    def on_key(self, event: Any) -> None:
        decision = self.key_decision(event.key, getattr(event, "character", None))
        if decision is None:
            return
        event.prevent_default()
        event.stop()
        self.dismiss(decision)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")


FormField: TypeAlias = tuple[str, str, str, str]


def infer_domain_from_server(server: str) -> str:
    value = server.strip().rstrip(".")
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or value).strip().rstrip(".")
    if not host:
        return ""
    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        return ""
    labels = [label for label in host.split(".") if label]
    if len(labels) < 3:
        return ""
    if any("_" in label for label in labels):
        return ""
    return ".".join(labels[1:])


class HelpScreen(ModalScreen[None]):
    CSS = """
    HelpScreen { align: center middle; }
    #help_dialog {
        width: 82;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #help_title { text-style: bold; color: $accent; margin-bottom: 1; }
    #help_body { color: $text; margin-bottom: 1; }
    #help_hint { color: $text-muted; margin-bottom: 1; }
    #help_buttons { height: auto; align-horizontal: right; }
    #help_buttons Button { width: 14; margin-left: 1; }
    """

    HELP_TEXT = """Connection
  Ctrl+O    Open/edit connection settings (also via sidebar Connection…)
  p/P       Load/save password file
  c         Discover AD domain controllers

Main tabs
  DNS       Load zones, select a zone, manage records
  LDAP      Search AD directory over LDAP (read-only)
  Smart     Read-only DNS/LDAP hygiene findings
  L         Search LDAP from anywhere
  S         Run smart views from anywhere
  z         Load DNS zones

Navigation
  Tab       Switch zones/records table
  h/l       Focus zones/records
  j/k       Move cursor
  gg/G      Top/bottom
  Ctrl+d/u  Half-page down/up

Records
  Enter     Select zone or toggle record select
  q         Query records
  a/u/d     Add, update, delete records
  /         Search records
  n/t/e     Sort by name/type/value
  Space     Toggle record selection
  v/V       Visual/range select
  Esc       Clear visual/select/search state

App
  ?         Show this help
  Ctrl+Q    Quit"""

    def compose(self) -> ComposeResult:
        with Vertical(id="help_dialog"):
            yield Static("Help", id="help_title")
            yield Static(self.HELP_TEXT, id="help_body")
            yield Static("Press Esc, Enter, or Close to return.", id="help_hint")
            with Horizontal(id="help_buttons"):
                yield Button("Close", id="close", variant="primary")

    def on_key(self, event: Any) -> None:
        if event.key in {"escape", "enter"}:
            event.prevent_default()
            event.stop()
            self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)


class FormScreen(ModalScreen[dict[str, str] | None]):
    CSS = """
    FormScreen { align: center middle; }
    #form_dialog {
        width: 88;
        height: auto;
        max-height: 92%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #form_title { text-style: bold; color: $accent; margin-bottom: 1; }
    #form_hint { color: $text-muted; margin-bottom: 1; }
    #form_fields { height: auto; max-height: 72%; margin-bottom: 1; }
    .hint { color: $text-muted; margin-bottom: 0; }
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
        self._autofilled: dict[str, str] = {}
        self._suppress_autofill = False

    def compose(self) -> ComposeResult:
        with Vertical(id="form_dialog"):
            yield Static(self.form_title, id="form_title")
            if self.hint:
                yield Static(self.hint, id="form_hint")
            with VerticalScroll(id="form_fields"):
                for label, field_id, placeholder, value in self.fields:
                    yield Static(label, classes="hint")
                    with Horizontal(classes="form_row"):
                        yield Input(
                            value=value,
                            placeholder=placeholder,
                            password=field_id == "password",
                            id=field_id,
                        )
            with Horizontal(id="form_buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(self.submit_label, id="submit", variant="primary")

    def form_values(self) -> dict[str, str]:
        values = {}
        for _, field_id, _, _ in self.fields:
            values[field_id] = self.query_one(f"#{field_id}", Input).value.strip()
        return values

    def maybe_autofill_connection_fields(self) -> None:
        field_ids = {field_id for _, field_id, _, _ in self.fields}
        if not {"server", "zone", "ldap_base"}.issubset(field_ids):
            return

        server = self.query_one("#server", Input).value.strip()
        zone_input = self.query_one("#zone", Input)
        ldap_base_input = self.query_one("#ldap_base", Input)
        zone = zone_input.value.strip()

        inferred_zone = infer_domain_from_server(server)
        if inferred_zone and self.can_autofill("zone", zone):
            self.autofill("zone", inferred_zone)
            zone = inferred_zone

        base_dn = domain_to_base_dn(zone)
        if base_dn and self.can_autofill("ldap_base", ldap_base_input.value.strip()):
            self.autofill("ldap_base", base_dn)

    def can_autofill(self, field_id: str, current: str) -> bool:
        return not current or self._autofilled.get(field_id) == current

    def autofill(self, field_id: str, value: str) -> None:
        self._suppress_autofill = True
        try:
            self.query_one(f"#{field_id}", Input).value = value
        finally:
            self._suppress_autofill = False
        self._autofilled[field_id] = value

    def submit(self) -> None:
        self.dismiss(self.form_values())

    def on_mount(self) -> None:
        self.maybe_autofill_connection_fields()

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._suppress_autofill:
            return
        field_id = str(event.input.id)
        if self._autofilled.get(field_id) == event.input.value.strip():
            return
        self._autofilled.pop(field_id, None)
        self.maybe_autofill_connection_fields()

    def on_key(self, event: Any) -> None:
        if isinstance(self.focused, Button) and event.key in {"enter", "space"}:
            return
        if event.key == "escape":
            event.prevent_default()
            event.stop()
            self.dismiss(None)
            return
        if event.key == "enter":
            event.prevent_default()
            event.stop()
            self.submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        self.submit()
