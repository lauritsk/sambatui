from __future__ import annotations

from ipaddress import ip_address
from collections.abc import Callable
from contextlib import suppress
from typing import Any, TypeAlias
from urllib.parse import urlparse

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static

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
FormValidator: TypeAlias = Callable[[dict[str, str]], str | None]
SmartViewChoice: TypeAlias = tuple[str, str, str, str, str]
CommandPaletteChoice: TypeAlias = tuple[str, str, str, str]


def command_palette_choice_matches(choice: CommandPaletteChoice, query: str) -> bool:
    terms = [term.casefold() for term in query.split() if term]
    if not terms:
        return True
    haystack = " ".join(choice).casefold()
    return all(term in haystack for term in terms)


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
  Ctrl+P    Open searchable command palette
  w         Run first-run setup wizard
  Ctrl+O    Open/edit connection settings (also via command palette)
  p/P       Load/save password file
  c         Discover AD domain controllers

Main tabs
  DNS       Load zones, select a zone, manage records
  LDAP      Search AD directory over LDAP (read-only)
  Smart     Read-only DNS/LDAP hygiene findings
  L         Search LDAP from anywhere
  m         Load 200 more rows for the last LDAP search
  S         Pick a smart view from a list
  1-8       Run smart views directly; 8 runs full health dashboard
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
  /         Inline search source records; filters loaded smart findings
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


class SmartViewPickerScreen(ModalScreen[str | None]):
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


class CommandPaletteScreen(ModalScreen[str | None]):
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

    def on_key(self, event: Any) -> None:
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
    #form_error { color: $error; margin-bottom: 1; }
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
        validator: FormValidator | None = None,
    ) -> None:
        super().__init__()
        self.form_title = title
        self.hint = hint
        self.fields = fields
        self.submit_label = submit_label
        self.validator = validator
        self._autofilled: dict[str, str] = {}
        self._suppress_autofill = False

    def compose(self) -> ComposeResult:
        with Vertical(id="form_dialog"):
            yield Static(self.form_title, id="form_title")
            if self.hint:
                yield Static(self.hint, id="form_hint")
            if self.validator:
                yield Static("", id="form_error")
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

    def validation_error(self) -> str | None:
        if self.validator is None:
            return None
        return self.validator(self.form_values())

    def refresh_validation(self) -> str | None:
        error = self.validation_error()
        with suppress(Exception):
            self.query_one("#form_error", Static).update(error or "")
        with suppress(Exception):
            self.query_one("#submit", Button).disabled = error is not None
        return error

    def submit(self) -> None:
        if self.refresh_validation() is not None:
            return
        self.dismiss(self.form_values())

    def on_mount(self) -> None:
        self.maybe_autofill_connection_fields()
        self.refresh_validation()

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._suppress_autofill:
            return
        field_id = str(event.input.id)
        if self._autofilled.get(field_id) == event.input.value.strip():
            self.refresh_validation()
            return
        self._autofilled.pop(field_id, None)
        self.maybe_autofill_connection_fields()
        self.refresh_validation()

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
