from __future__ import annotations

from textual.app import ComposeResult
from textual.events import Key
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from .base import FocusedModalScreen


class HelpScreen(FocusedModalScreen[None]):
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
  DNS       Load zones, select a zone, manage records, run DNS findings
  LDAP      Search AD directory over LDAP; a/u/d add, edit, delete entries, run LDAP findings
  L         Search LDAP from anywhere
  m         Load 200 more rows for the last LDAP search
  S         Pick a DNS/LDAP finding filter from a list
  1-8       Open finding filters directly; 8 runs full health dashboard
  z         Load DNS zones

Navigation
  Tab       Switch sidebar findings/records table
  h/l       Focus sidebar/records
  j/k       Move cursor
  gg/G      Top/bottom
  Ctrl+d/u  Half-page down/up

Records / directory
  Enter     Select zone or toggle DNS record select; LDAP shows row-action hint
  q         Query records
  a/d       Add or delete DNS records / LDAP entries
  u         Update DNS record or one selected LDAP entry's attributes
  /         Inline search source records; filters loaded findings
  n/t/e     Sort by name/type/value
  Space     Toggle DNS record or LDAP entry selection
  v/V       Visual/range select DNS records or LDAP entries
  Esc       Clear visual/select/search/finding filter state

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

    def on_mount(self) -> None:
        self.query_one("#close", Button).focus()

    def on_key(self, event: Key) -> None:
        if event.key in {"escape", "enter"}:
            event.prevent_default()
            event.stop()
            self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)
