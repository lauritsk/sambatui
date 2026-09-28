from __future__ import annotations

from textual.app import ComposeResult
from textual.events import Key
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sambatui.app_actions import shortcut_for
from sambatui.smart_view_catalog import (
    all_smart_view_shortcut_range,
    smart_view_shortcut_range,
)

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

    FINDING_SHORTCUTS = all_smart_view_shortcut_range()
    DASHBOARD_SHORTCUT = smart_view_shortcut_range("Full")
    HELP_TEXT = f"""Connection
  {shortcut_for("open_command_palette"):9} Open searchable command palette
  {shortcut_for("setup_wizard"):9} Run first-run setup wizard
  {shortcut_for("connection"):9} Open/edit connection settings
  {shortcut_for("load_password")}/{shortcut_for("save_password"):7} Load/save password file
  {shortcut_for("discover_ad"):9} Discover AD domain controllers

Main tabs
  DNS       Load zones, select a zone, manage records, run DNS findings
  LDAP      Search AD directory over LDAP; add, edit, and delete entries
  {shortcut_for("ldap_search"):9} Search LDAP from anywhere
  {shortcut_for("ldap_load_more"):9} Load 200 more rows for the last LDAP search
  {shortcut_for("smart_view_picker"):9} Pick a DNS/LDAP finding filter
  {FINDING_SHORTCUTS:9} Open finding filters; {DASHBOARD_SHORTCUT} runs health dashboard
  {shortcut_for("load_zones"):9} Load DNS zones

Navigation
  {shortcut_for("next_table"):9} Switch sidebar findings/records table
  {shortcut_for("focus_zones")}/{shortcut_for("focus_records"):7} Focus sidebar/records
  {shortcut_for("cursor_down")}/{shortcut_for("cursor_up"):7} Move cursor
  gg/{shortcut_for("cursor_bottom_g"):6} Top/bottom
  {shortcut_for("half_page_down")}/{shortcut_for("half_page_up"):2} Half-page down/up

Records / directory
  {shortcut_for("activate"):9} Activate the highlighted row
  {shortcut_for("query_record"):9} Query records
  {shortcut_for("add_record")}/{shortcut_for("delete_records"):7} Add or delete DNS records / LDAP entries
  {shortcut_for("update_record"):9} Update a DNS value or LDAP attributes
  {shortcut_for("filter_results"):9} Search source records or filter findings
  {shortcut_for("sort_name")}/{shortcut_for("sort_type")}/{shortcut_for("sort_value"):5} Sort by name/type/value
  {shortcut_for("toggle_select"):9} Toggle record or LDAP entry selection
  {shortcut_for("visual_select")}/{shortcut_for("select_range"):7} Visual/range selection
  {shortcut_for("clear"):9} Clear visual/select/search/finding state

App
  {shortcut_for("help"):9} Show this help
  {shortcut_for("quit"):9} Quit"""

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
