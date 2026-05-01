from __future__ import annotations

from contextlib import suppress

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Input, Label, Static, TabbedContent, TabPane

from .app_constants import CONNECTION_STATE_INPUTS, KEY_HINTS
from .smart_view_catalog import SMART_VIEWS
from .ui.tables import DNS_COLUMNS


class AppLayoutMixin(App):
    def smart_view_hint_text(self) -> str:
        lines = ["Press S to pick a view, or press a number:"]
        for view in SMART_VIEWS:
            lines.append(f"  {view.shortcut}  {view.label}")
        return "\n".join(lines)

    def keys_hint_for_tab(self, tab_id: str | None) -> str:
        return KEY_HINTS.get(tab_id or "", KEY_HINTS["dns_tab"])

    def active_side_tab_id(self) -> str:
        with suppress(Exception):
            return str(self.query_one("#side_tabs", TabbedContent).active or "dns_tab")
        return "dns_tab"

    def refresh_key_hints(self) -> None:
        with suppress(Exception):
            self.query_one("#keys", Static).update(
                self.keys_hint_for_tab(self.active_side_tab_id())
            )

    def compose_connection_state(self) -> ComposeResult:
        with Vertical(id="connection_state"):
            for value, input_id, is_password in CONNECTION_STATE_INPUTS:
                yield Input(value, password=is_password, id=input_id)

    def compose_dns_tab(self) -> ComposeResult:
        with TabPane("DNS", id="dns_tab"):
            with Vertical(id="dns_panel"):
                yield Static("DNS zones", classes="section-title")
                zones = DataTable(id="zones", cursor_type="row")
                zones.add_columns("DNS zones")
                yield zones

    def compose_ldap_tab(self) -> ComposeResult:
        with TabPane("LDAP", id="ldap_tab"):
            with Vertical(id="ldap_panel"):
                yield Static("LDAP structure", classes="section-title")
                structure = DataTable(id="ldap_structure", cursor_type="row")
                structure.add_columns("LDAP structure")
                yield structure

    def compose_smart_tab(self) -> ComposeResult:
        with TabPane("Smart", id="smart_tab"):
            with Vertical(id="smart_panel"):
                yield Static("Smart views", classes="section-title")
                yield Static(
                    self.smart_view_hint_text(),
                    id="smart_hint",
                    classes="hint",
                )

    def compose_sidebar(self) -> ComposeResult:
        with Vertical(id="sidebar", classes="panel"):
            yield Static("Connection: not checked", id="connection_summary")
            with TabbedContent(id="side_tabs"):
                yield from self.compose_dns_tab()
                yield from self.compose_ldap_tab()
                yield from self.compose_smart_tab()
            yield Static("Ready", id="status")

    def compose_results_panel(self) -> ComposeResult:
        with Vertical(id="results", classes="panel"):
            with Horizontal(id="records_header"):
                yield Label("Records", id="records_title", classes="section-title")
                yield Input(
                    "",
                    placeholder="/ search source records",
                    id="inline_search",
                )
            table = DataTable(id="records", cursor_type="row")
            table.add_columns(*DNS_COLUMNS)
            yield table
            yield Static(
                "Details\nNo row selected.",
                id="record_details",
                classes="hint",
                markup=False,
            )

    def compose(self) -> ComposeResult:
        yield from self.compose_connection_state()
        with Horizontal(id="main"):
            yield from self.compose_sidebar()
            yield from self.compose_results_panel()
        yield Static(self.keys_hint_for_tab("dns_tab"), id="keys")
