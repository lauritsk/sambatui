from __future__ import annotations

from contextlib import suppress

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Input, Label, Static, TabbedContent, TabPane

from .app_constants import CONNECTION_STATE_INPUTS, KEY_HINTS
from .ui.tables import DNS_COLUMNS


class AppLayoutMixin(App):
    def findings_hint_text(self) -> str:
        return "Saved hygiene filters. Enter runs; Esc clears active finding."

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
                yield Static("Findings", classes="section-title")
                yield Static(
                    self.findings_hint_text(), id="dns_findings_hint", classes="hint"
                )
                dns_findings = DataTable(id="dns_findings", cursor_type="row")
                dns_findings.add_columns("Run", "DNS finding")
                yield dns_findings

    def compose_ldap_tab(self) -> ComposeResult:
        with TabPane("LDAP", id="ldap_tab"):
            with Vertical(id="ldap_panel"):
                yield Static("LDAP structure", classes="section-title")
                structure = DataTable(id="ldap_structure", cursor_type="row")
                structure.add_columns("LDAP structure")
                yield structure
                yield Static("Findings", classes="section-title")
                yield Static(
                    self.findings_hint_text(), id="ldap_findings_hint", classes="hint"
                )
                ldap_findings = DataTable(id="ldap_findings", cursor_type="row")
                ldap_findings.add_columns("Run", "LDAP finding")
                yield ldap_findings

    def compose_sidebar(self) -> ComposeResult:
        with Vertical(id="sidebar", classes="panel"):
            yield Static("Connection: not checked", id="connection_summary")
            with TabbedContent(id="side_tabs"):
                yield from self.compose_dns_tab()
                yield from self.compose_ldap_tab()
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
