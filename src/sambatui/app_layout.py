from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING

from textual.app import ComposeResult, ScreenStackError
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import DataTable, Input, Label, Static, TabbedContent, TabPane

from sambatui.app_constants import KEY_HINTS

from .ui.tables import DNS_COLUMNS

if TYPE_CHECKING:
    from .app import SambatuiApp


class AppLayoutMixin:
    def findings_hint_text(self: SambatuiApp) -> str:
        return "Enter to open · Esc to clear"

    def keys_hint_for_tab(self: SambatuiApp, tab_id: str | None) -> str:
        return KEY_HINTS.get(tab_id or "", KEY_HINTS["dns_tab"])

    def active_side_tab_id(self: SambatuiApp) -> str:
        with suppress(NoMatches, ScreenStackError):
            return str(self.query_one("#side_tabs", TabbedContent).active or "dns_tab")
        return "dns_tab"

    def refresh_key_hints(self: SambatuiApp) -> None:
        with suppress(NoMatches, ScreenStackError):
            self.query_one("#keys", Static).update(
                self.keys_hint_for_tab(self.active_side_tab_id())
            )

    def compose_dns_tab(self: SambatuiApp) -> ComposeResult:
        with TabPane("DNS", id="dns_tab"), Vertical(id="dns_panel"):
            yield Static("DNS zones", classes="section-title")
            zones = DataTable(id="zones", cursor_type="row", show_header=False)
            zones.add_columns("DNS zones")
            yield zones
            yield Static("Findings", classes="section-title")
            yield Static(
                self.findings_hint_text(), id="dns_findings_hint", classes="hint"
            )
            dns_findings = DataTable(
                id="dns_findings", cursor_type="row", show_header=False
            )
            dns_findings.add_columns("DNS finding")
            yield dns_findings

    def compose_ldap_tab(self: SambatuiApp) -> ComposeResult:
        with TabPane("LDAP", id="ldap_tab"), Vertical(id="ldap_panel"):
            yield Static("LDAP structure", classes="section-title")
            structure = DataTable(
                id="ldap_structure", cursor_type="row", show_header=False
            )
            structure.add_columns("LDAP structure")
            yield structure
            yield Static("Findings", classes="section-title")
            yield Static(
                self.findings_hint_text(), id="ldap_findings_hint", classes="hint"
            )
            ldap_findings = DataTable(
                id="ldap_findings", cursor_type="row", show_header=False
            )
            ldap_findings.add_columns("LDAP finding")
            yield ldap_findings

    def compose_sidebar(self: SambatuiApp) -> ComposeResult:
        with Vertical(id="sidebar", classes="panel"):
            yield Static("Not connected", id="connection_summary", markup=False)
            with TabbedContent(id="side_tabs"):
                yield from self.compose_dns_tab()
                yield from self.compose_ldap_tab()
            yield Static("Ready", id="status", markup=False)

    def compose_results_panel(self: SambatuiApp) -> ComposeResult:
        with Vertical(id="results", classes="panel"):
            with Horizontal(id="records_header"):
                yield Label(
                    "Records", id="records_title", classes="section-title", markup=False
                )
                yield Static("", id="selection_state", markup=False)
                yield Input(
                    "",
                    placeholder="/ Search records",
                    id="inline_search",
                )
            table = DataTable(id="records", cursor_type="row")
            table.add_columns(*DNS_COLUMNS)
            yield table
            yield Static(
                "Select a row to see details.",
                id="record_details",
                classes="hint",
                markup=False,
            )

    def compose(self: SambatuiApp) -> ComposeResult:
        with Horizontal(id="main"):
            yield from self.compose_sidebar()
            yield from self.compose_results_panel()
        yield Static(self.keys_hint_for_tab("dns_tab"), id="keys")
