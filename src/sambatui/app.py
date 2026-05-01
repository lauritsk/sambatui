from __future__ import annotations

import asyncio
import inspect
import os
import shutil
import socket
from collections.abc import AsyncIterator, Callable, Iterable
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any, TypeVar

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.coordinate import Coordinate
from textual.widgets import (
    Button,
    DataTable,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
)

from .client import SambaToolClient, SambaToolConfig, parse_samba_options
from .config import (
    DEFAULT_AUTH,
    DEFAULT_AUTO_PTR,
    DEFAULT_CONFIGFILE,
    DEFAULT_KERBEROS,
    DEFAULT_KRB5_CCACHE,
    DEFAULT_LDAP_BASE,
    DEFAULT_LDAP_COMPATIBILITY,
    DEFAULT_LDAP_ENCRYPTION,
    DEFAULT_OPTIONS,
    DEFAULT_PASSWORD,
    DEFAULT_PASSWORD_FILE,
    DEFAULT_SERVER,
    DEFAULT_SMART_DAYS,
    DEFAULT_SMART_DISABLED_DAYS,
    DEFAULT_SMART_MAX_ROWS,
    DEFAULT_SMART_NEVER_LOGGED_DAYS,
    DEFAULT_USER,
    DEFAULT_ZONE,
    fix_password_file_permissions,
    password_file_permissions_too_open,
    password_file_warning,
    read_password_file,
    save_user_config,
    user_config_validation_error,
)
from .discovery import (
    DiscoveredService,
    discover_ad_services,
    normalize_domain,
    preferred_domain_controller,
)
from .dns import (
    NAME_RE,
    REC_RE,
    parse_records,
    parse_zones,
    ptr_target_for_name as dns_ptr_target_for_name,
    reverse_record_for_ipv4 as dns_reverse_record_for_ipv4,
    valid_dns_name,
    validate_record,
)
from .ldap_directory import (
    DirectoryRow,
    LdapDirectoryClient,
    LdapSearchConfig,
    domain_to_base_dn,
)
from .models import DnsRow
from .remediation import actionable_error, bounded_int
from .screens import (
    CommandPaletteChoice,
    CommandPaletteScreen,
    ConfirmScreen,
    FormField,
    FormScreen,
    FormValidator,
    HelpScreen,
    SmartViewChoice,
    SmartViewPickerScreen,
    infer_domain_from_server,
)
from .settings import ConnectionSettings
from .smart_view_catalog import (
    FULL_HEALTH_DNS_VIEW_IDS,
    FULL_HEALTH_LDAP_VIEW_IDS,
    FULL_HEALTH_VIEW_ID,
    SMART_VIEW_BY_ID,
    SMART_VIEW_BY_SHORTCUT,
    SMART_VIEW_LABELS,
    SMART_VIEWS,
    SmartViewDefinition,
    SmartViewOptions,
)
from .smart_views import (
    SmartViewCheckResult,
    SmartViewRow,
    dns_a_without_ptr,
    dns_duplicate_records,
    dns_ptr_without_a,
    full_health_dashboard_rows,
    ldap_delete_candidate_users,
    ldap_inactive_users,
    ldap_stale_computers,
    ldap_users_without_groups,
)
from .ui.details import (
    details_empty_text,
    directory_details_text,
    dns_details_text,
    dns_ptr_status,
    smart_details_text,
)
from .ui.styles import APP_CSS
from .ui.tables import (
    DIRECTORY_COLUMNS,
    DNS_COLUMNS,
    DNS_EMPTY_STATE,
    SMART_COLUMNS,
    RowValues,
    directory_result_values,
    directory_search_values,
    dns_result_values,
    dns_search_values,
    empty_state_text,
    matches_search,
    smart_result_values,
    smart_search_values,
)

TableRow = TypeVar("TableRow")


KEY_HINTS = {
    "dns_tab": "DNS: ? help  Ctrl+P palette  w setup  Ctrl+O connection  z zones  c discover  S smart  q query  a add  u update  d delete  / filter",
    "ldap_tab": "LDAP: ? help  Ctrl+P palette  w setup  Ctrl+O connection  c discover  L search directory  S smart views  / filter  j/k move  r refresh",
    "smart_tab": "Smart: ? help  Ctrl+P palette  w setup  Ctrl+O connection  S pick view  1-8 quick run  f fix DNS finding  / filter  r refresh",
}
SIDE_TAB_IDS = ("dns_tab", "ldap_tab", "smart_tab")
DNS_ACTION_BUTTONS = (
    ("setup_wizard", "Setup wizard"),
    ("load_zones", "Load zones"),
    ("refresh_zone", "Refresh zone"),
    ("query_record", "Query"),
    ("add_record", "Add record"),
    ("delete_records", "Delete selected"),
)
LDAP_ACTION_BUTTONS = (
    ("ldap_search_users", "Search users"),
    ("ldap_search_groups", "Search groups"),
    ("ldap_search_computers", "Search computers"),
)
SMART_ACTION_BUTTONS = (
    ("smart_full_health", "Full health dashboard"),
    ("smart_dns_health", "DNS duplicate check"),
    ("smart_ldap_cleanup", "LDAP cleanup check"),
)
CONNECTION_STATE_INPUTS = (
    (DEFAULT_SERVER, "server", False),
    (DEFAULT_ZONE, "zone", False),
    (DEFAULT_USER, "user", False),
    (DEFAULT_PASSWORD, "password", True),
    (DEFAULT_AUTH, "auth", False),
    (DEFAULT_KERBEROS, "kerberos", False),
    (DEFAULT_KRB5_CCACHE, "krb5_ccache", False),
    (DEFAULT_CONFIGFILE, "configfile", False),
    (DEFAULT_OPTIONS, "options", False),
    (DEFAULT_LDAP_BASE, "ldap_base", False),
    (DEFAULT_LDAP_ENCRYPTION, "ldap_encryption", False),
    (DEFAULT_LDAP_COMPATIBILITY, "ldap_compatibility", False),
    (DEFAULT_AUTO_PTR, "auto_ptr", False),
    (DEFAULT_SMART_DAYS, "smart_days", False),
    (DEFAULT_SMART_DISABLED_DAYS, "smart_disabled_days", False),
    (DEFAULT_SMART_NEVER_LOGGED_DAYS, "smart_never_logged_days", False),
    (DEFAULT_SMART_MAX_ROWS, "smart_max_rows", False),
    (str(DEFAULT_PASSWORD_FILE), "password_file", False),
)
RECORD_SORT_KEYS: dict[str, Callable[[DnsRow], str]] = {
    "name": lambda row: row.name.casefold(),
    "type": lambda row: row.rtype.casefold(),
    "value": lambda row: row.value.casefold(),
}
GUIDED_RECORD_TYPES = ("A", "AAAA", "CNAME", "PTR", "TXT", "MX", "SRV", "NS")
GUIDED_RECORD_TYPE_FIELDS: dict[str, tuple[FormField, ...]] = {
    "A": (("IPv4 address", "address", "192.0.2.10", ""),),
    "AAAA": (("IPv6 address", "address", "2001:db8::10", ""),),
    "CNAME": (("Canonical target", "target", "host.example.com.", ""),),
    "PTR": (("PTR target", "target", "host.example.com.", ""),),
    "TXT": (("TXT text", "text", "v=spf1 include:example.com ~all", ""),),
    "MX": (
        ("Priority", "priority", "10", "10"),
        ("Mail exchanger", "target", "mail.example.com.", ""),
    ),
    "SRV": (
        ("Priority", "priority", "0", "0"),
        ("Weight", "weight", "100", "100"),
        ("Port", "port", "389", ""),
        ("Target", "target", "dc01.example.com.", ""),
    ),
    "NS": (("Name server", "target", "ns1.example.com.", ""),),
}
GUIDED_RECORD_VALUE_FIELDS = {
    "A": ("address",),
    "AAAA": ("address",),
    "CNAME": ("target",),
    "PTR": ("target",),
    "NS": ("target",),
    "TXT": ("text",),
    "MX": ("priority", "target"),
    "SRV": ("priority", "weight", "port", "target"),
}
KEY_ACTION_NAMES: dict[str, str] = {
    "ctrl+o": "action_connection",
    "ctrl+p": "action_open_command_palette",
    "escape": "action_clear_navigation_state",
    "tab": "action_next_table",
    "shift+tab": "action_previous_table",
    "space": "action_toggle_select",
    "ctrl+space": "action_toggle_select",
    "shift+up": "action_extend_up",
    "shift+down": "action_extend_down",
    "ctrl+d": "action_cursor_half_page_down",
    "ctrl+u": "action_cursor_half_page_up",
    "pagedown": "action_cursor_page_down",
    "pageup": "action_cursor_page_up",
    "home": "action_cursor_top",
    "end": "action_cursor_bottom",
    "slash": "action_search",
    "enter": "action_activate_row",
}
CHAR_ACTION_NAMES: dict[str, str] = {
    "?": "action_help",
    "p": "load_password",
    "]": "action_next_side_tab",
    "[": "action_previous_side_tab",
    " ": "action_toggle_select",
    "w": "action_setup_wizard",
    "z": "action_load_zones",
    "c": "action_discover_ad",
    "r": "action_refresh",
    "q": "action_query",
    "a": "action_add",
    "u": "action_update",
    "d": "action_delete",
    "f": "action_fix_smart",
    "v": "action_visual_select",
    "j": "action_cursor_down",
    "k": "action_cursor_up",
    "h": "action_focus_zones",
    "l": "action_focus_records",
    "/": "action_search",
    "n": "action_sort_name",
    "t": "action_sort_type",
    "e": "action_sort_value",
}
CASE_SENSITIVE_ACTION_NAMES: dict[str, str] = {
    "P": "save_password",
    "L": "action_ldap_search",
    "S": "action_smart_view",
    "V": "action_select_range",
}
PALETTE_ACTIONS: tuple[CommandPaletteChoice, ...] = (
    ("help", "Show help", "?", "Open the keyboard shortcut and workflow help."),
    (
        "setup_wizard",
        "Run first-run setup wizard",
        "w",
        "Enter AD domain and credentials, discover a DC, check DNS/LDAP, and load zones.",
    ),
    (
        "connection",
        "Open connection settings",
        "Ctrl+O",
        "Edit server, zone, auth, LDAP, and smart-view defaults.",
    ),
    (
        "load_password",
        "Load password file",
        "p",
        "Load the configured password file after checking permissions.",
    ),
    (
        "save_password",
        "Save password file",
        "P",
        "Write the current password field to disk with chmod 600.",
    ),
    (
        "discover_ad",
        "Discover AD domain controller",
        "c",
        "Find domain controllers from DNS SRV records and fill connection fields.",
    ),
    ("load_zones", "Load DNS zones", "z", "List DNS zones from samba-tool."),
    (
        "refresh",
        "Refresh current view",
        "r",
        "Reload the current DNS zone or rerun the active smart view.",
    ),
    ("query_record", "Query DNS records", "q", "Query one DNS name and type."),
    ("add_record", "Add DNS record", "a", "Create a DNS record in the active zone."),
    (
        "update_record",
        "Update selected DNS record",
        "u",
        "Edit one selected DNS record, including type changes.",
    ),
    (
        "delete_records",
        "Delete selected DNS records",
        "d",
        "Delete selected DNS records after confirmation.",
    ),
    (
        "filter_results",
        "Filter current results",
        "/",
        "Focus inline search for DNS, LDAP, or smart-view rows.",
    ),
    (
        "ldap_search",
        "Search LDAP directory",
        "L",
        "Search AD users, groups, computers, OUs, or all entries.",
    ),
    (
        "ldap_search_users",
        "Search LDAP users",
        "",
        "Open LDAP search prefilled for users.",
    ),
    (
        "ldap_search_groups",
        "Search LDAP groups",
        "",
        "Open LDAP search prefilled for groups.",
    ),
    (
        "ldap_search_computers",
        "Search LDAP computers",
        "",
        "Open LDAP search prefilled for computers.",
    ),
    (
        "smart_view_picker",
        "Pick smart view",
        "S",
        "Choose a DNS or LDAP health view from a list.",
    ),
    *(
        (
            f"smart_view_{view.shortcut}",
            f"Run smart view: {view.label}",
            view.shortcut,
            view.description,
        )
        for view in SMART_VIEWS
    ),
    (
        "fix_smart",
        "Fix selected smart finding",
        "f",
        "Apply the available guided DNS fix for the selected smart-view finding.",
    ),
)
PALETTE_ACTION_MAP: dict[str, tuple[str, tuple[Any, ...]]] = {
    "help": ("action_help", ()),
    "setup_wizard": ("action_setup_wizard", ()),
    "connection": ("action_connection", ()),
    "load_password": ("load_password", ()),
    "save_password": ("save_password", ()),
    "discover_ad": ("action_discover_ad", ()),
    "load_zones": ("action_load_zones", ()),
    "refresh": ("action_refresh", ()),
    "query_record": ("action_query", ()),
    "add_record": ("action_add", ()),
    "update_record": ("action_update", ()),
    "delete_records": ("action_delete", ()),
    "filter_results": ("action_search", ()),
    "ldap_search": ("action_ldap_search", ()),
    "ldap_search_users": ("action_ldap_search_kind", ("users",)),
    "ldap_search_groups": ("action_ldap_search_kind", ("groups",)),
    "ldap_search_computers": ("action_ldap_search_kind", ("computers",)),
    "smart_view_picker": ("action_smart_view", ()),
    **{
        f"smart_view_{view.shortcut}": ("action_smart_view_shortcut", (view.shortcut,))
        for view in SMART_VIEWS
    },
    "fix_smart": ("action_fix_smart", ()),
}
SIDEBAR_ACTIONS: dict[str, tuple[str, tuple[Any, ...]]] = {
    "load_password": ("load_password", ()),
    "save_password": ("save_password", ()),
    "setup_wizard": ("action_setup_wizard", ()),
    "load_zones": ("action_load_zones", ()),
    "refresh_zone": ("action_refresh", ()),
    "query_record": ("action_query", ()),
    "add_record": ("action_add", ()),
    "delete_records": ("action_delete", ()),
    "discover_ad": ("action_discover_ad", ()),
    "ldap_search_users": ("action_ldap_search_kind", ("users",)),
    "ldap_search_groups": ("action_ldap_search_kind", ("groups",)),
    "ldap_search_computers": ("action_ldap_search_kind", ("computers",)),
    "smart_full_health": ("action_smart_view_shortcut", ("8",)),
    "smart_dns_health": ("action_smart_view_shortcut", ("1",)),
    "smart_ldap_cleanup": ("action_smart_view_shortcut", ("5",)),
}

__all__ = [
    "DEFAULT_AUTH",
    "DEFAULT_AUTO_PTR",
    "DEFAULT_CONFIGFILE",
    "DEFAULT_KERBEROS",
    "DEFAULT_KRB5_CCACHE",
    "DEFAULT_LDAP_BASE",
    "DEFAULT_LDAP_COMPATIBILITY",
    "DEFAULT_LDAP_ENCRYPTION",
    "DEFAULT_OPTIONS",
    "DEFAULT_PASSWORD",
    "DEFAULT_PASSWORD_FILE",
    "DEFAULT_SERVER",
    "DEFAULT_SMART_DAYS",
    "DEFAULT_SMART_DISABLED_DAYS",
    "DEFAULT_SMART_MAX_ROWS",
    "DEFAULT_SMART_NEVER_LOGGED_DAYS",
    "DEFAULT_USER",
    "DEFAULT_ZONE",
    "NAME_RE",
    "REC_RE",
    "CommandPaletteScreen",
    "ConfirmScreen",
    "DnsRow",
    "FormField",
    "FormScreen",
    "HelpScreen",
    "SmartViewPickerScreen",
    "SambaToolClient",
    "SambaToolConfig",
    "SMART_VIEW_LABELS",
    "SambatuiApp",
    "main",
    "parse_records",
    "parse_zones",
    "password_file_warning",
    "parse_samba_options",
    "read_password_file",
    "valid_dns_name",
    "validate_record",
    "actionable_error",
]


class SambatuiApp(App):
    CSS = APP_CSS

    BINDINGS = [
        ("question_mark", "help", "Help"),
        ("ctrl+p", "open_command_palette", "Command palette"),
        ("ctrl+o", "connection", "Connection"),
        ("w", "setup_wizard", "Setup wizard"),
        ("p", "load_password_file", "Load password"),
        ("P", "save_password_file", "Save password"),
        ("z", "load_zones", "Zones"),
        ("c", "discover_ad", "Discover DC"),
        ("L", "ldap_search", "LDAP"),
        ("S", "smart_view", "Smart views"),
        ("r", "refresh", "Refresh"),
        ("q", "query", "Query"),
        ("a", "add", "Add"),
        ("u", "update", "Update selected"),
        ("d", "delete", "Delete selected"),
        ("space", "toggle_select", "Toggle select"),
        ("ctrl+space", "toggle_select", "Toggle select"),
        ("v", "visual_select", "Visual select"),
        ("V", "select_range", "Select range"),
        ("escape", "clear_navigation_state", "Clear"),
        ("shift+up", "extend_up", "Extend up"),
        ("shift+down", "extend_down", "Extend down"),
        ("tab", "next_table", "Next table"),
        ("shift+tab", "previous_table", "Previous table"),
        ("]", "next_side_tab", "Next DNS/LDAP tab"),
        ("[", "previous_side_tab", "Previous DNS/LDAP tab"),
        ("h", "focus_zones", "Focus zones"),
        ("l", "focus_records", "Focus records"),
        ("j", "cursor_down", "Down"),
        ("k", "cursor_up", "Up"),
        ("ctrl+d", "cursor_half_page_down", "Half page down"),
        ("ctrl+u", "cursor_half_page_up", "Half page up"),
        ("pagedown", "cursor_page_down", "Page down"),
        ("pageup", "cursor_page_up", "Page up"),
        ("home", "cursor_top", "Top"),
        ("end", "cursor_bottom", "Bottom"),
        ("G", "cursor_bottom", "Bottom"),
        ("enter", "activate_row", "Activate"),
        ("f", "fix_smart", "Fix smart finding"),
        ("slash", "search", "Search"),
        ("n", "sort_name", "Sort name"),
        ("t", "sort_type", "Sort type"),
        ("e", "sort_value", "Sort value"),
        ("ctrl+q", "quit", "Quit"),
    ]

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

    def compose_action_buttons(
        self, container_id: str, buttons: tuple[tuple[str, str], ...]
    ) -> ComposeResult:
        with Vertical(id=container_id, classes="action-buttons"):
            for button_id, label in buttons:
                yield Button(label, id=button_id)

    def compose_dns_tab(self) -> ComposeResult:
        with TabPane("DNS", id="dns_tab"):
            with Vertical(id="dns_panel"):
                yield Static("DNS zones", classes="section-title")
                yield from self.compose_action_buttons(
                    "dns_actions", DNS_ACTION_BUTTONS
                )
                zones = DataTable(id="zones", cursor_type="row")
                zones.add_columns("DNS zones")
                yield zones

    def compose_ldap_tab(self) -> ComposeResult:
        with TabPane("LDAP", id="ldap_tab"):
            with Vertical(id="ldap_panel"):
                yield Static("LDAP directory", classes="section-title")
                yield from self.compose_action_buttons(
                    "ldap_actions", LDAP_ACTION_BUTTONS
                )
                yield Static(
                    "Search AD directory. Results open in the main table.",
                    id="ldap_hint",
                    classes="hint",
                )

    def compose_smart_tab(self) -> ComposeResult:
        with TabPane("Smart", id="smart_tab"):
            with Vertical(id="smart_panel"):
                yield Static("Smart views", classes="section-title")
                yield from self.compose_action_buttons(
                    "smart_actions", SMART_ACTION_BUTTONS
                )
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
                    placeholder="/ search current results",
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

    def on_mount(self) -> None:
        self.initialize_state()
        self.initialize_view()

        if not shutil.which("samba-tool"):
            self.report_error("samba-tool not found in PATH")
            return

        self.set_initial_connection_status()
        if self.connection_needs_setup():
            self.set_status(
                "Connection incomplete. Press w for setup wizard or Ctrl+O."
            )
        else:
            self.call_after_refresh(self.load_zones)

    def initialize_state(self) -> None:
        self.selected_record_rows: set[int] = set()
        self.selection_anchor: int | None = None
        self.visual_selecting = False
        self.record_rows: list[DnsRow] = []
        self.directory_rows: list[DirectoryRow] = []
        self.smart_view_rows: list[SmartViewRow] = []
        self.current_smart_view_id = ""
        self.current_smart_max_rows = 500
        self.current_smart_values: dict[str, str] = {}
        self.records_columns = DNS_COLUMNS
        self.view_mode = "dns"
        self.sort_field = "name"
        self.sort_reverse = False
        self.search_text = ""
        self._syncing_search_input = False
        self.zones: list[str] = []
        self.pending_g = False

    def initialize_view(self) -> None:
        self.refresh_connection_summary()
        self.update_records_title()
        self.action_focus_records()
        self.refresh_key_hints()
        self.render_records([])

    def set_initial_connection_status(self) -> None:
        if (self.val("auth") or DEFAULT_AUTH).casefold() == "kerberos":
            self.set_status("Kerberos auth selected. Run kinit if the ticket expires.")
            return
        warning = password_file_warning(self.password_file())
        if warning:
            self.report_error(warning)
        elif self.val("password"):
            self.set_status(f"Password loaded from env or {DEFAULT_PASSWORD_FILE}")
        else:
            self.set_status("Enter password, load password file, or use kerberos auth")

    def val(self, widget_id: str) -> str:
        return self.query_one(f"#{widget_id}", Input).value.strip()

    def set_status(self, message: str) -> None:
        with suppress(Exception):
            self.query_one("#status", Static).update(message)

    def report_error(self, message: str) -> None:
        text = actionable_error(message)
        self.notify(text[:200], severity="error")
        self.set_status(text[:180])

    def set_val(self, widget_id: str, value: str) -> None:
        self.query_one(f"#{widget_id}", Input).value = value

    def preference_values(self) -> dict[str, str]:
        zone = self.val("zone")
        return {
            "server": self.val("server"),
            "zone": zone,
            "auth": self.val("auth") or DEFAULT_AUTH,
            "ldap_base": self.val("ldap_base"),
            "ldap_encryption": self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            "ldap_compatibility": self.val("ldap_compatibility")
            or DEFAULT_LDAP_COMPATIBILITY,
            "auto_ptr": self.val("auto_ptr") or DEFAULT_AUTO_PTR,
            "last_zone": zone,
            "smart_days": self.val("smart_days") or DEFAULT_SMART_DAYS,
            "smart_disabled_days": self.val("smart_disabled_days")
            or DEFAULT_SMART_DISABLED_DAYS,
            "smart_never_logged_days": self.val("smart_never_logged_days")
            or DEFAULT_SMART_NEVER_LOGGED_DAYS,
            "smart_max_rows": self.val("smart_max_rows") or DEFAULT_SMART_MAX_ROWS,
        }

    def save_preferences(self) -> None:
        try:
            save_user_config(self.preference_values())
        except OSError as exc:
            self.report_error(f"Cannot save preferences: {exc}")

    def connection_settings(self) -> ConnectionSettings:
        return ConnectionSettings.from_lookup(self.val)

    def connection_summary(self) -> str:
        return self.connection_settings().summary

    def connection_needs_setup(self) -> bool:
        return self.connection_settings().needs_setup(read_password_file)

    def discovery_domain_default(self) -> str:
        candidates = [
            self.val("zone"),
            infer_domain_from_server(self.val("server")),
            os.getenv("USERDNSDOMAIN", ""),
            os.getenv("SAMBATUI_DOMAIN", ""),
            infer_domain_from_server(socket.getfqdn()),
        ]
        return next(
            (
                candidate.strip().rstrip(".").lower()
                for candidate in candidates
                if candidate.strip()
            ),
            "",
        )

    def refresh_connection_summary(self) -> None:
        with suppress(Exception):
            self.query_one("#connection_summary", Static).update(
                f"Connection: {self.connection_summary()}"
            )

    def connection_fields(self) -> list[FormField]:
        return self.connection_settings().form_fields()

    def password_file(self) -> Path:
        return self.connection_settings().path_password_file

    def samba_config(self) -> SambaToolConfig:
        return self.connection_settings().samba_config()

    def samba_client(self) -> SambaToolClient:
        return SambaToolClient(self.samba_config())

    def ldap_config(self, base_dn: str = "") -> LdapSearchConfig:
        return self.connection_settings().ldap_config(base_dn)

    def ldap_client(self, base_dn: str = "") -> LdapDirectoryClient:
        return LdapDirectoryClient(self.ldap_config(base_dn))

    async def load_password(self) -> None:
        path = self.password_file()
        warning = password_file_warning(path)
        if warning:
            if not password_file_permissions_too_open(path):
                self.report_error(warning)
                return
            if not await self.confirm(
                f"Password file permissions too open: {path}\n\nFix with chmod 600 and load?"
            ):
                self.report_error(warning)
                return
            try:
                fix_password_file_permissions(path)
            except OSError as exc:
                self.report_error(
                    f"Cannot fix password file permissions for {path}: {exc}"
                )
                return
        password = read_password_file(path)
        if not password:
            self.report_error(f"No password found in {path}")
            return
        self.query_one("#password", Input).value = password
        self.set_status(f"Loaded password from {path}")
        self.notify("Password loaded")

    @work
    async def save_password(self) -> None:
        path = self.password_file()
        password = self.val("password")
        if not password:
            self.notify("Password field empty; nothing saved", severity="error")
            return
        if not await self.confirm(
            f"Save password to {path}?\n\nThis writes a secret to disk with chmod 600."
        ):
            self.notify("Save cancelled")
            return
        parent_exists = path.parent.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not parent_exists:
            path.parent.chmod(0o700)
        path.write_text(password + "\n", encoding="utf-8")
        path.chmod(0o600)
        self.set_status(f"Saved password to {path}")
        self.notify("Password saved")

    async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
        return bool(
            await self.push_screen_wait(
                ConfirmScreen(message, default_confirm=default_confirm)
            )
        )

    async def form(
        self,
        title: str,
        hint: str,
        fields: list[FormField],
        submit_label: str = "Continue",
        validator: FormValidator | None = None,
    ) -> dict[str, str] | None:
        return await self.push_screen_wait(
            FormScreen(title, hint, fields, submit_label, validator)
        )

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    async def action_open_command_palette(self) -> None:
        action_id = await self.push_screen_wait(
            CommandPaletteScreen(list(PALETTE_ACTIONS))
        )
        if action_id is None:
            return
        await self.run_command_palette_action(action_id)

    async def run_command_palette_action(self, action_id: str | None) -> bool:
        action = PALETTE_ACTION_MAP.get(action_id or "")
        if action is None:
            return False
        action_name, args = action
        await self.invoke_action(action_name, *args)
        return True

    def setup_wizard_fields(self) -> list[FormField]:
        auth = self.val("auth") or DEFAULT_AUTH
        kerberos = self.val("kerberos") or DEFAULT_KERBEROS
        if auth.casefold() == "kerberos" and kerberos.casefold() == "off":
            kerberos = "required"
        return [
            (
                "AD DNS domain — used to discover domain controllers and zones.",
                "domain",
                "example.com",
                self.discovery_domain_default(),
            ),
            (
                "User — DOMAIN\\user for password auth; optional with Kerberos.",
                "user",
                "EXAMPLE\\admin",
                self.val("user"),
            ),
            (
                "Password — hidden; leave empty for Kerberos or configured password file.",
                "password",
                "password",
                self.val("password"),
            ),
            ("Auth mode — password or kerberos.", "auth", "password | kerberos", auth),
            (
                "Kerberos option — required is safest for Kerberos setup.",
                "kerberos",
                "required | desired | off",
                kerberos,
            ),
            (
                "LDAP encryption — password bind requires ldaps or starttls.",
                "ldap_encryption",
                "ldaps | starttls | off",
                self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            ),
            (
                "LDAP compatibility — use on only for legacy Samba/old TLS DCs.",
                "ldap_compatibility",
                "on | off",
                self.val("ldap_compatibility") or DEFAULT_LDAP_COMPATIBILITY,
            ),
        ]

    def setup_wizard_validation_error(self, values: dict[str, str]) -> str | None:
        try:
            normalize_domain(values.get("domain", ""))
        except ValueError as exc:
            return str(exc)
        error = user_config_validation_error(values)
        if error:
            return error
        if (values.get("auth") or DEFAULT_AUTH).casefold() != "password":
            return None
        if not values.get("user"):
            return "Enter username or switch auth to kerberos."
        if values.get("password") or read_password_file(self.password_file()):
            return None
        return "Enter password, load password file, or switch auth to kerberos."

    async def discover_setup_services(self, domain: str) -> list[DiscoveredService]:
        return await asyncio.to_thread(discover_ad_services, domain)

    def apply_setup_wizard_values(
        self, domain: str, server: str, values: dict[str, str]
    ) -> None:
        auth = values.get("auth") or DEFAULT_AUTH
        kerberos = values.get("kerberos") or DEFAULT_KERBEROS
        if auth.casefold() == "kerberos" and kerberos.casefold() == "off":
            kerberos = "required"
        password = values.get("password") or read_password_file(self.password_file())
        self.set_val("server", server)
        self.set_val("zone", domain)
        self.set_val("ldap_base", domain_to_base_dn(domain))
        self.set_val("user", values.get("user", self.val("user")))
        self.set_val("password", password)
        self.set_val("auth", auth)
        self.set_val("kerberos", kerberos)
        self.set_val(
            "ldap_encryption", values.get("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION
        )
        self.set_val(
            "ldap_compatibility",
            values.get("ldap_compatibility") or DEFAULT_LDAP_COMPATIBILITY,
        )
        self.refresh_connection_summary()
        self.update_records_title()

    async def check_ldap_connectivity(self) -> str | None:
        try:
            await asyncio.to_thread(self.ldap_client().check_connection)
        except Exception as exc:
            return str(exc)
        return None

    def setup_check_failed(self, check: str, message: str, action: str) -> bool:
        detail = next(
            (line.strip() for line in message.splitlines() if line.strip()), ""
        )
        suffix = f": {detail}" if detail else ""
        self.report_error(f"Setup {check} check failed{suffix} Action: {action}.")
        return False

    async def run_setup_wizard(self, values: dict[str, str]) -> bool:
        domain = normalize_domain(values.get("domain", "")).lower()
        async with self.busy():
            self.set_status(f"Setup: discovering domain controllers for {domain}")
            try:
                services = await self.discover_setup_services(domain)
            except ValueError as exc:
                self.report_error(str(exc))
                return False
            controller = preferred_domain_controller(services)
            if controller is None:
                self.report_error(f"No AD SRV records found for {domain}")
                return False

            self.apply_setup_wizard_values(domain, controller.target, values)
            self.set_status("Setup: checking DNS zones")
            code, output = await self.run_zonelist()
            if code != 0:
                return self.setup_check_failed(
                    "DNS",
                    output,
                    "check credentials, DC reachability, samba-tool rights, and domain",
                )
            zones = parse_zones(output)
            if not zones:
                return self.setup_check_failed(
                    "DNS",
                    "no zones returned",
                    "check DNS service health and account rights on the selected DC",
                )

            self.set_status("Setup: checking LDAP bind")
            ldap_error = await self.check_ldap_connectivity()
            if ldap_error:
                return self.setup_check_failed(
                    "LDAP",
                    ldap_error,
                    "check LDAP encryption, credentials, Base DN, firewall, or Kerberos ticket",
                )

            self.zones = zones
            self.populate_zones(zones)
            self.save_preferences()

        if self.val("zone") in self.zones:
            await self.activate_zone(self.val("zone"), save=False)
        else:
            self.set_status(
                f"Setup complete: loaded {len(self.zones)} zones; select a zone and press Enter"
            )
        self.notify(f"Setup complete: loaded {len(self.zones)} zones")
        return True

    async def open_setup_wizard(self) -> bool:
        values = await self.form(
            "First-run setup wizard",
            "Enter the AD DNS domain and required credentials. sambatui discovers a DC, checks DNS/LDAP connectivity, then loads zones.",
            self.setup_wizard_fields(),
            "Run checks",
            self.setup_wizard_validation_error,
        )
        if values is None:
            self.refresh_connection_summary()
            return False
        return await self.run_setup_wizard(values)

    @work
    async def action_setup_wizard(self) -> None:
        await self.open_setup_wizard()

    async def action_load_password_file(self) -> None:
        await self.load_password()

    def action_save_password_file(self) -> None:
        self.save_password()

    async def open_connection_settings(self) -> bool:
        values = await self.form(
            "Connection settings",
            "These values feed samba-tool and LDAP. Press Apply to close; reopen with Ctrl+O or ? help.",
            self.connection_fields(),
            "Apply",
            user_config_validation_error,
        )
        if values is None:
            self.refresh_connection_summary()
            return False
        for widget_id, value in values.items():
            self.set_val(widget_id, value)
        if (self.val("auth") or DEFAULT_AUTH).casefold() == "password" and not self.val(
            "password"
        ):
            warning = password_file_warning(self.password_file())
            if warning:
                self.report_error(warning)
            else:
                password = read_password_file(self.password_file())
                if password:
                    self.set_val("password", password)
        self.refresh_connection_summary()
        self.save_preferences()
        self.set_status("Connection settings updated")
        if not self.connection_needs_setup():
            await self.load_zones()
        return True

    @work
    async def action_connection(self) -> None:
        await self.open_connection_settings()

    async def run_command(
        self, client: SambaToolClient, cmd: list[str]
    ) -> tuple[int, str]:
        error = client.authentication_error()
        if error:
            self.report_error(error)
            return 2, error

        self.set_status(f"Running: {client.status_command(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out_bytes, _ = await proc.communicate()
        output = out_bytes.decode(errors="replace")
        code = proc.returncode or 0
        if code == 0:
            self.set_status("OK")
        else:
            first_line = next(
                (line for line in output.splitlines() if line.strip()), f"exit {code}"
            )
            self.report_error(first_line)
        return code, output

    async def run_samba(self, action: str, args: list[str]) -> tuple[int, str]:
        client = self.samba_client()
        return await self.run_command(
            client, client.dns_command(action, self.val("zone"), args)
        )

    async def run_samba_zone(
        self, action: str, zone: str, args: list[str]
    ) -> tuple[int, str]:
        client = self.samba_client()
        return await self.run_command(
            client, client.dns_zone_command(action, zone, args)
        )

    async def run_zonelist(self) -> tuple[int, str]:
        client = self.samba_client()
        return await self.run_command(client, client.zonelist_command())

    def set_busy(self, busy: bool) -> None:
        for button in self.query(Button):
            button.disabled = busy

    @asynccontextmanager
    async def busy(self) -> AsyncIterator[None]:
        self.set_busy(True)
        try:
            yield
        finally:
            self.set_busy(False)

    async def do_command(
        self, action: str, args: list[str], update_table: bool = False
    ) -> int:
        async with self.busy():
            code, output = await self.run_samba(action, args)
            if update_table and code == 0:
                self.populate_records(parse_records(output))
            if code == 0:
                self.notify("OK")
            return code

    def ptr_target_for_name(self, name: str) -> str:
        return dns_ptr_target_for_name(name, self.val("zone"))

    def reverse_record_for_ipv4(self, ip_value: str) -> tuple[str, str] | None:
        return dns_reverse_record_for_ipv4(ip_value, self.zones)

    async def add_ptr(self, name: str, ip_value: str) -> int:
        reverse = self.reverse_record_for_ipv4(ip_value)
        if reverse is None:
            return 0
        ptr_zone, ptr_name = reverse
        ptr_target = self.ptr_target_for_name(name)
        code, _ = await self.run_samba_zone(
            "add", ptr_zone, [ptr_name, "PTR", ptr_target]
        )
        if code == 0:
            self.notify(f"Added PTR {ptr_name} -> {ptr_target}")
        return code

    async def load_zones(self, *, restore_active_zone: bool = True) -> None:
        async with self.busy():
            code, output = await self.run_zonelist()
            if code != 0:
                return
            zones = parse_zones(output)
            self.zones = zones
            self.populate_zones(zones)
            self.notify(f"Loaded {len(zones)} zones")
            if restore_active_zone and await self.restore_active_zone_records():
                return
            if not zones:
                self.set_status(DNS_EMPTY_STATE[1])
                return
            active_zone = self.val("zone")
            if active_zone:
                self.set_status(
                    f"Loaded {len(zones)} zones; saved zone {active_zone} not found"
                )
            else:
                self.set_status(
                    f"Loaded {len(zones)} zones; select a zone and press Enter"
                )

    def populate_zones(self, zones: list[str]) -> None:
        table = self.query_one("#zones", DataTable)
        table.clear()
        if not zones:
            table.add_row("No zones loaded — press z to load zones")
            return
        for zone in zones:
            table.add_row(zone)
        self.select_zone_cursor(self.val("zone"))

    def select_zone_cursor(self, zone: str) -> None:
        if not zone or zone not in self.zones:
            return
        table = self.query_one("#zones", DataTable)
        with suppress(Exception):
            table.move_cursor(row=self.zones.index(zone))

    async def restore_active_zone_records(self) -> bool:
        zone = self.val("zone")
        if not zone or zone not in self.zones:
            return False
        self.select_zone_cursor(zone)
        await self.activate_zone(zone, save=False)
        return True

    def records_title(self) -> str:
        zone = self.val("zone")
        return f"Records — {zone}" if zone else "Records"

    def update_records_title(self) -> None:
        self.query_one("#records_title", Label).update(self.records_title())

    async def activate_zone(self, zone: str, *, save: bool = True) -> bool:
        if zone not in self.zones:
            self.set_status(DNS_EMPTY_STATE[1])
            return False
        self.query_one("#zone", Input).value = zone
        self.refresh_connection_summary()
        self.update_records_title()
        if save:
            self.save_preferences()
        self.set_status(f"Loading records for {zone}")
        await self.refresh_current_zone()
        return True

    def set_records_columns(self, columns: tuple[str, ...]) -> None:
        if self.records_columns == columns:
            return
        table = self.query_one("#records", DataTable)
        table.clear(columns=True)
        table.add_columns(*columns)
        self.records_columns = columns

    def populate_records(self, rows: list[DnsRow]) -> None:
        self.view_mode = "dns"
        self.set_records_columns(DNS_COLUMNS)
        self.update_records_title()
        self.record_rows = self.sorted_records(rows)
        self.refresh_record_view()
        self.set_status(
            f"Loaded {len(rows)} records from {self.val('zone')}; sorted by {self.sort_field}"
        )

    def populate_directory(self, rows: list[DirectoryRow]) -> None:
        self.view_mode = "directory"
        self.set_records_columns(DIRECTORY_COLUMNS)
        self.query_one("#records_title", Label).update("Directory (read-only LDAP)")
        self.directory_rows = rows
        self.refresh_directory_view()
        self.set_status(f"Loaded {len(rows)} LDAP entries")

    def populate_smart_view(self, title: str, rows: list[SmartViewRow]) -> None:
        self.view_mode = "smart"
        with suppress(Exception):
            self.query_one("#side_tabs", TabbedContent).active = "smart_tab"
            self.refresh_key_hints()
        self.set_records_columns(SMART_COLUMNS)
        self.query_one("#records_title", Label).update(f"Smart View: {title}")
        self.smart_view_rows = rows
        self.refresh_smart_view()
        self.set_status(f"Loaded {len(rows)} smart-view findings")

    def reset_render_state(self) -> None:
        self.selected_record_rows.clear()
        self.selection_anchor = None
        self.visual_selecting = False

    def render_result_rows(
        self,
        rows: list[TableRow],
        view_mode: str,
        row_values: Callable[[TableRow], RowValues],
    ) -> None:
        self.reset_render_state()
        table = self.query_one("#records", DataTable)
        table.clear()
        if rows:
            for row in rows:
                table.add_row("", *row_values(row))
        else:
            title, hint = self.empty_state_text(view_mode)
            table.add_row("", title, "-", hint, "", "", "")
        table.move_cursor(row=0)
        self.update_details_pane()

    def render_records(self, rows: list[DnsRow]) -> None:
        self.render_result_rows(rows, "dns", dns_result_values)

    def render_directory(self, rows: list[DirectoryRow]) -> None:
        self.render_result_rows(rows, "directory", directory_result_values)

    def render_smart_view(self, rows: list[SmartViewRow]) -> None:
        self.render_result_rows(rows, "smart", smart_result_values)

    def details_empty_text(self) -> str:
        return details_empty_text(self.empty_state_text(self.view_mode))

    def records_cursor_row(self) -> int:
        with suppress(Exception):
            return self.query_one("#records", DataTable).cursor_row
        return 0

    def visible_row_at(self, rows: list[TableRow], row_index: int) -> TableRow | None:
        if row_index < 0 or row_index >= len(rows):
            return None
        return rows[row_index]

    def dns_details_text(self, row_index: int) -> str:
        row = self.visible_row_at(self.visible_records(), row_index)
        if row is None:
            return self.details_empty_text()
        ptr_status = dns_ptr_status(
            row,
            zones=self.zones,
            reverse_record_for_ipv4=self.reverse_record_for_ipv4,
            ptr_target_for_name=self.ptr_target_for_name,
        )
        return dns_details_text(row, zone=self.val("zone"), ptr_status=ptr_status)

    def directory_details_text(self, row_index: int) -> str:
        row = self.visible_row_at(self.visible_directory(), row_index)
        return self.details_empty_text() if row is None else directory_details_text(row)

    def smart_details_text(self, row_index: int) -> str:
        row = self.visible_row_at(self.visible_smart_view(), row_index)
        return self.details_empty_text() if row is None else smart_details_text(row)

    def current_details_text(self) -> str:
        row_index = self.records_cursor_row()
        if self.view_mode == "directory":
            return self.directory_details_text(row_index)
        if self.view_mode == "smart":
            return self.smart_details_text(row_index)
        return self.dns_details_text(row_index)

    def update_details_pane(self) -> None:
        with suppress(Exception):
            self.query_one("#record_details", Static).update(
                self.current_details_text()
            )

    def empty_state_text(self, view_mode: str) -> tuple[str, str]:
        return empty_state_text(view_mode, self.search_text)

    def empty_state_status(self, view_mode: str) -> str:
        title, hint = self.empty_state_text(view_mode)
        return f"{title}. {hint}"

    def matches_search(self, values: Iterable[str]) -> bool:
        return matches_search(values, self.search_text)

    def visible_rows(
        self,
        rows: list[TableRow],
        search_values: Callable[[TableRow], Iterable[str]],
    ) -> list[TableRow]:
        if not self.search_text:
            return rows
        return [row for row in rows if self.matches_search(search_values(row))]

    def visible_records(self) -> list[DnsRow]:
        return self.visible_rows(self.record_rows, dns_search_values)

    def visible_directory(self) -> list[DirectoryRow]:
        return self.visible_rows(self.directory_rows, directory_search_values)

    def visible_smart_view(self) -> list[SmartViewRow]:
        return self.visible_rows(self.smart_view_rows, smart_search_values)

    def set_visible_status(
        self, shown: int, total: int, label: str, view_mode: str
    ) -> None:
        if not shown:
            self.set_status(self.empty_state_status(view_mode))
            return
        extra = f" matching /{self.search_text}/" if self.search_text else ""
        self.set_status(f"Showing {shown} of {total} {label}{extra}")

    def refresh_record_view(self) -> None:
        rows = self.visible_records()
        self.render_records(rows)
        self.set_visible_status(len(rows), len(self.record_rows), "records", "dns")

    def refresh_directory_view(self) -> None:
        rows = self.visible_directory()
        self.render_directory(rows)
        self.set_visible_status(
            len(rows), len(self.directory_rows), "LDAP entries", "directory"
        )

    def refresh_smart_view(self) -> None:
        rows = self.visible_smart_view()
        self.render_smart_view(rows)
        self.set_visible_status(
            len(rows), len(self.smart_view_rows), "smart-view findings", "smart"
        )

    def refresh_current_view(self) -> None:
        if self.view_mode == "directory":
            self.refresh_directory_view()
        elif self.view_mode == "smart":
            self.refresh_smart_view()
        else:
            self.refresh_record_view()

    def sorted_records(self, rows: list[DnsRow]) -> list[DnsRow]:
        return sorted(
            rows,
            key=RECORD_SORT_KEYS[self.sort_field],
            reverse=self.sort_reverse,
        )

    def sort_records(self, field: str) -> None:
        if self.view_mode != "dns":
            self.set_status(
                "Current view is read-only; sorting applies to DNS records."
            )
            return
        if self.sort_field == field:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_field = field
            self.sort_reverse = False
        self.record_rows = self.sorted_records(self.record_rows)
        self.refresh_record_view()
        direction = "desc" if self.sort_reverse else "asc"
        self.set_status(f"Sorted by {field} ({direction}); selection cleared")

    def set_record_selected(self, row_index: int, selected: bool) -> None:
        table = self.query_one("#records", DataTable)
        if row_index < 0 or row_index >= table.row_count:
            return
        if selected:
            self.selected_record_rows.add(row_index)
        else:
            self.selected_record_rows.discard(row_index)
        table.update_cell_at(Coordinate(row_index, 0), "✓" if selected else "")
        table.refresh_row(row_index)

    def clear_record_selection(self) -> None:
        for row_index in list(self.selected_record_rows):
            self.set_record_selected(row_index, False)
        self.visual_selecting = False
        self.selection_anchor = None

    def select_record_range(self, start: int, end: int, *, clear: bool = True) -> None:
        table = self.query_one("#records", DataTable)
        if not table.row_count:
            return
        start = max(0, min(start, table.row_count - 1))
        end = max(0, min(end, table.row_count - 1))
        if clear:
            self.clear_record_selection()
        low, high = sorted((start, end))
        for row_index in range(low, high + 1):
            self.set_record_selected(row_index, True)
        self.set_status(f"Selected {len(self.selected_record_rows)} record(s)")

    def row_to_record(self, row_index: int) -> dict[str, str] | None:
        if self.view_mode != "dns":
            return None
        table = self.query_one("#records", DataTable)
        try:
            row = table.get_row_at(row_index)
        except Exception:
            return None
        if not row:
            return None
        values = [str(cell) for cell in row]
        if len(values) < 4 or values[2] == "-":
            return None
        return {
            "name": values[1],
            "rtype": values[2],
            "value": values[3],
            "ttl": values[4] if len(values) > 4 else "",
        }

    def selected_records(self) -> list[dict[str, str]]:
        row_indices = sorted(self.selected_record_rows) or [
            self.query_one("#records", DataTable).cursor_row
        ]
        records = [self.row_to_record(row_index) for row_index in row_indices]
        return [record for record in records if record]

    def selected_record(self) -> dict[str, str] | None:
        records = self.selected_records()
        return records[0] if len(records) == 1 else None

    async def refresh_current_zone(self) -> None:
        await self.do_command("query", ["@", "ALL"], update_table=True)

    async def action_load_zones(self) -> None:
        await self.load_zones()

    async def open_discover_ad(self, default_domain: str = "") -> bool:
        values = await self.form(
            "Discover AD domain controllers",
            "Uses DNS SRV records. No LDAP bind or new dependency required.",
            [
                (
                    "AD DNS domain",
                    "domain",
                    "example.com",
                    default_domain or self.val("zone"),
                )
            ],
            "Discover",
        )
        if not values:
            return False
        domain = values["domain"] or self.val("zone")
        async with self.busy():
            try:
                services = await asyncio.to_thread(discover_ad_services, domain)
            except ValueError as exc:
                self.report_error(str(exc))
                return False
            controller = preferred_domain_controller(services)
            if controller is None:
                self.report_error(f"No AD SRV records found for {domain}")
                return False
            self.set_val("server", controller.target)
            if not self.val("zone"):
                self.set_val("zone", controller.domain)
            if not self.val("ldap_base"):
                self.set_val("ldap_base", domain_to_base_dn(controller.domain))
            self.refresh_connection_summary()
            self.save_preferences()
            message = (
                f"Discovered {len(services)} AD SRV record(s); "
                f"selected {controller.target}:{controller.port}"
            )
            self.set_status(message)
            self.notify(message)
            return True

    @work
    async def action_discover_ad(self) -> None:
        await self.open_discover_ad(self.discovery_domain_default())

    def ldap_base_default(self) -> str:
        return self.val("ldap_base") or domain_to_base_dn(self.val("zone"))

    def ldap_connection_fields(self, base_dn: str) -> list[FormField]:
        return [
            ("Base DN", "base_dn", "DC=example,DC=com", base_dn),
            (
                "LDAP encryption",
                "ldap_encryption",
                "off | ldaps | starttls",
                self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            ),
            (
                "LDAP compatibility",
                "ldap_compatibility",
                "on | off",
                self.val("ldap_compatibility") or DEFAULT_LDAP_COMPATIBILITY,
            ),
        ]

    def smart_max_rows_field(self) -> FormField:
        return (
            "Max rows",
            "max_rows",
            "500",
            self.val("smart_max_rows") or DEFAULT_SMART_MAX_ROWS,
        )

    def ldap_search_fields(self, default_kind: str = "users") -> list[FormField]:
        return [
            (
                "Search type",
                "kind",
                "users | groups | computers | ous | all",
                default_kind,
            ),
            ("Search text", "text", "name, login, mail, DN fragment", ""),
            *self.ldap_connection_fields(self.ldap_base_default()),
            ("Max rows", "max_rows", "200", "200"),
        ]

    def apply_ldap_connection_values(self, values: dict[str, str]) -> None:
        self.set_val("ldap_base", values["base_dn"])
        self.set_val("ldap_encryption", values["ldap_encryption"])
        self.set_val("ldap_compatibility", values["ldap_compatibility"])
        self.save_preferences()

    async def directory_search_rows(
        self, client: LdapDirectoryClient, kind: str, text: str
    ) -> list[DirectoryRow] | None:
        async with self.busy():
            try:
                return await asyncio.to_thread(client.search, kind, text)
            except ValueError as exc:
                self.report_error(str(exc))
                return None

    async def open_ldap_search(self, default_kind: str = "users") -> None:
        values = await self.form(
            "Search AD directory",
            "Read-only LDAP via ldap3. Password bind requires LDAPS/StartTLS; kerberos uses current ticket.",
            self.ldap_search_fields(default_kind),
            "Search",
        )
        if not values:
            return

        self.apply_ldap_connection_values(values)
        max_rows = bounded_int(values["max_rows"], 200, maximum=1000)
        client = self.ldap_client(values["base_dn"])
        error = client.validation_error()
        if error:
            self.report_error(error)
            return

        rows = await self.directory_search_rows(
            client, values["kind"] or default_kind, values["text"]
        )
        if rows is None:
            return
        self.set_search_text("", refresh=False)
        self.populate_directory(rows[:max_rows])
        self.notify(f"Loaded {min(len(rows), max_rows)} LDAP entries")

    @work
    async def action_ldap_search(self) -> None:
        await self.open_ldap_search()

    @work
    async def action_ldap_search_kind(self, kind: str) -> None:
        await self.open_ldap_search(kind)

    def smart_view_choices(self) -> list[SmartViewChoice]:
        return [
            (view.shortcut, view.view_id, view.source, view.label, view.description)
            for view in SMART_VIEWS
        ]

    def smart_threshold_fields(self, view: SmartViewDefinition) -> list[FormField]:
        fields: list[FormField] = []
        if view.needs_days:
            fields.append(
                (
                    "Stale/inactive days",
                    "days",
                    "90",
                    self.val("smart_days") or DEFAULT_SMART_DAYS,
                )
            )
        if view.needs_disabled_days:
            fields.append(
                (
                    "Disabled cleanup days",
                    "disabled_days",
                    "180",
                    self.val("smart_disabled_days") or DEFAULT_SMART_DISABLED_DAYS,
                )
            )
        if view.needs_never_logged_days:
            fields.append(
                (
                    "Never-logged-in days",
                    "never_logged_days",
                    "30",
                    self.val("smart_never_logged_days")
                    or DEFAULT_SMART_NEVER_LOGGED_DAYS,
                )
            )
        return fields

    def smart_view_fields(self, view: SmartViewDefinition) -> list[FormField]:
        fields = self.smart_threshold_fields(view)
        if view.needs_ldap:
            fields.extend(self.ldap_connection_fields(self.ldap_base_default()))
        fields.append(self.smart_max_rows_field())
        return fields

    async def dns_records_with_failures_for_smart_view(
        self,
    ) -> tuple[dict[str, list[DnsRow]], list[str]] | None:
        if not self.zones:
            await self.load_zones(restore_active_zone=False)
        if not self.zones:
            self.report_error("Load zones before DNS smart views.")
            return None

        records_by_zone: dict[str, list[DnsRow]] = {}
        failures: list[str] = []
        async with self.busy():
            for zone in self.zones:
                code, output = await self.run_samba_zone("query", zone, ["@", "ALL"])
                if code != 0:
                    failures.append(f"{zone}: {output.strip() or 'query failed'}")
                    continue
                records_by_zone[zone] = parse_records(output)
        return records_by_zone, failures

    async def dns_records_for_smart_view(self) -> dict[str, list[DnsRow]] | None:
        result = await self.dns_records_with_failures_for_smart_view()
        if result is None:
            return None
        records_by_zone, failures = result
        if failures:
            self.notify(
                f"Skipped {len(failures)} zone(s) with query errors", severity="error"
            )
        return records_by_zone

    def dns_smart_rows(
        self, view_id: str, records_by_zone: dict[str, list[DnsRow]]
    ) -> list[SmartViewRow]:
        match view_id:
            case "dns_duplicates":
                return dns_duplicate_records(records_by_zone)
            case "dns_a_without_ptr":
                return dns_a_without_ptr(records_by_zone)
            case "dns_ptr_without_a":
                return dns_ptr_without_a(records_by_zone)
            case _:
                return []

    async def refresh_current_smart_view(self) -> None:
        view = SMART_VIEW_BY_ID.get(self.current_smart_view_id)
        if view is None:
            self.refresh_smart_view()
            return
        if view.view_id == FULL_HEALTH_VIEW_ID:
            values = getattr(self, "current_smart_values", {})
            if not values:
                self.refresh_smart_view()
                return
            await self.load_full_health_dashboard(
                values, SmartViewOptions.from_values(values), refreshed=True
            )
            return
        if view.source != "DNS":
            self.refresh_smart_view()
            return
        records_by_zone = await self.dns_records_for_smart_view()
        if records_by_zone is None:
            return
        rows = self.dns_smart_rows(view.view_id, records_by_zone)
        self.populate_smart_view(view.label, rows[: self.current_smart_max_rows])
        self.notify("Refreshed smart-view findings")

    def selected_smart_row(self) -> SmartViewRow | None:
        if self.view_mode != "smart":
            return None
        return self.visible_row_at(self.visible_smart_view(), self.records_cursor_row())

    @work
    async def action_smart_view(self) -> None:
        view_id = await self.push_screen_wait(
            SmartViewPickerScreen(self.smart_view_choices())
        )
        if view_id is None:
            return
        await self.run_smart_view(view_id)

    @work
    async def action_smart_view_shortcut(self, shortcut: str) -> None:
        view = SMART_VIEW_BY_SHORTCUT.get(shortcut)
        if view is None:
            return
        await self.run_smart_view(view.view_id)

    def apply_smart_view_options(
        self, view: SmartViewDefinition, options: SmartViewOptions
    ) -> None:
        if view.needs_days:
            self.set_val("smart_days", str(options.days))
        if view.needs_disabled_days:
            self.set_val("smart_disabled_days", str(options.disabled_days))
        if view.needs_never_logged_days:
            self.set_val("smart_never_logged_days", str(options.never_logged_days))
        self.set_val("smart_max_rows", str(options.max_rows))
        self.save_preferences()

    def populate_smart_view_results(
        self, label: str, rows: list[SmartViewRow], max_rows: int
    ) -> None:
        self.set_search_text("", refresh=False)
        self.populate_smart_view(label, rows[:max_rows])
        self.notify(f"Loaded {min(len(rows), max_rows)} smart-view findings")

    async def ldap_directory_for_smart_view(
        self, view: SmartViewDefinition, values: dict[str, str]
    ) -> list[DirectoryRow] | None:
        self.apply_ldap_connection_values(values)

        client = self.ldap_client(values["base_dn"])
        error = client.validation_error()
        if error:
            self.report_error(error)
            return None

        kind = "computers" if view.view_id == "ldap_stale_computers" else "users"
        return await self.directory_search_rows(client, kind, "")

    def ldap_smart_rows(
        self,
        view_id: str,
        directory_rows: list[DirectoryRow],
        options: SmartViewOptions,
    ) -> list[SmartViewRow]:
        match view_id:
            case "ldap_inactive_users":
                return ldap_inactive_users(directory_rows, days=options.days)
            case "ldap_delete_candidates":
                return ldap_delete_candidate_users(
                    directory_rows,
                    disabled_days=options.disabled_days,
                    never_logged_days=options.never_logged_days,
                )
            case "ldap_stale_computers":
                return ldap_stale_computers(directory_rows, days=options.days)
            case "ldap_users_without_groups":
                return ldap_users_without_groups(directory_rows)
            case _:
                return []

    async def dashboard_ldap_rows(
        self, client: LdapDirectoryClient, kind: str
    ) -> tuple[list[DirectoryRow] | None, str]:
        async with self.busy():
            try:
                return await asyncio.to_thread(client.search, kind, ""), ""
            except ValueError as exc:
                return None, str(exc)

    def dns_dashboard_results(
        self,
        records_by_zone: dict[str, list[DnsRow]],
        failures: list[str],
    ) -> list[SmartViewCheckResult]:
        results = [
            SmartViewCheckResult(
                view_id=view_id,
                label=SMART_VIEW_BY_ID[view_id].label,
                source="DNS",
                rows=self.dns_smart_rows(view_id, records_by_zone),
            )
            for view_id in FULL_HEALTH_DNS_VIEW_IDS
        ]
        if failures:
            results.append(
                SmartViewCheckResult(
                    view_id="dns_zone_queries",
                    label="DNS zone queries",
                    source="DNS",
                    error="; ".join(failures),
                )
            )
        return results

    def ldap_dashboard_results(
        self,
        user_rows: list[DirectoryRow] | None,
        user_error: str,
        computer_rows: list[DirectoryRow] | None,
        computer_error: str,
        options: SmartViewOptions,
    ) -> list[SmartViewCheckResult]:
        results: list[SmartViewCheckResult] = []
        for view_id in FULL_HEALTH_LDAP_VIEW_IDS:
            view = SMART_VIEW_BY_ID[view_id]
            if view_id == "ldap_stale_computers":
                rows = computer_rows
                error = computer_error
            else:
                rows = user_rows
                error = user_error
            results.append(
                SmartViewCheckResult(
                    view_id=view_id,
                    label=view.label,
                    source="LDAP",
                    rows=()
                    if rows is None
                    else self.ldap_smart_rows(view_id, rows, options),
                    error=error,
                )
            )
        return results

    async def load_full_health_dashboard(
        self,
        values: dict[str, str],
        options: SmartViewOptions,
        *,
        refreshed: bool = False,
    ) -> None:
        results: list[SmartViewCheckResult] = []
        dns_result = await self.dns_records_with_failures_for_smart_view()
        if dns_result is None:
            for view_id in FULL_HEALTH_DNS_VIEW_IDS:
                view = SMART_VIEW_BY_ID[view_id]
                results.append(
                    SmartViewCheckResult(
                        view_id=view_id,
                        label=view.label,
                        source="DNS",
                        error="DNS zones are not loaded.",
                    )
                )
        else:
            records_by_zone, failures = dns_result
            results.extend(self.dns_dashboard_results(records_by_zone, failures))

        self.apply_ldap_connection_values(values)
        client = self.ldap_client(values["base_dn"])
        validation_error = client.validation_error()
        if validation_error:
            results.extend(
                SmartViewCheckResult(
                    view_id=view_id,
                    label=SMART_VIEW_BY_ID[view_id].label,
                    source="LDAP",
                    error=validation_error,
                )
                for view_id in FULL_HEALTH_LDAP_VIEW_IDS
            )
        else:
            user_rows, user_error = await self.dashboard_ldap_rows(client, "users")
            computer_rows, computer_error = await self.dashboard_ldap_rows(
                client, "computers"
            )
            results.extend(
                self.ldap_dashboard_results(
                    user_rows, user_error, computer_rows, computer_error, options
                )
            )

        rows = full_health_dashboard_rows(results)
        self.populate_smart_view(
            "Full health dashboard",
            rows[: 1 + len(results) + options.max_rows],
        )
        action = "Refreshed" if refreshed else "Loaded"
        self.notify(f"{action} full health dashboard")

    async def run_smart_view(self, view_id: str) -> None:
        view = SMART_VIEW_BY_ID[view_id]
        values = await self.form(
            view.label,
            f"{view.description}\nRead-only hygiene findings. No deletes/changes are performed.",
            self.smart_view_fields(view),
            "Run",
        )
        if not values:
            return

        options = SmartViewOptions.from_values(values)
        self.apply_smart_view_options(view, options)
        self.current_smart_view_id = view.view_id
        self.current_smart_max_rows = options.max_rows
        self.current_smart_values = values

        if view.view_id == FULL_HEALTH_VIEW_ID:
            await self.load_full_health_dashboard(values, options)
            return

        if view.source == "DNS":
            records_by_zone = await self.dns_records_for_smart_view()
            if records_by_zone is None:
                return
            rows = self.dns_smart_rows(view.view_id, records_by_zone)
            self.populate_smart_view_results(view.label, rows, options.max_rows)
            return

        directory_rows = await self.ldap_directory_for_smart_view(view, values)
        if directory_rows is None:
            return
        rows = self.ldap_smart_rows(view.view_id, directory_rows, options)
        self.populate_smart_view_results(view.label, rows, options.max_rows)

    async def apply_smart_fix(self, row: SmartViewRow) -> None:
        if row.source == "ldap":
            self.notify("LDAP findings are read-only/export-only.", severity="error")
            return
        if row.fix_action != "dns_add_ptr":
            self.notify(
                "No guided fix is available for this finding.", severity="error"
            )
            return
        error = validate_record(row.fix_name, row.fix_rtype, row.fix_value)
        if error:
            self.report_error(error)
            return
        if not await self.confirm(
            "Fix smart finding?\n\n"
            "ADD DNS record\n"
            f"Zone: {row.fix_zone}\n"
            f"{row.fix_name} {row.fix_rtype} {row.fix_value}\n\n"
            f"Finding: {row.finding}\n"
            f"Evidence: {row.evidence}",
            default_confirm=True,
        ):
            self.notify("Fix cancelled")
            return
        async with self.busy():
            code, _ = await self.run_samba_zone(
                "add", row.fix_zone, [row.fix_name, row.fix_rtype, row.fix_value]
            )
        if code != 0:
            return
        self.notify(f"Applied fix: {row.fix_label}")
        await self.refresh_current_smart_view()

    @work
    async def action_fix_smart(self) -> None:
        row = self.selected_smart_row()
        if row is None:
            self.notify("Select a smart-view finding first.", severity="error")
            return
        await self.apply_smart_fix(row)

    async def action_refresh(self) -> None:
        if self.view_mode == "smart":
            await self.refresh_current_smart_view()
            return
        await self.refresh_current_zone()

    @work
    async def action_query(self) -> None:
        values = await self.form(
            "Query DNS",
            "Query one name/type in the currently selected zone.",
            [
                ("Record name", "name", "name, @ = zone root", "@"),
                ("Record type", "rtype", "type, e.g. A or ALL", "ALL"),
            ],
            "Query",
        )
        if not values:
            return
        name = values["name"] or "@"
        rtype = (values["rtype"] or "ALL").upper()
        await self.do_command("query", [name, rtype], update_table=True)

    async def maybe_add_matching_ptr(self, name: str, rtype: str, value: str) -> None:
        if rtype != "A":
            return
        reverse = self.reverse_record_for_ipv4(value)
        auto_ptr = (self.val("auto_ptr") or DEFAULT_AUTO_PTR).casefold()
        if reverse is None or auto_ptr == "off":
            return
        ptr_zone, ptr_name = reverse
        ptr_target = self.ptr_target_for_name(name)
        if auto_ptr == "on" or await self.confirm(
            "Add matching PTR record?\n\n"
            f"Zone: {ptr_zone}\n{ptr_name} PTR {ptr_target}",
            default_confirm=True,
        ):
            await self.add_ptr(name, value)

    def add_record_args(self, name: str, rtype: str, value: str, ttl: str) -> list[str]:
        args = [name, rtype, value]
        if ttl:
            args.append(f"--ttl={ttl}")
        return args

    def record_type_selection_error(self, values: dict[str, str]) -> str | None:
        rtype = (values.get("rtype") or "").upper()
        if rtype in GUIDED_RECORD_TYPES:
            return None
        return f"Choose one of: {', '.join(GUIDED_RECORD_TYPES)}."

    def add_record_type_fields(self, rtype: str) -> list[FormField]:
        return [
            ("Record name", "name", "name, @ for zone root", ""),
            *GUIDED_RECORD_TYPE_FIELDS.get(rtype.upper(), ()),
            ("TTL", "ttl", "optional seconds, e.g. 3600", ""),
        ]

    def add_record_value_from_fields(self, rtype: str, values: dict[str, str]) -> str:
        value_fields = GUIDED_RECORD_VALUE_FIELDS.get(rtype.upper())
        if value_fields is None:
            return values.get("value", "")
        if len(value_fields) == 1:
            return values.get(value_fields[0], "")
        return " ".join(values.get(key, "") for key in value_fields).strip()

    def ttl_error(self, ttl: str) -> str | None:
        if not ttl:
            return None
        if not ttl.isdecimal():
            return "TTL must be whole seconds, e.g. 3600."
        if int(ttl) <= 0:
            return "TTL must be greater than zero."
        return None

    def duplicate_record_error(self, name: str, rtype: str, value: str) -> str | None:
        for row in self.record_rows:
            if row.name == name and row.rtype == rtype and row.value == value:
                return "Duplicate record already exists in the loaded zone view."
        return None

    def guided_add_record_error(self, rtype: str, values: dict[str, str]) -> str | None:
        name = values.get("name", "")
        value = self.add_record_value_from_fields(rtype, values)
        ttl = values.get("ttl", "")
        return (
            validate_record(name, rtype, value)
            or self.ttl_error(ttl)
            or self.duplicate_record_error(name, rtype.upper(), value)
        )

    def existing_reverse_record_for_ipv4(self, ip_value: str) -> tuple[str, str] | None:
        reverse = self.reverse_record_for_ipv4(ip_value)
        if reverse is None:
            return None
        ptr_zone, ptr_name = reverse
        if ptr_zone not in self.zones:
            return None
        return ptr_zone, ptr_name

    def ptr_preview_text(self, name: str, rtype: str, value: str) -> str:
        if rtype != "A":
            return "PTR suggestion: not applicable."
        reverse = self.existing_reverse_record_for_ipv4(value)
        if reverse is None:
            return "PTR suggestion: no loaded reverse zone matches this IPv4 address."
        ptr_zone, ptr_name = reverse
        ptr_target = self.ptr_target_for_name(name)
        return f"PTR suggestion: reverse zone exists; {ptr_zone}: {ptr_name} PTR {ptr_target}"

    def add_record_preview(self, name: str, rtype: str, value: str, ttl: str) -> str:
        args = self.add_record_args(name, rtype, value, ttl)
        client = self.samba_client()
        command = " ".join(
            client.redact_command(client.dns_command("add", self.val("zone"), args))
        )
        return (
            "Add DNS record?\n\n"
            f"Zone: {self.val('zone')}\n"
            f"Record: {name} {rtype} {value}\n"
            f"TTL: {ttl or 'default'}\n"
            f"{self.ptr_preview_text(name, rtype, value)}\n\n"
            f"Command preview: {command}"
        )

    @work
    async def action_add(self) -> None:
        type_values = await self.form(
            "Add DNS record — choose type",
            f"Zone: {self.val('zone')}. Guided flow shows fields for one record type.",
            [
                (
                    "Record type",
                    "rtype",
                    "A / AAAA / CNAME / PTR / TXT / MX / SRV / NS",
                    "A",
                ),
            ],
            "Next",
            self.record_type_selection_error,
        )
        if not type_values:
            return
        rtype = (type_values["rtype"] or "A").upper()
        values = await self.form(
            f"Add {rtype} record",
            "Invalid input is caught before confirmation. Examples are shown in each field.",
            self.add_record_type_fields(rtype),
            "Preview",
            lambda form_values: self.guided_add_record_error(rtype, form_values),
        )
        if not values:
            return
        name = values["name"]
        value = self.add_record_value_from_fields(rtype, values)
        ttl = values["ttl"]
        error = self.guided_add_record_error(rtype, values)
        if error:
            self.report_error(error)
            return
        if not await self.confirm(
            self.add_record_preview(name, rtype, value, ttl),
            default_confirm=True,
        ):
            self.notify("Add cancelled")
            return
        if (
            await self.do_command("add", self.add_record_args(name, rtype, value, ttl))
            == 0
        ):
            await self.maybe_add_matching_ptr(name, rtype, value)
            await self.refresh_current_zone()

    def selected_record_for_update(self) -> dict[str, str] | None:
        records = self.selected_records()
        if len(records) > 1:
            self.notify(
                "Update works on one record only. Select one row.", severity="error"
            )
            return None
        selected = records[0] if records else None
        if selected:
            return selected
        self.notify(
            "Select a real record row first. Rows with type '-' are empty/folder nodes.",
            severity="error",
        )
        return None

    def update_record_fields(self, selected: dict[str, str]) -> list[FormField]:
        return [
            ("Record name", "name", "name, @ for zone root", selected["name"]),
            (
                "Current type (used to find/delete old record)",
                "old_rtype",
                "current type",
                selected["rtype"],
            ),
            (
                "New type",
                "rtype",
                "A / AAAA / CNAME / PTR / TXT / MX / SRV",
                selected["rtype"],
            ),
            (
                "Old/current DNS value (exact match required)",
                "old_value",
                "old/current value",
                selected["value"],
            ),
            ("New DNS value", "value", "new value", selected["value"]),
        ]

    async def change_record_type(
        self, name: str, old_rtype: str, old_value: str, rtype: str, value: str
    ) -> None:
        message = (
            "Change DNS record type?\n\n"
            f"Zone: {self.val('zone')}\n"
            f"DELETE: {name} {old_rtype} {old_value}\n"
            f"ADD:    {name} {rtype} {value}\n\n"
            "If the add fails, the old record may already be deleted."
        )
        if not await self.confirm(message):
            self.notify("Type change cancelled")
            return
        if (
            await self.do_command("delete", [name, old_rtype, old_value]) == 0
            and await self.do_command("add", [name, rtype, value]) == 0
        ):
            await self.refresh_current_zone()

    async def update_record_value(
        self, name: str, rtype: str, old_value: str, value: str
    ) -> None:
        if not await self.confirm(
            f"Update DNS record?\n\nZone: {self.val('zone')}\n{name} {rtype}\nOld: {old_value}\nNew: {value}"
        ):
            self.notify("Update cancelled")
            return
        if await self.do_command("update", [name, rtype, old_value, value]) == 0:
            await self.refresh_current_zone()

    @work
    async def action_update(self) -> None:
        selected = self.selected_record_for_update()
        if selected is None:
            return
        values = await self.form(
            "Update selected DNS record",
            "To change record type (example A -> CNAME), set New type. That will DELETE the old record, then ADD the new one.",
            self.update_record_fields(selected),
            "Update",
        )
        if not values:
            return
        name = values["name"]
        old_rtype = (values["old_rtype"] or selected["rtype"]).upper()
        rtype = (values["rtype"] or old_rtype).upper()
        old_value = values["old_value"]
        value = values["value"]
        error = validate_record(
            name, old_rtype, "", require_value=False
        ) or validate_record(name, rtype, value)
        if error:
            self.report_error(error)
            return

        if old_rtype != rtype:
            await self.change_record_type(name, old_rtype, old_value, rtype, value)
            return
        await self.update_record_value(name, rtype, old_value, value)

    @work
    async def action_delete(self) -> None:
        records = self.selected_records()
        if not records:
            self.notify(
                "Select one or more real record rows first. Rows with type '-' are empty/folder nodes.",
                severity="error",
            )
            return
        preview = "\n".join(
            f"{record['name']} {record['rtype']} {record['value']}"
            for record in records[:12]
        )
        if len(records) > 12:
            preview += f"\n... and {len(records) - 12} more"
        if not await self.confirm(
            f"DELETE {len(records)} selected DNS record(s)?\n\nZone: {self.val('zone')}\n{preview}\n\nThis cannot be undone from this app."
        ):
            self.notify("Delete cancelled")
            return
        failed = 0
        for record in records:
            code = await self.do_command(
                "delete", [record["name"], record["rtype"], record["value"]]
            )
            if code != 0:
                failed += 1
        if failed:
            self.notify(f"Deleted with {failed} failure(s)", severity="error")
        await self.refresh_current_zone()

    def sync_inline_search_input(self) -> None:
        with suppress(Exception):
            search = self.query_one("#inline_search", Input)
            if search.value == self.search_text:
                return
            self._syncing_search_input = True
            try:
                search.value = self.search_text
            finally:
                self._syncing_search_input = False

    def set_search_text(self, text: str, *, refresh: bool = True) -> None:
        self.search_text = text
        self.sync_inline_search_input()
        if refresh:
            self.refresh_current_view()

    def action_search(self) -> None:
        self.pending_g = False
        search = self.query_one("#inline_search", Input)
        search.focus()
        self.set_status(
            "Inline search: type to filter; Esc clears, Enter returns to table"
        )

    def focused_table(self) -> DataTable | None:
        focused = self.focused
        return focused if isinstance(focused, DataTable) else None

    def action_focus_zones(self) -> None:
        self.pending_g = False
        self.query_one("#zones", DataTable).focus()

    def action_focus_records(self) -> None:
        self.pending_g = False
        self.query_one("#records", DataTable).focus()

    def action_next_table(self) -> None:
        table = self.focused_table()
        if table and table.id == "zones":
            self.action_focus_records()
        else:
            self.action_focus_zones()

    def action_previous_table(self) -> None:
        table = self.focused_table()
        if table and table.id == "records":
            self.action_focus_zones()
        else:
            self.action_focus_records()

    def action_next_side_tab(self) -> None:
        self.switch_side_tab(1)

    def action_previous_side_tab(self) -> None:
        self.switch_side_tab(-1)

    def switch_side_tab(self, delta: int) -> None:
        tabs = self.query_one("#side_tabs", TabbedContent)
        current = tabs.active if tabs.active in SIDE_TAB_IDS else "dns_tab"
        current_index = SIDE_TAB_IDS.index(current)
        tabs.active = SIDE_TAB_IDS[(current_index + delta) % len(SIDE_TAB_IDS)]
        self.refresh_key_hints()
        if tabs.active == "dns_tab":
            self.action_focus_zones()
        else:
            self.action_focus_records()

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated
    ) -> None:
        if event.tabbed_content.id == "side_tabs":
            self.refresh_key_hints()

    def action_sort_name(self) -> None:
        self.sort_records("name")

    def action_sort_type(self) -> None:
        self.sort_records("type")

    def action_sort_value(self) -> None:
        self.sort_records("value")

    def update_visual_selection(self) -> None:
        if not self.visual_selecting or self.selection_anchor is None:
            return
        table = self.query_one("#records", DataTable)
        if self.focused_table() is table:
            self.select_record_range(self.selection_anchor, table.cursor_row)

    def active_table(self) -> DataTable:
        return self.focused_table() or self.query_one("#records", DataTable)

    def page_rows(self, table: DataTable) -> int:
        height = getattr(table.size, "height", 0)
        return max(1, height - 3) if height else 10

    def move_cursor_by(self, delta: int) -> None:
        table = self.active_table()
        if not table.row_count:
            return
        row = max(0, min(table.cursor_row + delta, table.row_count - 1))
        table.move_cursor(row=row)
        self.update_visual_selection()
        self.update_details_pane()

    def action_cursor_down(self) -> None:
        self.pending_g = False
        self.move_cursor_by(1)

    def action_cursor_up(self) -> None:
        self.pending_g = False
        self.move_cursor_by(-1)

    def action_cursor_page_down(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(self.page_rows(table))

    def action_cursor_page_up(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(-self.page_rows(table))

    def action_cursor_half_page_down(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(max(1, self.page_rows(table) // 2))

    def action_cursor_half_page_up(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(-max(1, self.page_rows(table) // 2))

    def action_cursor_top(self) -> None:
        self.pending_g = False
        table = self.active_table()
        table.move_cursor(row=0)
        self.update_visual_selection()
        self.update_details_pane()

    def action_cursor_bottom(self) -> None:
        self.pending_g = False
        table = self.active_table()
        if table.row_count:
            table.move_cursor(row=table.row_count - 1)
            self.update_visual_selection()
            self.update_details_pane()

    def ensure_dns_records_view(self) -> bool:
        if self.view_mode == "dns":
            return True
        self.set_status("Current view is read-only.")
        return False

    def action_toggle_select(self) -> None:
        self.pending_g = False
        table = self.focused_table() or self.query_one("#records", DataTable)
        if table.id != "records" or not table.row_count:
            return
        if not self.ensure_dns_records_view():
            return
        row_index = table.cursor_row
        self.selection_anchor = (
            row_index if self.selection_anchor is None else self.selection_anchor
        )
        self.set_record_selected(row_index, row_index not in self.selected_record_rows)
        self.set_status(f"Selected {len(self.selected_record_rows)} record(s)")

    def action_visual_select(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not table.row_count:
            return
        if not self.ensure_dns_records_view():
            return
        if self.visual_selecting:
            self.visual_selecting = False
            self.set_status(
                f"Visual selection off; selected {len(self.selected_record_rows)} record(s)"
            )
            return
        self.visual_selecting = True
        self.selection_anchor = table.cursor_row
        self.select_record_range(table.cursor_row, table.cursor_row)
        self.set_status("Visual selection on: use j/k, then d to delete selected")

    def action_select_range(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not table.row_count:
            return
        if not self.ensure_dns_records_view():
            return
        if self.selection_anchor is None:
            self.selection_anchor = table.cursor_row
        self.select_record_range(self.selection_anchor, table.cursor_row)

    def action_extend_up(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not self.ensure_dns_records_view():
            return
        if self.selection_anchor is None:
            self.selection_anchor = table.cursor_row
        self.move_cursor_by(-1)
        self.select_record_range(self.selection_anchor, table.cursor_row)

    def action_extend_down(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not self.ensure_dns_records_view():
            return
        if self.selection_anchor is None:
            self.selection_anchor = table.cursor_row
        self.move_cursor_by(1)
        self.select_record_range(self.selection_anchor, table.cursor_row)

    def action_clear_navigation_state(self) -> None:
        self.pending_g = False
        if self.focused_inline_search():
            if self.search_text:
                self.set_search_text("")
                self.action_focus_records()
                self.set_status("Search cleared")
                return
            self.action_focus_records()
            self.set_status("Search closed")
            return
        if self.visual_selecting:
            self.visual_selecting = False
            self.set_status(
                f"Visual selection off; selected {len(self.selected_record_rows)} record(s)"
            )
            return
        if self.selected_record_rows:
            self.clear_record_selection()
            self.set_status("Selection cleared")
            return
        if self.search_text:
            self.set_search_text("")
            self.set_status("Search cleared")
            return
        self.action_focus_records()

    async def action_activate_row(self) -> None:
        self.pending_g = False
        table = self.focused_table()
        if table and table.id == "records":
            if self.view_mode == "smart":
                self.action_fix_smart()
            else:
                self.action_toggle_select()
            return
        if table and table.id == "zones":
            try:
                row = table.get_row_at(table.cursor_row)
            except Exception:
                return
            if row:
                await self.activate_zone(str(row[0]))

    async def on_key(self, event: Any) -> None:
        if self.handle_inline_search_key(event):
            event.prevent_default()
            event.stop()
            return
        if self.should_ignore_key_event(event):
            return
        handled = await self.handle_key(event.key, getattr(event, "character", None))
        if handled:
            event.prevent_default()
            event.stop()

    def focused_inline_search(self) -> bool:
        return isinstance(self.focused, Input) and self.focused.id == "inline_search"

    def handle_inline_search_key(self, event: Any) -> bool:
        if not self.focused_inline_search():
            return False
        if event.key == "escape":
            self.action_clear_navigation_state()
            return True
        if event.key == "enter":
            self.action_focus_records()
            self.set_status("Search kept; press Esc to clear it")
            return True
        return False

    def should_ignore_key_event(self, event: Any) -> bool:
        if isinstance(self.focused, Input):
            return True
        return isinstance(self.focused, Button) and event.key in {"enter", "space"}

    async def handle_key(self, key: str, char: str | None) -> bool:
        char_lower = char.casefold() if char else ""
        if char_lower != "g":
            self.pending_g = False
        if await self.handle_case_sensitive_key(char):
            return True
        if self.handle_smart_view_shortcut(char_lower):
            return True
        if self.handle_g_key(char, char_lower):
            return True
        if await self.handle_mapped_key(key, char_lower):
            return True
        self.pending_g = False
        return False

    async def handle_case_sensitive_key(self, char: str | None) -> bool:
        action_name = CASE_SENSITIVE_ACTION_NAMES.get(char or "")
        if action_name is None:
            return False
        await self.invoke_action(action_name)
        return True

    def handle_smart_view_shortcut(self, char_lower: str) -> bool:
        if char_lower not in SMART_VIEW_BY_SHORTCUT:
            return False
        self.action_smart_view_shortcut(char_lower)
        return True

    def handle_g_key(self, char: str | None, char_lower: str) -> bool:
        if char_lower != "g":
            return False
        if char == "G":
            self.action_cursor_bottom()
        elif self.pending_g:
            self.action_cursor_top()
        else:
            self.pending_g = True
            self.set_status("g pressed: press g again for top; G goes bottom")
        return True

    async def handle_mapped_key(self, key: str, char_lower: str) -> bool:
        action_name = KEY_ACTION_NAMES.get(key) or CHAR_ACTION_NAMES.get(char_lower)
        if action_name is None:
            return False
        await self.invoke_action(action_name)
        return True

    async def invoke_action(self, action_name: str, *args: Any) -> None:
        result = getattr(self, action_name)(*args)
        if inspect.isawaitable(result):
            await result

    async def run_sidebar_button_action(self, button_id: str | None) -> bool:
        action = SIDEBAR_ACTIONS.get(button_id or "")
        if action is None:
            return False
        action_name, args = action
        await self.invoke_action(action_name, *args)
        return True

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        await self.run_sidebar_button_action(event.button.id)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "inline_search":
            return
        event.stop()
        if getattr(self, "_syncing_search_input", False):
            return
        self.search_text = event.value
        self.refresh_current_view()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "records":
            self.update_details_pane()

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "zones":
            return
        row = event.data_table.get_row_at(event.cursor_row)
        if not row:
            return
        zone = str(row[0])
        if zone not in self.zones:
            self.set_status(DNS_EMPTY_STATE[1])
            return
        await self.activate_zone(zone)

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        if event.data_table.id != "records":
            return
        match event.column_index:
            case 1:
                self.sort_records("name")
            case 2:
                self.sort_records("type")
            case 3:
                self.sort_records("value")


def main() -> None:
    SambatuiApp().run()


if __name__ == "__main__":
    main()
