from __future__ import annotations

from collections.abc import Callable
from typing import Any

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
)
from .models import DnsRow
from .screens import CommandPaletteChoice, FormField
from .smart_view_catalog import SMART_VIEWS

KEY_HINTS = {
    "dns_tab": "DNS: ? help  Ctrl+P palette  w setup  Ctrl+O connection  z zones  c discover  S smart  q query  a add  u update  d delete  / filter",
    "ldap_tab": "LDAP: ? help  Ctrl+P palette  w setup  Ctrl+O connection  c discover  L search  m load more  S smart  / filter  j/k move  r refresh",
    "smart_tab": "Smart: ? help  Ctrl+P palette  w setup  Ctrl+O connection  S pick view  1-8 quick run  f fix DNS finding  / filter  r refresh",
}
SIDE_TAB_IDS = ("dns_tab", "ldap_tab", "smart_tab")
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
LDAP_DEFAULT_MAX_ROWS = 200
LDAP_LOAD_MORE_ROWS = 200
LDAP_MAX_ROWS = 5000
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
    "m": "action_load_more_directory",
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
        "ldap_load_more",
        "Load more LDAP entries",
        "m",
        "Rerun the last LDAP search with 200 more rows.",
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
    "ldap_load_more": ("action_load_more_directory", ()),
    "smart_view_picker": ("action_smart_view", ()),
    **{
        f"smart_view_{view.shortcut}": ("action_smart_view_shortcut", (view.shortcut,))
        for view in SMART_VIEWS
    },
    "fix_smart": ("action_fix_smart", ()),
}
