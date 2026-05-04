from __future__ import annotations

from textual.app import App

from .client import SambaToolClient, SambaToolConfig, parse_samba_options
from .config import (
    password_file_warning,
    read_password_file,
)
from .dns import (
    NAME_RE,
    REC_RE,
    parse_records,
    parse_zones,
    valid_dns_name,
    validate_record,
)
from .ldap_sidebar import (
    ldap_structure_labels,
    ldap_structure_nodes,
    split_ldap_dn,
)
from .models import DnsRow
from .remediation import actionable_error
from .screens import (
    CommandPaletteScreen,
    ConfirmScreen,
    FormField,
    FormScreen,
    HelpScreen,
    SmartViewPickerScreen,
)
from .smart_view_catalog import (
    SMART_VIEW_LABELS,
)
from .ui.styles import APP_CSS
from .app_layout import AppLayoutMixin
from .app_navigation import AppNavigationMixin
from .controllers import (
    AppCoreMixin,
    AppDnsActionsMixin,
    AppLdapActionsMixin,
    AppSetupMixin,
    AppSmartActionsMixin,
    AppViewsMixin,
)
from .app_constants import (
    DEFAULT_AUTH,
    DEFAULT_AUTO_PTR,
    DEFAULT_CONFIGFILE,
    DEFAULT_DOMAIN,
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


__all__ = [
    "DEFAULT_AUTH",
    "DEFAULT_AUTO_PTR",
    "DEFAULT_CONFIGFILE",
    "DEFAULT_DOMAIN",
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
    "ldap_structure_labels",
    "ldap_structure_nodes",
    "split_ldap_dn",
]


class SambatuiApp(
    AppCoreMixin,
    AppSetupMixin,
    AppViewsMixin,
    AppLdapActionsMixin,
    AppSmartActionsMixin,
    AppDnsActionsMixin,
    AppLayoutMixin,
    AppNavigationMixin,
    App,
):
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
        ("m", "load_more_directory", "Load more LDAP"),
        ("slash", "search", "Search"),
        ("n", "sort_name", "Sort name"),
        ("t", "sort_type", "Sort type"),
        ("e", "sort_value", "Sort value"),
        ("ctrl+q", "quit", "Quit"),
    ]


def main() -> None:
    SambatuiApp().run()


if __name__ == "__main__":
    main()
