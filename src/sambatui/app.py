from __future__ import annotations

import os

from textual.app import App

from .app_actions import APP_BINDINGS
from .samba.client import SambaToolClient, SambaToolConfig, parse_samba_options
from .core.config import (
    password_file_warning,
    read_password_file,
)
from .dns.parsing import NAME_RE, REC_RE, parse_records, parse_zones
from .dns.validation import valid_dns_name, validate_record
from .ldap.sidebar import (
    ldap_structure_labels,
    ldap_structure_nodes,
    split_ldap_dn,
)
from .core.models import DnsRow
from .core.remediation import actionable_error
from .ui.screens import (
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

    BINDINGS = APP_BINDINGS

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # ANSI themes use the terminal's own foreground, background, and palette.
        # Keep Textual's standard override available for users who prefer a theme.
        requested_theme = os.getenv("SAMBATUI_THEME") or os.getenv("TEXTUAL_THEME")
        self.theme = (
            requested_theme
            if requested_theme in self.available_themes
            else "ansi-dark"
        )


def main() -> None:
    SambatuiApp().run()


if __name__ == "__main__":
    main()
