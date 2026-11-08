from __future__ import annotations

from collections.abc import Callable

from .app_actions import (
    shortcut_for,
)
from .core.models import DnsRow
from .dns.record_types import DNS_RECORD_TYPE_SPECS, SUPPORTED_DNS_RECORD_TYPES
from .ldap.rows import DirectoryRow
from .smart_view_catalog import (
    SmartViewSource,
    all_smart_view_shortcut_range,
    smart_view_shortcut_range,
)

DNS_FINDING_SHORTCUTS = smart_view_shortcut_range(SmartViewSource.DNS)
LDAP_FINDING_SHORTCUTS = smart_view_shortcut_range(SmartViewSource.LDAP)
ALL_FINDING_SHORTCUTS = all_smart_view_shortcut_range()
DASHBOARD_FINDING_SHORTCUT = smart_view_shortcut_range(SmartViewSource.FULL)
KEY_HINTS = {
    "dns_tab": (
        f"DNS:  {shortcut_for('open_command_palette')} Commands   "
        f"{shortcut_for('filter_results')} Search   "
        f"{shortcut_for('add_record')} Add   "
        f"{shortcut_for('update_record')} Edit   "
        f"{shortcut_for('delete_records')} Delete   "
        f"{shortcut_for('refresh')} Refresh   "
        f"{shortcut_for('help')} Help"
    ),
    "ldap_tab": (
        f"LDAP:  {shortcut_for('open_command_palette')} Commands   "
        f"{shortcut_for('ldap_search')} Search LDAP   "
        f"{shortcut_for('add_record')} Add   "
        f"{shortcut_for('update_record')} Edit   "
        f"{shortcut_for('delete_records')} Delete   "
        f"{shortcut_for('refresh')} Refresh   "
        f"{shortcut_for('help')} Help"
    ),
}
SIDE_TAB_IDS = ("dns_tab", "ldap_tab")
RECORD_SORT_KEYS: dict[str, Callable[[DnsRow], str]] = {
    "name": lambda row: row.name.casefold(),
    "type": lambda row: row.rtype.casefold(),
    "value": lambda row: row.value.casefold(),
}
DIRECTORY_SORT_KEYS: dict[str, Callable[[DirectoryRow], str]] = {
    "name": lambda row: row.name.casefold(),
    "type": lambda row: row.kind.casefold(),
    "value": lambda row: row.summary.casefold(),
}
LDAP_DEFAULT_MAX_ROWS = 200
LDAP_LOAD_MORE_ROWS = 200
LDAP_MAX_ROWS = 5000
GUIDED_RECORD_TYPES = SUPPORTED_DNS_RECORD_TYPES
GUIDED_RECORD_TYPE_FIELDS = {
    rtype: spec.fields for rtype, spec in DNS_RECORD_TYPE_SPECS.items()
}
GUIDED_RECORD_VALUE_FIELDS = {
    rtype: spec.value_fields for rtype, spec in DNS_RECORD_TYPE_SPECS.items()
}
