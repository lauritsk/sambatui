from __future__ import annotations

from collections.abc import Iterable

from sambatui.core.models import DnsRow
from sambatui.ldap.rows import DirectoryRow
from sambatui.smart_view_catalog import all_smart_view_shortcut_range
from sambatui.smart_views import SmartViewRow

DNS_COLUMNS = ("Select", "Risk", "Name", "Type", "Value", "TTL")
DIRECTORY_COLUMNS = ("Select", "Risk", "Name", "Kind", "Summary")
SMART_COLUMNS = ("Select", "Severity", "Object", "Finding")

type RowValues = tuple[str, ...]

DNS_EMPTY_STATE = (
    "No DNS records shown",
    "Press z to load zones, select zone, then q to query; a adds record.",
)
LDAP_EMPTY_STATE = (
    "No LDAP entries shown",
    "Press L to search directory; check Base DN, text, max rows.",
)
SMART_EMPTY_STATE = (
    "No findings shown",
    f"Press S to pick a DNS/LDAP finding or {all_smart_view_shortcut_range()} for shortcuts; / filters findings.",
)


def dns_result_values(row: DnsRow) -> RowValues:
    return row.name, row.rtype, row.value, row.ttl


def directory_result_values(row: DirectoryRow) -> RowValues:
    return row.name, row.kind, row.summary


def smart_result_values(row: SmartViewRow) -> RowValues:
    return row.severity, row.object, row.finding


def dns_search_values(row: DnsRow) -> RowValues:
    return row.name, row.rtype, row.value


def directory_search_values(row: DirectoryRow) -> RowValues:
    return row.name, row.kind, row.summary, row.dn


def smart_search_values(row: SmartViewRow) -> RowValues:
    return (
        row.severity,
        row.object,
        row.finding,
        row.evidence,
        row.suggested_action,
        row.source,
        row.fix_label,
    )


EMPTY_STATE_BY_VIEW_MODE = {
    "dns": DNS_EMPTY_STATE,
    "directory": LDAP_EMPTY_STATE,
    "smart": SMART_EMPTY_STATE,
}
UNKNOWN_EMPTY_STATE = (
    "No active records view",
    "Switch to DNS, LDAP, or a finding filter to show rows.",
)


def empty_state_text(view_mode: str, search_text: str = "") -> tuple[str, str]:
    if search_text:
        return (
            "No matches",
            f"Esc clears /{search_text}/; / changes search text.",
        )
    return EMPTY_STATE_BY_VIEW_MODE.get(view_mode, UNKNOWN_EMPTY_STATE)


def matches_search(values: Iterable[str], search_text: str) -> bool:
    needle = search_text.casefold()
    return any(needle in value.casefold() for value in values)
