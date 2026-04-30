from __future__ import annotations

from collections.abc import Iterable
from typing import TypeAlias

from sambatui.ldap_directory import DirectoryRow
from sambatui.models import DnsRow
from sambatui.smart_views import SmartViewRow

DNS_COLUMNS = ("✓", "Name", "Type", "Value", "TTL", "Records", "Children")
DIRECTORY_COLUMNS = ("✓", "Name", "Kind", "Summary", "", "", "DN")
SMART_COLUMNS = (
    "✓",
    "Severity",
    "Object",
    "Finding",
    "Evidence",
    "Suggested action",
    "Source",
)

RowValues: TypeAlias = tuple[str, ...]

DNS_EMPTY_STATE = (
    "No DNS records shown",
    "Press z to load zones, select zone, then q to query; a adds record.",
)
LDAP_EMPTY_STATE = (
    "No LDAP entries shown",
    "Press L to search directory; check Base DN, text, max rows.",
)
SMART_EMPTY_STATE = (
    "No smart-view findings shown",
    "Press S to pick view or 1-7 quick run; / filters findings.",
)


def dns_result_values(row: DnsRow) -> RowValues:
    return row.name, row.rtype, row.value, row.ttl, row.records, row.children


def directory_result_values(row: DirectoryRow) -> RowValues:
    return row.name, row.kind, row.summary, "", "", row.dn


def smart_fix_hint(row: SmartViewRow) -> str:
    if row.fix_action:
        return f"{row.suggested_action} Fix: press f to {row.fix_label}."
    if row.source == "ldap":
        return f"{row.suggested_action} LDAP findings are read-only/export-only."
    return row.suggested_action


def smart_result_values(row: SmartViewRow) -> RowValues:
    return (
        row.severity,
        row.object,
        row.finding,
        row.evidence,
        smart_fix_hint(row),
        row.source,
    )


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


def empty_state_text(view_mode: str, search_text: str = "") -> tuple[str, str]:
    if search_text:
        return (
            "No matches",
            f"Esc clears /{search_text}/; / changes search text.",
        )
    if view_mode == "directory":
        return LDAP_EMPTY_STATE
    if view_mode == "smart":
        return SMART_EMPTY_STATE
    return DNS_EMPTY_STATE


def matches_search(values: Iterable[str], search_text: str) -> bool:
    needle = search_text.casefold()
    return any(needle in value.casefold() for value in values)
