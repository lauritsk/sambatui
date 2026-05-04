from __future__ import annotations

import re
from collections.abc import Callable
from typing import TypeVar

from ..smart_views import (
    SmartViewRow,
    dns_a_without_ptr,
    dns_duplicate_records,
    dns_ptr_without_a,
)

TableRow = TypeVar("TableRow")

DIRECTORY_SORT_LABELS = {"type": "kind", "value": "summary"}
SMART_SORT_LABELS = {"name": "object", "type": "finding", "value": "evidence"}
SEVERITY_RANK = {"error": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
AGE_RE = re.compile(r"(\d+)\s+day")
SMART_DEFAULT_SORTS = {
    "dns_duplicates": ("severity", False),
    "dns_a_without_ptr": ("severity", False),
    "dns_ptr_without_a": ("severity", False),
    "ldap_inactive_users": ("age", True),
    "ldap_delete_candidates": ("age", True),
    "ldap_stale_computers": ("age", True),
    "ldap_users_without_groups": ("object", False),
}


def smart_age_sort_key(row: SmartViewRow) -> str:
    match = AGE_RE.search(row.evidence)
    days = int(match.group(1)) if match else -1
    return f"{days:010d}"


SMART_SORT_KEYS: dict[str, Callable[[SmartViewRow], str]] = {
    "severity": lambda row: (
        f"{SEVERITY_RANK.get(row.severity.casefold(), 99):02d}:{row.object.casefold()}"
    ),
    "object": lambda row: row.object.casefold(),
    "name": lambda row: row.object.casefold(),
    "finding": lambda row: row.finding.casefold(),
    "type": lambda row: row.finding.casefold(),
    "evidence": lambda row: row.evidence.casefold(),
    "value": lambda row: row.evidence.casefold(),
    "action": lambda row: row.suggested_action.casefold(),
    "source": lambda row: row.source.casefold(),
    "age": smart_age_sort_key,
}
DNS_SMART_ROW_BUILDERS = {
    "dns_duplicates": dns_duplicate_records,
    "dns_a_without_ptr": dns_a_without_ptr,
    "dns_ptr_without_a": dns_ptr_without_a,
}


def setup_auth_values(auth: str, kerberos: str) -> tuple[str, str]:
    if auth.casefold() == "kerberos" and kerberos.casefold() == "off":
        return auth, "required"
    return auth, kerberos


def directory_sort_label(field: str) -> str:
    return DIRECTORY_SORT_LABELS.get(field, field)


def smart_sort_label(field: str) -> str:
    return SMART_SORT_LABELS.get(field, field)


def ldap_limit_suffix(row_count: int, limit: int) -> str:
    if row_count < limit:
        return ""
    return " — limit reached; press m to load more"


def next_sort_state(
    current_field: str, current_reverse: bool, requested_field: str
) -> tuple[str, bool]:
    if current_field == requested_field:
        return requested_field, not current_reverse
    return requested_field, False


def sort_direction(reverse: bool) -> str:
    if reverse:
        return "desc"
    return "asc"
