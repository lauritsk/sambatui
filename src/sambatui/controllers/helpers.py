from __future__ import annotations

from typing import TypeVar

from ..smart_views import dns_a_without_ptr, dns_duplicate_records, dns_ptr_without_a

TableRow = TypeVar("TableRow")

DIRECTORY_SORT_LABELS = {"type": "kind", "value": "summary"}
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
