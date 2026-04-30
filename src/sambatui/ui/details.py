from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

from sambatui.ldap_directory import DirectoryRow
from sambatui.models import DnsRow
from sambatui.smart_views import SmartViewRow

LDAP_DETAIL_ATTRIBUTES = (
    "sAMAccountName",
    "userPrincipalName",
    "mail",
    "description",
    "memberOf",
    "member",
    "userAccountControl",
    "lastLogonTimestamp",
    "whenCreated",
    "whenChanged",
    "dNSHostName",
    "servicePrincipalName",
)


def detail_text(title: str, fields: Iterable[tuple[str, str]]) -> str:
    lines = [title]
    for label, value in fields:
        lines.append(f"{label}: {value.strip() or '—'}")
    return "\n".join(lines)


def details_empty_text(empty_state: tuple[str, str]) -> str:
    title, hint = empty_state
    return detail_text("Details", (("Status", title), ("Next", hint)))


def dns_ptr_status(
    row: DnsRow,
    *,
    zones: Sequence[str],
    reverse_record_for_ipv4: Callable[[str], tuple[str, str] | None],
    ptr_target_for_name: Callable[[str], str],
) -> str:
    rtype = row.rtype.upper()
    if rtype == "A":
        reverse = reverse_record_for_ipv4(row.value)
        if reverse is None:
            return "unknown for this value"
        ptr_zone, ptr_name = reverse
        target = ptr_target_for_name(row.name)
        status = f"expected {ptr_name}.{ptr_zone} PTR {target}"
        if ptr_zone in zones:
            return f"{status}; query reverse zone to verify"
        return f"{status}; reverse zone not loaded"
    if rtype == "PTR":
        return f"points to {row.value}" if row.value else "PTR target unavailable"
    return "not applicable"


def dns_details_text(
    row: DnsRow,
    *,
    zone: str,
    ptr_status: str,
) -> str:
    return detail_text(
        "DNS details",
        (
            ("Name", row.name),
            ("Type", row.rtype),
            ("Value", row.value),
            ("Zone", zone),
            ("TTL", row.ttl),
            ("PTR status", ptr_status),
            ("Records", row.records),
            ("Children", row.children),
        ),
    )


def attribute_detail_value(values: Iterable[str]) -> str:
    items = [value for value in values if value]
    if not items:
        return ""
    shown = "; ".join(items[:3])
    remaining = len(items) - 3
    return f"{shown}; … (+{remaining} more)" if remaining > 0 else shown


def directory_details_text(row: DirectoryRow) -> str:
    fields = [
        ("Name", row.name),
        ("Kind", row.kind),
        ("Summary", row.summary),
        ("DN", row.dn),
    ]
    for attribute in LDAP_DETAIL_ATTRIBUTES:
        value = attribute_detail_value(row.attributes.get(attribute, ()))
        if value:
            fields.append((attribute, value))
    return detail_text("LDAP details", fields)


def smart_details_text(row: SmartViewRow) -> str:
    remediation = "Manual review only"
    if row.fix_action:
        remediation = f"Press f to {row.fix_label}"
    elif row.source == "ldap":
        remediation = "LDAP findings are read-only/export-only"
    return detail_text(
        "Smart-view details",
        (
            ("Severity", row.severity),
            ("Object", row.object),
            ("Finding", row.finding),
            ("Evidence", row.evidence),
            ("Suggested action", row.suggested_action),
            ("Remediation", remediation),
            ("Source", row.source),
        ),
    )
