from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import ipaddress

import dns.exception
import dns.name
import dns.reversename

from .dns import reverse_record_for_ipv4
from .ldap_directory import DirectoryRow
from .models import DnsRow

ACCOUNTDISABLE = 0x0002


@dataclass(frozen=True)
class SmartViewRow:
    severity: str
    object: str
    finding: str
    evidence: str
    suggested_action: str
    source: str
    fix_action: str = ""
    fix_label: str = ""
    fix_zone: str = ""
    fix_name: str = ""
    fix_rtype: str = ""
    fix_value: str = ""


@dataclass(frozen=True)
class DnsRecordRef:
    zone: str
    row: DnsRow

    @property
    def name(self) -> str:
        return self.row.name

    @property
    def rtype(self) -> str:
        return self.row.rtype.upper()

    @property
    def value(self) -> str:
        return self.row.value

    @property
    def fqdn(self) -> str:
        return dns_fqdn(self.row.name, self.zone)


def dns_duplicate_records(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> list[SmartViewRow]:
    findings: list[SmartViewRow] = []
    buckets: dict[tuple[str, str, str, str], list[DnsRecordRef]] = defaultdict(list)
    by_name: dict[tuple[str, str], list[DnsRecordRef]] = defaultdict(list)

    for record in iter_dns_records(records_by_zone):
        if record.rtype == "-":
            continue
        key = (
            normalize_dns_name(record.zone),
            normalize_dns_name(record.name),
            record.rtype,
            normalize_dns_value(record.value),
        )
        buckets[key].append(record)
        by_name[
            (normalize_dns_name(record.zone), normalize_dns_name(record.name))
        ].append(record)

    for (_zone, name, rtype, value), duplicates in sorted(buckets.items()):
        if len(duplicates) < 2:
            continue
        first = duplicates[0]
        findings.append(
            SmartViewRow(
                severity="medium",
                object=f"{first.zone}:{first.name}",
                finding="Duplicate DNS record",
                evidence=f"{len(duplicates)} identical {rtype} record(s): {value}",
                suggested_action="Remove duplicate copies; keep one valid record.",
                source="dns",
            )
        )

    for (_zone, _name), records in sorted(by_name.items()):
        types = {record.rtype for record in records}
        if "CNAME" not in types or len(types) == 1:
            continue
        first = records[0]
        findings.append(
            SmartViewRow(
                severity="high",
                object=f"{first.zone}:{first.name}",
                finding="CNAME conflicts with other records",
                evidence=f"Types on same name: {', '.join(sorted(types))}",
                suggested_action="Keep CNAME alone or replace it with address/alias records.",
                source="dns",
            )
        )

    return findings


def dns_a_without_ptr(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> list[SmartViewRow]:
    zones = tuple(records_by_zone)
    zone_names = {normalize_dns_name(zone) for zone in zones}
    ptr_targets = ptr_targets_by_reverse_key(records_by_zone)
    findings: list[SmartViewRow] = []

    for record in iter_dns_records(records_by_zone):
        if record.rtype != "A":
            continue
        try:
            ipaddress.IPv4Address(record.value)
        except ValueError:
            continue
        expected = reverse_record_for_ipv4(record.value, zones)
        if expected is None:
            continue
        ptr_zone, ptr_name = expected
        object_name = f"{record.fqdn} A {record.value}"
        if normalize_dns_name(ptr_zone) not in zone_names:
            findings.append(
                SmartViewRow(
                    severity="low",
                    object=object_name,
                    finding="No loaded reverse zone for A record",
                    evidence=f"Expected PTR zone {ptr_zone} not loaded.",
                    suggested_action="Create/load reverse zone, then add PTR if needed.",
                    source="dns",
                )
            )
            continue
        key = (normalize_dns_name(ptr_zone), normalize_dns_name(ptr_name))
        expected_target = normalize_dns_name(record.fqdn)
        actual_targets = ptr_targets.get(key, set())
        if not actual_targets:
            findings.append(
                SmartViewRow(
                    severity="medium",
                    object=object_name,
                    finding="A record missing PTR",
                    evidence=f"Expected {ptr_name}.{ptr_zone} PTR {record.fqdn}.",
                    suggested_action="Add PTR or confirm host should not have reverse DNS.",
                    source="dns",
                    fix_action="dns_add_ptr",
                    fix_label=f"add PTR {ptr_name}.{ptr_zone} -> {record.fqdn}",
                    fix_zone=ptr_zone,
                    fix_name=ptr_name,
                    fix_rtype="PTR",
                    fix_value=record.fqdn,
                )
            )
        elif expected_target not in actual_targets:
            findings.append(
                SmartViewRow(
                    severity="medium",
                    object=object_name,
                    finding="A record PTR points elsewhere",
                    evidence=f"PTR target(s): {', '.join(sorted(actual_targets))}",
                    suggested_action="Update PTR to match forward A record, or fix A record.",
                    source="dns",
                )
            )
    return findings


def dns_ptr_without_a(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> list[SmartViewRow]:
    forward_a: dict[str, set[str]] = defaultdict(set)
    findings: list[SmartViewRow] = []

    for record in iter_dns_records(records_by_zone):
        if record.rtype == "A":
            try:
                ipaddress.IPv4Address(record.value)
            except ValueError:
                continue
            forward_a[normalize_dns_name(record.fqdn)].add(record.value)

    for record in iter_dns_records(records_by_zone):
        if record.rtype != "PTR" or not is_reverse_zone(record.zone):
            continue
        ip_value = ipv4_from_ptr_name(record.name, record.zone)
        if ip_value is None:
            continue
        target = normalize_dns_name(record.value)
        ips = forward_a.get(target, set())
        object_name = f"{record.name}.{record.zone} PTR {record.value}"
        if not ips:
            findings.append(
                SmartViewRow(
                    severity="medium",
                    object=object_name,
                    finding="PTR target missing forward A",
                    evidence=f"No loaded A record for {record.value}.",
                    suggested_action="Add matching A record or remove stale PTR.",
                    source="dns",
                )
            )
        elif ip_value not in ips:
            findings.append(
                SmartViewRow(
                    severity="medium",
                    object=object_name,
                    finding="PTR does not match forward A",
                    evidence=f"PTR IP {ip_value}; forward A IP(s): {', '.join(sorted(ips))}",
                    suggested_action="Update PTR or forward A so both directions match.",
                    source="dns",
                )
            )
    return findings


def ldap_inactive_users(
    rows: Sequence[DirectoryRow], *, days: int = 90, now: datetime | None = None
) -> list[SmartViewRow]:
    now = normalized_now(now)
    cutoff = now - timedelta(days=days)
    findings: list[SmartViewRow] = []
    for row in rows:
        if row.kind != "user" or ldap_is_disabled(row):
            continue
        last_logon = first_ad_datetime(row, "lastLogonTimestamp", "lastLogon")
        if last_logon is None or last_logon >= cutoff:
            continue
        findings.append(
            SmartViewRow(
                severity="medium",
                object=directory_object_name(row),
                finding="Enabled user inactive",
                evidence=f"lastLogonTimestamp {age_text(last_logon, now)} ago (replicated AD value).",
                suggested_action="Review owner; disable first, then delete after retention policy.",
                source="ldap",
            )
        )
    return findings


def ldap_delete_candidate_users(
    rows: Sequence[DirectoryRow],
    *,
    disabled_days: int = 180,
    never_logged_days: int = 30,
    now: datetime | None = None,
) -> list[SmartViewRow]:
    now = normalized_now(now)
    disabled_cutoff = now - timedelta(days=disabled_days)
    never_logged_cutoff = now - timedelta(days=never_logged_days)
    findings: list[SmartViewRow] = []
    for row in rows:
        if row.kind != "user":
            continue
        created = first_ad_datetime(row, "whenCreated")
        changed = first_ad_datetime(row, "whenChanged")
        last_logon = first_ad_datetime(row, "lastLogonTimestamp", "lastLogon")
        disabled_reference = changed or created
        if ldap_is_disabled(row) and (
            disabled_reference is None or disabled_reference < disabled_cutoff
        ):
            evidence = "disabled"
            if changed is not None:
                evidence += f"; changed {age_text(changed, now)} ago"
            elif created is not None:
                evidence += f"; created {age_text(created, now)} ago"
            findings.append(
                SmartViewRow(
                    severity="medium",
                    object=directory_object_name(row),
                    finding="Disabled user cleanup candidate",
                    evidence=evidence,
                    suggested_action="Verify retention/legal hold; delete or archive per policy.",
                    source="ldap",
                )
            )
            continue
        if (
            not ldap_is_disabled(row)
            and last_logon is None
            and created is not None
            and created < never_logged_cutoff
        ):
            findings.append(
                SmartViewRow(
                    severity="low",
                    object=directory_object_name(row),
                    finding="User never logged in",
                    evidence=f"created {age_text(created, now)} ago; no lastLogonTimestamp.",
                    suggested_action="Confirm onboarding status; disable/delete if abandoned.",
                    source="ldap",
                )
            )
    return findings


def ldap_stale_computers(
    rows: Sequence[DirectoryRow], *, days: int = 90, now: datetime | None = None
) -> list[SmartViewRow]:
    now = normalized_now(now)
    cutoff = now - timedelta(days=days)
    findings: list[SmartViewRow] = []
    for row in rows:
        if row.kind != "computer" or ldap_is_disabled(row):
            continue
        last_logon = first_ad_datetime(row, "lastLogonTimestamp", "lastLogon")
        created = first_ad_datetime(row, "whenCreated")
        if last_logon is not None and last_logon >= cutoff:
            continue
        if last_logon is None and (created is None or created >= cutoff):
            continue
        host = first_attr(row.attributes, "dNSHostName") or row.name
        evidence = (
            f"lastLogonTimestamp {age_text(last_logon, now)} ago"
            if last_logon is not None
            else f"created {age_text(created, now)} ago; no lastLogonTimestamp"
        )
        findings.append(
            SmartViewRow(
                severity="medium",
                object=host,
                finding="Stale computer account",
                evidence=evidence,
                suggested_action="Confirm device retired; disable/delete and clean DNS if stale.",
                source="ldap",
            )
        )
    return findings


def ldap_users_without_groups(rows: Sequence[DirectoryRow]) -> list[SmartViewRow]:
    findings: list[SmartViewRow] = []
    for row in rows:
        if row.kind != "user" or ldap_is_disabled(row):
            continue
        if row.attributes.get("memberOf"):
            continue
        primary_group = first_attr(row.attributes, "primaryGroupID") or "unknown"
        findings.append(
            SmartViewRow(
                severity="low",
                object=directory_object_name(row),
                finding="User has no secondary groups",
                evidence=f"memberOf empty; primaryGroupID={primary_group}. AD primary group is not listed in memberOf.",
                suggested_action="Confirm user still needed; add expected groups or disable/remove.",
                source="ldap",
            )
        )
    return findings


def iter_dns_records(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> list[DnsRecordRef]:
    return [
        DnsRecordRef(zone, row)
        for zone, rows in records_by_zone.items()
        for row in rows
    ]


def ptr_targets_by_reverse_key(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> dict[tuple[str, str], set[str]]:
    targets: dict[tuple[str, str], set[str]] = defaultdict(set)
    for record in iter_dns_records(records_by_zone):
        if record.rtype != "PTR":
            continue
        key = (normalize_dns_name(record.zone), normalize_dns_name(record.name))
        targets[key].add(normalize_dns_name(record.value))
    return targets


def dns_fqdn(name: str, zone: str) -> str:
    zone = zone.rstrip(".")
    if name == "@":
        return zone
    if name.endswith("."):
        return name.rstrip(".")
    return f"{name}.{zone}"


def normalize_dns_name(value: str) -> str:
    return value.strip().rstrip(".").casefold()


def normalize_dns_value(value: str) -> str:
    return " ".join(value.strip().rstrip(".").casefold().split())


def is_reverse_zone(zone: str) -> bool:
    return normalize_dns_name(zone).endswith(".in-addr.arpa")


def ipv4_from_ptr_name(name: str, zone: str) -> str | None:
    reverse_name = dns_fqdn(name, zone)
    try:
        return dns.reversename.to_address(dns.name.from_text(f"{reverse_name}."))
    except dns.exception.DNSException, ValueError:
        return None


def first_attr(attrs: Mapping[str, Sequence[str]], *names: str) -> str:
    for name in names:
        values = attrs.get(name, ())
        if values:
            return values[0]
    return ""


def directory_object_name(row: DirectoryRow) -> str:
    account = first_attr(
        row.attributes, "sAMAccountName", "userPrincipalName", "dNSHostName"
    )
    return account or row.name or row.dn


def ldap_is_disabled(row: DirectoryRow) -> bool:
    value = first_attr(row.attributes, "userAccountControl")
    try:
        return bool(int(value) & ACCOUNTDISABLE)
    except ValueError:
        return False


def first_ad_datetime(row: DirectoryRow, *names: str) -> datetime | None:
    for name in names:
        parsed = parse_ad_datetime(first_attr(row.attributes, name))
        if parsed is not None:
            return parsed
    return None


def parse_ad_datetime(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text or text == "0":
        return None
    if text.isdigit():
        filetime = int(text)
        if filetime <= 0:
            return None
        return datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=filetime // 10)

    normalized = text.replace("Z", "+00:00")
    for candidate in (normalized, normalized.replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return ensure_utc(parsed)

    for fmt in ("%Y%m%d%H%M%S.%f%z", "%Y%m%d%H%M%S%z"):
        try:
            return ensure_utc(datetime.strptime(normalized, fmt))
        except ValueError:
            continue
    return None


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def normalized_now(now: datetime | None) -> datetime:
    return ensure_utc(now or datetime.now(UTC))


def age_text(value: datetime | None, now: datetime) -> str:
    if value is None:
        return "unknown age"
    days = max(0, (now - ensure_utc(value)).days)
    return f"{days} day{'s' if days != 1 else ''}"
