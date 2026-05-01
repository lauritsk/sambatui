from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import ipaddress

import dns.exception
import dns.name
import dns.reversename

from .dns import reverse_record_for_ipv4
from .ldap_directory import DirectoryRow, first_attr
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
class SmartViewCheckResult:
    view_id: str
    label: str
    source: str
    rows: Sequence[SmartViewRow] = ()
    error: str = ""


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


SEVERITY_ORDER = {"error": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def full_health_dashboard_rows(
    results: Sequence[SmartViewCheckResult],
) -> list[SmartViewRow]:
    details: list[tuple[SmartViewCheckResult, SmartViewRow]] = []
    summary_rows: list[SmartViewRow] = []
    failure_rows: list[SmartViewRow] = []
    total_findings = 0

    for result in results:
        if result.error:
            failure_rows.append(dashboard_failure_row(result))
            continue
        rows = list(result.rows)
        total_findings += len(rows)
        details.extend((result, row) for row in rows)
        summary_rows.append(dashboard_summary_row(result, rows))

    top_row = dashboard_total_row(total_findings, summary_rows, failure_rows)
    detail_rows = [
        dashboard_detail_row(result, row) for result, row in sorted_details(details)
    ]
    return [top_row, *summary_rows, *failure_rows, *detail_rows]


def dashboard_failure_row(result: SmartViewCheckResult) -> SmartViewRow:
    return SmartViewRow(
        severity="error",
        object=f"{result.source}:{result.label}",
        finding=f"{result.label}: Health check failed",
        evidence=result.error,
        suggested_action="Fix the connection or permissions, then rerun the dashboard.",
        source="dashboard",
    )


def dashboard_summary_row(
    result: SmartViewCheckResult, rows: Sequence[SmartViewRow]
) -> SmartViewRow:
    return SmartViewRow(
        severity="summary",
        object=result.source,
        finding=result.label,
        evidence=severity_count_text(rows),
        suggested_action="Review detailed rows below; high severity first.",
        source="dashboard",
    )


def dashboard_total_row(
    total_findings: int,
    summary_rows: Sequence[SmartViewRow],
    failure_rows: Sequence[SmartViewRow],
) -> SmartViewRow:
    return SmartViewRow(
        severity="summary",
        object="Total",
        finding="Full health dashboard",
        evidence=(
            f"{total_findings} finding(s); {len(summary_rows)} check(s) succeeded; "
            f"{len(failure_rows)} check(s) failed."
        ),
        suggested_action="Review failures first, then high and medium findings.",
        source="dashboard",
    )


def severity_count_text(rows: Sequence[SmartViewRow]) -> str:
    if not rows:
        return "0 findings"
    counts = Counter(row.severity for row in rows)
    return ", ".join(
        f"{severity}={counts[severity]}"
        for severity in sorted(counts, key=severity_rank)
    )


def sorted_details(
    details: Sequence[tuple[SmartViewCheckResult, SmartViewRow]],
) -> list[tuple[SmartViewCheckResult, SmartViewRow]]:
    return sorted(
        details,
        key=lambda item: (
            severity_rank(item[1].severity),
            item[1].source.casefold(),
            item[0].label.casefold(),
            item[1].object.casefold(),
            item[1].finding.casefold(),
        ),
    )


def dashboard_detail_row(
    result: SmartViewCheckResult, row: SmartViewRow
) -> SmartViewRow:
    return SmartViewRow(
        severity=row.severity,
        object=row.object,
        finding=f"{result.label}: {row.finding}",
        evidence=row.evidence,
        suggested_action=row.suggested_action,
        source=row.source,
        fix_action=row.fix_action,
        fix_label=row.fix_label,
        fix_zone=row.fix_zone,
        fix_name=row.fix_name,
        fix_rtype=row.fix_rtype,
        fix_value=row.fix_value,
    )


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.casefold(), 99)


def dns_duplicate_records(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> list[SmartViewRow]:
    buckets, by_name = bucket_dns_records(records_by_zone)
    return [
        *duplicate_dns_record_findings(buckets),
        *cname_conflict_findings(by_name),
    ]


def bucket_dns_records(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> tuple[
    dict[tuple[str, str, str, str], list[DnsRecordRef]],
    dict[tuple[str, str], list[DnsRecordRef]],
]:
    buckets: dict[tuple[str, str, str, str], list[DnsRecordRef]] = defaultdict(list)
    by_name: dict[tuple[str, str], list[DnsRecordRef]] = defaultdict(list)
    for record in iter_dns_records(records_by_zone):
        if record.rtype == "-":
            continue
        buckets[dns_record_identity(record)].append(record)
        by_name[dns_record_name_key(record)].append(record)
    return buckets, by_name


def duplicate_dns_record_findings(
    buckets: Mapping[tuple[str, str, str, str], Sequence[DnsRecordRef]],
) -> list[SmartViewRow]:
    findings: list[SmartViewRow] = []
    for (_zone, _name, rtype, value), duplicates in sorted(buckets.items()):
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
    return findings


def cname_conflict_findings(
    records_by_name: Mapping[tuple[str, str], Sequence[DnsRecordRef]],
) -> list[SmartViewRow]:
    findings: list[SmartViewRow] = []
    for (_zone, _name), records in sorted(records_by_name.items()):
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
        finding = a_record_ptr_finding(record, zones, zone_names, ptr_targets)
        if finding is not None:
            findings.append(finding)
    return findings


def a_record_ptr_finding(
    record: DnsRecordRef,
    zones: Sequence[str],
    zone_names: set[str],
    ptr_targets: Mapping[tuple[str, str], set[str]],
) -> SmartViewRow | None:
    if record.rtype != "A" or not valid_ipv4(record.value):
        return None

    expected = reverse_record_for_ipv4(record.value, zones)
    if expected is None:
        return None

    ptr_zone, ptr_name = expected
    object_name = f"{record.fqdn} A {record.value}"
    if normalize_dns_name(ptr_zone) not in zone_names:
        return SmartViewRow(
            severity="low",
            object=object_name,
            finding="No loaded reverse zone for A record",
            evidence=f"Expected PTR zone {ptr_zone} not loaded.",
            suggested_action="Create/load reverse zone, then add PTR if needed.",
            source="dns",
        )

    key = (normalize_dns_name(ptr_zone), normalize_dns_name(ptr_name))
    expected_target = normalize_dns_name(record.fqdn)
    actual_targets = ptr_targets.get(key, set())
    if not actual_targets:
        return missing_ptr_finding(record, object_name, ptr_zone, ptr_name)
    if expected_target not in actual_targets:
        return mismatched_ptr_finding(object_name, actual_targets)
    return None


def missing_ptr_finding(
    record: DnsRecordRef, object_name: str, ptr_zone: str, ptr_name: str
) -> SmartViewRow:
    return SmartViewRow(
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


def mismatched_ptr_finding(object_name: str, actual_targets: set[str]) -> SmartViewRow:
    return SmartViewRow(
        severity="medium",
        object=object_name,
        finding="A record PTR points elsewhere",
        evidence=f"PTR target(s): {', '.join(sorted(actual_targets))}",
        suggested_action="Update PTR to match forward A record, or fix A record.",
        source="dns",
    )


def dns_ptr_without_a(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> list[SmartViewRow]:
    forward_a = forward_a_records(records_by_zone)
    findings: list[SmartViewRow] = []

    for record in iter_dns_records(records_by_zone):
        finding = ptr_record_forward_finding(record, forward_a)
        if finding is not None:
            findings.append(finding)
    return findings


def forward_a_records(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> dict[str, set[str]]:
    forward_a: dict[str, set[str]] = defaultdict(set)
    for record in iter_dns_records(records_by_zone):
        if record.rtype == "A" and valid_ipv4(record.value):
            forward_a[normalize_dns_name(record.fqdn)].add(record.value)
    return forward_a


def ptr_record_forward_finding(
    record: DnsRecordRef, forward_a: Mapping[str, set[str]]
) -> SmartViewRow | None:
    if record.rtype != "PTR" or not is_reverse_zone(record.zone):
        return None

    ip_value = ipv4_from_ptr_name(record.name, record.zone)
    if ip_value is None:
        return None

    target = normalize_dns_name(record.value)
    ips = forward_a.get(target, set())
    object_name = f"{record.name}.{record.zone} PTR {record.value}"
    if not ips:
        return SmartViewRow(
            severity="medium",
            object=object_name,
            finding="PTR target missing forward A",
            evidence=f"No loaded A record for {record.value}.",
            suggested_action="Add matching A record or remove stale PTR.",
            source="dns",
        )
    if ip_value not in ips:
        return SmartViewRow(
            severity="medium",
            object=object_name,
            finding="PTR does not match forward A",
            evidence=f"PTR IP {ip_value}; forward A IP(s): {', '.join(sorted(ips))}",
            suggested_action="Update PTR or forward A so both directions match.",
            source="dns",
        )
    return None


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
        finding = delete_candidate_user_finding(
            row,
            disabled_cutoff=disabled_cutoff,
            never_logged_cutoff=never_logged_cutoff,
            now=now,
        )
        if finding is not None:
            findings.append(finding)
    return findings


def delete_candidate_user_finding(
    row: DirectoryRow,
    *,
    disabled_cutoff: datetime,
    never_logged_cutoff: datetime,
    now: datetime,
) -> SmartViewRow | None:
    if row.kind != "user":
        return None

    created = first_ad_datetime(row, "whenCreated")
    changed = first_ad_datetime(row, "whenChanged")
    last_logon = first_ad_datetime(row, "lastLogonTimestamp", "lastLogon")
    if ldap_is_disabled(row):
        return disabled_user_cleanup_finding(
            row, changed, created, disabled_cutoff, now
        )
    if last_logon is None and created is not None and created < never_logged_cutoff:
        return never_logged_user_finding(row, created, now)
    return None


def disabled_user_cleanup_finding(
    row: DirectoryRow,
    changed: datetime | None,
    created: datetime | None,
    cutoff: datetime,
    now: datetime,
) -> SmartViewRow | None:
    reference = changed or created
    if reference is not None and reference >= cutoff:
        return None
    return SmartViewRow(
        severity="medium",
        object=directory_object_name(row),
        finding="Disabled user cleanup candidate",
        evidence=disabled_user_evidence(changed, created, now),
        suggested_action="Verify retention/legal hold; delete or archive per policy.",
        source="ldap",
    )


def never_logged_user_finding(
    row: DirectoryRow, created: datetime, now: datetime
) -> SmartViewRow:
    return SmartViewRow(
        severity="low",
        object=directory_object_name(row),
        finding="User never logged in",
        evidence=f"created {age_text(created, now)} ago; no lastLogonTimestamp.",
        suggested_action="Confirm onboarding status; disable/delete if abandoned.",
        source="ldap",
    )


def disabled_user_evidence(
    changed: datetime | None, created: datetime | None, now: datetime
) -> str:
    if changed is not None:
        return f"disabled; changed {age_text(changed, now)} ago"
    if created is not None:
        return f"disabled; created {age_text(created, now)} ago"
    return "disabled"


def ldap_stale_computers(
    rows: Sequence[DirectoryRow], *, days: int = 90, now: datetime | None = None
) -> list[SmartViewRow]:
    now = normalized_now(now)
    cutoff = now - timedelta(days=days)
    findings: list[SmartViewRow] = []
    for row in rows:
        finding = stale_computer_finding(row, cutoff=cutoff, now=now)
        if finding is not None:
            findings.append(finding)
    return findings


def stale_computer_finding(
    row: DirectoryRow, *, cutoff: datetime, now: datetime
) -> SmartViewRow | None:
    if row.kind != "computer" or ldap_is_disabled(row):
        return None

    last_logon = first_ad_datetime(row, "lastLogonTimestamp", "lastLogon")
    created = first_ad_datetime(row, "whenCreated")
    if last_logon is not None and last_logon >= cutoff:
        return None
    if last_logon is None and (created is None or created >= cutoff):
        return None

    host = first_attr(row.attributes, "dNSHostName") or row.name
    evidence = stale_computer_evidence(last_logon, created, now)
    return SmartViewRow(
        severity="medium",
        object=host,
        finding="Stale computer account",
        evidence=evidence,
        suggested_action="Confirm device retired; disable/delete and clean DNS if stale.",
        source="ldap",
    )


def stale_computer_evidence(
    last_logon: datetime | None, created: datetime | None, now: datetime
) -> str:
    if last_logon is not None:
        return f"lastLogonTimestamp {age_text(last_logon, now)} ago"
    return f"created {age_text(created, now)} ago; no lastLogonTimestamp"


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
        targets[dns_record_name_key(record)].add(normalize_dns_name(record.value))
    return targets


def dns_record_identity(record: DnsRecordRef) -> tuple[str, str, str, str]:
    return (
        normalize_dns_name(record.zone),
        normalize_dns_name(record.name),
        record.rtype,
        normalize_dns_value(record.value),
    )


def dns_record_name_key(record: DnsRecordRef) -> tuple[str, str]:
    return normalize_dns_name(record.zone), normalize_dns_name(record.name)


def valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


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
