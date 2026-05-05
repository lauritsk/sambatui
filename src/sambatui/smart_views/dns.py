from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import ipaddress

import dns.exception
import dns.name
import dns.reversename

from ..dns.names import is_ipv4_reverse_zone, normalize_dns_name, normalize_dns_value
from ..dns.ptr import reverse_record_for_ipv4
from ..core.models import DnsRow
from .models import SmartViewRow


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
    assert expected is not None
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


def is_reverse_zone(zone: str) -> bool:
    return is_ipv4_reverse_zone(zone)


def ipv4_from_ptr_name(name: str, zone: str) -> str | None:
    reverse_name = dns_fqdn(name, zone)
    try:
        return dns.reversename.to_address(dns.name.from_text(f"{reverse_name}."))
    except dns.exception.DNSException, ValueError:
        return None
