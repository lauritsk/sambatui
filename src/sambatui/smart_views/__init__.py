from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..dns import reverse_record_for_ipv4 as reverse_record_for_ipv4
from ..models import DnsRow
from . import dns as _dns
from .dashboard import (
    dashboard_detail_row,
    dashboard_failure_row,
    dashboard_summary_row,
    dashboard_total_row,
    full_health_dashboard_rows,
    severity_count_text,
    severity_rank,
    sorted_details,
)
from .dns import (
    DnsRecordRef,
    bucket_dns_records,
    cname_conflict_findings,
    dns_duplicate_records,
    dns_fqdn,
    dns_ptr_without_a,
    dns_record_identity,
    dns_record_name_key,
    duplicate_dns_record_findings,
    forward_a_records,
    ipv4_from_ptr_name,
    is_reverse_zone,
    iter_dns_records,
    mismatched_ptr_finding,
    missing_ptr_finding,
    normalize_dns_name,
    normalize_dns_value,
    ptr_record_forward_finding,
    ptr_targets_by_reverse_key,
    valid_ipv4,
)
from .ldap import (
    ACCOUNTDISABLE,
    age_text,
    delete_candidate_user_finding,
    directory_object_name,
    disabled_user_cleanup_finding,
    disabled_user_evidence,
    ensure_utc,
    first_ad_datetime,
    ldap_delete_candidate_users,
    ldap_inactive_users,
    ldap_is_disabled,
    ldap_stale_computers,
    ldap_users_without_groups,
    never_logged_user_finding,
    normalized_now,
    parse_ad_datetime,
    stale_computer_evidence,
    stale_computer_finding,
)
from .models import SmartViewCheckResult, SmartViewRow


def dns_a_without_ptr(
    records_by_zone: Mapping[str, Sequence[DnsRow]],
) -> list[SmartViewRow]:
    original = _dns.reverse_record_for_ipv4
    _dns.reverse_record_for_ipv4 = reverse_record_for_ipv4
    try:
        return _dns.dns_a_without_ptr(records_by_zone)
    finally:
        _dns.reverse_record_for_ipv4 = original


__all__ = [
    "ACCOUNTDISABLE",
    "DnsRecordRef",
    "SmartViewCheckResult",
    "SmartViewRow",
    "age_text",
    "bucket_dns_records",
    "cname_conflict_findings",
    "dashboard_detail_row",
    "dashboard_failure_row",
    "dashboard_summary_row",
    "dashboard_total_row",
    "delete_candidate_user_finding",
    "directory_object_name",
    "disabled_user_cleanup_finding",
    "disabled_user_evidence",
    "dns_a_without_ptr",
    "dns_duplicate_records",
    "dns_fqdn",
    "dns_ptr_without_a",
    "dns_record_identity",
    "dns_record_name_key",
    "duplicate_dns_record_findings",
    "ensure_utc",
    "first_ad_datetime",
    "forward_a_records",
    "full_health_dashboard_rows",
    "ipv4_from_ptr_name",
    "is_reverse_zone",
    "iter_dns_records",
    "ldap_delete_candidate_users",
    "ldap_inactive_users",
    "ldap_is_disabled",
    "ldap_stale_computers",
    "ldap_users_without_groups",
    "mismatched_ptr_finding",
    "missing_ptr_finding",
    "never_logged_user_finding",
    "normalize_dns_name",
    "normalize_dns_value",
    "normalized_now",
    "parse_ad_datetime",
    "ptr_record_forward_finding",
    "ptr_targets_by_reverse_key",
    "reverse_record_for_ipv4",
    "severity_count_text",
    "severity_rank",
    "sorted_details",
    "stale_computer_evidence",
    "stale_computer_finding",
    "valid_ipv4",
]
