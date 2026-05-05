from __future__ import annotations

from datetime import UTC, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

from sambatui.ldap.rows import DirectoryRow
from sambatui.core.models import DnsRow
from sambatui.smart_views import (
    ACCOUNTDISABLE,
    SmartViewCheckResult,
    SmartViewRow,
    dns_a_without_ptr,
    dns_duplicate_records,
    dns_fqdn,
    dns_ptr_without_a,
    full_health_dashboard_rows,
    ldap_delete_candidate_users,
    ldap_inactive_users,
    ldap_stale_computers,
    ldap_users_without_groups,
    normalize_dns_name,
    normalize_dns_value,
    parse_ad_datetime,
)

DNS_LABEL = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"))
    | st.sampled_from("_-"),
    min_size=1,
    max_size=20,
).filter(lambda value: value[0].isalnum() and value[-1].isalnum() and value.isascii())
DNS_NAME = st.lists(DNS_LABEL, min_size=1, max_size=5).map(".".join)
RECORD_TYPES = st.sampled_from(["A", "AAAA", "CNAME", "PTR", "TXT", "MX", "SRV", "NS"])


def dns_row(name: str, rtype: str, value: str) -> DnsRow:
    return DnsRow(
        name=name,
        records="1",
        children="0",
        rtype=rtype,
        value=value,
        ttl="900",
        raw="",
    )


def directory_row(
    *,
    kind: str = "user",
    name: str = "Alice",
    attrs: dict[str, tuple[str, ...]],
) -> DirectoryRow:
    return DirectoryRow(
        dn=f"CN={name},DC=example,DC=com",
        kind=kind,
        name=name,
        summary="",
        attributes=attrs,
    )


def filetime_for(value: datetime) -> str:
    ad_epoch = datetime(1601, 1, 1, tzinfo=UTC)
    return str(int((value - ad_epoch).total_seconds() * 10_000_000))


def test_full_health_dashboard_rows_show_summary_failures_then_details() -> None:
    high = SmartViewRow(
        severity="high",
        object="example.com:alias",
        finding="CNAME conflicts with other records",
        evidence="Types on same name: A, CNAME",
        suggested_action="Keep CNAME alone.",
        source="dns",
    )
    low = SmartViewRow(
        severity="low",
        object="solo",
        finding="User has no secondary groups",
        evidence="memberOf empty",
        suggested_action="Review groups.",
        source="ldap",
    )

    rows = full_health_dashboard_rows(
        [
            SmartViewCheckResult(
                "dns_duplicates", "DNS duplicates/conflicts", "DNS", [high]
            ),
            SmartViewCheckResult(
                "ldap_users_without_groups",
                "LDAP users with no secondary groups",
                "LDAP",
                [low],
            ),
            SmartViewCheckResult(
                "ldap_stale_computers",
                "LDAP stale computer accounts",
                "LDAP",
                error="LDAP timeout",
            ),
        ]
    )

    assert rows[0].finding == "Full health dashboard"
    assert rows[0].evidence == "2 finding(s); 2 check(s) succeeded; 1 check(s) failed."
    assert [row.severity for row in rows[:4]] == [
        "summary",
        "summary",
        "summary",
        "error",
    ]
    assert (
        rows[4].finding
        == "DNS duplicates/conflicts: CNAME conflicts with other records"
    )
    assert (
        rows[5].finding
        == "LDAP users with no secondary groups: User has no secondary groups"
    )


def test_dns_duplicate_records_flags_identical_records_and_cname_conflicts() -> None:
    rows = {
        "example.com": [
            dns_row("www", "A", "192.0.2.10"),
            dns_row("www", "A", "192.0.2.10"),
            dns_row("alias", "CNAME", "www.example.com."),
            dns_row("alias", "TXT", '"conflict"'),
        ]
    }

    findings = dns_duplicate_records(rows)

    assert [finding.finding for finding in findings] == [
        "Duplicate DNS record",
        "CNAME conflicts with other records",
    ]


def test_dns_a_without_ptr_flags_missing_and_wrong_ptr() -> None:
    rows = {
        "example.com": [
            dns_row("host", "A", "192.0.2.10"),
            dns_row("wrong", "A", "192.0.2.11"),
        ],
        "2.0.192.in-addr.arpa": [
            dns_row("11", "PTR", "other.example.com."),
        ],
    }

    findings = dns_a_without_ptr(rows)

    assert [finding.finding for finding in findings] == [
        "A record missing PTR",
        "A record PTR points elsewhere",
    ]
    assert findings[0].fix_action == "dns_add_ptr"
    assert findings[0].fix_zone == "2.0.192.in-addr.arpa"
    assert findings[0].fix_name == "10"
    assert findings[0].fix_rtype == "PTR"
    assert findings[0].fix_value == "host.example.com"
    assert findings[1].fix_action == ""


def test_dns_ptr_without_a_flags_missing_and_mismatched_forward() -> None:
    rows = {
        "example.com": [dns_row("host", "A", "192.0.2.10")],
        "2.0.192.in-addr.arpa": [
            dns_row("10", "PTR", "host.example.com."),
            dns_row("11", "PTR", "host.example.com."),
            dns_row("12", "PTR", "missing.example.com."),
        ],
    }

    findings = dns_ptr_without_a(rows)

    assert [finding.finding for finding in findings] == [
        "PTR does not match forward A",
        "PTR target missing forward A",
    ]


def test_parse_ad_datetime_accepts_filetime_and_iso_values() -> None:
    value = datetime(2025, 1, 1, tzinfo=UTC)

    assert parse_ad_datetime(filetime_for(value)) == value
    assert parse_ad_datetime("2025-01-01T00:00:00+00:00") == value


def test_ldap_inactive_users_ignores_disabled_and_recent_users() -> None:
    now = datetime(2026, 4, 30, tzinfo=UTC)
    old = filetime_for(now - timedelta(days=120))
    recent = filetime_for(now - timedelta(days=10))
    rows = [
        directory_row(
            attrs={
                "sAMAccountName": ("old",),
                "lastLogonTimestamp": (old,),
                "userAccountControl": ("512",),
            }
        ),
        directory_row(
            attrs={
                "sAMAccountName": ("recent",),
                "lastLogonTimestamp": (recent,),
                "userAccountControl": ("512",),
            }
        ),
        directory_row(
            attrs={
                "sAMAccountName": ("disabled",),
                "lastLogonTimestamp": (old,),
                "userAccountControl": (str(ACCOUNTDISABLE),),
            }
        ),
    ]

    findings = ldap_inactive_users(rows, days=90, now=now)

    assert [finding.object for finding in findings] == ["old"]
    assert findings[0].fix_action == "ldap_disable_account"
    assert findings[0].fix_dn == "CN=Alice,DC=example,DC=com"
    assert findings[0].fix_attribute == "userAccountControl"
    assert findings[0].fix_value == str(512 | ACCOUNTDISABLE)


def test_ldap_delete_candidate_users_flags_disabled_old_and_never_logged_in() -> None:
    now = datetime(2026, 4, 30, tzinfo=UTC)
    rows = [
        directory_row(
            attrs={
                "sAMAccountName": ("disabled",),
                "whenCreated": (filetime_for(now - timedelta(days=365)),),
                "userAccountControl": (str(ACCOUNTDISABLE),),
            }
        ),
        directory_row(
            attrs={
                "sAMAccountName": ("never",),
                "whenCreated": (filetime_for(now - timedelta(days=45)),),
                "userAccountControl": ("512",),
            }
        ),
    ]

    findings = ldap_delete_candidate_users(
        rows, disabled_days=180, never_logged_days=30, now=now
    )

    assert [finding.finding for finding in findings] == [
        "Disabled user cleanup candidate",
        "User never logged in",
    ]
    assert findings[0].fix_action == "ldap_delete_entry"
    assert findings[0].fix_dn == "CN=Alice,DC=example,DC=com"
    assert findings[1].fix_action == "ldap_disable_account"
    assert findings[1].fix_value == str(512 | ACCOUNTDISABLE)


def test_ldap_stale_computers_flags_old_logon() -> None:
    now = datetime(2026, 4, 30, tzinfo=UTC)
    rows = [
        directory_row(
            kind="computer",
            name="HOST$",
            attrs={
                "sAMAccountName": ("HOST$",),
                "dNSHostName": ("host.example.com",),
                "lastLogonTimestamp": (filetime_for(now - timedelta(days=180)),),
                "userAccountControl": ("4096",),
            },
        )
    ]

    findings = ldap_stale_computers(rows, days=90, now=now)

    assert findings[0].object == "host.example.com"
    assert findings[0].finding == "Stale computer account"
    assert findings[0].fix_action == "ldap_disable_account"
    assert findings[0].fix_value == str(4096 | ACCOUNTDISABLE)


def test_ldap_users_without_groups_flags_empty_memberof() -> None:
    rows = [
        directory_row(
            attrs={
                "sAMAccountName": ("solo",),
                "userAccountControl": ("512",),
                "primaryGroupID": ("513",),
            }
        ),
        directory_row(
            attrs={
                "sAMAccountName": ("grouped",),
                "userAccountControl": ("512",),
                "memberOf": ("CN=Staff,DC=example,DC=com",),
            }
        ),
    ]

    findings = ldap_users_without_groups(rows)

    assert [finding.object for finding in findings] == ["solo"]
    assert "primaryGroupID=513" in findings[0].evidence


@given(st.text())
def test_normalize_dns_value_is_trimmed_lowercase_and_dotless(value: str) -> None:
    normalized = normalize_dns_value(value)

    assert normalized == normalized.casefold()
    assert normalized == normalized.strip()
    assert not normalized.endswith(".")
    assert "  " not in normalized


@given(DNS_NAME)
def test_normalize_dns_name_matches_absolute_generated_name(name: str) -> None:
    assert normalize_dns_name(f"{name}.") == normalize_dns_name(name)
    assert dns_fqdn("@", f"{name}.") == name


@given(DNS_NAME, DNS_NAME, st.booleans())
def test_dns_fqdn_normalizes_relative_and_absolute_names(
    name: str, zone: str, absolute: bool
) -> None:
    input_name = f"{name}." if absolute else name
    fqdn = dns_fqdn(input_name, zone)

    assert fqdn == fqdn.rstrip(".")
    if absolute:
        assert normalize_dns_name(fqdn) == normalize_dns_name(name)
    else:
        assert (
            normalize_dns_name(fqdn)
            == f"{normalize_dns_name(name)}.{normalize_dns_name(zone)}"
        )


@given(
    st.dictionaries(
        DNS_NAME,
        st.lists(st.tuples(DNS_NAME, RECORD_TYPES, st.text(max_size=40)), max_size=8),
        max_size=4,
    )
)
def test_dns_duplicate_records_handles_generated_records(
    records_by_zone: dict[str, list[tuple[str, str, str]]],
) -> None:
    rows = {
        zone: [dns_row(name, rtype, value) for name, rtype, value in records]
        for zone, records in records_by_zone.items()
    }

    findings = dns_duplicate_records(rows)

    assert len(findings) <= sum(len(records) for records in rows.values())
    assert all(finding.source == "dns" for finding in findings)
    assert all(finding.severity in {"low", "medium", "high"} for finding in findings)
