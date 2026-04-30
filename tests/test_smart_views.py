from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sambatui.ldap_directory import DirectoryRow
from sambatui.models import DnsRow
from sambatui.smart_views import (
    ACCOUNTDISABLE,
    dns_a_without_ptr,
    dns_duplicate_records,
    dns_ptr_without_a,
    ldap_delete_candidate_users,
    ldap_inactive_users,
    ldap_stale_computers,
    ldap_users_without_groups,
    parse_ad_datetime,
)


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
