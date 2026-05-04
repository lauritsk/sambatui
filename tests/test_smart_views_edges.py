from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sambatui import smart_views as smart_module
from sambatui.ldap_directory import DirectoryRow
from sambatui.models import DnsRow
from sambatui.smart_views import (
    ACCOUNTDISABLE,
    disabled_user_evidence,
    dns_a_without_ptr,
    ldap_delete_candidate_users,
    parse_ad_datetime,
)


def dns_row(name: str, rtype: str, value: str) -> DnsRow:
    return DnsRow(name, "1", "0", rtype, value, "900", "raw")


def directory_row(attrs: dict[str, tuple[str, ...]]) -> DirectoryRow:
    return DirectoryRow("CN=Alice,DC=example,DC=com", "user", "Alice", "", attrs)


def filetime_for(value: datetime) -> str:
    ad_epoch = datetime(1601, 1, 1, tzinfo=UTC)
    return str(int((value - ad_epoch).total_seconds() * 10_000_000))


def test_smart_view_remaining_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(smart_module, "reverse_record_for_ipv4", lambda *_args: None)
    assert (
        dns_a_without_ptr({"example.com": [dns_row("host", "A", "192.0.2.10")]}) == []
    )

    now = datetime(2026, 4, 30, tzinfo=UTC)
    recent_disabled = directory_row(
        {
            "sAMAccountName": ("recent",),
            "whenChanged": (filetime_for(now - timedelta(days=1)),),
            "userAccountControl": (str(ACCOUNTDISABLE),),
        }
    )
    assert ldap_delete_candidate_users([recent_disabled], now=now) == []
    assert disabled_user_evidence(None, None, now) == "disabled"
    assert parse_ad_datetime("2026-04-30 12:00:00") == datetime(
        2026, 4, 30, 12, tzinfo=UTC
    )
