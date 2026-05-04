from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sambatui import smart_views as smart_module
from sambatui.ldap.client import DirectoryRow
from sambatui.core.models import DnsRow
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


AD_DATETIMES = st.datetimes(
    min_value=datetime(1900, 1, 1),
    max_value=datetime(2099, 12, 31, 23, 59, 59),
    timezones=st.just(UTC),
).map(lambda value: value.replace(microsecond=0))


@given(AD_DATETIMES)
def test_parse_ad_datetime_round_trips_generated_filetimes(value: datetime) -> None:
    assert parse_ad_datetime(filetime_for(value)) == value


@given(AD_DATETIMES)
def test_parse_ad_datetime_accepts_generated_iso_text(value: datetime) -> None:
    assert parse_ad_datetime(value.isoformat()) == value


@given(st.integers(min_value=0, max_value=3650), st.booleans())
def test_disabled_user_evidence_reports_generated_age(
    days_old: int, prefer_changed: bool
) -> None:
    now = datetime(2026, 4, 30, tzinfo=UTC)
    observed = now - timedelta(days=days_old)
    evidence = disabled_user_evidence(
        observed if prefer_changed else None,
        None if prefer_changed else observed,
        now,
    )

    assert evidence.startswith("disabled; ")
    assert f"{days_old} day" in evidence
    assert ("changed" in evidence) is prefer_changed
    assert ("created" in evidence) is not prefer_changed


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
