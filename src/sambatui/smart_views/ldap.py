from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta


from ..ldap.client import DirectoryRow, first_attr
from .models import SmartViewRow


ACCOUNTDISABLE = 0x0002


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
