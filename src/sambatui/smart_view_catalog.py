from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from .core.config import (
    DEFAULT_SMART_DAYS,
    DEFAULT_SMART_DISABLED_DAYS,
    DEFAULT_SMART_MAX_ROWS,
    DEFAULT_SMART_NEVER_LOGGED_DAYS,
)
from .core.remediation import bounded_int


FULL_HEALTH_VIEW_ID = "full_health_dashboard"
FULL_HEALTH_DNS_VIEW_IDS = (
    "dns_duplicates",
    "dns_a_without_ptr",
    "dns_ptr_without_a",
)
FULL_HEALTH_LDAP_VIEW_IDS = (
    "ldap_inactive_users",
    "ldap_stale_computers",
    "ldap_users_without_groups",
    "ldap_delete_candidates",
)
SMART_DAYS_FALLBACK = 90
SMART_DISABLED_DAYS_FALLBACK = 180
SMART_NEVER_LOGGED_DAYS_FALLBACK = 30
SMART_ROW_LIMIT_FALLBACK = 500
SMART_ROW_LIMIT_STEP = 200
SMART_ROW_LIMIT_MAX = 5000


class SmartViewSource(StrEnum):
    DNS = "DNS"
    LDAP = "LDAP"
    FULL = "Full"

    @property
    def row_source(self) -> str:
        return "dashboard" if self is SmartViewSource.FULL else self.value.lower()

    @property
    def sidebar_source(self) -> "SmartViewSource | None":
        return self if self in {SmartViewSource.DNS, SmartViewSource.LDAP} else None


@dataclass(frozen=True)
class SmartViewDefaults:
    days: int
    disabled_days: int
    never_logged_days: int
    max_rows: int

    @classmethod
    def configured(cls) -> "SmartViewDefaults":
        return cls(
            days=bounded_int(DEFAULT_SMART_DAYS, SMART_DAYS_FALLBACK),
            disabled_days=bounded_int(
                DEFAULT_SMART_DISABLED_DAYS, SMART_DISABLED_DAYS_FALLBACK
            ),
            never_logged_days=bounded_int(
                DEFAULT_SMART_NEVER_LOGGED_DAYS, SMART_NEVER_LOGGED_DAYS_FALLBACK
            ),
            max_rows=bounded_int(
                DEFAULT_SMART_MAX_ROWS,
                SMART_ROW_LIMIT_FALLBACK,
                maximum=SMART_ROW_LIMIT_MAX,
            ),
        )


SMART_VIEW_DEFAULTS = SmartViewDefaults.configured()
SMART_ROW_LIMIT_DEFAULT = SMART_VIEW_DEFAULTS.max_rows


@dataclass(frozen=True)
class SmartViewDefinition:
    view_id: str
    shortcut: str
    source: SmartViewSource
    label: str
    description: str
    needs_days: bool = False
    needs_disabled_days: bool = False
    needs_never_logged_days: bool = False
    needs_ldap_connection: bool = False
    default_sort_field: str = "severity"
    default_sort_reverse: bool = False
    directory_kind: str = "users"

    @property
    def needs_ldap(self) -> bool:
        return self.source is SmartViewSource.LDAP or self.needs_ldap_connection

    @property
    def source_label(self) -> str:
        return self.source.value

    @property
    def row_source(self) -> str:
        return self.source.row_source


@dataclass(frozen=True)
class SmartViewOptions:
    days: int
    disabled_days: int
    never_logged_days: int
    max_rows: int

    @classmethod
    def from_values(
        cls,
        values: Mapping[str, str],
        defaults: SmartViewDefaults = SMART_VIEW_DEFAULTS,
    ) -> "SmartViewOptions":
        return cls(
            days=bounded_int(
                values.get("days") or values.get("smart_days"), defaults.days
            ),
            disabled_days=bounded_int(
                values.get("disabled_days") or values.get("smart_disabled_days"),
                defaults.disabled_days,
            ),
            never_logged_days=bounded_int(
                values.get("never_logged_days")
                or values.get("smart_never_logged_days"),
                defaults.never_logged_days,
            ),
            max_rows=bounded_int(
                values.get("max_rows") or values.get("smart_max_rows"),
                defaults.max_rows,
                maximum=SMART_ROW_LIMIT_MAX,
            ),
        )


SMART_VIEWS = (
    SmartViewDefinition(
        FULL_HEALTH_VIEW_ID,
        "8",
        SmartViewSource.FULL,
        "Full health dashboard",
        "Run key DNS and LDAP hygiene checks together with grouped summary counts.",
        needs_days=True,
        needs_disabled_days=True,
        needs_never_logged_days=True,
        needs_ldap_connection=True,
        default_sort_field="",
    ),
    SmartViewDefinition(
        "dns_duplicates",
        "1",
        SmartViewSource.DNS,
        "DNS duplicates/conflicts",
        "Identical DNS records and CNAME names that also have other record types.",
    ),
    SmartViewDefinition(
        "dns_a_without_ptr",
        "2",
        SmartViewSource.DNS,
        "DNS A records without matching PTR",
        "Forward IPv4 A records missing reverse DNS, or pointing at the wrong PTR.",
    ),
    SmartViewDefinition(
        "dns_ptr_without_a",
        "3",
        SmartViewSource.DNS,
        "DNS PTR records without matching A",
        "Reverse PTR records with no forward A record, or mismatched forward IPs.",
    ),
    SmartViewDefinition(
        "ldap_inactive_users",
        "4",
        SmartViewSource.LDAP,
        "LDAP inactive enabled users",
        "Enabled users whose last logon is older than the inactivity threshold.",
        needs_days=True,
        default_sort_field="age",
        default_sort_reverse=True,
    ),
    SmartViewDefinition(
        "ldap_delete_candidates",
        "5",
        SmartViewSource.LDAP,
        "LDAP user cleanup candidates",
        "Disabled users past retention, plus enabled users that never logged in.",
        needs_disabled_days=True,
        needs_never_logged_days=True,
        default_sort_field="age",
        default_sort_reverse=True,
    ),
    SmartViewDefinition(
        "ldap_stale_computers",
        "6",
        SmartViewSource.LDAP,
        "LDAP stale computer accounts",
        "Computer accounts with old or missing last-logon data.",
        needs_days=True,
        default_sort_field="age",
        default_sort_reverse=True,
        directory_kind="computers",
    ),
    SmartViewDefinition(
        "ldap_users_without_groups",
        "7",
        SmartViewSource.LDAP,
        "LDAP users with no secondary groups",
        "Enabled users whose memberOf list is empty except for their primary group.",
        default_sort_field="object",
    ),
)

SMART_VIEW_BY_ID = {view.view_id: view for view in SMART_VIEWS}
SMART_VIEW_BY_SHORTCUT = {view.shortcut: view for view in SMART_VIEWS}
SMART_VIEW_LABELS = {view.view_id: view.label for view in SMART_VIEWS}
SMART_DEFAULT_SORTS = {
    view.view_id: (view.default_sort_field, view.default_sort_reverse)
    for view in SMART_VIEWS
    if view.default_sort_field
}


def smart_view_source(value: str | SmartViewSource) -> SmartViewSource | None:
    try:
        return value if isinstance(value, SmartViewSource) else SmartViewSource(value)
    except ValueError:
        return None


def smart_views_for_source(
    source: str | SmartViewSource,
) -> tuple[SmartViewDefinition, ...]:
    parsed_source = smart_view_source(source)
    return tuple(view for view in SMART_VIEWS if view.source is parsed_source)


def shortcut_range(shortcuts: list[str]) -> str:
    if not shortcuts:
        return ""
    return shortcuts[0] if len(shortcuts) == 1 else f"{shortcuts[0]}-{shortcuts[-1]}"


def smart_view_shortcut_range(source: str | SmartViewSource) -> str:
    return shortcut_range([view.shortcut for view in smart_views_for_source(source)])


def all_smart_view_shortcut_range() -> str:
    return shortcut_range(
        [view.shortcut for view in sorted(SMART_VIEWS, key=lambda view: view.shortcut)]
    )
