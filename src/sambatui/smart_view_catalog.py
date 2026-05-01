from __future__ import annotations

from dataclasses import dataclass

from .remediation import bounded_int


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


@dataclass(frozen=True)
class SmartViewDefinition:
    view_id: str
    shortcut: str
    source: str
    label: str
    description: str
    needs_days: bool = False
    needs_disabled_days: bool = False
    needs_never_logged_days: bool = False
    needs_ldap_connection: bool = False

    @property
    def needs_ldap(self) -> bool:
        return self.source == "LDAP" or self.needs_ldap_connection


@dataclass(frozen=True)
class SmartViewOptions:
    days: int
    disabled_days: int
    never_logged_days: int
    max_rows: int

    @classmethod
    def from_values(cls, values: dict[str, str]) -> SmartViewOptions:
        return cls(
            days=bounded_int(values.get("days"), 90),
            disabled_days=bounded_int(values.get("disabled_days"), 180),
            never_logged_days=bounded_int(values.get("never_logged_days"), 30),
            max_rows=bounded_int(values.get("max_rows"), 500, maximum=5000),
        )


SMART_VIEWS = (
    SmartViewDefinition(
        FULL_HEALTH_VIEW_ID,
        "8",
        "Full",
        "Full health dashboard",
        "Run key DNS and LDAP hygiene checks together with grouped summary counts.",
        needs_days=True,
        needs_disabled_days=True,
        needs_never_logged_days=True,
        needs_ldap_connection=True,
    ),
    SmartViewDefinition(
        "dns_duplicates",
        "1",
        "DNS",
        "DNS duplicates/conflicts",
        "Identical DNS records and CNAME names that also have other record types.",
    ),
    SmartViewDefinition(
        "dns_a_without_ptr",
        "2",
        "DNS",
        "DNS A records without matching PTR",
        "Forward IPv4 A records missing reverse DNS, or pointing at the wrong PTR.",
    ),
    SmartViewDefinition(
        "dns_ptr_without_a",
        "3",
        "DNS",
        "DNS PTR records without matching A",
        "Reverse PTR records with no forward A record, or mismatched forward IPs.",
    ),
    SmartViewDefinition(
        "ldap_inactive_users",
        "4",
        "LDAP",
        "LDAP inactive enabled users",
        "Enabled users whose last logon is older than the inactivity threshold.",
        needs_days=True,
    ),
    SmartViewDefinition(
        "ldap_delete_candidates",
        "5",
        "LDAP",
        "LDAP user cleanup candidates",
        "Disabled users past retention, plus enabled users that never logged in.",
        needs_disabled_days=True,
        needs_never_logged_days=True,
    ),
    SmartViewDefinition(
        "ldap_stale_computers",
        "6",
        "LDAP",
        "LDAP stale computer accounts",
        "Computer accounts with old or missing last-logon data.",
        needs_days=True,
    ),
    SmartViewDefinition(
        "ldap_users_without_groups",
        "7",
        "LDAP",
        "LDAP users with no secondary groups",
        "Enabled users whose memberOf list is empty except for their primary group.",
    ),
)

SMART_VIEW_BY_ID = {view.view_id: view for view in SMART_VIEWS}
SMART_VIEW_BY_SHORTCUT = {view.shortcut: view for view in SMART_VIEWS}
SMART_VIEW_LABELS = {view.view_id: view.label for view in SMART_VIEWS}
