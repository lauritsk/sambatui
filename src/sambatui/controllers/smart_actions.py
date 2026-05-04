from __future__ import annotations

import asyncio

from textual import work

from ..dns.parsing import parse_records
from ..dns.validation import validate_record
from ..ldap.client import (
    DirectoryRow,
    LdapDirectoryClient,
)
from ..core.models import DnsRow
from ..ui.screens import (
    FormField,
    SmartViewChoice,
    SmartViewPickerScreen,
)
from ..smart_view_catalog import (
    FULL_HEALTH_DNS_VIEW_IDS,
    FULL_HEALTH_LDAP_VIEW_IDS,
    FULL_HEALTH_VIEW_ID,
    SMART_VIEW_BY_ID,
    SMART_VIEW_BY_SHORTCUT,
    SMART_VIEWS,
    SmartViewDefinition,
    SmartViewOptions,
)
from ..smart_views import (
    SmartViewCheckResult,
    SmartViewRow,
    full_health_dashboard_rows,
    ldap_delete_candidate_users,
    ldap_inactive_users,
    ldap_stale_computers,
    ldap_users_without_groups,
)
from ..app_constants import (
    DEFAULT_SMART_DAYS,
    DEFAULT_SMART_DISABLED_DAYS,
    DEFAULT_SMART_NEVER_LOGGED_DAYS,
    LDAP_LOAD_MORE_ROWS,
    LDAP_MAX_ROWS,
)
from .base import AppControllerBase
from .helpers import (
    DNS_SMART_ROW_BUILDERS,
)


class AppSmartActionsMixin(AppControllerBase):
    def smart_view_choices(self) -> list[SmartViewChoice]:
        return [
            (view.shortcut, view.view_id, view.source, view.label, view.description)
            for view in SMART_VIEWS
        ]

    def smart_threshold_fields(self, view: SmartViewDefinition) -> list[FormField]:
        fields: list[FormField] = []
        if view.needs_days:
            fields.append(
                (
                    "Stale/inactive days",
                    "days",
                    "90",
                    self.val("smart_days") or DEFAULT_SMART_DAYS,
                )
            )
        if view.needs_disabled_days:
            fields.append(
                (
                    "Disabled cleanup days",
                    "disabled_days",
                    "180",
                    self.val("smart_disabled_days") or DEFAULT_SMART_DISABLED_DAYS,
                )
            )
        if view.needs_never_logged_days:
            fields.append(
                (
                    "Never-logged-in days",
                    "never_logged_days",
                    "30",
                    self.val("smart_never_logged_days")
                    or DEFAULT_SMART_NEVER_LOGGED_DAYS,
                )
            )
        return fields

    def smart_view_fields(self, view: SmartViewDefinition) -> list[FormField]:
        fields = self.smart_threshold_fields(view)
        if view.needs_ldap:
            fields.extend(self.ldap_connection_fields(self.ldap_base_default()))
        fields.append(self.smart_max_rows_field())
        return fields

    async def dns_records_with_failures_for_smart_view(
        self,
    ) -> tuple[dict[str, list[DnsRow]], list[str]] | None:
        if not self.zones:
            await self.load_zones(restore_active_zone=False)
        if not self.zones:
            self.report_error("Load zones before DNS smart views.")
            return None

        records_by_zone: dict[str, list[DnsRow]] = {}
        failures: list[str] = []
        async with self.busy():
            for zone in self.zones:
                code, output = await self.run_samba_zone("query", zone, ["@", "ALL"])
                if code != 0:
                    failures.append(f"{zone}: {output.strip() or 'query failed'}")
                    continue
                records_by_zone[zone] = parse_records(output)
        return records_by_zone, failures

    async def dns_records_for_smart_view(self) -> dict[str, list[DnsRow]] | None:
        result = await self.dns_records_with_failures_for_smart_view()
        if result is None:
            return None
        records_by_zone, failures = result
        if failures:
            self.notify(
                f"Skipped {len(failures)} zone(s) with query errors", severity="error"
            )
        return records_by_zone

    def dns_smart_rows(
        self, view_id: str, records_by_zone: dict[str, list[DnsRow]]
    ) -> list[SmartViewRow]:
        builder = DNS_SMART_ROW_BUILDERS.get(view_id)
        if builder is None:
            return []
        return builder(records_by_zone)

    async def refresh_current_smart_view(self) -> None:
        view = SMART_VIEW_BY_ID.get(self.current_smart_view_id)
        values = getattr(self, "current_smart_values", {})
        if view is None:
            self.refresh_smart_view()
            return
        if view.view_id == FULL_HEALTH_VIEW_ID:
            if not values:
                self.refresh_smart_view()
                return
            await self.load_full_health_dashboard(
                values, SmartViewOptions.from_values(values), refreshed=True
            )
            return
        if view.source == "DNS":
            records_by_zone = await self.dns_records_for_smart_view()
            if records_by_zone is None:
                return
            rows = self.dns_smart_rows(view.view_id, records_by_zone)
        else:
            if not values:
                self.refresh_smart_view()
                return
            directory_rows = await self.ldap_directory_for_smart_view(view, values)
            if directory_rows is None:
                return
            rows = self.ldap_smart_rows(
                view.view_id,
                directory_rows,
                SmartViewOptions.from_values(values),
            )
        self.populate_smart_view(view.label, rows[: self.current_smart_max_rows])
        self.notify("Refreshed smart-view findings")

    async def load_more_smart_view(self) -> bool:
        if not self.current_smart_values or not self.current_smart_view_id:
            self.set_status("No smart view to extend. Press S to run a smart view.")
            return False
        max_rows = min(self.current_smart_max_rows + LDAP_LOAD_MORE_ROWS, LDAP_MAX_ROWS)
        if max_rows == self.current_smart_max_rows:
            self.set_status(f"Smart-view row limit already at {LDAP_MAX_ROWS}.")
            return False
        self.current_smart_max_rows = max_rows
        self.current_smart_values = {
            **self.current_smart_values,
            "max_rows": str(max_rows),
        }
        await self.refresh_current_smart_view()
        return True

    def selected_smart_row(self) -> SmartViewRow | None:
        if self.view_mode != "smart":
            return None
        return self.visible_row_at(self.visible_smart_view(), self.records_cursor_row())

    @work
    async def action_smart_view(self) -> None:
        view_id = await self.push_screen_wait(
            SmartViewPickerScreen(self.smart_view_choices())
        )
        if view_id is None:
            return
        await self.run_smart_view(view_id)

    @work
    async def action_smart_view_shortcut(self, shortcut: str) -> None:
        view = SMART_VIEW_BY_SHORTCUT.get(shortcut)
        if view is None:
            return
        await self.run_smart_view(view.view_id)

    def apply_smart_view_options(
        self, view: SmartViewDefinition, options: SmartViewOptions
    ) -> None:
        if view.needs_days:
            self.set_val("smart_days", str(options.days))
        if view.needs_disabled_days:
            self.set_val("smart_disabled_days", str(options.disabled_days))
        if view.needs_never_logged_days:
            self.set_val("smart_never_logged_days", str(options.never_logged_days))
        self.set_val("smart_max_rows", str(options.max_rows))
        self.save_preferences()

    def populate_smart_view_results(
        self, label: str, rows: list[SmartViewRow], max_rows: int
    ) -> None:
        self.set_search_text("", refresh=False)
        self.populate_smart_view(label, rows[:max_rows])
        self.notify(f"Loaded {min(len(rows), max_rows)} smart-view findings")

    async def ldap_directory_for_smart_view(
        self, view: SmartViewDefinition, values: dict[str, str]
    ) -> list[DirectoryRow] | None:
        self.apply_ldap_connection_values(values)

        client = self.ldap_client(values["base_dn"])
        error = client.validation_error()
        if error:
            self.report_error(error)
            return None

        kind = "computers" if view.view_id == "ldap_stale_computers" else "users"
        max_rows = SmartViewOptions.from_values(values).max_rows
        return await self.directory_search_rows(client, kind, "", max_rows)

    def ldap_smart_rows(
        self,
        view_id: str,
        directory_rows: list[DirectoryRow],
        options: SmartViewOptions,
    ) -> list[SmartViewRow]:
        match view_id:
            case "ldap_inactive_users":
                return ldap_inactive_users(directory_rows, days=options.days)
            case "ldap_delete_candidates":
                return ldap_delete_candidate_users(
                    directory_rows,
                    disabled_days=options.disabled_days,
                    never_logged_days=options.never_logged_days,
                )
            case "ldap_stale_computers":
                return ldap_stale_computers(directory_rows, days=options.days)
            case "ldap_users_without_groups":
                return ldap_users_without_groups(directory_rows)
            case _:
                return []

    async def dashboard_ldap_rows(
        self, client: LdapDirectoryClient, kind: str
    ) -> tuple[list[DirectoryRow] | None, str]:
        async with self.busy():
            try:
                return await asyncio.to_thread(client.search, kind, ""), ""
            except ValueError as exc:
                return None, str(exc)

    def dns_dashboard_results(
        self,
        records_by_zone: dict[str, list[DnsRow]],
        failures: list[str],
    ) -> list[SmartViewCheckResult]:
        results = [
            SmartViewCheckResult(
                view_id=view_id,
                label=SMART_VIEW_BY_ID[view_id].label,
                source="DNS",
                rows=self.dns_smart_rows(view_id, records_by_zone),
            )
            for view_id in FULL_HEALTH_DNS_VIEW_IDS
        ]
        if failures:
            results.append(
                SmartViewCheckResult(
                    view_id="dns_zone_queries",
                    label="DNS zone queries",
                    source="DNS",
                    error="; ".join(failures),
                )
            )
        return results

    def ldap_dashboard_results(
        self,
        user_rows: list[DirectoryRow] | None,
        user_error: str,
        computer_rows: list[DirectoryRow] | None,
        computer_error: str,
        options: SmartViewOptions,
    ) -> list[SmartViewCheckResult]:
        results: list[SmartViewCheckResult] = []
        for view_id in FULL_HEALTH_LDAP_VIEW_IDS:
            view = SMART_VIEW_BY_ID[view_id]
            if view_id == "ldap_stale_computers":
                rows = computer_rows
                error = computer_error
            else:
                rows = user_rows
                error = user_error
            results.append(
                SmartViewCheckResult(
                    view_id=view_id,
                    label=view.label,
                    source="LDAP",
                    rows=()
                    if rows is None
                    else self.ldap_smart_rows(view_id, rows, options),
                    error=error,
                )
            )
        return results

    def dns_dashboard_unloaded_results(self) -> list[SmartViewCheckResult]:
        return [
            SmartViewCheckResult(
                view_id=view_id,
                label=SMART_VIEW_BY_ID[view_id].label,
                source="DNS",
                error="DNS zones are not loaded.",
            )
            for view_id in FULL_HEALTH_DNS_VIEW_IDS
        ]

    async def dns_dashboard_check_results(self) -> list[SmartViewCheckResult]:
        dns_result = await self.dns_records_with_failures_for_smart_view()
        if dns_result is None:
            return self.dns_dashboard_unloaded_results()
        records_by_zone, failures = dns_result
        return self.dns_dashboard_results(records_by_zone, failures)

    def ldap_dashboard_validation_results(
        self, validation_error: str
    ) -> list[SmartViewCheckResult]:
        return [
            SmartViewCheckResult(
                view_id=view_id,
                label=SMART_VIEW_BY_ID[view_id].label,
                source="LDAP",
                error=validation_error,
            )
            for view_id in FULL_HEALTH_LDAP_VIEW_IDS
        ]

    async def ldap_dashboard_check_results(
        self, values: dict[str, str], options: SmartViewOptions
    ) -> list[SmartViewCheckResult]:
        self.apply_ldap_connection_values(values)
        client = self.ldap_client(values["base_dn"])
        validation_error = client.validation_error()
        if validation_error:
            return self.ldap_dashboard_validation_results(validation_error)

        user_rows, user_error = await self.dashboard_ldap_rows(client, "users")
        computer_rows, computer_error = await self.dashboard_ldap_rows(
            client, "computers"
        )
        return self.ldap_dashboard_results(
            user_rows, user_error, computer_rows, computer_error, options
        )

    async def load_full_health_dashboard(
        self,
        values: dict[str, str],
        options: SmartViewOptions,
        *,
        refreshed: bool = False,
    ) -> None:
        results = await self.dns_dashboard_check_results()
        results.extend(await self.ldap_dashboard_check_results(values, options))

        rows = full_health_dashboard_rows(results)
        self.populate_smart_view(
            "Full health dashboard",
            rows[: 1 + len(results) + options.max_rows],
        )
        action = "Refreshed" if refreshed else "Loaded"
        self.notify(f"{action} full health dashboard")

    async def run_smart_view(self, view_id: str) -> None:
        view = SMART_VIEW_BY_ID[view_id]
        values = await self.form(
            view.label,
            f"{view.description}\nRead-only hygiene findings. No deletes/changes are performed.",
            self.smart_view_fields(view),
            "Run",
        )
        if not values:
            return

        options = SmartViewOptions.from_values(values)
        self.apply_smart_view_options(view, options)
        self.current_smart_view_id = view.view_id
        self.current_smart_max_rows = options.max_rows
        self.current_smart_values = values

        if view.view_id == FULL_HEALTH_VIEW_ID:
            await self.load_full_health_dashboard(values, options)
            return

        if view.source == "DNS":
            records_by_zone = await self.dns_records_for_smart_view()
            if records_by_zone is None:
                return
            rows = self.dns_smart_rows(view.view_id, records_by_zone)
            self.populate_smart_view_results(view.label, rows, options.max_rows)
            return

        directory_rows = await self.ldap_directory_for_smart_view(view, values)
        if directory_rows is None:
            return
        rows = self.ldap_smart_rows(view.view_id, directory_rows, options)
        self.populate_smart_view_results(view.label, rows, options.max_rows)

    async def apply_smart_fix(self, row: SmartViewRow) -> None:
        if row.source == "ldap":
            self.notify("LDAP findings are read-only/export-only.", severity="error")
            return
        if row.fix_action != "dns_add_ptr":
            self.notify(
                "No guided fix is available for this finding.", severity="error"
            )
            return
        error = validate_record(row.fix_name, row.fix_rtype, row.fix_value)
        if error:
            self.report_error(error)
            return
        if not await self.confirm(
            "Fix smart finding?\n\n"
            "ADD DNS record\n"
            f"Zone: {row.fix_zone}\n"
            f"{row.fix_name} {row.fix_rtype} {row.fix_value}\n\n"
            f"Finding: {row.finding}\n"
            f"Evidence: {row.evidence}",
            default_confirm=True,
        ):
            self.notify("Fix cancelled")
            return
        async with self.busy():
            code, _ = await self.run_samba_zone(
                "add", row.fix_zone, [row.fix_name, row.fix_rtype, row.fix_value]
            )
        if code != 0:
            return
        self.notify(f"Applied fix: {row.fix_label}")
        await self.refresh_current_smart_view()

    @work
    async def action_fix_smart(self) -> None:
        row = self.selected_smart_row()
        if row is None:
            self.notify("Select a smart-view finding first.", severity="error")
            return
        await self.apply_smart_fix(row)
