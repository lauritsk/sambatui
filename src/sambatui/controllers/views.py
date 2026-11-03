from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from contextlib import suppress

from rich.text import Text
from textual.widgets import DataTable, Input, Label, Static, TabbedContent

from ..app_constants import (
    DEFAULT_LDAP_COMPATIBILITY,
    DEFAULT_LDAP_ENCRYPTION,
    DIRECTORY_SORT_KEYS,
    LDAP_DEFAULT_MAX_ROWS,
    RECORD_SORT_KEYS,
)
from ..core.models import DnsRow
from ..core.view_state import ViewMode
from ..ldap.rows import DirectoryRow
from ..ldap.sidebar import (
    SidebarItem,
    active_ldap_sidebar_item,
    ldap_sidebar_items,
)
from ..smart_view_catalog import (
    FULL_HEALTH_VIEW_ID,
    SMART_DEFAULT_SORTS,
    SMART_VIEW_BY_ID,
    SmartViewOptions,
    SmartViewSource,
    smart_views_for_source,
)
from ..smart_views import (
    SmartViewRow,
    directory_object_name,
    dns_duplicate_records,
    ldap_delete_candidate_users,
    ldap_inactive_users,
    ldap_stale_computers,
    ldap_users_without_groups,
)
from ..ui.details import (
    details_empty_text,
    directory_details_text,
    dns_details_text,
    dns_ptr_status,
    smart_details_text,
)
from ..ui.tables import (
    DIRECTORY_COLUMNS,
    DNS_COLUMNS,
    DNS_EMPTY_STATE,
    SMART_COLUMNS,
    RowValues,
    directory_result_values,
    directory_search_values,
    dns_result_values,
    dns_search_values,
    empty_state_text,
    matches_search,
    smart_result_values,
    smart_search_values,
)
from .helpers import (
    SMART_SORT_KEYS,
    TableRow,
    directory_sort_label,
    smart_sort_label,
    sort_direction,
)
from .selection import AppSelectionMixin
from .view_data import AppViewDataMixin

RESULT_COLUMNS = {
    ViewMode.DNS: DNS_COLUMNS,
    ViewMode.DIRECTORY: DIRECTORY_COLUMNS,
    ViewMode.SMART: SMART_COLUMNS,
}


class AppViewsMixin(AppViewDataMixin, AppSelectionMixin):
    def populate_sidebar_table(
        self, table_id: str, items: Sequence[SidebarItem]
    ) -> None:
        table = self.query_one(f"#{table_id}", DataTable)
        self.sidebar_items[table_id] = list(items)
        table.clear()
        for item in items:
            table.add_row(item.label)

    def sidebar_item_at(self, table_id: str, row_index: int) -> SidebarItem | None:
        items = self.sidebar_items.get(table_id, [])
        if 0 <= row_index < len(items):
            return items[row_index]
        return None

    def select_sidebar_cursor(self, table_id: str, target: SidebarItem) -> bool:
        table = self.query_one(f"#{table_id}", DataTable)
        for row_index, item in enumerate(self.sidebar_items.get(table_id, [])):
            if item.action == target.action and item.value == target.value:
                with suppress(Exception):
                    table.move_cursor(row=row_index)
                return True
        return False

    def populate_zones(self, zones: list[str]) -> None:
        items = [SidebarItem(zone, zone, "dns_zone") for zone in zones] or [
            SidebarItem("No zones loaded — press z to load zones", "", "empty")
        ]
        self.populate_sidebar_table("zones", items)
        self.select_zone_cursor(self.val("zone"))

    def populate_smart_views_sidebar(self) -> None:
        self.populate_finding_sidebar("dns_findings", "DNS")
        self.populate_finding_sidebar("ldap_findings", "LDAP")
        self.select_smart_view_cursor()

    def populate_finding_sidebar(self, table_id: str, source: str) -> None:
        self.populate_sidebar_table(
            table_id,
            [
                SidebarItem(
                    view.label.removeprefix(f"{source} "), view.view_id, "smart_view"
                )
                for view in smart_views_for_source(source)
            ],
        )

    def ldap_sidebar_items(self, rows: Sequence[DirectoryRow]) -> list[SidebarItem]:
        return ldap_sidebar_items(rows, self.ldap_base_default())

    def active_ldap_sidebar_item(self) -> SidebarItem | None:
        return active_ldap_sidebar_item(
            self.views.directory.values, self.ldap_base_default()
        )

    def select_ldap_sidebar_cursor(self) -> None:
        active_item = self.active_ldap_sidebar_item()
        if active_item is not None:
            self.select_sidebar_cursor("ldap_structure", active_item)

    def populate_ldap_structure(self, rows: Sequence[DirectoryRow]) -> None:
        self.populate_sidebar_table("ldap_structure", self.ldap_sidebar_items(rows))
        self.select_ldap_sidebar_cursor()

    def select_zone_cursor(self, zone: str) -> None:
        if zone:
            self.select_sidebar_cursor("zones", SidebarItem("", zone, "dns_zone"))

    def select_smart_view_cursor(self) -> None:
        view_id = self.views.smart.view_id
        if view_id:
            for table_id in ("dns_findings", "ldap_findings"):
                self.select_sidebar_cursor(
                    table_id, SidebarItem("", view_id, "smart_view")
                )

    async def restore_active_zone_records(self) -> bool:
        zone = self.val("zone")
        if not zone or zone not in self.zones:
            return False
        self.select_zone_cursor(zone)
        await self.activate_zone(zone, save=False)
        return True

    def dns_title(self) -> str:
        zone = self.val("zone")
        return f"Records — {zone}" if zone else "Records"

    def records_title(self) -> str:
        suffix = self.active_smart_filter_suffix()
        base = self.dns_title()
        return f"{base} {suffix}" if suffix else base

    def active_smart_filter_suffix(self) -> str:
        view = SMART_VIEW_BY_ID.get(self.views.smart.view_id)
        if view is None or view.view_id == FULL_HEALTH_VIEW_ID:
            return ""
        label = view.label.removeprefix(f"{view.source_label} ")
        return f"— {label}"

    def update_records_title(self) -> None:
        self.query_one("#records_title", Label).update(self.records_title())

    async def activate_zone(self, zone: str, *, save: bool = True) -> bool:
        if zone not in self.zones:
            self.set_status(DNS_EMPTY_STATE[1])
            return False
        self.query_one("#zone", Input).value = zone
        self.refresh_connection_summary()
        self.update_records_title()
        if save:
            self.save_preferences()
        self.set_status(f"Loading records for {zone}")
        await self.refresh_current_zone()
        return True

    def ldap_sidebar_values(
        self, kind: str, text: str = "", search_base_dn: str = ""
    ) -> dict[str, str]:
        base_dn = self.ldap_base_default()
        return {
            "kind": kind,
            "text": text,
            "base_dn": base_dn,
            "search_base_dn": search_base_dn or base_dn,
            "ldap_encryption": self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            "ldap_compatibility": self.val("ldap_compatibility")
            or DEFAULT_LDAP_COMPATIBILITY,
            "max_rows": str(LDAP_DEFAULT_MAX_ROWS),
        }

    async def activate_ldap_sidebar(
        self, kind: str, text: str = "", search_base_dn: str = ""
    ) -> bool:
        with suppress(Exception):
            self.query_one("#side_tabs", TabbedContent).active = "ldap_tab"
            self.refresh_key_hints()
        label = search_base_dn or text or kind
        self.set_status(f"Loading LDAP {label}")
        return await self.run_directory_search(
            self.ldap_sidebar_values(kind, text, search_base_dn),
            default_kind=kind,
            action="Loaded",
        )

    async def activate_sidebar_item(self, item: SidebarItem | None) -> bool:
        if item is None or item.action == "empty":
            return False
        if item.action == "dns_zone":
            return await self.activate_zone(item.value)
        if item.action == "ldap_root":
            return await self.activate_ldap_sidebar("all")
        if item.action == "ldap_dn":
            return await self.activate_ldap_sidebar("all", search_base_dn=item.value)
        if item.action == "smart_view" and item.value in SMART_VIEW_BY_ID:
            self.action_smart_view_shortcut(SMART_VIEW_BY_ID[item.value].shortcut)
            return True
        return False

    async def activate_sidebar_selection(self, table: DataTable) -> bool:
        return await self.activate_sidebar_item(
            self.sidebar_item_at(str(table.id or ""), table.cursor_row)
        )

    def set_records_columns(self, columns: tuple[str, ...]) -> None:
        if self.records_columns == columns:
            return
        table = self.query_one("#records", DataTable)
        table.clear(columns=True)
        table.add_columns(*columns)
        self.records_columns = columns

    def activate_results_view(self, mode: ViewMode, title: str) -> None:
        self.views.activate(mode)
        self.set_records_columns(RESULT_COLUMNS[mode])
        self.query_one("#records_title", Label).update(title)

    def populate_records(self, rows: list[DnsRow]) -> None:
        self.activate_results_view(ViewMode.DNS, self.dns_title())
        self.views.dns.rows = self.sorted_records(rows)
        self.refresh_record_view()
        self.set_status(
            f"Loaded {len(rows)} records from {self.val('zone')}; sorted by {self.views.dns.sort_field}"
        )

    def remember_ldap_structure_rows(self, rows: Sequence[DirectoryRow]) -> None:
        by_dn = {row.dn.casefold(): row for row in self.ldap_structure_rows}
        for row in rows:
            by_dn.setdefault(row.dn.casefold(), row)
        self.ldap_structure_rows = list(by_dn.values())

    def populate_directory(self, rows: list[DirectoryRow]) -> None:
        self.activate_results_view(ViewMode.DIRECTORY, "Directory (LDAP)")
        self.views.directory.rows = self.sorted_directory(rows)
        self.remember_ldap_structure_rows(rows)
        self.populate_ldap_structure(self.ldap_structure_rows)
        self.refresh_directory_view()
        self.set_status(f"Loaded {len(rows)} LDAP entries")

    def populate_smart_view(self, title: str, rows: list[SmartViewRow]) -> None:
        self.activate_results_view(ViewMode.SMART, title)
        view = SMART_VIEW_BY_ID.get(self.views.smart.view_id)
        source = view.source.sidebar_source if view is not None else None
        tab_id = "ldap_tab" if source is SmartViewSource.LDAP else "dns_tab"
        with suppress(Exception):
            self.query_one("#side_tabs", TabbedContent).active = tab_id
            self.refresh_key_hints()
        self.views.smart.rows = self.sorted_smart_view(rows)
        self.select_smart_view_cursor()
        self.refresh_smart_view()
        self.set_status(f"Loaded {len(rows)} smart-view findings")

    def smart_options_for_passive_findings(self) -> tuple[int, int, int]:
        options = SmartViewOptions.from_values(
            {
                "smart_days": self.val("smart_days"),
                "smart_disabled_days": self.val("smart_disabled_days"),
                "smart_never_logged_days": self.val("smart_never_logged_days"),
            }
        )
        return options.days, options.disabled_days, options.never_logged_days

    def passive_dns_findings(self, rows: Sequence[DnsRow]) -> list[SmartViewRow]:
        zone = self.val("zone")
        if not zone:
            return []
        # This view only has records from one zone. Forward/reverse checks
        # require both zones and belong in the explicit DNS finding views.
        return dns_duplicate_records({zone: rows})

    def passive_directory_findings(
        self, rows: Sequence[DirectoryRow]
    ) -> list[SmartViewRow]:
        days, disabled_days, never_logged_days = (
            self.smart_options_for_passive_findings()
        )
        return [
            *ldap_inactive_users(rows, days=days),
            *ldap_delete_candidate_users(
                rows,
                disabled_days=disabled_days,
                never_logged_days=never_logged_days,
            ),
            *ldap_stale_computers(rows, days=days),
            *ldap_users_without_groups(rows),
        ]

    def highest_severity(self, severities: Iterable[str]) -> str:
        order = {"critical": 0, "error": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return min(
            severities,
            key=lambda severity: order.get(severity.casefold(), 99),
            default="",
        )

    def dns_row_severity(self, row: DnsRow, findings: Sequence[SmartViewRow]) -> str:
        zone_prefix = f"{self.val('zone')}:"
        exact = f"{zone_prefix}{row.name}".casefold()
        fqdn = f"{row.name}.{self.val('zone')}".casefold()
        return self.highest_severity(
            finding.severity
            for finding in findings
            if finding.object.casefold() == exact or fqdn in finding.object.casefold()
        )

    def directory_row_severity(
        self, row: DirectoryRow, findings: Sequence[SmartViewRow]
    ) -> str:
        object_names = {
            row.name.casefold(),
            row.dn.casefold(),
            directory_object_name(row).casefold(),
        }
        return self.highest_severity(
            finding.severity
            for finding in findings
            if finding.object.casefold() in object_names
            or finding.fix_dn.casefold() == row.dn.casefold()
        )

    def severity_marker(self, severity: str, *, quiet: bool = False) -> Text | str:
        if not severity:
            return ""
        styles = {
            "critical": "red",
            "error": "red",
            "high": "orange3",
            "medium": "yellow3",
            "low": "steel_blue",
            "info": "grey54",
        }
        marker = "•" if quiet else "▌"
        return Text(marker, style=styles.get(severity.casefold(), "grey54"))

    def smart_row_marker(self, row: SmartViewRow) -> Text | str:
        return self.severity_marker(row.severity, quiet=True)

    def render_result_rows(
        self,
        rows: list[TableRow],
        view_mode: str,
        row_values: Callable[[TableRow], RowValues],
        marker: Callable[[TableRow], Text | str] | None = None,
    ) -> None:
        self.reset_render_state()
        table = self.query_one("#records", DataTable)
        table.clear()
        if rows:
            for row in rows:
                values = row_values(row)
                if marker is None:
                    table.add_row("", *values)
                else:
                    table.add_row("", marker(row), *values)
        else:
            title, hint = self.empty_state_text(view_mode)
            empty_values = {
                "dns": ("", "", title, "-", hint, ""),
                "directory": ("", "", title, "-", hint),
                "smart": ("", "-", title, hint),
            }
            table.add_row(*empty_values[view_mode])
        table.move_cursor(row=0)
        self.update_details_pane()

    def render_records(self, rows: list[DnsRow]) -> None:
        findings = self.passive_dns_findings(rows)
        self.render_result_rows(
            rows,
            "dns",
            dns_result_values,
            lambda row: self.severity_marker(self.dns_row_severity(row, findings)),
        )

    def render_directory(self, rows: list[DirectoryRow]) -> None:
        findings = self.passive_directory_findings(rows)
        self.render_result_rows(
            rows,
            "directory",
            directory_result_values,
            lambda row: self.severity_marker(
                self.directory_row_severity(row, findings)
            ),
        )

    def render_smart_view(self, rows: list[SmartViewRow]) -> None:
        self.render_result_rows(rows, "smart", smart_result_values)

    def details_empty_text(self) -> str:
        return details_empty_text(self.empty_state_text(self.views.mode))

    def records_cursor_row(self) -> int:
        with suppress(Exception):
            return self.query_one("#records", DataTable).cursor_row
        return 0

    def visible_row_at(self, rows: list[TableRow], row_index: int) -> TableRow | None:
        if 0 <= row_index < len(rows):
            return rows[row_index]
        return None

    def dns_details_text(self, row_index: int) -> str:
        row = self.visible_row_at(self.visible_records(), row_index)
        if row is None:
            return self.details_empty_text()
        ptr_status = dns_ptr_status(
            row,
            zones=self.zones,
            reverse_record_for_ipv4=self.reverse_record_for_ipv4,
            ptr_target_for_name=self.ptr_target_for_name,
        )
        return dns_details_text(row, zone=self.val("zone"), ptr_status=ptr_status)

    def directory_details_text(self, row_index: int) -> str:
        row = self.visible_row_at(self.visible_directory(), row_index)
        return self.details_empty_text() if row is None else directory_details_text(row)

    def smart_details_text(self, row_index: int) -> str:
        row = self.visible_row_at(self.visible_smart_view(), row_index)
        return self.details_empty_text() if row is None else smart_details_text(row)

    def current_details_text(self) -> str:
        getter = {
            ViewMode.DNS: self.dns_details_text,
            ViewMode.DIRECTORY: self.directory_details_text,
            ViewMode.SMART: self.smart_details_text,
        }.get(self.views.mode)
        return (
            self.details_empty_text()
            if getter is None
            else getter(self.records_cursor_row())
        )

    def update_details_pane(self) -> None:
        with suppress(Exception):
            self.query_one("#record_details", Static).update(
                self.current_details_text()
            )

    def empty_state_text(self, view_mode: str) -> tuple[str, str]:
        return empty_state_text(view_mode, self.search_text)

    def empty_state_status(self, view_mode: str) -> str:
        title, hint = self.empty_state_text(view_mode)
        return f"{title}. {hint}"

    def matches_search(self, values: Iterable[str]) -> bool:
        return matches_search(values, self.search_text)

    def visible_rows(
        self,
        rows: list[TableRow],
        search_values: Callable[[TableRow], Iterable[str]],
    ) -> list[TableRow]:
        if not self.search_text:
            return rows
        return [row for row in rows if self.matches_search(search_values(row))]

    def visible_records(self) -> list[DnsRow]:
        return self.visible_rows(self.views.dns.rows, dns_search_values)

    def visible_directory(self) -> list[DirectoryRow]:
        return self.visible_rows(self.views.directory.rows, directory_search_values)

    def visible_smart_view(self) -> list[SmartViewRow]:
        return self.visible_rows(self.views.smart.rows, smart_search_values)

    def visible_rows_for_mode(
        self, mode: ViewMode | str
    ) -> list[DnsRow] | list[DirectoryRow] | list[SmartViewRow]:
        getter = {
            ViewMode.DNS: self.visible_records,
            ViewMode.DIRECTORY: self.visible_directory,
            ViewMode.SMART: self.visible_smart_view,
        }.get(mode)
        return [] if getter is None else getter()

    def set_visible_status(
        self, shown: int, total: int, label: str, view_mode: str
    ) -> None:
        if not shown:
            self.set_status(self.empty_state_status(view_mode))
            return
        extra = f" matching /{self.search_text}/" if self.search_text else ""
        self.set_status(f"Showing {shown} of {total} {label}{extra}")

    def refresh_record_view(self) -> None:
        rows = self.visible_records()
        self.render_records(rows)
        self.set_visible_status(len(rows), len(self.views.dns.rows), "records", "dns")

    def refresh_directory_view(self) -> None:
        rows = self.visible_directory()
        self.render_directory(rows)
        self.set_visible_status(
            len(rows), len(self.views.directory.rows), "LDAP entries", "directory"
        )

    def refresh_smart_view(self) -> None:
        rows = self.visible_smart_view()
        self.render_smart_view(rows)
        self.set_visible_status(
            len(rows), len(self.views.smart.rows), "smart-view findings", "smart"
        )

    def clear_current_smart_view(self) -> None:
        view = SMART_VIEW_BY_ID.get(self.views.smart.view_id)
        if view is not None and view.source is SmartViewSource.LDAP:
            self.activate_results_view(ViewMode.DIRECTORY, "Directory (LDAP)")
        else:
            self.activate_results_view(ViewMode.DNS, self.dns_title())
        self.refresh_current_view()
        self.set_status("Finding filter cleared")

    def refresh_current_view(self) -> None:
        refresh = {
            ViewMode.DNS: self.refresh_record_view,
            ViewMode.DIRECTORY: self.refresh_directory_view,
            ViewMode.SMART: self.refresh_smart_view,
        }.get(self.views.mode)
        if refresh is None:
            self.set_status(self.empty_state_status(self.views.mode))
        else:
            refresh()

    def sorted_records(self, rows: list[DnsRow]) -> list[DnsRow]:
        state = self.views.dns
        return sorted(
            rows, key=RECORD_SORT_KEYS[state.sort_field], reverse=state.sort_reverse
        )

    def sorted_directory(self, rows: list[DirectoryRow]) -> list[DirectoryRow]:
        state = self.views.directory
        if not state.sort_field:
            return rows
        return sorted(
            rows, key=DIRECTORY_SORT_KEYS[state.sort_field], reverse=state.sort_reverse
        )

    def smart_sort_state(self) -> tuple[str, bool]:
        state = self.views.smart
        if state.sort_field:
            return state.sort_field, state.sort_reverse
        return SMART_DEFAULT_SORTS.get(state.view_id, ("", False))

    def sorted_smart_view(self, rows: list[SmartViewRow]) -> list[SmartViewRow]:
        field, reverse = self.smart_sort_state()
        if not field:
            return rows
        return sorted(rows, key=SMART_SORT_KEYS[field], reverse=reverse)

    def sort_smart_view(self, field: str) -> None:
        if field not in SMART_SORT_KEYS:
            return
        state = self.views.smart
        state.sort_by(field)
        state.rows = self.sorted_smart_view(state.rows)
        self.refresh_smart_view()
        direction = sort_direction(state.sort_reverse)
        self.set_status(f"Sorted smart view by {smart_sort_label(field)} ({direction})")

    def sort_directory(self, field: str) -> None:
        if field not in DIRECTORY_SORT_KEYS:
            return
        state = self.views.directory
        state.sort_by(field)
        state.rows = self.sorted_directory(state.rows)
        self.refresh_directory_view()
        direction = sort_direction(state.sort_reverse)
        self.set_status(
            f"Sorted LDAP by {directory_sort_label(field)} ({direction}); selection cleared"
        )

    def sort_records(self, field: str) -> None:
        match self.views.mode:
            case "dns":
                if field not in RECORD_SORT_KEYS:
                    return
                state = self.views.dns
                state.sort_by(field)
                state.rows = self.sorted_records(state.rows)
                self.refresh_record_view()
                direction = sort_direction(state.sort_reverse)
                self.set_status(f"Sorted by {field} ({direction}); selection cleared")
            case "directory":
                self.sort_directory(field)
            case "smart":
                self.sort_smart_view(field)
            case _:
                self.set_status(self.empty_state_status(self.views.mode))

    def row_to_record(self, row_index: int) -> dict[str, str] | None:
        if self.views.mode != "dns":
            return None
        row = self.visible_row_at(self.visible_records(), row_index)
        if row is None or row.rtype == "-":
            return None
        return {
            "name": row.name,
            "rtype": row.rtype,
            "value": row.value,
            "ttl": row.ttl,
        }

    def selected_records(self) -> list[dict[str, str]]:
        row_indices = sorted(self.views.dns.selected_rows) or [
            self.records_cursor_row()
        ]
        records = [self.row_to_record(row_index) for row_index in row_indices]
        return [record for record in records if record]

    def selected_record(self) -> dict[str, str] | None:
        records = self.selected_records()
        return records[0] if len(records) == 1 else None
