from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable, Sequence
from contextlib import suppress

from textual import work
from textual.coordinate import Coordinate
from textual.widgets import (
    DataTable,
    Input,
    Label,
    Static,
    TabbedContent,
)

from ..dns.parsing import parse_records, parse_zones
from ..dns.ptr import (
    ptr_target_for_name as dns_ptr_target_for_name,
    reverse_record_for_ipv4 as dns_reverse_record_for_ipv4,
)
from ..ldap.client import (
    DirectoryRow,
)
from ..ldap.sidebar import (
    SidebarItem,
    active_ldap_sidebar_item,
    ldap_sidebar_items,
)
from ..core.models import DnsRow
from ..smart_views import (
    SmartViewRow,
)
from ..smart_view_catalog import SMART_VIEW_BY_ID, SMART_VIEWS
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
from ..app_constants import (
    DEFAULT_LDAP_COMPATIBILITY,
    DEFAULT_LDAP_ENCRYPTION,
    DIRECTORY_SORT_KEYS,
    LDAP_DEFAULT_MAX_ROWS,
    RECORD_SORT_KEYS,
)
from .base import AppControllerBase
from .helpers import (
    SMART_DEFAULT_SORTS,
    SMART_SORT_KEYS,
    TableRow,
    directory_sort_label,
    ldap_limit_suffix,
    next_sort_state,
    smart_sort_label,
    sort_direction,
)


class AppViewsMixin(AppControllerBase):
    def ptr_target_for_name(self, name: str) -> str:
        return dns_ptr_target_for_name(name, self.val("zone"))

    def reverse_record_for_ipv4(self, ip_value: str) -> tuple[str, str] | None:
        return dns_reverse_record_for_ipv4(ip_value, self.zones)

    async def add_ptr(self, name: str, ip_value: str) -> int:
        reverse = self.reverse_record_for_ipv4(ip_value)
        if reverse is None:
            return 0
        ptr_zone, ptr_name = reverse
        ptr_target = self.ptr_target_for_name(name)
        code, _ = await self.run_samba_zone(
            "add", ptr_zone, [ptr_name, "PTR", ptr_target]
        )
        if code == 0:
            self.notify(f"Added PTR {ptr_name} -> {ptr_target}")
        return code

    async def load_zones(self, *, restore_active_zone: bool = True) -> None:
        async with self.busy():
            code, output = await self.run_zonelist()
            if code != 0:
                return
            zones = parse_zones(output)
            self.zones = zones
            self.populate_zones(zones)
            self.notify(f"Loaded {len(zones)} zones")
            if restore_active_zone and await self.restore_active_zone_records():
                return
            if not zones:
                self.set_status(DNS_EMPTY_STATE[1])
                return
            active_zone = self.val("zone")
            if active_zone:
                self.set_status(
                    f"Loaded {len(zones)} zones; saved zone {active_zone} not found"
                )
            else:
                self.set_status(
                    f"Loaded {len(zones)} zones; select a zone and press Enter"
                )

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
        items = [
            SidebarItem(f"Run {view.shortcut}", view.view_id, "smart_view")
            for view in SMART_VIEWS
        ]
        table = self.query_one("#smart_views", DataTable)
        self.sidebar_items["smart_views"] = items
        table.clear()
        for view in SMART_VIEWS:
            table.add_row(f"Run {view.shortcut}", view.label)
        self.select_smart_view_cursor()

    def ldap_sidebar_items(self, rows: Sequence[DirectoryRow]) -> list[SidebarItem]:
        return ldap_sidebar_items(rows, self.ldap_base_default())

    def active_ldap_sidebar_item(self) -> SidebarItem | None:
        return active_ldap_sidebar_item(
            self.current_directory_values, self.ldap_base_default()
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
        if self.current_smart_view_id:
            self.select_sidebar_cursor(
                "smart_views", SidebarItem("", self.current_smart_view_id, "smart_view")
            )

    async def restore_active_zone_records(self) -> bool:
        zone = self.val("zone")
        if not zone or zone not in self.zones:
            return False
        self.select_zone_cursor(zone)
        await self.activate_zone(zone, save=False)
        return True

    def records_title(self) -> str:
        zone = self.val("zone")
        return f"Records — {zone}" if zone else "Records"

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

    def populate_records(self, rows: list[DnsRow]) -> None:
        self.view_mode = "dns"
        self.set_records_columns(DNS_COLUMNS)
        self.update_records_title()
        self.record_rows = self.sorted_records(rows)
        self.refresh_record_view()
        self.set_status(
            f"Loaded {len(rows)} records from {self.val('zone')}; sorted by {self.sort_field}"
        )

    def remember_ldap_structure_rows(self, rows: Sequence[DirectoryRow]) -> None:
        by_dn = {row.dn.casefold(): row for row in self.ldap_structure_rows}
        for row in rows:
            by_dn.setdefault(row.dn.casefold(), row)
        self.ldap_structure_rows = list(by_dn.values())

    def populate_directory(self, rows: list[DirectoryRow]) -> None:
        self.view_mode = "directory"
        self.set_records_columns(DIRECTORY_COLUMNS)
        self.query_one("#records_title", Label).update("Directory (LDAP)")
        self.directory_rows = self.sorted_directory(rows)
        self.remember_ldap_structure_rows(rows)
        self.populate_ldap_structure(self.ldap_structure_rows)
        self.refresh_directory_view()
        self.set_status(f"Loaded {len(rows)} LDAP entries")

    def populate_smart_view(self, title: str, rows: list[SmartViewRow]) -> None:
        self.view_mode = "smart"
        with suppress(Exception):
            self.query_one("#side_tabs", TabbedContent).active = "smart_tab"
            self.refresh_key_hints()
        self.set_records_columns(SMART_COLUMNS)
        self.query_one("#records_title", Label).update(f"Smart View: {title}")
        self.smart_view_rows = self.sorted_smart_view(rows)
        self.select_smart_view_cursor()
        self.refresh_smart_view()
        self.set_status(f"Loaded {len(rows)} smart-view findings")

    def reset_render_state(self) -> None:
        self.selected_record_rows.clear()
        self.selection_anchor = None
        self.visual_selecting = False

    def render_result_rows(
        self,
        rows: list[TableRow],
        view_mode: str,
        row_values: Callable[[TableRow], RowValues],
    ) -> None:
        self.reset_render_state()
        table = self.query_one("#records", DataTable)
        table.clear()
        if rows:
            for row in rows:
                table.add_row("", *row_values(row))
        else:
            title, hint = self.empty_state_text(view_mode)
            table.add_row("", title, "-", hint, "", "", "")
        table.move_cursor(row=0)
        self.update_details_pane()

    def render_records(self, rows: list[DnsRow]) -> None:
        self.render_result_rows(rows, "dns", dns_result_values)

    def render_directory(self, rows: list[DirectoryRow]) -> None:
        self.render_result_rows(rows, "directory", directory_result_values)

    def render_smart_view(self, rows: list[SmartViewRow]) -> None:
        self.render_result_rows(rows, "smart", smart_result_values)

    def details_empty_text(self) -> str:
        return details_empty_text(self.empty_state_text(self.view_mode))

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
        row_index = self.records_cursor_row()
        match self.view_mode:
            case "dns":
                return self.dns_details_text(row_index)
            case "directory":
                return self.directory_details_text(row_index)
            case "smart":
                return self.smart_details_text(row_index)
            case _:
                return self.details_empty_text()

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
        return self.visible_rows(self.record_rows, dns_search_values)

    def visible_directory(self) -> list[DirectoryRow]:
        return self.visible_rows(self.directory_rows, directory_search_values)

    def visible_smart_view(self) -> list[SmartViewRow]:
        return self.visible_rows(self.smart_view_rows, smart_search_values)

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
        self.set_visible_status(len(rows), len(self.record_rows), "records", "dns")

    def refresh_directory_view(self) -> None:
        rows = self.visible_directory()
        self.render_directory(rows)
        self.set_visible_status(
            len(rows), len(self.directory_rows), "LDAP entries", "directory"
        )

    def refresh_smart_view(self) -> None:
        rows = self.visible_smart_view()
        self.render_smart_view(rows)
        self.set_visible_status(
            len(rows), len(self.smart_view_rows), "smart-view findings", "smart"
        )

    def refresh_current_view(self) -> None:
        match self.view_mode:
            case "dns":
                self.refresh_record_view()
            case "directory":
                self.refresh_directory_view()
            case "smart":
                self.refresh_smart_view()
            case _:
                self.set_status(self.empty_state_status(self.view_mode))

    @work(group="inline_search", exclusive=True)
    async def refresh_inline_search_scope(
        self, search_text: str, view_mode: str
    ) -> None:
        await asyncio.sleep(0.35)
        if search_text != self.search_text or view_mode != self.view_mode:
            return
        if view_mode == "directory":
            await self.refresh_directory_search_scope(search_text)
        elif view_mode == "dns" and search_text:
            await self.refresh_dns_search_scope(search_text)

    async def refresh_directory_search_scope(self, search_text: str) -> bool:
        if not self.current_directory_values:
            return False
        values = {
            **self.current_directory_values,
            "text": search_text,
            "max_rows": str(self.current_directory_max_rows),
        }
        limit = self.ldap_search_max_rows(values)
        kind = values.get("kind") or "users"
        client = self.ldap_client(values.get("search_base_dn") or values["base_dn"])
        error = client.validation_error()
        if error:
            self.report_error(error)
            return False

        rows = await self.directory_search_rows(client, kind, search_text, limit)
        if rows is None:
            return False
        if search_text != self.search_text or self.view_mode != "directory":
            return False

        self.current_directory_values = {**values, "kind": kind, "max_rows": str(limit)}
        self.current_directory_max_rows = limit
        self.populate_directory(rows)
        self.set_status(
            f"Search matched {len(rows)} LDAP entries across directory "
            f"(limit {limit}){ldap_limit_suffix(len(rows), limit)}"
        )
        return True

    async def refresh_dns_search_scope(self, search_text: str) -> bool:
        zone = self.val("zone")
        if not zone:
            return False
        if self._last_dns_search_zone == zone:
            return False
        async with self.busy():
            code, output = await self.run_samba("query", ["@", "ALL"])
        if code != 0:
            return False
        if search_text != self.search_text or self.view_mode != "dns":
            return False
        self._last_dns_search_zone = zone
        self.populate_records(parse_records(output))
        return True

    def sorted_records(self, rows: list[DnsRow]) -> list[DnsRow]:
        return sorted(
            rows,
            key=RECORD_SORT_KEYS[self.sort_field],
            reverse=self.sort_reverse,
        )

    def sorted_directory(self, rows: list[DirectoryRow]) -> list[DirectoryRow]:
        if not self.directory_sort_field:
            return rows
        return sorted(
            rows,
            key=DIRECTORY_SORT_KEYS[self.directory_sort_field],
            reverse=self.directory_sort_reverse,
        )

    def smart_sort_state(self) -> tuple[str, bool]:
        if self.current_smart_sort_field:
            return self.current_smart_sort_field, self.current_smart_sort_reverse
        return SMART_DEFAULT_SORTS.get(self.current_smart_view_id, ("", False))

    def sorted_smart_view(self, rows: list[SmartViewRow]) -> list[SmartViewRow]:
        field, reverse = self.smart_sort_state()
        if not field:
            return rows
        return sorted(rows, key=SMART_SORT_KEYS[field], reverse=reverse)

    def sort_smart_view(self, field: str) -> None:
        if field not in SMART_SORT_KEYS:
            return
        self.current_smart_sort_field, self.current_smart_sort_reverse = (
            next_sort_state(
                self.current_smart_sort_field, self.current_smart_sort_reverse, field
            )
        )
        self.smart_view_rows = self.sorted_smart_view(self.smart_view_rows)
        self.refresh_smart_view()
        direction = sort_direction(self.current_smart_sort_reverse)
        self.set_status(f"Sorted smart view by {smart_sort_label(field)} ({direction})")

    def sort_directory(self, field: str) -> None:
        if field not in DIRECTORY_SORT_KEYS:
            return
        self.directory_sort_field, self.directory_sort_reverse = next_sort_state(
            self.directory_sort_field, self.directory_sort_reverse, field
        )
        self.directory_rows = self.sorted_directory(self.directory_rows)
        self.refresh_directory_view()
        direction = sort_direction(self.directory_sort_reverse)
        self.set_status(f"Sorted LDAP by {directory_sort_label(field)} ({direction})")

    def sort_records(self, field: str) -> None:
        match self.view_mode:
            case "dns":
                self.sort_field, self.sort_reverse = next_sort_state(
                    self.sort_field, self.sort_reverse, field
                )
                self.record_rows = self.sorted_records(self.record_rows)
                self.refresh_record_view()
                direction = sort_direction(self.sort_reverse)
                self.set_status(f"Sorted by {field} ({direction}); selection cleared")
            case "directory":
                self.sort_directory(field)
            case "smart":
                self.sort_smart_view(field)
            case _:
                self.set_status(self.empty_state_status(self.view_mode))

    def set_record_selected(self, row_index: int, selected: bool) -> None:
        table = self.query_one("#records", DataTable)
        if not 0 <= row_index < table.row_count:
            return
        if selected:
            self.selected_record_rows.add(row_index)
        else:
            self.selected_record_rows.discard(row_index)
        table.update_cell_at(Coordinate(row_index, 0), "✓" if selected else "")
        table.refresh_row(row_index)

    def clear_record_selection(self) -> None:
        for row_index in list(self.selected_record_rows):
            self.set_record_selected(row_index, False)
        self.visual_selecting = False
        self.selection_anchor = None

    def select_record_range(self, start: int, end: int, *, clear: bool = True) -> None:
        table = self.query_one("#records", DataTable)
        if not table.row_count:
            return
        start = max(0, min(start, table.row_count - 1))
        end = max(0, min(end, table.row_count - 1))
        if clear:
            self.clear_record_selection()
        low, high = sorted((start, end))
        for row_index in range(low, high + 1):
            self.set_record_selected(row_index, True)
        self.set_status(f"Selected {len(self.selected_record_rows)} record(s)")

    def row_to_record(self, row_index: int) -> dict[str, str] | None:
        if self.view_mode != "dns":
            return None
        table = self.query_one("#records", DataTable)
        try:
            row = table.get_row_at(row_index)
        except Exception:
            return None
        if not row:
            return None
        values = [str(cell) for cell in row]
        if len(values) < 4 or values[2] == "-":
            return None
        return {
            "name": values[1],
            "rtype": values[2],
            "value": values[3],
            "ttl": values[4] if len(values) > 4 else "",
        }

    def selected_records(self) -> list[dict[str, str]]:
        row_indices = sorted(self.selected_record_rows) or [
            self.query_one("#records", DataTable).cursor_row
        ]
        records = [self.row_to_record(row_index) for row_index in row_indices]
        return [record for record in records if record]

    def selected_record(self) -> dict[str, str] | None:
        records = self.selected_records()
        return records[0] if len(records) == 1 else None

    async def refresh_current_zone(self) -> None:
        await self.do_command("query", ["@", "ALL"], update_table=True)

    async def action_load_zones(self) -> None:
        await self.load_zones()
