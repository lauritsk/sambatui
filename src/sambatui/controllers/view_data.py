from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from textual import work

from ..dns.parsing import parse_records, parse_zones
from ..dns.ptr import ptr_target_for_name, reverse_record_for_ipv4
from ..ui.tables import DNS_EMPTY_STATE

if TYPE_CHECKING:
    from ..app import SambatuiApp
from .helpers import ldap_limit_suffix


class AppViewDataMixin:
    """Network-backed loading for DNS and inline directory searches."""

    def ptr_target_for_name(self: SambatuiApp, name: str) -> str:
        return ptr_target_for_name(name, self.val("zone"))

    def reverse_record_for_ipv4(
        self: SambatuiApp, ip_value: str
    ) -> tuple[str, str] | None:
        return reverse_record_for_ipv4(ip_value, self.zones)

    async def add_ptr(self: SambatuiApp, name: str, ip_value: str) -> int:
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

    async def load_zones(
        self: SambatuiApp, *, restore_active_zone: bool = True
    ) -> None:
        revision = self.connection_revision
        async with self.busy():
            code, output = await self.run_zonelist()
            if code != 0 or revision != self.connection_revision:
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

    @work(group="inline_search", exclusive=True)
    async def refresh_inline_search_scope(
        self: SambatuiApp, search_text: str, view_mode: str
    ) -> None:
        await asyncio.sleep(0.35)
        if search_text != self.search_text or view_mode != self.views.mode:
            return
        if view_mode == "directory":
            await self.refresh_directory_search_scope(search_text)
        elif view_mode == "dns" and search_text:
            await self.refresh_dns_search_scope(search_text)

    async def refresh_directory_search_scope(
        self: SambatuiApp, search_text: str
    ) -> bool:
        if not self.views.directory.values:
            return False
        values = {
            **self.views.directory.values,
            "text": search_text,
            "max_rows": str(self.views.directory.max_rows),
        }
        limit = self.ldap_search_max_rows(values)
        kind = values.get("kind") or "users"
        client = self.ldap_client(values.get("search_base_dn") or values["base_dn"])
        error = client.validation_error()
        if error:
            self.report_error(error)
            return False

        revision = self.connection_revision
        rows = await self.directory_search_rows(client, kind, search_text, limit)
        if rows is None:
            return False
        if (
            search_text != self.search_text
            or self.views.mode != "directory"
            or revision != self.connection_revision
        ):
            return False

        self.views.directory.values = {**values, "kind": kind, "max_rows": str(limit)}
        self.views.directory.max_rows = limit
        self.populate_directory(rows)
        self.set_status(
            f"Search matched {len(rows)} LDAP entries across directory "
            f"(limit {limit}){ldap_limit_suffix(len(rows), limit)}"
        )
        return True

    async def refresh_dns_search_scope(self: SambatuiApp, search_text: str) -> bool:
        revision = self.connection_revision
        zone = self.val("zone")
        if not zone or self.views.dns.last_search_zone == zone:
            return False
        async with self.busy():
            code, output = await self.run_samba("query", ["@", "ALL"])
        if code != 0:
            return False
        if (
            search_text != self.search_text
            or self.views.mode != "dns"
            or zone != self.val("zone")
            or revision != self.connection_revision
        ):
            return False
        self.views.dns.last_search_zone = zone
        self.populate_records(parse_records(output))
        return True

    async def refresh_current_zone(self: SambatuiApp) -> None:
        if not self.connection_is_current():
            return
        await self.do_command("query", ["@", "ALL"], update_table=True)

    async def action_load_zones(self: SambatuiApp) -> None:
        await self.load_zones()
