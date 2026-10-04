from __future__ import annotations

import asyncio

from textual import work

from ..dns.parsing import parse_records, parse_zones
from ..dns.ptr import ptr_target_for_name, reverse_record_for_ipv4
from ..ui.tables import DNS_EMPTY_STATE
from .base import AppControllerBase
from .helpers import ldap_limit_suffix


class AppViewDataMixin(AppControllerBase):
    """Network-backed loading for DNS and inline directory searches."""

    def ptr_target_for_name(self, name: str) -> str:
        return ptr_target_for_name(name, self.val("zone"))

    def reverse_record_for_ipv4(self, ip_value: str) -> tuple[str, str] | None:
        return reverse_record_for_ipv4(ip_value, self.zones)

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

    @work(group="inline_search", exclusive=True)
    async def refresh_inline_search_scope(
        self, search_text: str, view_mode: str
    ) -> None:
        await asyncio.sleep(0.35)
        if search_text != self.search_text or view_mode != self.views.mode:
            return
        if view_mode == "directory":
            await self.refresh_directory_search_scope(search_text)
        elif view_mode == "dns" and search_text:
            await self.refresh_dns_search_scope(search_text)

    async def refresh_directory_search_scope(self, search_text: str) -> bool:
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

        rows = await self.directory_search_rows(client, kind, search_text, limit)
        if rows is None:
            return False
        if search_text != self.search_text or self.views.mode != "directory":
            return False

        self.views.directory.values = {**values, "kind": kind, "max_rows": str(limit)}
        self.views.directory.max_rows = limit
        self.populate_directory(rows)
        self.set_status(
            f"Search matched {len(rows)} LDAP entries across directory "
            f"(limit {limit}){ldap_limit_suffix(len(rows), limit)}"
        )
        return True

    async def refresh_dns_search_scope(self, search_text: str) -> bool:
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
        ):
            return False
        self.views.dns.last_search_zone = zone
        self.populate_records(parse_records(output))
        return True

    async def refresh_current_zone(self) -> None:
        await self.do_command("query", ["@", "ALL"], update_table=True)

    async def action_load_zones(self) -> None:
        await self.load_zones()
