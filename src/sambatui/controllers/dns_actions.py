from __future__ import annotations

from textual import work

from ..dns.validation import validate_record
from ..ui.screens import (
    FormField,
)
from ..app_constants import (
    DEFAULT_AUTO_PTR,
    GUIDED_RECORD_TYPE_FIELDS,
    GUIDED_RECORD_TYPES,
    GUIDED_RECORD_VALUE_FIELDS,
)
from .base import AppControllerBase


class AppDnsActionsMixin(AppControllerBase):
    @work
    async def action_query(self) -> None:
        values = await self.form(
            "Query DNS",
            "Query one name/type in the currently selected zone.",
            [
                ("Record name", "name", "name, @ = zone root", "@"),
                ("Record type", "rtype", "type, e.g. A or ALL", "ALL"),
            ],
            "Query",
        )
        if not values:
            return
        name = values["name"] or "@"
        rtype = (values["rtype"] or "ALL").upper()
        await self.do_command("query", [name, rtype], update_table=True)

    async def maybe_add_matching_ptr(self, name: str, rtype: str, value: str) -> None:
        if rtype != "A":
            return
        reverse = self.reverse_record_for_ipv4(value)
        auto_ptr = (self.val("auto_ptr") or DEFAULT_AUTO_PTR).casefold()
        if reverse is None or auto_ptr == "off":
            return
        ptr_zone, ptr_name = reverse
        ptr_target = self.ptr_target_for_name(name)
        if auto_ptr == "on" or await self.confirm(
            "Add matching PTR record?\n\n"
            f"Zone: {ptr_zone}\n{ptr_name} PTR {ptr_target}",
            default_confirm=True,
        ):
            await self.add_ptr(name, value)

    def add_record_args(self, name: str, rtype: str, value: str, ttl: str) -> list[str]:
        args = [name, rtype, value]
        if ttl:
            args.append(f"--ttl={ttl}")
        return args

    def record_type_selection_error(self, values: dict[str, str]) -> str | None:
        rtype = (values.get("rtype") or "").upper()
        if rtype in GUIDED_RECORD_TYPES:
            return None
        return f"Choose one of: {', '.join(GUIDED_RECORD_TYPES)}."

    def add_record_type_fields(self, rtype: str) -> list[FormField]:
        return [
            ("Record name", "name", "name, @ for zone root", ""),
            *GUIDED_RECORD_TYPE_FIELDS.get(rtype.upper(), ()),
            ("TTL", "ttl", "optional seconds, e.g. 3600", ""),
        ]

    def add_record_value_from_fields(self, rtype: str, values: dict[str, str]) -> str:
        value_fields = GUIDED_RECORD_VALUE_FIELDS.get(rtype.upper())
        if value_fields is None:
            return values.get("value", "")
        if len(value_fields) == 1:
            return values.get(value_fields[0], "")
        return " ".join(values.get(key, "") for key in value_fields).strip()

    def ttl_error(self, ttl: str) -> str | None:
        if not ttl:
            return None
        if not ttl.isdecimal():
            return "TTL must be whole seconds, e.g. 3600."
        if int(ttl) <= 0:
            return "TTL must be greater than zero."
        return None

    def duplicate_record_error(self, name: str, rtype: str, value: str) -> str | None:
        for row in self.record_rows:
            if row.name == name and row.rtype == rtype and row.value == value:
                return "Duplicate record already exists in the loaded zone view."
        return None

    def guided_add_record_error(self, rtype: str, values: dict[str, str]) -> str | None:
        name = values.get("name", "")
        value = self.add_record_value_from_fields(rtype, values)
        ttl = values.get("ttl", "")
        return (
            validate_record(name, rtype, value)
            or self.ttl_error(ttl)
            or self.duplicate_record_error(name, rtype.upper(), value)
        )

    def existing_reverse_record_for_ipv4(self, ip_value: str) -> tuple[str, str] | None:
        reverse = self.reverse_record_for_ipv4(ip_value)
        if reverse is None:
            return None
        ptr_zone, ptr_name = reverse
        if ptr_zone not in self.zones:
            return None
        return ptr_zone, ptr_name

    def ptr_preview_text(self, name: str, rtype: str, value: str) -> str:
        if rtype != "A":
            return "PTR suggestion: not applicable."
        reverse = self.existing_reverse_record_for_ipv4(value)
        if reverse is None:
            return "PTR suggestion: no loaded reverse zone matches this IPv4 address."
        ptr_zone, ptr_name = reverse
        ptr_target = self.ptr_target_for_name(name)
        return f"PTR suggestion: reverse zone exists; {ptr_zone}: {ptr_name} PTR {ptr_target}"

    def add_record_preview(self, name: str, rtype: str, value: str, ttl: str) -> str:
        args = self.add_record_args(name, rtype, value, ttl)
        client = self.samba_client()
        command = " ".join(
            client.redact_command(client.dns_command("add", self.val("zone"), args))
        )
        return (
            "Add DNS record?\n\n"
            f"Zone: {self.val('zone')}\n"
            f"Record: {name} {rtype} {value}\n"
            f"TTL: {ttl or 'default'}\n"
            f"{self.ptr_preview_text(name, rtype, value)}\n\n"
            f"Command preview: {command}"
        )

    async def add_record_form_values(self) -> tuple[str, str, str, str] | None:
        type_values = await self.form(
            "Add DNS record — choose type",
            f"Zone: {self.val('zone')}. Guided flow shows fields for one record type.",
            [
                (
                    "Record type",
                    "rtype",
                    "A / AAAA / CNAME / PTR / TXT / MX / SRV / NS",
                    "A",
                ),
            ],
            "Next",
            self.record_type_selection_error,
        )
        if not type_values:
            return None

        rtype = (type_values["rtype"] or "A").upper()
        values = await self.form(
            f"Add {rtype} record",
            "Invalid input is caught before confirmation. Examples are shown in each field.",
            self.add_record_type_fields(rtype),
            "Preview",
            lambda form_values: self.guided_add_record_error(rtype, form_values),
        )
        if not values:
            return None

        name = values["name"]
        value = self.add_record_value_from_fields(rtype, values)
        ttl = values["ttl"]
        error = self.guided_add_record_error(rtype, values)
        if error:
            self.report_error(error)
            return None
        return name, rtype, value, ttl

    @work
    async def action_add(self) -> None:
        if self.view_mode == "directory":
            await self.add_ldap_entry()
            return
        record_values = await self.add_record_form_values()
        if record_values is None:
            return
        name, rtype, value, ttl = record_values
        if not await self.confirm(
            self.add_record_preview(name, rtype, value, ttl),
            default_confirm=True,
        ):
            self.notify("Add cancelled")
            return
        if (
            await self.do_command("add", self.add_record_args(name, rtype, value, ttl))
            == 0
        ):
            await self.maybe_add_matching_ptr(name, rtype, value)
            await self.refresh_current_zone()

    def selected_record_for_update(self) -> dict[str, str] | None:
        records = self.selected_records()
        if len(records) > 1:
            self.notify(
                "Update works on one record only. Select one row.", severity="error"
            )
            return None
        if records:
            return records[0]
        self.notify(
            "Select a real record row first. Rows with type '-' are empty/folder nodes.",
            severity="error",
        )
        return None

    def update_record_fields(self, selected: dict[str, str]) -> list[FormField]:
        return [
            ("Record name", "name", "name, @ for zone root", selected["name"]),
            (
                "Current type (used to find/delete old record)",
                "old_rtype",
                "current type",
                selected["rtype"],
            ),
            (
                "New type",
                "rtype",
                "A / AAAA / CNAME / PTR / TXT / MX / SRV",
                selected["rtype"],
            ),
            (
                "Old/current DNS value (exact match required)",
                "old_value",
                "old/current value",
                selected["value"],
            ),
            ("New DNS value", "value", "new value", selected["value"]),
        ]

    async def change_record_type(
        self, name: str, old_rtype: str, old_value: str, rtype: str, value: str
    ) -> None:
        message = (
            "Change DNS record type?\n\n"
            f"Zone: {self.val('zone')}\n"
            f"DELETE: {name} {old_rtype} {old_value}\n"
            f"ADD:    {name} {rtype} {value}\n\n"
            "If the add fails, the old record may already be deleted."
        )
        if not await self.confirm(message):
            self.notify("Type change cancelled")
            return
        if (
            await self.do_command("delete", [name, old_rtype, old_value]) == 0
            and await self.do_command("add", [name, rtype, value]) == 0
        ):
            await self.refresh_current_zone()

    async def update_record_value(
        self, name: str, rtype: str, old_value: str, value: str
    ) -> None:
        if not await self.confirm(
            f"Update DNS record?\n\nZone: {self.val('zone')}\n{name} {rtype}\nOld: {old_value}\nNew: {value}"
        ):
            self.notify("Update cancelled")
            return
        if await self.do_command("update", [name, rtype, old_value, value]) == 0:
            await self.refresh_current_zone()

    @work
    async def action_update(self) -> None:
        if self.view_mode == "directory":
            await self.update_ldap_entry()
            return
        selected = self.selected_record_for_update()
        if selected is None:
            return
        values = await self.form(
            "Update selected DNS record",
            "To change record type (example A -> CNAME), set New type. That will DELETE the old record, then ADD the new one.",
            self.update_record_fields(selected),
            "Update",
        )
        if not values:
            return
        name = values["name"]
        old_rtype = (values["old_rtype"] or selected["rtype"]).upper()
        rtype = (values["rtype"] or old_rtype).upper()
        old_value = values["old_value"]
        value = values["value"]
        error = validate_record(
            name, old_rtype, "", require_value=False
        ) or validate_record(name, rtype, value)
        if error:
            self.report_error(error)
            return

        if old_rtype != rtype:
            await self.change_record_type(name, old_rtype, old_value, rtype, value)
            return
        await self.update_record_value(name, rtype, old_value, value)

    @work
    async def action_delete(self) -> None:
        if self.view_mode == "directory":
            await self.delete_ldap_entry()
            return
        records = self.selected_records()
        if not records:
            self.notify(
                "Select one or more real record rows first. Rows with type '-' are empty/folder nodes.",
                severity="error",
            )
            return
        preview = "\n".join(
            f"{record['name']} {record['rtype']} {record['value']}"
            for record in records[:12]
        )
        if len(records) > 12:
            preview += f"\n... and {len(records) - 12} more"
        if not await self.confirm(
            f"DELETE {len(records)} selected DNS record(s)?\n\nZone: {self.val('zone')}\n{preview}\n\nThis cannot be undone from this app."
        ):
            self.notify("Delete cancelled")
            return
        failed = 0
        for record in records:
            code = await self.do_command(
                "delete", [record["name"], record["rtype"], record["value"]]
            )
            if code != 0:
                failed += 1
        if failed:
            self.notify(f"Deleted with {failed} failure(s)", severity="error")
        await self.refresh_current_zone()
