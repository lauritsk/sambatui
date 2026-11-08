from __future__ import annotations

from typing import TYPE_CHECKING

from textual import work

from sambatui.app_constants import (
    GUIDED_RECORD_TYPE_FIELDS,
    GUIDED_RECORD_TYPES,
    GUIDED_RECORD_VALUE_FIELDS,
)
from sambatui.core.config import DEFAULT_AUTO_PTR

from ..core.mutations import mutation_action
from ..core.operations import DnsAddOperation, DnsDeleteOperation, DnsUpdateOperation
from ..dns.record_types import SUPPORTED_DNS_RECORD_TYPES_TEXT
from ..ui.screens import (
    FormField,
)

if TYPE_CHECKING:
    from ..app import SambatuiApp


class AppDnsActionsMixin:
    @work
    async def action_query(self: SambatuiApp) -> None:
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

    async def maybe_add_matching_ptr(
        self: SambatuiApp, name: str, rtype: str, value: str
    ) -> None:
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

    def record_type_selection_error(
        self: SambatuiApp, values: dict[str, str]
    ) -> str | None:
        rtype = (values.get("rtype") or "").upper()
        if rtype in GUIDED_RECORD_TYPES:
            return None
        return f"Choose one of: {', '.join(GUIDED_RECORD_TYPES)}."

    def add_record_type_fields(self: SambatuiApp, rtype: str) -> list[FormField]:
        return [
            ("Record name", "name", "name, @ for zone root", ""),
            *GUIDED_RECORD_TYPE_FIELDS.get(rtype.upper(), ()),
        ]

    def add_record_value_from_fields(
        self: SambatuiApp, rtype: str, values: dict[str, str]
    ) -> str:
        value_fields = GUIDED_RECORD_VALUE_FIELDS.get(rtype.upper())
        if value_fields is None:
            return values.get("value", "")
        if len(value_fields) == 1:
            return values.get(value_fields[0], "")
        return " ".join(values.get(key, "") for key in value_fields).strip()

    def duplicate_record_error(
        self: SambatuiApp, name: str, rtype: str, value: str
    ) -> str | None:
        for row in self.views.dns.rows:
            if row.name == name and row.rtype == rtype and row.value == value:
                return "Duplicate record already exists in the loaded zone view."
        return None

    def guided_add_record_error(
        self: SambatuiApp, rtype: str, values: dict[str, str]
    ) -> str | None:
        name = values.get("name", "")
        value = self.add_record_value_from_fields(rtype, values)
        operation = DnsAddOperation("", name, rtype, value)
        return operation.validation_error() or self.duplicate_record_error(
            name, rtype.upper(), value
        )

    def existing_reverse_record_for_ipv4(
        self: SambatuiApp, ip_value: str
    ) -> tuple[str, str] | None:
        reverse = self.reverse_record_for_ipv4(ip_value)
        if reverse is None:
            return None
        ptr_zone, ptr_name = reverse
        if ptr_zone not in self.zones:
            return None
        return ptr_zone, ptr_name

    def ptr_preview_text(self: SambatuiApp, name: str, rtype: str, value: str) -> str:
        if rtype != "A":
            return "PTR suggestion: not applicable."
        reverse = self.existing_reverse_record_for_ipv4(value)
        if reverse is None:
            return "PTR suggestion: no loaded reverse zone matches this IPv4 address."
        ptr_zone, ptr_name = reverse
        ptr_target = self.ptr_target_for_name(name)
        return f"PTR suggestion: reverse zone exists; {ptr_zone}: {ptr_name} PTR {ptr_target}"

    def add_operation_preview(self: SambatuiApp, operation: DnsAddOperation) -> str:
        client = self.samba_client()
        command = " ".join(
            client.redact_command(
                client.dns_command("add", operation.zone, operation.command_args)
            )
        )
        return (
            "Add DNS record?\n\n"
            f"Zone: {operation.zone}\n"
            f"Record: {operation.name} {operation.rtype} {operation.value}\n"
            "TTL: Samba default\n"
            f"{self.ptr_preview_text(operation.name, operation.rtype, operation.value)}\n\n"
            f"Command preview: {command}"
        )

    async def add_record_form_values(self: SambatuiApp) -> DnsAddOperation | None:
        type_values = await self.form(
            "Add DNS record — choose type",
            f"Zone: {self.val('zone')}. Guided flow shows fields for one record type.",
            [
                (
                    "Record type",
                    "rtype",
                    SUPPORTED_DNS_RECORD_TYPES_TEXT,
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
        error = self.guided_add_record_error(rtype, values)
        if error:
            self.report_error(error)
            return None
        return DnsAddOperation(self.val("zone"), name, rtype, value)

    @work
    @mutation_action
    async def action_add(self: SambatuiApp) -> None:
        match self.views.mode:
            case "directory":
                await self.add_ldap_entry()
                return
            case "smart":
                self.set_status(
                    "Add is unavailable in smart views; press f to fix DNS findings."
                )
                return
            case "dns":
                pass
            case _:
                self.set_status("No editable records view active.")
                return
        operation = await self.add_record_form_values()
        if operation is None:
            return
        if not await self.confirm(
            self.add_operation_preview(operation), default_confirm=True
        ):
            self.notify("Add cancelled")
            return
        async with self.busy():
            code, _ = await self.run_samba_zone(
                "add", operation.zone, list(operation.command_args)
            )
        if code == 0:
            self.notify("OK")
            await self.maybe_add_matching_ptr(
                operation.name, operation.rtype, operation.value
            )
            await self.refresh_current_zone()

    def selected_record_for_update(self: SambatuiApp) -> dict[str, str] | None:
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

    def update_record_fields(
        self: SambatuiApp, selected: dict[str, str]
    ) -> list[FormField]:
        return [("New DNS value", "value", "new value", selected["value"])]

    def update_record_error(
        self: SambatuiApp, selected: dict[str, str], values: dict[str, str]
    ) -> str | None:
        operation = DnsUpdateOperation(
            "",
            selected["name"],
            selected["rtype"],
            selected["value"],
            values.get("value", ""),
        )
        return operation.validation_error()

    @mutation_action
    async def apply_dns_update(
        self: SambatuiApp, operation: DnsUpdateOperation
    ) -> None:
        if not await self.confirm(
            "Update DNS record?\n\n"
            f"Zone: {operation.zone}\n"
            f"{operation.name} {operation.rtype}\n"
            f"Old: {operation.old_value}\n"
            f"New: {operation.new_value}"
        ):
            self.notify("Update cancelled")
            return
        async with self.busy():
            code, _ = await self.run_samba_zone(
                "update", operation.zone, list(operation.command_args)
            )
        if code == 0:
            self.notify("OK")
            await self.refresh_current_zone()

    async def update_record_value(
        self: SambatuiApp, name: str, rtype: str, old_value: str, value: str
    ) -> None:
        await self.apply_dns_update(
            DnsUpdateOperation(self.val("zone"), name, rtype, old_value, value)
        )

    @work
    @mutation_action
    async def action_update(self: SambatuiApp) -> None:
        match self.views.mode:
            case "directory":
                await self.update_ldap_entry()
                return
            case "smart":
                self.set_status(
                    "Update is unavailable in smart views; press f to fix DNS findings."
                )
                return
            case "dns":
                pass
            case _:
                self.set_status("No editable records view active.")
                return
        selected = self.selected_record_for_update()
        if selected is None:
            return
        values = await self.form(
            "Update selected DNS record",
            f"Selected: {selected['name']} {selected['rtype']} {selected['value']}. "
            "Name and type are fixed; add a new record explicitly to change either.",
            self.update_record_fields(selected),
            "Update",
            lambda form_values: self.update_record_error(selected, form_values),
        )
        if not values:
            return
        error = self.update_record_error(selected, values)
        if error:
            self.report_error(error)
            return

        await self.apply_dns_update(
            DnsUpdateOperation(
                self.val("zone"),
                selected["name"],
                selected["rtype"].upper(),
                selected["value"],
                values["value"],
            )
        )

    @work
    @mutation_action
    async def action_delete(self: SambatuiApp) -> None:
        match self.views.mode:
            case "directory":
                await self.delete_ldap_entry()
                return
            case "smart":
                self.set_status(
                    "Delete is unavailable in smart views; press f to fix DNS findings."
                )
                return
            case "dns":
                pass
            case _:
                self.set_status("No editable records view active.")
                return
        records = self.selected_records()
        if not records:
            self.notify(
                "Select one or more real record rows first. Rows with type '-' are empty/folder nodes.",
                severity="error",
            )
            return
        operations = [
            DnsDeleteOperation(
                self.val("zone"), record["name"], record["rtype"], record["value"]
            )
            for record in records
        ]
        preview = "\n".join(
            f"{operation.name} {operation.rtype} {operation.value}"
            for operation in operations[:12]
        )
        if len(records) > 12:
            preview += f"\n... and {len(records) - 12} more"
        if not await self.confirm(
            f"DELETE {len(records)} selected DNS record(s)?\n\nZone: {self.val('zone')}\n{preview}\n\nThis cannot be undone from this app."
        ):
            self.notify("Delete cancelled")
            return
        failed = 0
        for operation in operations:
            async with self.busy():
                code, _ = await self.run_samba_zone(
                    "delete", operation.zone, list(operation.command_args)
                )
            if code != 0:
                failed += 1
        if failed:
            self.notify(f"Deleted with {failed} failure(s)", severity="error")
        await self.refresh_current_zone()
