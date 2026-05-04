from __future__ import annotations

import asyncio
import os
import shutil
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from textual import work
from textual.widgets import (
    Button,
    Input,
    Static,
)

from ..samba.client import SambaToolClient, SambaToolConfig
from ..core.config import (
    fix_password_file_permissions,
    is_reverse_dns_zone,
    password_file_permissions_too_open,
    password_file_warning,
    read_password_file,
    save_user_config,
    write_private_text,
)
from ..samba.discovery import (
    normalize_domain,
)
from ..dns.parsing import parse_records
from ..ldap.client import (
    DirectoryRow,
    LdapDirectoryClient,
    LdapSearchConfig,
)
from ..ldap.sidebar import (
    SidebarItem,
)
from ..core.models import DnsRow
from ..core.remediation import actionable_error
from ..ui.screens import (
    CommandPaletteScreen,
    ConfirmScreen,
    FormField,
    FormScreen,
    FormValidator,
    HelpScreen,
    infer_domain_from_server,
)
from ..core.settings import ConnectionSettings
from ..smart_views import (
    SmartViewRow,
)
from ..ui.tables import (
    DNS_COLUMNS,
)
from ..app_constants import (
    DEFAULT_AUTH,
    DEFAULT_AUTO_PTR,
    DEFAULT_LDAP_COMPATIBILITY,
    DEFAULT_LDAP_ENCRYPTION,
    DEFAULT_PASSWORD_FILE,
    DEFAULT_SMART_DAYS,
    DEFAULT_SMART_DISABLED_DAYS,
    DEFAULT_SMART_MAX_ROWS,
    DEFAULT_SMART_NEVER_LOGGED_DAYS,
    LDAP_DEFAULT_MAX_ROWS,
    PALETTE_ACTION_MAP,
    PALETTE_ACTIONS,
)
from .base import AppControllerBase


class AppCoreMixin(AppControllerBase):
    def on_mount(self) -> None:
        self.initialize_state()
        self.initialize_view()

        if not shutil.which("samba-tool"):
            self.report_error("samba-tool not found in PATH")
            return

        self.set_initial_connection_status()
        if self.connection_needs_setup():
            self.set_status(
                "Connection incomplete. Press w for setup wizard or Ctrl+O."
            )
        else:
            self.call_after_refresh(self.load_zones)

    def initialize_state(self) -> None:
        self.selected_record_rows: set[int] = set()
        self.selection_anchor: int | None = None
        self.visual_selecting = False
        self.record_rows: list[DnsRow] = []
        self.directory_rows: list[DirectoryRow] = []
        self.ldap_structure_rows: list[DirectoryRow] = []
        self.current_directory_values: dict[str, str] = {}
        self.current_directory_max_rows = LDAP_DEFAULT_MAX_ROWS
        self.smart_view_rows: list[SmartViewRow] = []
        self.current_smart_view_id = ""
        self.current_smart_max_rows = 500
        self.current_smart_values: dict[str, str] = {}
        self.current_smart_sort_field = ""
        self.current_smart_sort_reverse = False
        self.records_columns = DNS_COLUMNS
        self.view_mode = "dns"
        self.sort_field = "name"
        self.sort_reverse = False
        self.directory_sort_field = ""
        self.directory_sort_reverse = False
        self.search_text = ""
        self._syncing_search_input = False
        self.zones: list[str] = []
        self.sidebar_items: dict[str, list[SidebarItem]] = {}
        self.pending_g = False
        self._last_dns_search_zone = ""

    def initialize_view(self) -> None:
        self.refresh_connection_summary()
        self.update_records_title()
        self.populate_zones([])
        self.populate_ldap_structure([])
        self.action_focus_records()
        self.refresh_key_hints()
        self.render_records([])

    def set_initial_connection_status(self) -> None:
        if (self.val("auth") or DEFAULT_AUTH).casefold() == "kerberos":
            self.set_status("Kerberos auth selected. Run kinit if the ticket expires.")
            return
        warning = password_file_warning(self.password_file())
        if warning:
            self.report_error(warning)
        elif self.val("password"):
            self.set_status(f"Password loaded from env or {DEFAULT_PASSWORD_FILE}")
        else:
            self.set_status("Enter password, load password file, or use kerberos auth")

    def val(self, widget_id: str) -> str:
        return self.query_one(f"#{widget_id}", Input).value.strip()

    def set_status(self, message: str) -> None:
        with suppress(Exception):
            self.query_one("#status", Static).update(message)

    def report_error(self, message: str) -> None:
        text = actionable_error(message)
        self.notify(text[:200], severity="error", markup=False)
        self.set_status(text[:180])

    def set_val(self, widget_id: str, value: str) -> None:
        self.query_one(f"#{widget_id}", Input).value = value

    def preference_values(self) -> dict[str, str]:
        zone = self.val("zone")
        domain = self.connection_domain_default()
        return {
            "server": self.val("server"),
            "domain": domain,
            "zone": domain,
            "last_zone": zone,
            "auth": self.val("auth") or DEFAULT_AUTH,
            "ldap_base": self.val("ldap_base"),
            "ldap_encryption": self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            "ldap_compatibility": self.val("ldap_compatibility")
            or DEFAULT_LDAP_COMPATIBILITY,
            "auto_ptr": self.val("auto_ptr") or DEFAULT_AUTO_PTR,
            "smart_days": self.val("smart_days") or DEFAULT_SMART_DAYS,
            "smart_disabled_days": self.val("smart_disabled_days")
            or DEFAULT_SMART_DISABLED_DAYS,
            "smart_never_logged_days": self.val("smart_never_logged_days")
            or DEFAULT_SMART_NEVER_LOGGED_DAYS,
            "smart_max_rows": self.val("smart_max_rows") or DEFAULT_SMART_MAX_ROWS,
        }

    def save_preferences(self) -> None:
        try:
            save_user_config(self.preference_values())
        except OSError as exc:
            self.report_error(f"Cannot save preferences: {exc}")

    def connection_settings(self) -> ConnectionSettings:
        return ConnectionSettings.from_lookup(self.val)

    def connection_summary(self) -> str:
        return self.connection_settings().summary

    def connection_needs_setup(self) -> bool:
        return self.connection_settings().needs_setup(read_password_file)

    def normalized_domain_candidate(self, value: str) -> str:
        if not value or is_reverse_dns_zone(value):
            return ""
        try:
            return normalize_domain(value).lower()
        except ValueError:
            return ""

    def connection_domain_default(self) -> str:
        candidates = [
            self.val("domain"),
            self.val("zone"),
            infer_domain_from_server(self.val("server")),
            os.getenv("USERDNSDOMAIN", ""),
            os.getenv("SAMBATUI_DOMAIN", ""),
            infer_domain_from_server(socket.getfqdn()),
        ]
        return next(
            (
                normalized
                for candidate in candidates
                if (normalized := self.normalized_domain_candidate(candidate))
            ),
            "",
        )

    def discovery_domain_default(self) -> str:
        return self.connection_domain_default()

    def refresh_connection_summary(self) -> None:
        with suppress(Exception):
            self.query_one("#connection_summary", Static).update(
                f"Connection: {self.connection_summary()}"
            )

    def connection_fields(self) -> list[FormField]:
        return self.connection_settings().form_fields()

    def password_file(self) -> Path:
        return self.connection_settings().path_password_file

    def samba_config(self) -> SambaToolConfig:
        return self.connection_settings().samba_config()

    def samba_client(self) -> SambaToolClient:
        return SambaToolClient(self.samba_config())

    def ldap_config(self, base_dn: str = "") -> LdapSearchConfig:
        return self.connection_settings().ldap_config(base_dn)

    def ldap_client(self, base_dn: str = "") -> LdapDirectoryClient:
        return LdapDirectoryClient(self.ldap_config(base_dn))

    async def load_password(self) -> None:
        path = self.password_file()
        warning = password_file_warning(path)
        if warning:
            if not password_file_permissions_too_open(path):
                self.report_error(warning)
                return
            if not await self.confirm(
                f"Password file permissions too open: {path}\n\nFix with chmod 600 and load?"
            ):
                self.report_error(warning)
                return
            try:
                fix_password_file_permissions(path)
            except OSError as exc:
                self.report_error(
                    f"Cannot fix password file permissions for {path}: {exc}"
                )
                return
        password = read_password_file(path)
        if not password:
            self.report_error(f"No password found in {path}")
            return
        self.query_one("#password", Input).value = password
        self.set_status(f"Loaded password from {path}")
        self.notify("Password loaded")

    @work
    async def save_password(self) -> None:
        path = self.password_file()
        password = self.val("password")
        if not password:
            self.notify("Password field empty; nothing saved", severity="error")
            return
        if not await self.confirm(
            f"Save password to {path}?\n\nThis writes a secret to disk with chmod 600."
        ):
            self.notify("Save cancelled")
            return
        write_private_text(path, password + "\n")
        self.set_status(f"Saved password to {path}")
        self.notify("Password saved")

    async def confirm(self, message: str, *, default_confirm: bool = False) -> bool:
        return bool(
            await self.push_screen_wait(
                ConfirmScreen(message, default_confirm=default_confirm)
            )
        )

    async def form(
        self,
        title: str,
        hint: str,
        fields: list[FormField],
        submit_label: str = "Continue",
        validator: FormValidator | None = None,
    ) -> dict[str, str] | None:
        return await self.push_screen_wait(
            FormScreen(title, hint, fields, submit_label, validator)
        )

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    async def action_open_command_palette(self) -> None:
        action_id = await self.push_screen_wait(
            CommandPaletteScreen(list(PALETTE_ACTIONS))
        )
        if action_id is None:
            return
        await self.run_command_palette_action(action_id)

    async def run_command_palette_action(self, action_id: str | None) -> bool:
        action = PALETTE_ACTION_MAP.get(action_id or "")
        if action is None:
            return False
        action_name, args = action
        await self.invoke_action(action_name, *args)
        return True

    async def action_load_password_file(self) -> None:
        await self.load_password()

    def action_save_password_file(self) -> None:
        self.save_password()

    async def run_command(
        self, client: SambaToolClient, cmd: list[str]
    ) -> tuple[int, str]:
        error = client.authentication_error()
        if error:
            self.report_error(error)
            return 2, error

        self.set_status(f"Running: {client.status_command(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out_bytes, _ = await proc.communicate()
        output = out_bytes.decode(errors="replace")
        code = proc.returncode or 0
        if code == 0:
            self.set_status("OK")
        else:
            first_line = next(
                (line for line in output.splitlines() if line.strip()), f"exit {code}"
            )
            self.report_error(first_line)
        return code, output

    async def run_samba(self, action: str, args: list[str]) -> tuple[int, str]:
        client = self.samba_client()
        return await self.run_command(
            client, client.dns_command(action, self.val("zone"), args)
        )

    async def run_samba_zone(
        self, action: str, zone: str, args: list[str]
    ) -> tuple[int, str]:
        client = self.samba_client()
        return await self.run_command(
            client, client.dns_zone_command(action, zone, args)
        )

    async def run_zonelist(self) -> tuple[int, str]:
        client = self.samba_client()
        return await self.run_command(client, client.zonelist_command())

    def set_busy(self, busy: bool) -> None:
        for button in self.query(Button):
            button.disabled = busy

    @asynccontextmanager
    async def busy(self) -> AsyncIterator[None]:
        self.set_busy(True)
        try:
            yield
        finally:
            self.set_busy(False)

    async def do_command(
        self, action: str, args: list[str], update_table: bool = False
    ) -> int:
        async with self.busy():
            code, output = await self.run_samba(action, args)
            if update_table and code == 0:
                self._last_dns_search_zone = (
                    self.val("zone")
                    if action == "query" and args == ["@", "ALL"]
                    else ""
                )
                self.populate_records(parse_records(output))
            if code == 0:
                self.notify("OK")
            return code

    async def action_refresh(self) -> None:
        if self.view_mode == "smart":
            await self.refresh_current_smart_view()
            return
        if self.view_mode == "directory":
            await self.refresh_current_directory_search()
            return
        await self.refresh_current_zone()
