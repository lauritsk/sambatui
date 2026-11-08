from __future__ import annotations

import os
import shutil
import socket
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, nullcontext, suppress
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from textual import work
from textual.app import ScreenStackError
from textual.css.query import NoMatches
from textual.widgets import (
    Button,
    Static,
)

from sambatui.app_actions import PALETTE_ACTION_MAP, PALETTE_ACTIONS
from sambatui.app_constants import LDAP_DEFAULT_MAX_ROWS
from sambatui.core.config import (
    DEFAULT_AUTH,
    DEFAULT_AUTO_PTR,
    DEFAULT_LDAP_ENCRYPTION,
    DEFAULT_PASSWORD_FILE,
    DEFAULT_SMART_DAYS,
    DEFAULT_SMART_DISABLED_DAYS,
    DEFAULT_SMART_MAX_ROWS,
    DEFAULT_SMART_NEVER_LOGGED_DAYS,
)
from sambatui.ldap.client import LdapDirectoryClient
from sambatui.ldap.types import LdapSearchConfig

from ..core.config import (
    DEFAULT_COMMAND_TIMEOUT,
    fix_password_file_permissions,
    is_reverse_dns_zone,
    password_file_permissions_too_open,
    password_file_warning,
    read_password_file,
    save_user_config,
    write_private_text,
)
from ..core.mutations import MutationGuard, MutationInProgress
from ..core.remediation import actionable_error
from ..core.settings import ConnectionSettings
from ..core.view_state import AppViewState, DirectoryViewState, SmartViewState
from ..dns.parsing import parse_records
from ..ldap.rows import DirectoryRow
from ..ldap.sidebar import (
    SidebarItem,
)
from ..samba.client import SambaCommandClient, SambaToolClient, SambaToolConfig
from ..samba.discovery import (
    normalize_domain,
)
from ..samba.execution import execute_command
from ..smart_view_catalog import SMART_ROW_LIMIT_DEFAULT
from ..ui.screens import (
    CommandPaletteScreen,
    ConfirmScreen,
    FormField,
    FormScreen,
    FormValidator,
    HelpScreen,
    infer_domain_from_server,
)
from ..ui.tables import (
    DNS_COLUMNS,
)

if TYPE_CHECKING:
    from ..app import SambatuiApp


class AppCoreMixin:
    def on_mount(self: SambatuiApp) -> None:
        self.initialize_view()

        samba_tool = shutil.which("samba-tool")
        if not samba_tool:
            self.report_error("samba-tool not found in PATH")
            return
        self.samba_tool_executable = samba_tool

        self.set_initial_connection_status()
        if self.connection_needs_setup():
            self.set_status(
                "Connection incomplete. Press w for setup wizard or Ctrl+O."
            )
        else:
            self.call_after_refresh(self.load_zones)

    def initialize_state(self: SambatuiApp) -> None:
        self.samba_tool_executable = "samba-tool"
        self._connection = ConnectionSettings()
        self.connection_revision = 0
        self.mutations = MutationGuard()
        self.views = AppViewState(
            directory=DirectoryViewState(max_rows=LDAP_DEFAULT_MAX_ROWS),
            smart=SmartViewState(max_rows=SMART_ROW_LIMIT_DEFAULT),
        )
        self.ldap_structure_rows: list[DirectoryRow] = []
        self.records_columns = DNS_COLUMNS
        self.search_text = ""
        self._syncing_search_input = False
        self.zones: list[str] = []
        self.sidebar_items: dict[str, list[SidebarItem]] = {}
        self.pending_g = False
        self._busy_depth = 0

    def initialize_view(self: SambatuiApp) -> None:
        self.refresh_connection_summary()
        self.update_records_title()
        self.populate_zones([])
        self.populate_ldap_structure([])
        self.populate_smart_views_sidebar()
        self.action_focus_records()
        self.refresh_key_hints()
        self.render_records([])

    def set_initial_connection_status(self: SambatuiApp) -> None:
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

    def val(self: SambatuiApp, field: str) -> str:
        return self.connection_settings().value(field)

    def set_status(self: SambatuiApp, message: str) -> None:
        with suppress(NoMatches, ScreenStackError):
            self.query_one("#status", Static).update(message)

    def report_error(self: SambatuiApp, message: str) -> None:
        text = actionable_error(message)
        self.notify(text[:200], severity="error", markup=False)
        self.set_status(text[:180])

    def set_val(self: SambatuiApp, field: str, value: str) -> None:
        self.set_connection_values({field: value})

    def set_connection_values(self: SambatuiApp, values: dict[str, str]) -> None:
        updated = self._connection.updated(values)
        previous = self._connection
        if updated == previous:
            return
        self._connection = updated
        self.connection_revision += 1
        samba_changed = updated.samba_config() != previous.samba_config()
        ldap_changed = updated.ldap_config() != previous.ldap_config()
        if samba_changed or ldap_changed or updated.zone != previous.zone:
            self.views.invalidate()
            if samba_changed:
                self.zones = []
            if ldap_changed:
                self.ldap_structure_rows = []
            if self.screen_stack:
                if samba_changed:
                    self.populate_zones([])
                if ldap_changed:
                    self.populate_ldap_structure([])
                self.refresh_current_view()

    def preference_values(self: SambatuiApp) -> dict[str, str]:
        zone = self.val("zone")
        domain = self.connection_domain_default()
        return {
            "server": self.val("server"),
            "domain": domain,
            "zone": domain,
            "last_zone": zone,
            "user": self.val("user"),
            "auth": self.val("auth") or DEFAULT_AUTH,
            "kerberos": self.val("kerberos"),
            "krb5_ccache": self.val("krb5_ccache"),
            "configfile": self.val("configfile"),
            "options": self.val("options"),
            "ldap_base": self.val("ldap_base"),
            "ldap_encryption": self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            "auto_ptr": self.val("auto_ptr") or DEFAULT_AUTO_PTR,
            "smart_days": self.val("smart_days") or DEFAULT_SMART_DAYS,
            "smart_disabled_days": self.val("smart_disabled_days")
            or DEFAULT_SMART_DISABLED_DAYS,
            "smart_never_logged_days": self.val("smart_never_logged_days")
            or DEFAULT_SMART_NEVER_LOGGED_DAYS,
            "smart_max_rows": self.val("smart_max_rows") or DEFAULT_SMART_MAX_ROWS,
            "password_file": self.val("password_file"),
        }

    def save_preferences(self: SambatuiApp) -> None:
        try:
            save_user_config(self.preference_values())
        except OSError as exc:
            self.report_error(f"Cannot save preferences: {exc}")

    def connection_settings(self: SambatuiApp) -> ConnectionSettings:
        return self.mutations.snapshot or self._connection

    def connection_is_current(self: SambatuiApp) -> bool:
        return self._connection == self.connection_settings()

    def connection_needs_setup(self: SambatuiApp) -> bool:
        return self.connection_settings().needs_setup(read_password_file)

    def normalized_domain_candidate(self: SambatuiApp, value: str) -> str:
        if not value or is_reverse_dns_zone(value):
            return ""
        try:
            return normalize_domain(value).lower()
        except ValueError:
            return ""

    def connection_domain_default(self: SambatuiApp) -> str:
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

    def refresh_connection_summary(self: SambatuiApp) -> None:
        with suppress(NoMatches, ScreenStackError):
            self.query_one("#connection_summary", Static).update(
                f"Connection: {self.connection_settings().summary}"
            )

    def password_file(self: SambatuiApp) -> Path:
        return self.connection_settings().path_password_file

    def samba_config(self: SambatuiApp) -> SambaToolConfig:
        config = self.connection_settings().samba_config()
        return replace(config, executable=self.samba_tool_executable)

    def samba_client(self: SambatuiApp) -> SambaToolClient:
        return SambaToolClient(self.samba_config())

    def ldap_config(self: SambatuiApp, base_dn: str = "") -> LdapSearchConfig:
        return self.connection_settings().ldap_config(base_dn)

    def ldap_client(self: SambatuiApp, base_dn: str = "") -> LdapDirectoryClient:
        return LdapDirectoryClient(self.ldap_config(base_dn))

    async def load_password(self: SambatuiApp) -> None:
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
        self.set_val("password", password)
        self.set_status(f"Loaded password from {path}")
        self.notify("Password loaded")

    @work
    async def save_password(self: SambatuiApp) -> None:
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

    async def confirm(
        self: SambatuiApp, message: str, *, default_confirm: bool = False
    ) -> bool:
        return bool(
            await self.push_screen_wait(
                ConfirmScreen(message, default_confirm=default_confirm)
            )
        )

    async def form(
        self: SambatuiApp,
        title: str,
        hint: str,
        fields: list[FormField],
        submit_label: str = "Continue",
        validator: FormValidator | None = None,
    ) -> dict[str, str] | None:
        return await self.push_screen_wait(
            FormScreen(title, hint, fields, submit_label, validator)
        )

    def action_help(self: SambatuiApp) -> None:
        self.push_screen(HelpScreen())

    async def action_open_command_palette(self: SambatuiApp) -> None:
        action_id = await self.push_screen_wait(
            CommandPaletteScreen(list(PALETTE_ACTIONS))
        )
        if action_id is None:
            return
        await self.run_command_palette_action(action_id)

    async def run_command_palette_action(
        self: SambatuiApp, action_id: str | None
    ) -> bool:
        action = PALETTE_ACTION_MAP.get(action_id or "")
        if action is None:
            return False
        action_name, args = action
        await self.invoke_action(action_name, *args)
        return True

    async def action_load_password_file(self: SambatuiApp) -> None:
        await self.load_password()

    def action_save_password_file(self: SambatuiApp) -> None:
        self.save_password()

    async def run_command(
        self: SambatuiApp, client: SambaCommandClient, cmd: list[str]
    ) -> tuple[int, str]:
        error = client.authentication_error()
        if error:
            self.report_error(error)
            return 2, error

        self.set_status(f"Running: {client.status_command(cmd)}")
        result = await execute_command(
            cmd, env=client.execution_env(), timeout=DEFAULT_COMMAND_TIMEOUT
        )
        if result.error is not None:
            self.report_error(result.error)
        else:
            self.set_status("OK")
        return result.code, result.output

    async def run_samba(
        self: SambatuiApp, action: str, args: list[str]
    ) -> tuple[int, str]:
        return await self.run_samba_zone(action, self.val("zone"), args)

    async def run_samba_zone(
        self: SambatuiApp, action: str, zone: str, args: list[str]
    ) -> tuple[int, str]:
        try:
            reservation = (
                nullcontext()
                if action == "query"
                else self.mutations.reserve(self.connection_settings())
            )
            with reservation:
                client = self.samba_client()
                return await self.run_command(
                    client, client.dns_command(action, zone, args)
                )
        except MutationInProgress as exc:
            self.report_error(str(exc))
            return 2, str(exc)

    async def run_zonelist(self: SambatuiApp) -> tuple[int, str]:
        client = self.samba_client()
        return await self.run_command(client, client.zonelist_command())

    def set_busy(self: SambatuiApp, busy: bool) -> None:
        for button in self.query(Button):
            button.disabled = busy

    @asynccontextmanager
    async def busy(self: SambatuiApp) -> AsyncGenerator[None]:
        self._busy_depth += 1
        if self._busy_depth == 1:
            self.set_busy(True)
        try:
            yield
        finally:
            self._busy_depth -= 1
            if self._busy_depth == 0:
                self.set_busy(False)

    async def do_command(
        self: SambatuiApp, action: str, args: list[str], update_table: bool = False
    ) -> int:
        revision = self.connection_revision
        mode = self.views.mode
        async with self.busy():
            code, output = await self.run_samba(action, args)
            if (
                update_table
                and code == 0
                and revision == self.connection_revision
                and mode == self.views.mode
                and self.connection_is_current()
            ):
                self.views.dns.last_search_zone = (
                    self.val("zone")
                    if action == "query" and args == ["@", "ALL"]
                    else ""
                )
                self.populate_records(parse_records(output))
            if code == 0:
                self.notify("OK")
            return code

    async def action_refresh(self: SambatuiApp) -> None:
        match self.views.mode:
            case "dns":
                await self.refresh_current_zone()
            case "directory":
                await self.refresh_current_directory_search()
            case "smart":
                await self.refresh_current_smart_view()
            case _:
                self.set_status("No active view to refresh.")
