from __future__ import annotations

import asyncio
import shutil
from contextlib import suppress
from pathlib import Path
from typing import Any

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.coordinate import Coordinate
from textual.widgets import Button, DataTable, Input, Label, Static

from .client import SambaToolClient, SambaToolConfig, parse_samba_options
from .config import (
    DEFAULT_AUTH,
    DEFAULT_AUTO_PTR,
    DEFAULT_CONFIGFILE,
    DEFAULT_KERBEROS,
    DEFAULT_KRB5_CCACHE,
    DEFAULT_LDAP_BASE,
    DEFAULT_LDAP_ENCRYPTION,
    DEFAULT_OPTIONS,
    DEFAULT_PASSWORD,
    DEFAULT_PASSWORD_FILE,
    DEFAULT_SERVER,
    DEFAULT_USER,
    DEFAULT_ZONE,
    password_file_warning,
    read_password_file,
)
from .discovery import discover_ad_services, preferred_domain_controller
from .dns import (
    NAME_RE,
    REC_RE,
    parse_records,
    parse_zones,
    ptr_target_for_name as dns_ptr_target_for_name,
    reverse_record_for_ipv4 as dns_reverse_record_for_ipv4,
    valid_dns_name,
    validate_record,
)
from .ldap_directory import (
    DirectoryRow,
    LdapDirectoryClient,
    LdapSearchConfig,
    domain_to_base_dn,
)
from .models import DnsRow
from .screens import ConfirmScreen, FormField, FormScreen, HelpScreen

__all__ = [
    "DEFAULT_AUTH",
    "DEFAULT_AUTO_PTR",
    "DEFAULT_CONFIGFILE",
    "DEFAULT_KERBEROS",
    "DEFAULT_KRB5_CCACHE",
    "DEFAULT_LDAP_BASE",
    "DEFAULT_LDAP_ENCRYPTION",
    "DEFAULT_OPTIONS",
    "DEFAULT_PASSWORD",
    "DEFAULT_PASSWORD_FILE",
    "DEFAULT_SERVER",
    "DEFAULT_USER",
    "DEFAULT_ZONE",
    "NAME_RE",
    "REC_RE",
    "ConfirmScreen",
    "DnsRow",
    "FormField",
    "FormScreen",
    "HelpScreen",
    "SambaToolClient",
    "SambaToolConfig",
    "SambatuiApp",
    "main",
    "parse_records",
    "parse_zones",
    "password_file_warning",
    "parse_samba_options",
    "read_password_file",
    "valid_dns_name",
    "validate_record",
]


class SambatuiApp(App):
    CSS = """
    Screen { layout: vertical; }

    #connection_state { display: none; }

    #main {
        height: 1fr;
        margin: 0 1;
    }

    #sidebar {
        width: 42;
        min-width: 34;
        height: 1fr;
        margin-right: 1;
    }

    #results {
        width: 1fr;
        height: 1fr;
    }

    .panel {
        border: tall $surface;
        padding: 0 1;
    }

    #zones_panel { height: 1fr; }
    #zone_actions { height: auto; margin-bottom: 1; }

    .section-title { text-style: bold; color: $accent; margin-bottom: 1; }
    .hint { color: $text-muted; margin-bottom: 1; }
    #connection_summary { color: $text-muted; margin-bottom: 1; }
    #keys { height: 1; margin: 0 1; color: $text-muted; }

    Button { width: 1fr; }

    #zones { height: 1fr; margin-bottom: 1; }
    #records { height: 1fr; }
    #status { height: 3; color: $text-muted; }
    """

    BINDINGS = [
        ("question_mark", "help", "Help"),
        ("ctrl+o", "connection", "Connection"),
        ("p", "load_password_file", "Load password"),
        ("P", "save_password_file", "Save password"),
        ("z", "load_zones", "Zones"),
        ("c", "discover_ad", "Discover DC"),
        ("L", "ldap_search", "LDAP"),
        ("r", "refresh", "Refresh"),
        ("q", "query", "Query"),
        ("a", "add", "Add"),
        ("u", "update", "Update selected"),
        ("d", "delete", "Delete selected"),
        ("space", "toggle_select", "Toggle select"),
        ("ctrl+space", "toggle_select", "Toggle select"),
        ("v", "visual_select", "Visual select"),
        ("V", "select_range", "Select range"),
        ("escape", "clear_navigation_state", "Clear"),
        ("shift+up", "extend_up", "Extend up"),
        ("shift+down", "extend_down", "Extend down"),
        ("tab", "next_table", "Next table"),
        ("shift+tab", "previous_table", "Previous table"),
        ("h", "focus_zones", "Focus zones"),
        ("l", "focus_records", "Focus records"),
        ("j", "cursor_down", "Down"),
        ("k", "cursor_up", "Up"),
        ("ctrl+d", "cursor_half_page_down", "Half page down"),
        ("ctrl+u", "cursor_half_page_up", "Half page up"),
        ("pagedown", "cursor_page_down", "Page down"),
        ("pageup", "cursor_page_up", "Page up"),
        ("home", "cursor_top", "Top"),
        ("end", "cursor_bottom", "Bottom"),
        ("G", "cursor_bottom", "Bottom"),
        ("enter", "activate_row", "Activate"),
        ("slash", "search", "Search"),
        ("n", "sort_name", "Sort name"),
        ("t", "sort_type", "Sort type"),
        ("e", "sort_value", "Sort value"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="connection_state"):
            yield Input(DEFAULT_SERVER, id="server")
            yield Input(DEFAULT_ZONE, id="zone")
            yield Input(DEFAULT_USER, id="user")
            yield Input(DEFAULT_PASSWORD, password=True, id="password")
            yield Input(DEFAULT_AUTH, id="auth")
            yield Input(DEFAULT_KERBEROS, id="kerberos")
            yield Input(DEFAULT_AUTO_PTR, id="auto_ptr")
            yield Input(DEFAULT_KRB5_CCACHE, id="krb5_ccache")
            yield Input(DEFAULT_CONFIGFILE, id="configfile")
            yield Input(DEFAULT_OPTIONS, id="options")
            yield Input(DEFAULT_LDAP_BASE, id="ldap_base")
            yield Input(DEFAULT_LDAP_ENCRYPTION, id="ldap_encryption")
            yield Input(str(DEFAULT_PASSWORD_FILE), id="password_file")

        with Horizontal(id="main"):
            with Vertical(id="sidebar"):
                with Vertical(id="zones_panel", classes="panel"):
                    yield Static("Zones", classes="section-title")
                    yield Static("Connection: not checked", id="connection_summary")
                    with Horizontal(id="zone_actions"):
                        yield Button("Load zones", id="load_zones", variant="primary")
                        yield Button("Connection…", id="open_connection")
                    zones = DataTable(id="zones", cursor_type="row")
                    zones.add_columns("DNS zones")
                    yield zones
                    yield Static("Ready", id="status")

            with Vertical(id="results", classes="panel"):
                yield Label("Records", id="records_title", classes="section-title")
                table = DataTable(id="records", cursor_type="row")
                table.add_columns(
                    "✓", "Name", "Type", "Value", "TTL", "Records", "Children"
                )
                yield table
        yield Static(
            "? help  Ctrl+O connection  z zones  c discover  L ldap  r refresh  q query  a add  u update  d delete  / search  h/l focus  j/k move  Space select",
            id="keys",
        )

    def on_mount(self) -> None:
        self.selected_record_rows: set[int] = set()
        self.selection_anchor: int | None = None
        self.visual_selecting = False
        self.record_rows: list[DnsRow] = []
        self.directory_rows: list[DirectoryRow] = []
        self.view_mode = "dns"
        self.sort_field = "name"
        self.sort_reverse = False
        self.search_text = ""
        self.zones: list[str] = []
        self.pending_g = False
        self.refresh_connection_summary()

        if not shutil.which("samba-tool"):
            self.set_status("samba-tool not found in PATH")
            self.notify("samba-tool not found in PATH", severity="error")
            return

        warning = password_file_warning(self.password_file())
        if warning:
            self.set_status(warning)
            self.notify(warning, severity="error")
        elif self.val("password"):
            self.set_status(f"Password loaded from env or {DEFAULT_PASSWORD_FILE}")
        else:
            self.set_status("Enter password, load password file, or use kerberos auth")

        self.call_after_refresh(self.action_connection)

    def val(self, widget_id: str) -> str:
        return self.query_one(f"#{widget_id}", Input).value.strip()

    def set_status(self, message: str) -> None:
        with suppress(Exception):
            self.query_one("#status", Static).update(message)

    def set_val(self, widget_id: str, value: str) -> None:
        self.query_one(f"#{widget_id}", Input).value = value

    def connection_summary(self) -> str:
        server = self.val("server") or "no server"
        zone = self.val("zone") or "no zone"
        auth = self.val("auth") or DEFAULT_AUTH
        return f"{server} · {zone} · {auth} auth"

    def refresh_connection_summary(self) -> None:
        with suppress(Exception):
            self.query_one("#connection_summary", Static).update(
                f"Connection: {self.connection_summary()}"
            )

    def connection_fields(self) -> list[FormField]:
        return [
            (
                "Server — AD domain controller hostname or IP used by samba-tool -H.",
                "server",
                "dc01.example.com or 192.0.2.10",
                self.val("server"),
            ),
            (
                "DNS zone — zone to query and edit after you select/load zones.",
                "zone",
                "example.com",
                self.val("zone"),
            ),
            (
                "User — DOMAIN\\user or user accepted by Samba.",
                "user",
                "EXAMPLE\\admin",
                self.val("user"),
            ),
            (
                "Password — hidden. Leave empty for Kerberos or password file/env loading.",
                "password",
                "password",
                self.val("password"),
            ),
            (
                "Auth mode — password or kerberos.",
                "auth",
                "password | kerberos",
                self.val("auth"),
            ),
            (
                "Kerberos option — value passed to --use-kerberos.",
                "kerberos",
                "desired | required | off",
                self.val("kerberos"),
            ),
            (
                "Auto PTR — on adds matching reverse PTR when adding A records.",
                "auto_ptr",
                "on | off",
                self.val("auto_ptr"),
            ),
            (
                "Kerberos credential cache — optional --use-krb5-ccache path.",
                "krb5_ccache",
                "/tmp/krb5cc_1000",
                self.val("krb5_ccache"),
            ),
            (
                "smb.conf — optional --configfile path for Samba settings.",
                "configfile",
                "/etc/samba/smb.conf",
                self.val("configfile"),
            ),
            (
                "Extra samba-tool options — separate multiple options with semicolons.",
                "options",
                "--option=name=value; --debuglevel=1",
                self.val("options"),
            ),
            (
                "LDAP base DN — used by read-only directory search.",
                "ldap_base",
                "DC=example,DC=com",
                self.val("ldap_base") or domain_to_base_dn(self.val("zone")),
            ),
            (
                "LDAP encryption — password bind requires ldaps or starttls.",
                "ldap_encryption",
                "ldaps | starttls",
                self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            ),
            (
                "Password file — used at startup and by password load/save commands.",
                "password_file",
                "~/.config/sambatui/password",
                self.val("password_file"),
            ),
        ]

    def password_file(self) -> Path:
        return Path(self.val("password_file")).expanduser()

    def samba_config(self) -> SambaToolConfig:
        return SambaToolConfig(
            server=self.val("server"),
            user=self.val("user"),
            password=self.val("password"),
            auth_mode=self.val("auth") or DEFAULT_AUTH,
            kerberos=self.val("kerberos") or DEFAULT_KERBEROS,
            krb5_ccache=self.val("krb5_ccache"),
            configfile=self.val("configfile"),
            options=parse_samba_options(self.val("options")),
        )

    def samba_client(self) -> SambaToolClient:
        return SambaToolClient(self.samba_config())

    def ldap_config(self, base_dn: str = "") -> LdapSearchConfig:
        return LdapSearchConfig(
            server=self.val("server"),
            user=self.val("user"),
            password=self.val("password"),
            base_dn=base_dn
            or self.val("ldap_base")
            or domain_to_base_dn(self.val("zone")),
            encryption=self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
        )

    def ldap_client(self, base_dn: str = "") -> LdapDirectoryClient:
        return LdapDirectoryClient(self.ldap_config(base_dn))

    def load_password(self) -> None:
        path = self.password_file()
        warning = password_file_warning(path)
        if warning:
            self.notify(warning, severity="error")
            self.set_status(warning)
            return
        password = read_password_file(path)
        if not password:
            self.notify(f"No password found in {path}", severity="error")
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
        parent_exists = path.parent.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not parent_exists:
            path.parent.chmod(0o700)
        path.write_text(password + "\n", encoding="utf-8")
        path.chmod(0o600)
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
    ) -> dict[str, str] | None:
        return await self.push_screen_wait(
            FormScreen(title, hint, fields, submit_label)
        )

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_load_password_file(self) -> None:
        self.load_password()

    def action_save_password_file(self) -> None:
        self.save_password()

    @work
    async def action_connection(self) -> None:
        values = await self.form(
            "Connection settings",
            "These values feed samba-tool. Press Apply to close this setup screen; reopen with Ctrl+O.",
            self.connection_fields(),
            "Apply",
        )
        if values is None:
            self.refresh_connection_summary()
            return
        for widget_id, value in values.items():
            self.set_val(widget_id, value)
        if (self.val("auth") or DEFAULT_AUTH).casefold() == "password" and not self.val(
            "password"
        ):
            password = read_password_file(self.password_file())
            if password:
                self.set_val("password", password)
        self.refresh_connection_summary()
        self.set_status("Connection settings updated")

    async def run_command(
        self, client: SambaToolClient, cmd: list[str]
    ) -> tuple[int, str]:
        error = client.authentication_error()
        if error:
            self.notify(error, severity="error")
            self.set_status(error)
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
            self.set_status(first_line[:120])
            self.notify(first_line[:200], severity="error")
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

    async def do_command(
        self, action: str, args: list[str], update_table: bool = False
    ) -> int:
        self.set_busy(True)
        try:
            code, output = await self.run_samba(action, args)
            if update_table and code == 0:
                self.populate_records(parse_records(output))
            if code == 0:
                self.notify("OK")
            return code
        finally:
            self.set_busy(False)

    def auto_ptr_enabled(self) -> bool:
        return self.val("auto_ptr").casefold() in {"1", "yes", "y", "true", "on"}

    def ptr_target_for_name(self, name: str) -> str:
        return dns_ptr_target_for_name(name, self.val("zone"))

    def reverse_record_for_ipv4(self, ip_value: str) -> tuple[str, str] | None:
        return dns_reverse_record_for_ipv4(ip_value, self.zones)

    async def add_auto_ptr(self, name: str, ip_value: str) -> int:
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

    async def load_zones(self) -> None:
        self.set_busy(True)
        try:
            code, output = await self.run_zonelist()
            if code != 0:
                return
            zones = parse_zones(output)
            self.zones = zones
            self.populate_zones(zones)
            self.set_status(f"Loaded {len(zones)} zones")
            self.notify(f"Loaded {len(zones)} zones")
        finally:
            self.set_busy(False)

    def populate_zones(self, zones: list[str]) -> None:
        table = self.query_one("#zones", DataTable)
        table.clear()
        for zone in zones:
            table.add_row(zone)

    def populate_records(self, rows: list[DnsRow]) -> None:
        self.view_mode = "dns"
        self.query_one("#records_title", Label).update("Records")
        self.record_rows = self.sorted_records(rows)
        self.refresh_record_view()
        self.set_status(
            f"Loaded {len(rows)} records from {self.val('zone')}; sorted by {self.sort_field}"
        )

    def populate_directory(self, rows: list[DirectoryRow]) -> None:
        self.view_mode = "directory"
        self.query_one("#records_title", Label).update("Directory (read-only LDAP)")
        self.directory_rows = rows
        self.refresh_directory_view()
        self.set_status(f"Loaded {len(rows)} LDAP entries")

    def render_records(self, rows: list[DnsRow]) -> None:
        self.selected_record_rows.clear()
        self.selection_anchor = None
        self.visual_selecting = False
        table = self.query_one("#records", DataTable)
        table.clear()
        for row in rows:
            table.add_row(
                "", row.name, row.rtype, row.value, row.ttl, row.records, row.children
            )

    def render_directory(self, rows: list[DirectoryRow]) -> None:
        self.selected_record_rows.clear()
        self.selection_anchor = None
        self.visual_selecting = False
        table = self.query_one("#records", DataTable)
        table.clear()
        for row in rows:
            table.add_row("", row.name, row.kind, row.summary, "", "", row.dn)

    def visible_records(self) -> list[DnsRow]:
        rows = self.record_rows
        if self.search_text:
            needle = self.search_text.casefold()
            rows = [
                row
                for row in rows
                if needle in row.name.casefold()
                or needle in row.rtype.casefold()
                or needle in row.value.casefold()
            ]
        return rows

    def visible_directory(self) -> list[DirectoryRow]:
        rows = self.directory_rows
        if self.search_text:
            needle = self.search_text.casefold()
            rows = [
                row
                for row in rows
                if needle in row.name.casefold()
                or needle in row.kind.casefold()
                or needle in row.summary.casefold()
                or needle in row.dn.casefold()
            ]
        return rows

    def refresh_record_view(self) -> None:
        rows = self.visible_records()
        self.render_records(rows)
        extra = f" matching /{self.search_text}/" if self.search_text else ""
        self.set_status(
            f"Showing {len(rows)} of {len(self.record_rows)} records{extra}"
        )

    def refresh_directory_view(self) -> None:
        rows = self.visible_directory()
        self.render_directory(rows)
        extra = f" matching /{self.search_text}/" if self.search_text else ""
        self.set_status(
            f"Showing {len(rows)} of {len(self.directory_rows)} LDAP entries{extra}"
        )

    def sorted_records(self, rows: list[DnsRow]) -> list[DnsRow]:
        key_map = {
            "name": lambda row: row.name.casefold(),
            "type": lambda row: row.rtype.casefold(),
            "value": lambda row: row.value.casefold(),
        }
        return sorted(rows, key=key_map[self.sort_field], reverse=self.sort_reverse)

    def sort_records(self, field: str) -> None:
        if self.sort_field == field:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_field = field
            self.sort_reverse = False
        self.record_rows = self.sorted_records(self.record_rows)
        self.refresh_record_view()
        direction = "desc" if self.sort_reverse else "asc"
        self.set_status(f"Sorted by {field} ({direction}); selection cleared")

    def set_record_selected(self, row_index: int, selected: bool) -> None:
        table = self.query_one("#records", DataTable)
        if row_index < 0 or row_index >= table.row_count:
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
        rows = sorted(self.selected_record_rows)
        if not rows:
            rows = [self.query_one("#records", DataTable).cursor_row]
        records = [self.row_to_record(row_index) for row_index in rows]
        return [record for record in records if record]

    def selected_record(self) -> dict[str, str] | None:
        records = self.selected_records()
        return records[0] if len(records) == 1 else None

    async def refresh_current_zone(self) -> None:
        await self.do_command("query", ["@", "ALL"], update_table=True)

    async def action_load_zones(self) -> None:
        await self.load_zones()

    @work
    async def action_discover_ad(self) -> None:
        values = await self.form(
            "Discover AD domain controllers",
            "Uses DNS SRV records. No LDAP bind or new dependency required.",
            [("AD DNS domain", "domain", "example.com", self.val("zone"))],
            "Discover",
        )
        if not values:
            return
        domain = values["domain"] or self.val("zone")
        self.set_busy(True)
        try:
            try:
                services = await asyncio.to_thread(discover_ad_services, domain)
            except ValueError as exc:
                message = str(exc)
                self.notify(message, severity="error")
                self.set_status(message)
                return
            controller = preferred_domain_controller(services)
            if controller is None:
                message = f"No AD SRV records found for {domain}"
                self.notify(message, severity="error")
                self.set_status(message)
                return
            self.query_one("#server", Input).value = controller.target
            if not self.val("zone"):
                self.query_one("#zone", Input).value = controller.domain
            self.refresh_connection_summary()
            message = (
                f"Discovered {len(services)} AD SRV record(s); "
                f"selected {controller.target}:{controller.port}"
            )
            self.set_status(message)
            self.notify(message)
        finally:
            self.set_busy(False)

    @work
    async def action_ldap_search(self) -> None:
        base_dn = self.val("ldap_base") or domain_to_base_dn(self.val("zone"))
        values = await self.form(
            "Search AD directory",
            "Read-only LDAP via ldap3. Password bind requires LDAPS or StartTLS.",
            [
                (
                    "Search type",
                    "kind",
                    "users | groups | computers | ous | all",
                    "users",
                ),
                ("Search text", "text", "name, login, mail, DN fragment", ""),
                ("Base DN", "base_dn", "DC=example,DC=com", base_dn),
                (
                    "LDAP encryption",
                    "ldap_encryption",
                    "ldaps | starttls",
                    self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
                ),
                ("Max rows", "max_rows", "200", "200"),
            ],
            "Search",
        )
        if not values:
            return
        self.set_val("ldap_base", values["base_dn"])
        self.set_val("ldap_encryption", values["ldap_encryption"])
        try:
            max_rows = max(1, min(int(values["max_rows"] or "200"), 1000))
        except ValueError:
            max_rows = 200
        client = self.ldap_client(values["base_dn"])
        error = client.validation_error()
        if error:
            self.notify(error, severity="error")
            self.set_status(error)
            return
        self.set_busy(True)
        try:
            try:
                rows = await asyncio.to_thread(
                    client.search, values["kind"] or "users", values["text"]
                )
            except ValueError as exc:
                message = str(exc)
                self.notify(message, severity="error")
                self.set_status(message)
                return
            self.search_text = ""
            self.populate_directory(rows[:max_rows])
            self.notify(f"Loaded {min(len(rows), max_rows)} LDAP entries")
        finally:
            self.set_busy(False)

    async def action_refresh(self) -> None:
        await self.refresh_current_zone()

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

    @work
    async def action_add(self) -> None:
        values = await self.form(
            "Add DNS record",
            f"Zone: {self.val('zone')}. Examples: A=192.0.2.10, CNAME=target.example.com., PTR=host.example.com.",
            [
                ("Record name", "name", "name, @ for zone root", ""),
                (
                    "Record type",
                    "rtype",
                    "A / AAAA / CNAME / PTR / TXT / MX / SRV",
                    "A",
                ),
                ("DNS value", "value", "value for selected type", ""),
                ("TTL", "ttl", "optional", ""),
            ],
            "Add",
        )
        if not values:
            return
        name = values["name"]
        rtype = (values["rtype"] or "A").upper()
        value = values["value"]
        ttl = values["ttl"]
        error = validate_record(name, rtype, value)
        if error:
            self.notify(error, severity="error")
            self.set_status(error)
            return
        args = [name, rtype, value]
        if ttl:
            args.append(f"--ttl={ttl}")
        ptr_text = ""
        if rtype == "A" and self.auto_ptr_enabled():
            reverse = self.reverse_record_for_ipv4(value)
            if reverse:
                ptr_zone, ptr_name = reverse
                ptr_text = f"\nAuto PTR: {ptr_zone} / {ptr_name} PTR {self.ptr_target_for_name(name)}"
        if not await self.confirm(
            f"Add DNS record?\n\nZone: {self.val('zone')}\n{name} {rtype} {value}\nTTL: {ttl or 'default'}{ptr_text}",
            default_confirm=True,
        ):
            self.notify("Add cancelled")
            return
        if await self.do_command("add", args) == 0:
            if rtype == "A" and self.auto_ptr_enabled():
                await self.add_auto_ptr(name, value)
            await self.refresh_current_zone()

    @work
    async def action_update(self) -> None:
        records = self.selected_records()
        if len(records) > 1:
            self.notify(
                "Update works on one record only. Select one row.", severity="error"
            )
            return
        selected = records[0] if records else None
        if not selected:
            self.notify(
                "Select a real record row first. Rows with type '-' are empty/folder nodes.",
                severity="error",
            )
            return
        values = await self.form(
            "Update selected DNS record",
            "To change record type (example A -> CNAME), set New type. That will DELETE the old record, then ADD the new one.",
            [
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
            ],
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
            self.notify(error, severity="error")
            self.set_status(error)
            return

        if old_rtype != rtype:
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
            return

        if not await self.confirm(
            f"Update DNS record?\n\nZone: {self.val('zone')}\n{name} {rtype}\nOld: {old_value}\nNew: {value}"
        ):
            self.notify("Update cancelled")
            return
        if await self.do_command("update", [name, rtype, old_value, value]) == 0:
            await self.refresh_current_zone()

    @work
    async def action_delete(self) -> None:
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

    @work
    async def action_search(self) -> None:
        values = await self.form(
            "Search records",
            "Searches name, type, and value. Empty search clears filter.",
            [("Search text", "search", "search text", self.search_text)],
            "Search",
        )
        if values is None:
            return
        self.search_text = values["search"]
        if self.view_mode == "directory":
            self.refresh_directory_view()
        else:
            self.refresh_record_view()

    def focused_table(self) -> DataTable | None:
        focused = self.focused
        return focused if isinstance(focused, DataTable) else None

    def action_focus_zones(self) -> None:
        self.pending_g = False
        self.query_one("#zones", DataTable).focus()

    def action_focus_records(self) -> None:
        self.pending_g = False
        self.query_one("#records", DataTable).focus()

    def action_next_table(self) -> None:
        table = self.focused_table()
        if table and table.id == "zones":
            self.action_focus_records()
        else:
            self.action_focus_zones()

    def action_previous_table(self) -> None:
        table = self.focused_table()
        if table and table.id == "records":
            self.action_focus_zones()
        else:
            self.action_focus_records()

    def action_sort_name(self) -> None:
        self.sort_records("name")

    def action_sort_type(self) -> None:
        self.sort_records("type")

    def action_sort_value(self) -> None:
        self.sort_records("value")

    def update_visual_selection(self) -> None:
        if not self.visual_selecting or self.selection_anchor is None:
            return
        table = self.query_one("#records", DataTable)
        if self.focused_table() is table:
            self.select_record_range(self.selection_anchor, table.cursor_row)

    def active_table(self) -> DataTable:
        return self.focused_table() or self.query_one("#records", DataTable)

    def page_rows(self, table: DataTable) -> int:
        height = getattr(table.size, "height", 0)
        return max(1, height - 3) if height else 10

    def move_cursor_by(self, delta: int) -> None:
        table = self.active_table()
        if not table.row_count:
            return
        row = max(0, min(table.cursor_row + delta, table.row_count - 1))
        table.move_cursor(row=row)
        self.update_visual_selection()

    def action_cursor_down(self) -> None:
        self.pending_g = False
        self.move_cursor_by(1)

    def action_cursor_up(self) -> None:
        self.pending_g = False
        self.move_cursor_by(-1)

    def action_cursor_page_down(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(self.page_rows(table))

    def action_cursor_page_up(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(-self.page_rows(table))

    def action_cursor_half_page_down(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(max(1, self.page_rows(table) // 2))

    def action_cursor_half_page_up(self) -> None:
        self.pending_g = False
        table = self.active_table()
        self.move_cursor_by(-max(1, self.page_rows(table) // 2))

    def action_cursor_top(self) -> None:
        self.pending_g = False
        table = self.active_table()
        table.move_cursor(row=0)
        self.update_visual_selection()

    def action_cursor_bottom(self) -> None:
        self.pending_g = False
        table = self.active_table()
        if table.row_count:
            table.move_cursor(row=table.row_count - 1)
            self.update_visual_selection()

    def action_toggle_select(self) -> None:
        self.pending_g = False
        table = self.focused_table() or self.query_one("#records", DataTable)
        if table.id != "records" or not table.row_count:
            return
        if self.view_mode != "dns":
            self.set_status("LDAP directory rows are read-only.")
            return
        row_index = table.cursor_row
        self.selection_anchor = (
            row_index if self.selection_anchor is None else self.selection_anchor
        )
        self.set_record_selected(row_index, row_index not in self.selected_record_rows)
        self.set_status(f"Selected {len(self.selected_record_rows)} record(s)")

    def action_visual_select(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not table.row_count:
            return
        if self.visual_selecting:
            self.visual_selecting = False
            self.set_status(
                f"Visual selection off; selected {len(self.selected_record_rows)} record(s)"
            )
            return
        self.visual_selecting = True
        self.selection_anchor = table.cursor_row
        self.select_record_range(table.cursor_row, table.cursor_row)
        self.set_status("Visual selection on: use j/k, then d to delete selected")

    def action_select_range(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if not table.row_count:
            return
        if self.selection_anchor is None:
            self.selection_anchor = table.cursor_row
        self.select_record_range(self.selection_anchor, table.cursor_row)

    def action_extend_up(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if self.selection_anchor is None:
            self.selection_anchor = table.cursor_row
        self.move_cursor_by(-1)
        self.select_record_range(self.selection_anchor, table.cursor_row)

    def action_extend_down(self) -> None:
        self.pending_g = False
        table = self.query_one("#records", DataTable)
        table.focus()
        if self.selection_anchor is None:
            self.selection_anchor = table.cursor_row
        self.move_cursor_by(1)
        self.select_record_range(self.selection_anchor, table.cursor_row)

    def action_clear_navigation_state(self) -> None:
        self.pending_g = False
        if self.visual_selecting:
            self.visual_selecting = False
            self.set_status(
                f"Visual selection off; selected {len(self.selected_record_rows)} record(s)"
            )
            return
        if self.selected_record_rows:
            self.clear_record_selection()
            self.set_status("Selection cleared")
            return
        if self.search_text:
            self.search_text = ""
            self.refresh_record_view()
            self.set_status("Search cleared")
            return
        self.action_focus_records()

    async def action_activate_row(self) -> None:
        self.pending_g = False
        table = self.focused_table()
        if table and table.id == "records":
            self.action_toggle_select()
            return
        if table and table.id == "zones":
            try:
                row = table.get_row_at(table.cursor_row)
            except Exception:
                return
            if row:
                self.query_one("#zone", Input).value = str(row[0])
                self.refresh_connection_summary()
                self.set_status(f"Selected {row[0]}; refreshing records")
                await self.refresh_current_zone()

    async def on_key(self, event: Any) -> None:
        if isinstance(self.focused, Input):
            return
        key = event.key
        char = getattr(event, "character", None)
        if isinstance(self.focused, Button) and key in {"enter", "space"}:
            return

        handled = True
        char_lower = char.casefold() if char else ""
        if char_lower != "g":
            self.pending_g = False
        match key, char_lower:
            case "ctrl+o", _:
                self.action_connection()
            case _, "?":
                self.action_help()
            case _, "p" if char == "P":
                self.save_password()
            case _, "p":
                self.load_password()
            case "escape", _:
                self.action_clear_navigation_state()
            case "tab", _:
                self.action_next_table()
            case "shift+tab", _:
                self.action_previous_table()
            case "space" | "ctrl+space", _:
                self.action_toggle_select()
            case _, " ":
                self.action_toggle_select()
            case _, "z":
                await self.action_load_zones()
            case _, "c":
                self.action_discover_ad()
            case _, "l" if char == "L":
                self.action_ldap_search()
            case _, "r":
                await self.action_refresh()
            case _, "q":
                self.action_query()
            case _, "a":
                self.action_add()
            case _, "u":
                self.action_update()
            case _, "d":
                self.action_delete()
            case _, "v" if char == "V":
                self.action_select_range()
            case _, "v":
                self.action_visual_select()
            case "shift+up", _:
                self.action_extend_up()
            case "shift+down", _:
                self.action_extend_down()
            case _, "j":
                self.action_cursor_down()
            case _, "k":
                self.action_cursor_up()
            case _, "h":
                self.action_focus_zones()
            case _, "l":
                self.action_focus_records()
            case "ctrl+d", _:
                self.action_cursor_half_page_down()
            case "ctrl+u", _:
                self.action_cursor_half_page_up()
            case "pagedown", _:
                self.action_cursor_page_down()
            case "pageup", _:
                self.action_cursor_page_up()
            case "home", _:
                self.action_cursor_top()
            case "end", _:
                self.action_cursor_bottom()
            case _, "g" if char == "G":
                self.action_cursor_bottom()
            case _, "g" if self.pending_g:
                self.action_cursor_top()
            case _, "g":
                self.pending_g = True
                self.set_status("g pressed: press g again for top; G goes bottom")
            case "slash", _:
                self.action_search()
            case _, "/":
                self.action_search()
            case _, "n":
                self.action_sort_name()
            case _, "t":
                self.action_sort_type()
            case _, "e":
                self.action_sort_value()
            case "enter", _:
                await self.action_activate_row()
            case _:
                handled = False
                self.pending_g = False
        if handled:
            event.prevent_default()
            event.stop()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "load_password":
                self.load_password()
            case "save_password":
                self.save_password()
            case "load_zones":
                await self.load_zones()
            case "discover_ad":
                self.action_discover_ad()
            case "open_connection":
                self.action_connection()

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "zones":
            return
        row = event.data_table.get_row_at(event.cursor_row)
        if not row:
            return
        zone = str(row[0])
        self.query_one("#zone", Input).value = zone
        self.refresh_connection_summary()
        self.set_status(f"Selected {zone}; refreshing records")
        await self.refresh_current_zone()

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        if event.data_table.id != "records":
            return
        match event.column_index:
            case 1:
                self.sort_records("name")
            case 2:
                self.sort_records("type")
            case 3:
                self.sort_records("value")


def main() -> None:
    SambatuiApp().run()


if __name__ == "__main__":
    main()
