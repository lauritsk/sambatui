from __future__ import annotations

import asyncio

from textual import work

from ..core.config import (
    password_file_warning,
    read_password_file,
    user_config_validation_error,
)
from ..samba.discovery import (
    DiscoveredService,
    discover_ad_services,
    normalize_domain,
    preferred_domain_controller,
)
from ..dns.parsing import parse_zones
from ..ldap.client import (
    domain_to_base_dn,
)
from ..ui.screens import (
    FormField,
)
from ..app_constants import (
    DEFAULT_AUTH,
    DEFAULT_KERBEROS,
    DEFAULT_LDAP_COMPATIBILITY,
    DEFAULT_LDAP_ENCRYPTION,
)
from .base import AppControllerBase
from .helpers import (
    setup_auth_values,
)


class AppSetupMixin(AppControllerBase):
    def setup_wizard_auth_defaults(self) -> tuple[str, str]:
        auth = self.val("auth") or DEFAULT_AUTH
        kerberos = self.val("kerberos") or DEFAULT_KERBEROS
        return setup_auth_values(auth, kerberos)

    def setup_wizard_fields(self) -> list[FormField]:
        auth, kerberos = self.setup_wizard_auth_defaults()
        return [
            (
                "AD DNS domain — used to discover domain controllers and zones.",
                "domain",
                "example.com",
                self.connection_domain_default(),
            ),
            (
                "User — DOMAIN\\user or UPN; UPN is preferred for LDAP password bind.",
                "user",
                "admin@example.com",
                self.val("user"),
            ),
            (
                "Password — hidden; leave empty for Kerberos or configured password file.",
                "password",
                "password",
                self.val("password"),
            ),
            ("Auth mode — password or kerberos.", "auth", "password | kerberos", auth),
            (
                "Kerberos option — required is safest for Kerberos setup.",
                "kerberos",
                "required | desired | off",
                kerberos,
            ),
            (
                "LDAP encryption — password bind requires ldaps or starttls.",
                "ldap_encryption",
                "ldaps | starttls | off",
                self.val("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            ),
            (
                "LDAP compatibility — only if DC needs relaxed TLS/schema; with password auth prefer UPN user.",
                "ldap_compatibility",
                "on | off",
                self.val("ldap_compatibility") or DEFAULT_LDAP_COMPATIBILITY,
            ),
        ]

    def setup_wizard_validation_error(self, values: dict[str, str]) -> str | None:
        try:
            normalize_domain(values.get("domain", ""))
        except ValueError as exc:
            return str(exc)
        error = user_config_validation_error(values)
        if error:
            return error
        if (values.get("auth") or DEFAULT_AUTH).casefold() != "password":
            return None
        if not values.get("user"):
            return "Enter username or switch auth to kerberos."
        if values.get("password") or read_password_file(self.password_file()):
            return None
        return "Enter password, load password file, or switch auth to kerberos."

    async def discover_setup_services(self, domain: str) -> list[DiscoveredService]:
        return await asyncio.to_thread(discover_ad_services, domain)

    def apply_setup_wizard_values(
        self, domain: str, server: str, values: dict[str, str]
    ) -> None:
        auth = values.get("auth") or DEFAULT_AUTH
        kerberos = values.get("kerberos") or DEFAULT_KERBEROS
        auth, kerberos = setup_auth_values(auth, kerberos)
        password = values.get("password") or read_password_file(self.password_file())
        self.set_val("server", server)
        self.set_val("domain", domain)
        self.set_val("zone", domain)
        self.ldap_structure_rows = []
        self.set_val("ldap_base", domain_to_base_dn(domain))
        self.set_val("user", values.get("user", self.val("user")))
        self.set_val("password", password)
        self.set_val("auth", auth)
        self.set_val("kerberos", kerberos)
        self.set_val(
            "ldap_encryption", values.get("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION
        )
        self.set_val(
            "ldap_compatibility",
            values.get("ldap_compatibility") or DEFAULT_LDAP_COMPATIBILITY,
        )
        self.refresh_connection_summary()
        self.update_records_title()
        self.populate_ldap_structure(self.ldap_structure_rows)

    async def check_ldap_connectivity(self) -> str | None:
        try:
            await asyncio.to_thread(self.ldap_client().check_connection)
        except Exception as exc:
            return str(exc)
        return None

    def setup_check_failed(self, check: str, message: str, action: str) -> bool:
        detail = next(
            (line.strip() for line in message.splitlines() if line.strip()), ""
        )
        suffix = f": {detail}" if detail else ""
        self.report_error(f"Setup {check} check failed{suffix} Action: {action}.")
        return False

    async def setup_dns_zones(self) -> list[str] | None:
        self.set_status("Setup: checking DNS zones")
        code, output = await self.run_zonelist()
        if code != 0:
            self.setup_check_failed(
                "DNS",
                output,
                "check credentials, DC reachability, samba-tool rights, and domain",
            )
            return None

        zones = parse_zones(output)
        if not zones:
            self.setup_check_failed(
                "DNS",
                "no zones returned",
                "check DNS service health and account rights on the selected DC",
            )
            return None
        return zones

    async def setup_ldap_connectivity_ok(self) -> bool:
        self.set_status("Setup: checking LDAP bind")
        ldap_error = await self.check_ldap_connectivity()
        if not ldap_error:
            return True
        return self.setup_check_failed(
            "LDAP",
            ldap_error,
            "check LDAP encryption, credentials, Base DN, firewall, or Kerberos ticket",
        )

    async def run_setup_wizard(self, values: dict[str, str]) -> bool:
        domain = normalize_domain(values.get("domain", "")).lower()
        async with self.busy():
            self.set_status(f"Setup: discovering domain controllers for {domain}")
            try:
                services = await self.discover_setup_services(domain)
            except ValueError as exc:
                self.report_error(str(exc))
                return False

            controller = preferred_domain_controller(services)
            if controller is None:
                self.report_error(f"No AD SRV records found for {domain}")
                return False

            self.apply_setup_wizard_values(domain, controller.target, values)
            zones = await self.setup_dns_zones()
            if zones is None or not await self.setup_ldap_connectivity_ok():
                return False

            self.zones = zones
            self.populate_zones(zones)
            self.save_preferences()

        if self.val("zone") in self.zones:
            await self.activate_zone(self.val("zone"), save=False)
        else:
            self.set_status(
                f"Setup complete: loaded {len(self.zones)} zones; select a zone and press Enter"
            )
        self.notify(f"Setup complete: loaded {len(self.zones)} zones")
        return True

    async def open_setup_wizard(self) -> bool:
        values = await self.form(
            "First-run setup wizard",
            "Enter the AD DNS domain and required credentials. sambatui discovers a DC, checks DNS/LDAP connectivity, then loads zones.",
            self.setup_wizard_fields(),
            "Run checks",
            self.setup_wizard_validation_error,
        )
        if values is None:
            self.refresh_connection_summary()
            return False
        return await self.run_setup_wizard(values)

    @work
    async def action_setup_wizard(self) -> None:
        await self.open_setup_wizard()

    async def open_connection_settings(self) -> bool:
        values = await self.form(
            "Connection settings",
            "These values feed samba-tool and LDAP. Press Apply to close; reopen with Ctrl+O or ? help.",
            self.connection_fields(),
            "Apply",
            user_config_validation_error,
        )
        if values is None:
            self.refresh_connection_summary()
            return False
        for widget_id, value in values.items():
            self.set_val(widget_id, value)
        if (self.val("auth") or DEFAULT_AUTH).casefold() == "password" and not self.val(
            "password"
        ):
            warning = password_file_warning(self.password_file())
            if warning:
                self.report_error(warning)
            else:
                password = read_password_file(self.password_file())
                if password:
                    self.set_val("password", password)
        self.refresh_connection_summary()
        self.save_preferences()
        self.set_status("Connection settings updated")
        if not self.connection_needs_setup():
            await self.load_zones()
        return True

    @work
    async def action_connection(self) -> None:
        await self.open_connection_settings()

    async def discover_ad_controller(
        self, domain: str
    ) -> tuple[list[DiscoveredService], DiscoveredService] | None:
        try:
            services = await asyncio.to_thread(discover_ad_services, domain)
        except ValueError as exc:
            self.report_error(str(exc))
            return None

        controller = preferred_domain_controller(services)
        if controller is None:
            self.report_error(f"No AD SRV records found for {domain}")
            return None
        return services, controller

    def apply_discovered_ad_controller(self, controller: DiscoveredService) -> None:
        self.set_val("server", controller.target)
        self.set_val("domain", controller.domain)
        if not self.val("zone"):
            self.set_val("zone", controller.domain)
        if not self.val("ldap_base"):
            self.set_val("ldap_base", domain_to_base_dn(controller.domain))
            self.ldap_structure_rows = []
        self.populate_ldap_structure(self.ldap_structure_rows)
        self.refresh_connection_summary()
        self.save_preferences()

    async def open_discover_ad(self, default_domain: str = "") -> bool:
        values = await self.form(
            "Discover AD domain controllers",
            "Uses DNS SRV records. No LDAP bind or new dependency required.",
            [
                (
                    "AD DNS domain",
                    "domain",
                    "example.com",
                    default_domain or self.connection_domain_default(),
                )
            ],
            "Discover",
        )
        if not values:
            return False

        domain = values["domain"] or self.connection_domain_default()
        async with self.busy():
            discovery = await self.discover_ad_controller(domain)
            if discovery is None:
                return False
            services, controller = discovery
            self.apply_discovered_ad_controller(controller)
            message = (
                f"Discovered {len(services)} AD SRV record(s); "
                f"selected {controller.target}:{controller.port}"
            )
            self.set_status(message)
            self.notify(message)
            return True

    @work
    async def action_discover_ad(self) -> None:
        await self.open_discover_ad(self.discovery_domain_default())
