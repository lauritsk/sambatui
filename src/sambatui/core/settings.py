from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import Path

from sambatui.ldap.config import domain_to_base_dn
from sambatui.ldap.types import LdapSearchConfig
from sambatui.samba.client import SambaToolConfig, parse_samba_options

from .config import (
    DEFAULT_AUTH,
    DEFAULT_AUTO_PTR,
    DEFAULT_CONFIGFILE,
    DEFAULT_DOMAIN,
    DEFAULT_KERBEROS,
    DEFAULT_KRB5_CCACHE,
    DEFAULT_LDAP_BASE,
    DEFAULT_LDAP_ENCRYPTION,
    DEFAULT_OPTIONS,
    DEFAULT_PASSWORD,
    DEFAULT_PASSWORD_FILE,
    DEFAULT_SERVER,
    DEFAULT_SMART_DAYS,
    DEFAULT_SMART_DISABLED_DAYS,
    DEFAULT_SMART_MAX_ROWS,
    DEFAULT_SMART_NEVER_LOGGED_DAYS,
    DEFAULT_USER,
    DEFAULT_ZONE,
)

type FormField = tuple[str, str, str, str]
type FieldTemplate = tuple[str, str, str]

SAMBA_FIELD_TEMPLATES: tuple[FieldTemplate, ...] = (
    (
        "Server — AD domain controller hostname or IP used by samba-tool -H.",
        "server",
        "dc01.example.com or 192.0.2.10",
    ),
    (
        "AD DNS domain — used for setup/discovery and LDAP defaults.",
        "domain",
        "example.com",
    ),
    (
        "DNS zone — active zone to query/edit after loading zones.",
        "zone",
        "example.com or 2.0.192.in-addr.arpa",
    ),
    (
        "User — DOMAIN\\user or UPN; UPN is preferred for LDAP password bind.",
        "user",
        "admin@example.com",
    ),
    (
        "Password — hidden. Leave empty for Kerberos or password file/env loading.",
        "password",
        "password",
    ),
    ("Auth mode — password or kerberos.", "auth", "password | kerberos"),
    (
        "Kerberos option — value passed to --use-kerberos.",
        "kerberos",
        "desired | required | off",
    ),
    (
        "Kerberos credential cache — optional --use-krb5-ccache path.",
        "krb5_ccache",
        "/tmp/krb5cc_1000",
    ),
    (
        "smb.conf — optional --configfile path for Samba settings.",
        "configfile",
        "/etc/samba/smb.conf",
    ),
    (
        "Extra smb.conf option values — separate multiple values with semicolons.",
        "options",
        "client min protocol=SMB3; log level=1",
    ),
)


@dataclass(frozen=True)
class ConnectionSettings:
    server: str = DEFAULT_SERVER
    domain: str = DEFAULT_DOMAIN
    zone: str = DEFAULT_ZONE
    user: str = DEFAULT_USER
    password: str = field(default=DEFAULT_PASSWORD, repr=False)
    auth: str = DEFAULT_AUTH
    kerberos: str = DEFAULT_KERBEROS
    krb5_ccache: str = DEFAULT_KRB5_CCACHE
    configfile: str = DEFAULT_CONFIGFILE
    options: str = DEFAULT_OPTIONS
    ldap_base: str = DEFAULT_LDAP_BASE
    ldap_encryption: str = DEFAULT_LDAP_ENCRYPTION
    auto_ptr: str = DEFAULT_AUTO_PTR
    smart_days: str = DEFAULT_SMART_DAYS
    smart_disabled_days: str = DEFAULT_SMART_DISABLED_DAYS
    smart_never_logged_days: str = DEFAULT_SMART_NEVER_LOGGED_DAYS
    smart_max_rows: str = DEFAULT_SMART_MAX_ROWS
    password_file: str = str(DEFAULT_PASSWORD_FILE)

    def __post_init__(self) -> None:
        for setting in fields(self):
            if setting.name != "password":
                object.__setattr__(self, setting.name, self.value(setting.name).strip())

    def value(self, name: str) -> str:
        if name not in {setting.name for setting in fields(self)}:
            raise KeyError(name)
        value: str = getattr(self, name)
        return value

    def updated(self, values: Mapping[str, str]) -> ConnectionSettings:
        for name in values:
            self.value(name)
        return replace(self, **values)

    @property
    def path_password_file(self) -> Path:
        return Path(self.password_file).expanduser()

    @property
    def summary(self) -> str:
        server = self.server or "no server"
        zone = self.zone or "no zone"
        auth = self.auth or DEFAULT_AUTH
        return f"{server} · {zone} · {auth} auth"

    def needs_setup(self, password_loader: Callable[[Path], str]) -> bool:
        if not self.server:
            return True
        if (self.auth or DEFAULT_AUTH).casefold() != "password":
            return False
        if not self.user:
            return True
        return not (self.password or password_loader(self.path_password_file))

    def samba_config(self) -> SambaToolConfig:
        return SambaToolConfig(
            server=self.server,
            user=self.user,
            password=self.password,
            auth_mode=self.auth or DEFAULT_AUTH,
            kerberos=self.kerberos or DEFAULT_KERBEROS,
            krb5_ccache=self.krb5_ccache,
            configfile=self.configfile,
            options=parse_samba_options(self.options),
        )

    def ldap_config(self, base_dn: str = "") -> LdapSearchConfig:
        return LdapSearchConfig(
            server=self.server,
            user=self.user,
            password=self.password,
            base_dn=base_dn
            or self.ldap_base
            or domain_to_base_dn(self.domain or self.zone),
            encryption=self.ldap_encryption or DEFAULT_LDAP_ENCRYPTION,
            auth_mode=self.auth or DEFAULT_AUTH,
            krb5_ccache=self.krb5_ccache,
        )

    def samba_form_fields(self) -> list[FormField]:
        return [
            (label, field_name, placeholder, getattr(self, field_name))
            for label, field_name, placeholder in SAMBA_FIELD_TEMPLATES
        ]

    def ldap_form_fields(self) -> list[FormField]:
        return [
            (
                "LDAP base DN — used by directory search and LDAP edits.",
                "ldap_base",
                "DC=example,DC=com",
                self.ldap_base or domain_to_base_dn(self.domain or self.zone),
            ),
            (
                "LDAP encryption — verified TLS is required for both authentication modes.",
                "ldap_encryption",
                "ldaps | starttls",
                self.ldap_encryption or DEFAULT_LDAP_ENCRYPTION,
            ),
        ]

    def convenience_form_fields(self) -> list[FormField]:
        return [
            (
                "Auto PTR — ask prompts after A adds; on auto-adds; off skips.",
                "auto_ptr",
                "ask | on | off",
                self.auto_ptr or DEFAULT_AUTO_PTR,
            ),
            (
                "Password file — used at startup and by password load/save commands.",
                "password_file",
                str(DEFAULT_PASSWORD_FILE),
                self.password_file,
            ),
        ]

    def smart_form_fields(self) -> list[FormField]:
        return [
            (
                "Finding inactive/stale days — used by passive and LDAP findings.",
                "smart_days",
                DEFAULT_SMART_DAYS,
                self.smart_days or DEFAULT_SMART_DAYS,
            ),
            (
                "Finding disabled cleanup days — delete-candidate threshold.",
                "smart_disabled_days",
                DEFAULT_SMART_DISABLED_DAYS,
                self.smart_disabled_days or DEFAULT_SMART_DISABLED_DAYS,
            ),
            (
                "Finding never-logged-in days — delete-candidate threshold.",
                "smart_never_logged_days",
                DEFAULT_SMART_NEVER_LOGGED_DAYS,
                self.smart_never_logged_days or DEFAULT_SMART_NEVER_LOGGED_DAYS,
            ),
            (
                "Finding max rows — default smart-view directory/result limit.",
                "smart_max_rows",
                DEFAULT_SMART_MAX_ROWS,
                self.smart_max_rows or DEFAULT_SMART_MAX_ROWS,
            ),
        ]

    def form_fields(self) -> list[FormField]:
        return [
            *self.samba_form_fields(),
            *self.ldap_form_fields(),
            *self.smart_form_fields(),
            *self.convenience_form_fields(),
        ]
