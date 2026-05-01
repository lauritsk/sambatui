from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from .client import SambaToolConfig, parse_samba_options
from .config import (
    DEFAULT_AUTH,
    DEFAULT_AUTO_PTR,
    DEFAULT_CONFIGFILE,
    DEFAULT_DOMAIN,
    DEFAULT_KERBEROS,
    DEFAULT_KRB5_CCACHE,
    DEFAULT_LDAP_COMPATIBILITY,
    DEFAULT_LDAP_ENCRYPTION,
    DEFAULT_OPTIONS,
    DEFAULT_PASSWORD,
    DEFAULT_PASSWORD_FILE,
    DEFAULT_SERVER,
    DEFAULT_USER,
    DEFAULT_ZONE,
)
from .ldap_directory import LdapSearchConfig, domain_to_base_dn

FormField: TypeAlias = tuple[str, str, str, str]


@dataclass(frozen=True)
class ConnectionSettings:
    server: str = DEFAULT_SERVER
    domain: str = DEFAULT_DOMAIN
    zone: str = DEFAULT_ZONE
    user: str = DEFAULT_USER
    password: str = DEFAULT_PASSWORD
    auth: str = DEFAULT_AUTH
    kerberos: str = DEFAULT_KERBEROS
    krb5_ccache: str = DEFAULT_KRB5_CCACHE
    configfile: str = DEFAULT_CONFIGFILE
    options: str = DEFAULT_OPTIONS
    ldap_base: str = ""
    ldap_encryption: str = DEFAULT_LDAP_ENCRYPTION
    ldap_compatibility: str = DEFAULT_LDAP_COMPATIBILITY
    auto_ptr: str = DEFAULT_AUTO_PTR
    password_file: str = str(DEFAULT_PASSWORD_FILE)

    @classmethod
    def from_lookup(cls, lookup: Callable[[str], str]) -> ConnectionSettings:
        def value(key: str) -> str:
            try:
                return lookup(key)
            except KeyError, LookupError:
                return ""

        return cls(
            server=value("server"),
            domain=value("domain"),
            zone=value("zone"),
            user=value("user"),
            password=value("password"),
            auth=value("auth") or DEFAULT_AUTH,
            kerberos=value("kerberos") or DEFAULT_KERBEROS,
            krb5_ccache=value("krb5_ccache"),
            configfile=value("configfile"),
            options=value("options"),
            ldap_base=value("ldap_base"),
            ldap_encryption=value("ldap_encryption") or DEFAULT_LDAP_ENCRYPTION,
            ldap_compatibility=value("ldap_compatibility")
            or DEFAULT_LDAP_COMPATIBILITY,
            auto_ptr=value("auto_ptr") or DEFAULT_AUTO_PTR,
            password_file=value("password_file") or str(DEFAULT_PASSWORD_FILE),
        )

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
            compatibility=self.ldap_compatibility or DEFAULT_LDAP_COMPATIBILITY,
        )

    def samba_form_fields(self) -> list[FormField]:
        return [
            (
                "Server — AD domain controller hostname or IP used by samba-tool -H.",
                "server",
                "dc01.example.com or 192.0.2.10",
                self.server,
            ),
            (
                "AD DNS domain — used for setup/discovery and LDAP defaults.",
                "domain",
                "example.com",
                self.domain,
            ),
            (
                "DNS zone — active zone to query/edit after loading zones.",
                "zone",
                "example.com or 2.0.192.in-addr.arpa",
                self.zone,
            ),
            (
                "User — DOMAIN\\user or UPN; UPN is preferred for LDAP password bind.",
                "user",
                "admin@example.com",
                self.user,
            ),
            (
                "Password — hidden. Leave empty for Kerberos or password file/env loading.",
                "password",
                "password",
                self.password,
            ),
            (
                "Auth mode — password or kerberos.",
                "auth",
                "password | kerberos",
                self.auth,
            ),
            (
                "Kerberos option — value passed to --use-kerberos.",
                "kerberos",
                "desired | required | off",
                self.kerberos,
            ),
            (
                "Kerberos credential cache — optional --use-krb5-ccache path.",
                "krb5_ccache",
                "/tmp/krb5cc_1000",
                self.krb5_ccache,
            ),
            (
                "smb.conf — optional --configfile path for Samba settings.",
                "configfile",
                "/etc/samba/smb.conf",
                self.configfile,
            ),
            (
                "Extra samba-tool options — separate multiple options with semicolons.",
                "options",
                "--option=name=value; --debuglevel=1",
                self.options,
            ),
        ]

    def ldap_form_fields(self) -> list[FormField]:
        return [
            (
                "LDAP base DN — used by read-only directory search.",
                "ldap_base",
                "DC=example,DC=com",
                self.ldap_base or domain_to_base_dn(self.domain or self.zone),
            ),
            (
                "LDAP encryption — password bind requires ldaps or starttls; kerberos also supports off.",
                "ldap_encryption",
                "off | ldaps | starttls",
                self.ldap_encryption or DEFAULT_LDAP_ENCRYPTION,
            ),
            (
                "LDAP compatibility — on relaxes TLS/schema; with password auth prefer UPN user.",
                "ldap_compatibility",
                "on | off",
                self.ldap_compatibility or DEFAULT_LDAP_COMPATIBILITY,
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
                "~/.config/sambatui/password",
                self.password_file,
            ),
        ]

    def form_fields(self) -> list[FormField]:
        return [
            *self.samba_form_fields(),
            *self.ldap_form_fields(),
            *self.convenience_form_fields(),
        ]
