from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol
from urllib.parse import urlparse

# Raw LDAP responses are decoded defensively at the library boundary. Writes
# have a narrower contract: add values and modify operations are not interchangeable.
type LdapResult = Mapping[str, object]
type LdapAttributes = Mapping[str, str | int]
type LdapChanges = Mapping[str, Sequence[tuple[str, Sequence[str]]]]
type LdapCookie = bytes | str | None


class LdapEntry(Protocol):
    """Read-only projection of ldap3 entries used by the row decoder."""

    @property
    def entry_dn(self) -> str: ...

    @property
    def entry_attributes_as_dict(self) -> Mapping[str, object]: ...


DirectorySearchKind = Literal["users", "groups", "computers", "ous", "all"]
DirectoryAddKind = Literal["user", "group", "computer", "ou"]

LDAP_AUTH_MODES = frozenset({"password", "kerberos"})
LDAP_ENCRYPTION_MODES = frozenset({"ldaps", "starttls"})
LDAP_SEARCH_KINDS: tuple[DirectorySearchKind, ...] = (
    "users",
    "groups",
    "computers",
    "ous",
    "all",
)
LDAP_ADD_KINDS: tuple[DirectoryAddKind, ...] = ("user", "group", "computer", "ou")
LDAP_EDITABLE_ATTRIBUTES = {
    "user": ("displayName", "mail", "description"),
    "group": ("description", "mail"),
    "computer": ("description",),
    "ou": ("description",),
}
ALL_LDAP_EDITABLE_ATTRIBUTES = frozenset(
    attr for attrs in LDAP_EDITABLE_ATTRIBUTES.values() for attr in attrs
)


@dataclass(frozen=True)
class LdapSearchConfig:
    server: str
    user: str = ""
    password: str = field(default="", repr=False)
    base_dn: str = ""
    encryption: str = "ldaps"
    auth_mode: str = "password"
    krb5_ccache: str = ""
    page_size: int = 200
    timeout: int = 10

    @property
    def normalized_encryption(self) -> str:
        return (self.encryption or "ldaps").casefold()

    @property
    def normalized_auth_mode(self) -> str:
        return (self.auth_mode or "password").casefold()

    def validation_error(self) -> str | None:
        auth_mode = self.normalized_auth_mode
        encryption = self.normalized_encryption
        if auth_mode not in LDAP_AUTH_MODES:
            return "LDAP auth mode must be password or kerberos."
        if encryption not in LDAP_ENCRYPTION_MODES:
            return "LDAP encryption must be ldaps or starttls."
        if not self.server:
            return "Enter LDAP server/DC."
        scheme = urlparse(self.server.strip()).scheme.casefold()
        if scheme == "ldap" and encryption != "starttls":
            return "ldap:// server URLs require LDAP encryption starttls."
        if scheme == "ldaps" and encryption != "ldaps":
            return "ldaps:// server URLs require LDAP encryption ldaps."
        if auth_mode == "password":
            if not self.user:
                return "LDAP search needs a username."
            if not self.password:
                return "LDAP search needs a password or auth mode kerberos."
        if not self.base_dn:
            return "Enter LDAP base DN, e.g. DC=example,DC=com."
        return None


@dataclass(frozen=True)
class LdapServerSettings:
    host: str
    port: int
    use_ssl: bool
