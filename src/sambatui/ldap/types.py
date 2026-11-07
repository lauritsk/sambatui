from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol

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
LdapAuthMode = Literal["password", "kerberos"]

LDAP_AUTH_MODES = frozenset({"password", "kerberos"})
LDAP_ENCRYPTION_MODES = frozenset({"off", "ldaps", "starttls"})
LDAP_COMPATIBILITY_ON = frozenset({"on"})
LDAP_COMPATIBILITY_OFF = frozenset({"", "off"})
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
    compatibility: str = "off"
    page_size: int = 200
    timeout: int = 10

    @property
    def normalized_encryption(self) -> str:
        return (self.encryption or "ldaps").casefold()

    @property
    def normalized_auth_mode(self) -> str:
        return (self.auth_mode or "password").casefold()

    @property
    def normalized_compatibility(self) -> str:
        return (self.compatibility or "off").casefold()

    @property
    def compatibility_enabled(self) -> bool:
        from sambatui.ldap.config import ldap_compatibility_enabled

        return ldap_compatibility_enabled(self.compatibility)

    def validation_error(self) -> str | None:
        from sambatui.ldap.config import ldap_config_validation_error

        return ldap_config_validation_error(self)


@dataclass(frozen=True)
class LdapServerSettings:
    host: str
    port: int
    use_ssl: bool
