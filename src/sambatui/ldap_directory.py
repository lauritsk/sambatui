from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

from ldap3.utils.conv import escape_filter_chars

DirectorySearchKind = Literal["users", "groups", "computers", "ous", "all"]
LdapAuthMode = Literal["password", "kerberos"]
LDAP_AUTH_MODES = frozenset({"password", "kerberos"})
LDAP_ENCRYPTION_MODES = frozenset({"off", "ldaps", "starttls"})
LDAP_SEARCH_KINDS: tuple[DirectorySearchKind, ...] = (
    "users",
    "groups",
    "computers",
    "ous",
    "all",
)
DEFAULT_LDAP_ATTRIBUTES = (
    "cn",
    "name",
    "sAMAccountName",
    "userPrincipalName",
    "displayName",
    "description",
    "mail",
    "memberOf",
    "objectClass",
    "distinguishedName",
)

_KIND_FILTERS: Mapping[str, str] = {
    "users": "(&(objectCategory=person)(objectClass=user))",
    "groups": "(objectCategory=group)",
    "computers": "(objectCategory=computer)",
    "ous": "(objectClass=organizationalUnit)",
    "all": "(|(&(objectCategory=person)(objectClass=user))(objectCategory=group)(objectCategory=computer)(objectClass=organizationalUnit))",
}

_KIND_LABELS = {
    "users": "user",
    "groups": "group",
    "computers": "computer",
    "ous": "ou",
    "all": "object",
}


@dataclass(frozen=True)
class LdapSearchConfig:
    server: str
    user: str = ""
    password: str = ""
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
        if not self.server:
            return "Enter LDAP server/DC."
        if self.normalized_auth_mode not in LDAP_AUTH_MODES:
            return "LDAP auth mode must be password or kerberos."
        if self.normalized_encryption not in LDAP_ENCRYPTION_MODES:
            return "LDAP encryption must be off, ldaps, or starttls."
        scheme = ldap_server_scheme(self.server)
        if scheme == "ldap" and self.normalized_encryption == "ldaps":
            return "ldap:// server URLs require LDAP encryption starttls or off."
        if scheme == "ldaps" and self.normalized_encryption != "ldaps":
            return "ldaps:// server URLs require LDAP encryption ldaps."
        if (
            self.normalized_auth_mode == "password"
            and self.normalized_encryption == "off"
        ):
            return "LDAP password bind requires ldaps or starttls."
        if self.normalized_auth_mode == "password" and not self.user:
            return "LDAP search needs a username."
        if self.normalized_auth_mode == "password" and not self.password:
            return "LDAP search needs a password or auth mode kerberos."
        if not self.base_dn:
            return "Enter LDAP base DN, e.g. DC=example,DC=com."
        return None


@dataclass(frozen=True)
class LdapServerSettings:
    host: str
    port: int
    use_ssl: bool


@dataclass(frozen=True)
class DirectoryRow:
    dn: str
    kind: str
    name: str
    summary: str
    attributes: Mapping[str, Sequence[str]]


def domain_to_base_dn(domain: str) -> str:
    labels = [label.strip() for label in domain.strip().rstrip(".").split(".")]
    if not labels or any(not label for label in labels):
        return ""
    return ",".join(f"DC={label}" for label in labels)


def ldap_server_scheme(server: str) -> str:
    return urlparse(server.strip()).scheme.casefold()


def parse_ldap_server(server: str, encryption: str = "ldaps") -> LdapServerSettings:
    value = server.strip()
    normalized_encryption = (encryption or "ldaps").casefold()
    if "://" not in value:
        value = f"//{value}"
    parsed = urlparse(value)
    scheme = parsed.scheme.casefold()
    if scheme and scheme not in {"ldap", "ldaps"}:
        raise ValueError("LDAP server URL scheme must be ldap or ldaps.")
    use_ssl = scheme == "ldaps" or (not scheme and normalized_encryption == "ldaps")
    default_port = 636 if use_ssl else 389
    host = parsed.hostname or parsed.path
    if not host:
        raise ValueError("Enter LDAP server/DC.")
    return LdapServerSettings(
        host=host, port=parsed.port or default_port, use_ssl=use_ssl
    )


def gssapi_cred_store(krb5_ccache: str) -> dict[str, str] | None:
    if not krb5_ccache:
        return None
    ccache = krb5_ccache if ":" in krb5_ccache else f"FILE:{krb5_ccache}"
    return {"ccache": ccache}


def ldap_connection_kwargs(config: LdapSearchConfig) -> dict[str, Any]:
    from ldap3 import GSSAPI, NTLM, SASL, SIMPLE

    common: dict[str, Any] = {
        "receive_timeout": config.timeout,
        "auto_bind": False,
        "read_only": True,
    }
    if config.normalized_auth_mode == "kerberos":
        common.update(
            authentication=SASL,
            sasl_mechanism=GSSAPI,
            user=config.user or None,
            sasl_credentials=(False,),
            cred_store=gssapi_cred_store(config.krb5_ccache),
        )
        return common

    common.update(
        user=config.user,
        password=config.password,
        authentication=NTLM if "\\" in config.user else SIMPLE,
    )
    return common


def build_directory_filter(kind: str, text: str = "") -> str:
    normalized_kind = kind.casefold() or "users"
    base_filter = _KIND_FILTERS.get(normalized_kind)
    if base_filter is None:
        valid = ", ".join(LDAP_SEARCH_KINDS)
        raise ValueError(f"LDAP search type must be one of: {valid}.")
    needle = text.strip()
    if not needle:
        return base_filter
    escaped = escape_filter_chars(needle)
    text_filter = (
        f"(|(cn=*{escaped}*)(name=*{escaped}*)(sAMAccountName=*{escaped}*)"
        f"(userPrincipalName=*{escaped}*)(displayName=*{escaped}*)"
        f"(distinguishedName=*{escaped}*))"
    )
    return f"(&{base_filter}{text_filter})"


class LdapDirectoryClient:
    def __init__(self, config: LdapSearchConfig) -> None:
        self.config = config

    def validation_error(self) -> str | None:
        return self.config.validation_error()

    def search(self, kind: str, text: str = "") -> list[DirectoryRow]:
        error = self.validation_error()
        if error:
            raise ValueError(error)

        from ldap3 import ALL, SUBTREE, Connection, Server
        from ldap3.core.exceptions import LDAPException, LDAPPackageUnavailableError

        settings = parse_ldap_server(
            self.config.server, self.config.normalized_encryption
        )
        server = Server(
            settings.host,
            port=settings.port,
            use_ssl=settings.use_ssl,
            get_info=ALL,
            connect_timeout=self.config.timeout,
        )
        connection = Connection(server, **ldap_connection_kwargs(self.config))
        try:
            if self.config.normalized_encryption == "starttls" and not settings.use_ssl:
                try:
                    tls_started = connection.start_tls()
                except LDAPException as exc:
                    raise ValueError(
                        _ldap_exception_message(exc, "LDAP StartTLS failed")
                    ) from exc
                if not tls_started:
                    raise ValueError(
                        _ldap_result_message(connection.result, "LDAP StartTLS failed")
                    )
            try:
                bound = connection.bind()
            except LDAPPackageUnavailableError as exc:
                raise ValueError(
                    "LDAP Kerberos bind needs optional package. "
                    "Install sambatui[kerberos]."
                ) from exc
            except LDAPException as exc:
                raise ValueError(
                    _ldap_exception_message(exc, "LDAP bind failed")
                ) from exc
            if not bound:
                raise ValueError(
                    _ldap_result_message(connection.result, "LDAP bind failed")
                )
            search_filter = build_directory_filter(kind, text)
            try:
                ok = connection.search(
                    self.config.base_dn,
                    search_filter,
                    search_scope=SUBTREE,
                    attributes=list(DEFAULT_LDAP_ATTRIBUTES),
                    paged_size=self.config.page_size,
                )
            except LDAPException as exc:
                raise ValueError(
                    _ldap_exception_message(exc, "LDAP search failed")
                ) from exc
            if not ok:
                raise ValueError(
                    _ldap_result_message(connection.result, "LDAP search failed")
                )
            return [entry_to_directory_row(entry, kind) for entry in connection.entries]
        finally:
            try:
                connection.unbind()
            except LDAPException:
                pass


def entry_to_directory_row(entry: Any, kind: str = "all") -> DirectoryRow:
    attrs = normalize_entry_attributes(entry.entry_attributes_as_dict)
    dn = str(entry.entry_dn)
    name = first_attr(attrs, "displayName", "cn", "name", "sAMAccountName") or dn
    row_kind = infer_kind(attrs, kind)
    summary = directory_summary(attrs)
    return DirectoryRow(
        dn=dn, kind=row_kind, name=name, summary=summary, attributes=attrs
    )


def normalize_entry_attributes(
    attributes: Mapping[str, Any],
) -> dict[str, tuple[str, ...]]:
    normalized: dict[str, tuple[str, ...]] = {}
    for key, value in attributes.items():
        if isinstance(value, (list, tuple, set)):
            values = tuple(str(item) for item in value if item is not None)
        elif value is None:
            values = ()
        else:
            values = (str(value),)
        normalized[str(key)] = values
    return normalized


def first_attr(attrs: Mapping[str, Sequence[str]], *names: str) -> str:
    for name in names:
        values = attrs.get(name, ())
        if values:
            return values[0]
    return ""


def infer_kind(attrs: Mapping[str, Sequence[str]], requested_kind: str = "all") -> str:
    classes = {value.casefold() for value in attrs.get("objectClass", ())}
    if "computer" in classes:
        return "computer"
    if "group" in classes:
        return "group"
    if "organizationalunit" in classes:
        return "ou"
    if "user" in classes and "person" in classes:
        return "user"
    return _KIND_LABELS.get(requested_kind.casefold(), "object")


def directory_summary(attrs: Mapping[str, Sequence[str]]) -> str:
    parts = [
        first_attr(attrs, "sAMAccountName"),
        first_attr(attrs, "userPrincipalName"),
        first_attr(attrs, "mail"),
        first_attr(attrs, "description"),
    ]
    member_of = attrs.get("memberOf", ())
    if member_of:
        parts.append(f"memberOf={len(member_of)}")
    return " · ".join(part for part in parts if part)


def _ldap_result_message(result: Mapping[str, Any] | None, fallback: str) -> str:
    if result is None:
        return fallback
    description = str(result.get("description") or "").strip()
    message = str(result.get("message") or "").strip()
    detail = ": ".join(part for part in (description, message) if part)
    return f"{fallback}: {detail}" if detail else fallback


def _ldap_exception_message(exc: Exception, fallback: str) -> str:
    message = str(exc).strip()
    return f"{fallback}: {message}" if message else fallback
