from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse
import ssl
import warnings

from ldap3 import Tls
from ldap3.utils.conv import escape_filter_chars

DirectorySearchKind = Literal["users", "groups", "computers", "ous", "all"]
LdapAuthMode = Literal["password", "kerberos"]
LDAP_AUTH_MODES = frozenset({"password", "kerberos"})
LDAP_ENCRYPTION_MODES = frozenset({"off", "ldaps", "starttls"})
LDAP_COMPATIBILITY_ON = frozenset({"on"})
LDAP_COMPATIBILITY_OFF = frozenset({"", "off"})
LDAP_COMPATIBILITY_TLS_CIPHERS = "DEFAULT:@SECLEVEL=0"
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
    "member",
    "objectClass",
    "distinguishedName",
    "userAccountControl",
    "lastLogonTimestamp",
    "lastLogon",
    "whenCreated",
    "whenChanged",
    "pwdLastSet",
    "accountExpires",
    "primaryGroupID",
    "dNSHostName",
    "servicePrincipalName",
    "proxyAddresses",
)

_KIND_FILTERS: Mapping[str, str] = {
    "users": "(&(objectCategory=person)(objectClass=user))",
    "groups": "(objectCategory=group)",
    "computers": "(objectCategory=computer)",
    "ous": "(objectClass=organizationalUnit)",
    "all": "(|(&(objectCategory=person)(objectClass=user))(objectCategory=group)(objectCategory=computer)(objectClass=organizationalUnit))",
}

_CHILD_CONTAINER_FILTER = "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))"

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
        return ldap_compatibility_enabled(self.compatibility)

    def validation_error(self) -> str | None:
        auth_mode = self.normalized_auth_mode
        encryption = self.normalized_encryption
        compatibility = self.normalized_compatibility

        error = _ldap_mode_error(auth_mode, encryption, compatibility)
        if error:
            return error
        error = _ldap_server_error(self.server, encryption)
        if error:
            return error
        if auth_mode == "password":
            error = _ldap_password_auth_error(self.user, self.password, encryption)
            if error:
                return error
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


def _ldap_mode_error(auth_mode: str, encryption: str, compatibility: str) -> str | None:
    if auth_mode not in LDAP_AUTH_MODES:
        return "LDAP auth mode must be password or kerberos."
    if encryption not in LDAP_ENCRYPTION_MODES:
        return "LDAP encryption must be off, ldaps, or starttls."
    if compatibility not in LDAP_COMPATIBILITY_ON | LDAP_COMPATIBILITY_OFF:
        return "LDAP compatibility must be on or off."
    return None


def _ldap_server_error(server: str, encryption: str) -> str | None:
    if not server:
        return "Enter LDAP server/DC."
    scheme = ldap_server_scheme(server)
    if scheme == "ldap" and encryption == "ldaps":
        return "ldap:// server URLs require LDAP encryption starttls or off."
    if scheme == "ldaps" and encryption != "ldaps":
        return "ldaps:// server URLs require LDAP encryption ldaps."
    return None


def _ldap_password_auth_error(user: str, password: str, encryption: str) -> str | None:
    if encryption == "off":
        return "LDAP password bind requires ldaps or starttls."
    if not user:
        return "LDAP search needs a username."
    if not password:
        return "LDAP search needs a password or auth mode kerberos."
    return None


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


def ldap_compatibility_enabled(value: str) -> bool:
    return (value or "off").casefold() in LDAP_COMPATIBILITY_ON


def ldap_server_get_info(config: LdapSearchConfig) -> str:
    from ldap3 import ALL, NONE

    return NONE if config.compatibility_enabled else ALL


class LdapCompatibilityTls(Tls):
    def __init__(self) -> None:
        super().__init__(
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT,
            ciphers=LDAP_COMPATIBILITY_TLS_CIPHERS,
        )

    def wrap_socket(self, connection: Any, do_handshake: bool = False) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        _allow_compatibility_tls_versions(context)
        with suppress(ssl.SSLError):
            context.set_ciphers(LDAP_COMPATIBILITY_TLS_CIPHERS)
        connection.socket = context.wrap_socket(
            connection.socket,
            server_side=False,
            do_handshake_on_connect=do_handshake,
        )


def _allow_compatibility_tls_versions(context: ssl.SSLContext) -> None:
    minimum = getattr(ssl.TLSVersion, "TLSv1", None)
    if minimum is not None:
        with warnings.catch_warnings(), suppress(ValueError, ssl.SSLError):
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = minimum
    for option_name in ("OP_NO_TLSv1", "OP_NO_TLSv1_1"):
        option = getattr(ssl, option_name, 0)
        if option:
            context.options &= ~option


def ldap_server_tls(config: LdapSearchConfig) -> LdapCompatibilityTls | None:
    if config.normalized_encryption == "off" or not config.compatibility_enabled:
        return None
    return LdapCompatibilityTls()


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
        f"(mail=*{escaped}*)(proxyAddresses=*{escaped}*)"
        f"(dNSHostName=*{escaped}*)(distinguishedName=*{escaped}*))"
    )
    return f"(&{base_filter}{text_filter})"


class LdapDirectoryClient:
    def __init__(self, config: LdapSearchConfig) -> None:
        self.config = config

    def validation_error(self) -> str | None:
        return self.config.validation_error()

    def check_connection(self) -> None:
        error = self.validation_error()
        if error:
            raise ValueError(error)

        from ldap3.core.exceptions import LDAPException

        connection, settings = _new_ldap_connection(self.config)
        try:
            _start_tls_if_needed(connection, self.config, settings)
            _bind_connection(connection)
        finally:
            with suppress(LDAPException):
                connection.unbind()

    def search(
        self, kind: str, text: str = "", max_entries: int | None = None
    ) -> list[DirectoryRow]:
        return self._search_rows(
            build_directory_filter(kind, text), kind, max_entries=max_entries
        )

    def child_containers(self, max_entries: int | None = None) -> list[DirectoryRow]:
        return self._search_rows(
            _CHILD_CONTAINER_FILTER,
            "all",
            max_entries=max_entries,
            one_level=True,
        )

    def _search_rows(
        self,
        search_filter: str,
        kind: str,
        *,
        max_entries: int | None = None,
        one_level: bool = False,
    ) -> list[DirectoryRow]:
        error = self.validation_error()
        if error:
            raise ValueError(error)

        from ldap3.core.exceptions import LDAPException

        connection, settings = _new_ldap_connection(self.config)
        try:
            _start_tls_if_needed(connection, self.config, settings)
            _bind_connection(connection)
            entries = _search_connection(
                connection,
                self.config,
                search_filter,
                max_entries,
                one_level=one_level,
            )
            return [entry_to_directory_row(entry, kind) for entry in entries]
        finally:
            with suppress(LDAPException):
                connection.unbind()


def _new_ldap_connection(config: LdapSearchConfig) -> tuple[Any, LdapServerSettings]:
    from ldap3 import Connection, Server

    settings = parse_ldap_server(config.server, config.normalized_encryption)
    server = Server(
        settings.host,
        port=settings.port,
        use_ssl=settings.use_ssl,
        get_info=ldap_server_get_info(config),
        tls=ldap_server_tls(config),
        connect_timeout=config.timeout,
    )
    return Connection(server, **ldap_connection_kwargs(config)), settings


def _start_tls_if_needed(
    connection: Any, config: LdapSearchConfig, settings: LdapServerSettings
) -> None:
    if config.normalized_encryption != "starttls" or settings.use_ssl:
        return

    from ldap3.core.exceptions import LDAPException

    try:
        tls_started = connection.start_tls()
    except LDAPException as exc:
        raise ValueError(_ldap_exception_message(exc, "LDAP StartTLS failed")) from exc
    if not tls_started:
        raise ValueError(
            _ldap_result_message(connection.result, "LDAP StartTLS failed")
        )


def _bind_connection(connection: Any) -> None:
    from ldap3.core.exceptions import LDAPException, LDAPPackageUnavailableError

    try:
        bound = connection.bind()
    except LDAPPackageUnavailableError as exc:
        raise ValueError(
            "LDAP Kerberos bind needs optional package. Install sambatui[kerberos]."
        ) from exc
    except LDAPException as exc:
        raise ValueError(_ldap_exception_message(exc, "LDAP bind failed")) from exc
    if not bound:
        raise ValueError(_ldap_result_message(connection.result, "LDAP bind failed"))


def _search_connection(
    connection: Any,
    config: LdapSearchConfig,
    search_filter: str,
    max_entries: int | None = None,
    *,
    one_level: bool = False,
) -> list[Any]:
    from ldap3 import LEVEL, SUBTREE
    from ldap3.core.exceptions import LDAPException

    search_scope = LEVEL if one_level else SUBTREE
    rows: list[Any] = []
    cookie: bytes | str | None = None
    while True:
        try:
            ok = connection.search(
                config.base_dn,
                search_filter,
                search_scope=search_scope,
                attributes=list(DEFAULT_LDAP_ATTRIBUTES),
                paged_size=config.page_size,
                paged_cookie=cookie,
            )
        except LDAPException as exc:
            raise ValueError(
                _ldap_exception_message(exc, "LDAP search failed")
            ) from exc
        if not ok:
            raise ValueError(
                _ldap_result_message(connection.result, "LDAP search failed")
            )
        for entry in connection.entries:
            if max_entries is not None and len(rows) >= max_entries:
                return rows
            rows.append(entry)
        cookie = _paged_search_cookie(connection.result)
        if not cookie:
            return rows


def _paged_search_cookie(result: Mapping[str, Any] | None) -> bytes | str | None:
    if result is None:
        return None
    control = result.get("controls", {}).get("1.2.840.113556.1.4.319", {})
    value = control.get("value", {}) if isinstance(control, Mapping) else {}
    cookie = value.get("cookie") if isinstance(value, Mapping) else None
    return cookie or None


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
    return {
        str(key): normalize_attribute_values(value) for key, value in attributes.items()
    }


def normalize_attribute_values(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item) for item in value if item is not None)
    return (str(value),)


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
    if "container" in classes or "builtindomain" in classes:
        return "container"
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
