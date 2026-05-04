from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from typing import Protocol, cast

from sambatui.ldap.config import (
    gssapi_cred_store,
    ldap_server_get_info,
    parse_ldap_server,
)
from sambatui.ldap.tls import ldap_server_tls
from sambatui.ldap.types import LdapSearchConfig, LdapServerSettings

LDAPResult = Mapping[str, object]
LdapAttributes = Mapping[str, object]
LdapOperation = Callable[["LdapConnection"], bool]


class LdapConnection(Protocol):
    result: LDAPResult
    entries: Sequence[object]

    def start_tls(self) -> bool: ...

    def bind(self) -> bool: ...

    def search(
        self,
        search_base: str,
        search_filter: str,
        *,
        search_scope: object,
        attributes: list[str],
        paged_size: int,
        paged_cookie: bytes | str | None,
    ) -> bool: ...

    def add(
        self, dn: str, object_class: tuple[str, ...], attributes: LdapAttributes
    ) -> bool: ...

    def delete(self, dn: str) -> bool: ...

    def modify(self, dn: str, changes: LdapAttributes) -> bool: ...

    def unbind(self) -> object: ...


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


def ldap_connection_kwargs(
    config: LdapSearchConfig, *, read_only: bool = True
) -> dict[str, object]:
    from ldap3 import GSSAPI, NTLM, SASL, SIMPLE

    common: dict[str, object] = {
        "receive_timeout": config.timeout,
        "auto_bind": False,
        "read_only": read_only,
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


def new_ldap_connection(
    config: LdapSearchConfig, *, read_only: bool = True
) -> tuple[LdapConnection, LdapServerSettings]:
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
    return cast(
        LdapConnection,
        Connection(server, **ldap_connection_kwargs(config, read_only=read_only)),
    ), settings


def start_tls_if_needed(
    connection: LdapConnection, config: LdapSearchConfig, settings: LdapServerSettings
) -> None:
    if config.normalized_encryption != "starttls" or settings.use_ssl:
        return

    from ldap3.core.exceptions import LDAPException

    try:
        tls_started = connection.start_tls()
    except LDAPException as exc:
        raise ValueError(ldap_exception_message(exc, "LDAP StartTLS failed")) from exc
    if not tls_started:
        raise ValueError(ldap_result_message(connection.result, "LDAP StartTLS failed"))


def bind_connection(connection: LdapConnection) -> None:
    from ldap3.core.exceptions import LDAPException, LDAPPackageUnavailableError

    try:
        bound = connection.bind()
    except LDAPPackageUnavailableError as exc:
        raise ValueError(
            "LDAP Kerberos bind needs optional package. Install sambatui[kerberos]."
        ) from exc
    except LDAPException as exc:
        raise ValueError(ldap_exception_message(exc, "LDAP bind failed")) from exc
    if not bound:
        raise ValueError(ldap_result_message(connection.result, "LDAP bind failed"))


def search_connection(
    connection: LdapConnection,
    config: LdapSearchConfig,
    search_filter: str,
    max_entries: int | None = None,
    *,
    one_level: bool = False,
) -> list[object]:
    from ldap3 import LEVEL, SUBTREE
    from ldap3.core.exceptions import LDAPException

    search_scope = LEVEL if one_level else SUBTREE
    rows: list[object] = []
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
            raise ValueError(ldap_exception_message(exc, "LDAP search failed")) from exc
        if not ok:
            raise ValueError(
                ldap_result_message(connection.result, "LDAP search failed")
            )
        for entry in connection.entries:
            if max_entries is not None and len(rows) >= max_entries:
                return rows
            rows.append(entry)
        cookie = paged_search_cookie(connection.result)
        if not cookie:
            return rows


def paged_search_cookie(result: LDAPResult | None) -> bytes | str | None:
    if result is None:
        return None
    controls = object_mapping(result.get("controls"))
    if controls is None:
        return None
    control = object_mapping(controls.get("1.2.840.113556.1.4.319"))
    if control is None:
        return None
    value = object_mapping(control.get("value"))
    if value is None:
        return None
    cookie = value.get("cookie")
    return cookie if isinstance(cookie, (bytes, str)) and cookie else None


def object_mapping(value: object) -> Mapping[object, object] | None:
    return cast(Mapping[object, object], value) if isinstance(value, Mapping) else None


def unbind_suppressing_ldap_error(connection: LdapConnection) -> None:
    from ldap3.core.exceptions import LDAPException

    with suppress(LDAPException):
        connection.unbind()


def ldap_result_message(result: LDAPResult | None, fallback: str) -> str:
    if result is None:
        return fallback
    description = str(result.get("description") or "").strip()
    message = str(result.get("message") or "").strip()
    detail = ": ".join(part for part in (description, message) if part)
    return f"{fallback}: {detail}" if detail else fallback


def ldap_exception_message(exc: Exception, fallback: str) -> str:
    message = str(exc).strip()
    return f"{fallback}: {message}" if message else fallback
