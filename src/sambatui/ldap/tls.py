from __future__ import annotations

from contextlib import suppress
from typing import Any, cast
import importlib
import ssl

from sambatui.ldap.types import LdapSearchConfig

LDAP_COMPATIBILITY_TLS_CIPHERS = "DEFAULT:@SECLEVEL=0"

_ldap3_module = importlib.import_module("ldap3")
Tls = cast(Any, _ldap3_module).Tls


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
    minimum = getattr(ssl.TLSVersion, "MINIMUM_SUPPORTED", None)
    if minimum is not None:
        with suppress(ValueError, ssl.SSLError):
            context.minimum_version = minimum
    for option_name in ("OP_NO_TLSv1", "OP_NO_TLSv1_1"):
        option = getattr(ssl, option_name, 0)
        if option:
            context.options &= ~option


def ldap_server_tls(config: LdapSearchConfig) -> LdapCompatibilityTls | None:
    if config.normalized_encryption == "off" or not config.compatibility_enabled:
        return None
    return LdapCompatibilityTls()
