from __future__ import annotations

from urllib.parse import urlparse

from sambatui.ldap.types import (
    LDAP_AUTH_MODES,
    LDAP_COMPATIBILITY_OFF,
    LDAP_COMPATIBILITY_ON,
    LDAP_ENCRYPTION_MODES,
    LdapSearchConfig,
    LdapServerSettings,
)


def ldap_config_validation_error(config: LdapSearchConfig) -> str | None:
    auth_mode = config.normalized_auth_mode
    encryption = config.normalized_encryption
    compatibility = config.normalized_compatibility

    error = _ldap_mode_error(auth_mode, encryption, compatibility)
    if error:
        return error
    error = _ldap_server_error(config.server, encryption)
    if error:
        return error
    if auth_mode == "password":
        error = _ldap_password_auth_error(config.user, config.password, encryption)
        if error:
            return error
    if not config.base_dn:
        return "Enter LDAP base DN, e.g. DC=example,DC=com."
    return None


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
    port = parsed.port
    if port == 0:
        raise ValueError("LDAP server port must be between 1 and 65535.")
    return LdapServerSettings(host=host, port=port or default_port, use_ssl=use_ssl)


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
