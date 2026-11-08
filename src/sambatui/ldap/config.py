from __future__ import annotations

from urllib.parse import urlparse

from sambatui.ldap.types import LdapServerSettings


def domain_to_base_dn(domain: str) -> str:
    labels = [label.strip() for label in domain.strip().rstrip(".").split(".")]
    if not labels or any(not label for label in labels):
        return ""
    return ",".join(f"DC={label}" for label in labels)


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
