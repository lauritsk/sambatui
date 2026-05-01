from __future__ import annotations

from collections.abc import Callable

ErrorRule = tuple[Callable[[str], bool], str]

_NETWORK_ERROR_TERMS = (
    "timed out",
    "timeout",
    "connection refused",
    "no route to host",
    "host unreachable",
    "name or service not known",
    "could not resolve",
    "nt_status_host_unreachable",
)


def _contains(term: str) -> Callable[[str], bool]:
    return lambda message: term in message


def _contains_any(*terms: str) -> Callable[[str], bool]:
    return lambda message: any(term in message for term in terms)


ERROR_ACTION_RULES: tuple[ErrorRule, ...] = (
    (
        _contains("samba-tool not found"),
        "install Samba tools or run on a Samba admin host",
    ),
    (
        _contains("enter username"),
        "press Ctrl+O and set User, or switch auth to kerberos",
    ),
    (
        lambda message: "enter password" in message or "needs a password" in message,
        "press p to load password, Ctrl+O to edit, or use kerberos",
    ),
    (
        _contains("no password found"),
        "press P to save password file or Ctrl+O to enter password",
    ),
    (_contains("auth must"), "press Ctrl+O and set auth to password or kerberos"),
    (
        _contains("kerberos must"),
        "press Ctrl+O and set Kerberos to off, desired, or required",
    ),
    (
        _contains_any("kerberos", "kdc", "krb5"),
        "run kinit, set krb5 ccache, or switch auth to password",
    ),
    (
        _contains_any("ldap encryption", "starttls", "ldaps"),
        "use ldaps/starttls, or set LDAP compatibility on for DCs that need relaxed TLS/schema",
    ),
    (_contains("ldap base dn"), "set Base DN like DC=example,DC=com"),
    (
        _contains("ldap bind failed"),
        "check credentials, UPN username format, encryption, or Kerberos ticket",
    ),
    (
        _contains("ldap search failed"),
        "check Base DN, rights, filter text, and network reachability",
    ),
    (
        _contains("no ad srv records found"),
        "check AD DNS domain or set DC manually with Ctrl+O",
    ),
    (
        _contains("load zones before dns smart views"),
        "press z to load zones, or Ctrl+O to fix server/auth",
    ),
    (
        _contains_any(*_NETWORK_ERROR_TERMS),
        "check DC/server, DNS, VPN/firewall; Ctrl+O edits connection",
    ),
)


def actionable_error(message: str) -> str:
    base = " ".join(message.strip().split())
    lower = base.casefold()
    if not base or " action: " in lower:
        return base

    action = next(
        (action for matches, action in ERROR_ACTION_RULES if matches(lower)),
        "",
    )
    return f"{base} Action: {action}." if action else base


def bounded_int(
    value: str | None,
    default: int,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    try:
        number = int(value or str(default))
    except ValueError:
        return default
    number = max(minimum, number)
    return min(number, maximum) if maximum is not None else number
