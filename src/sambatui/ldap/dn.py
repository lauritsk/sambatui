from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Protocol, cast
import importlib

from sambatui.ldap.types import LDAP_ADD_KINDS


class ParseDn(Protocol):
    def __call__(
        self, dn: str, *, escape: bool = False
    ) -> list[tuple[str, str, str]]: ...


_ldap3_dn = importlib.import_module("ldap3.utils.dn")
escape_rdn = cast(Callable[[str], str], getattr(_ldap3_dn, "escape_rdn"))
parse_dn = cast(ParseDn, getattr(_ldap3_dn, "parse_dn"))

LDAP_ADD_OBJECT_CLASSES: Mapping[str, tuple[str, ...]] = {
    "user": ("top", "person", "organizationalPerson", "user"),
    "group": ("top", "group"),
    "computer": ("top", "person", "organizationalPerson", "user", "computer"),
    "ou": ("top", "organizationalUnit"),
}


def split_ldap_dn(dn: str) -> tuple[str, ...]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in dn.strip():
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == ",":
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return tuple(parts)


def normalized_ldap_dn_parts(dn: str) -> tuple[tuple[str, str], ...]:
    """Return comparable DN parts, accepting harmless whitespace around commas."""
    compact_dn = ",".join(split_ldap_dn(dn))
    return tuple(
        (attr.casefold(), value.casefold())
        for attr, value, _separator in parse_dn(compact_dn, escape=True)
    )


def ldap_dn_in_scope(dn: str, base_dn: str) -> bool:
    try:
        dn_parts = normalized_ldap_dn_parts(dn)
        base_parts = normalized_ldap_dn_parts(base_dn)
    except Exception:
        return False
    return (
        bool(base_parts)
        and len(dn_parts) >= len(base_parts)
        and dn_parts[-len(base_parts) :] == base_parts
    )


def ldap_dn_equal(left: str, right: str) -> bool:
    try:
        return normalized_ldap_dn_parts(left) == normalized_ldap_dn_parts(right)
    except Exception:
        return False


def build_add_entry(
    kind: str, parent_dn: str, name: str, attributes: Mapping[str, str]
) -> tuple[str, tuple[str, ...], dict[str, object]]:
    normalized_kind = kind.casefold()
    object_class = LDAP_ADD_OBJECT_CLASSES.get(normalized_kind)
    if object_class is None:
        valid = ", ".join(LDAP_ADD_KINDS)
        raise ValueError(f"LDAP add type must be one of: {valid}.")
    clean_name = name.strip()
    clean_parent = parent_dn.strip()
    if not clean_name:
        raise ValueError("LDAP add needs a name.")
    if not clean_parent:
        raise ValueError("LDAP add needs a parent DN.")

    rdn_attr = "OU" if normalized_kind == "ou" else "CN"
    dn = f"{rdn_attr}={escape_rdn(clean_name)},{clean_parent}"
    ldap_attributes: dict[str, object] = _clean_add_attributes(attributes)
    if normalized_kind == "ou":
        ldap_attributes["ou"] = clean_name
    else:
        ldap_attributes["cn"] = clean_name
    if normalized_kind == "user":
        ldap_attributes.setdefault("sAMAccountName", clean_name)
    elif normalized_kind == "group":
        ldap_attributes.setdefault("sAMAccountName", clean_name)
        ldap_attributes.setdefault("groupType", -2147483646)
    elif normalized_kind == "computer":
        account = ldap_attributes.get("sAMAccountName") or clean_name
        account = str(account).rstrip("$") + "$"
        ldap_attributes["sAMAccountName"] = account
        ldap_attributes.setdefault("userAccountControl", 4128)
    return dn, object_class, ldap_attributes


def _clean_add_attributes(attributes: Mapping[str, str]) -> dict[str, object]:
    return {key: value for key, value in attributes.items() if value != ""}
