from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import cast
import importlib

from sambatui.ldap.types import LDAP_SEARCH_KINDS

_ldap3_conv = importlib.import_module("ldap3.utils.conv")
escape_filter_chars = cast(
    Callable[[str], str], getattr(_ldap3_conv, "escape_filter_chars")
)

KIND_FILTERS: Mapping[str, str] = {
    "users": "(&(objectCategory=person)(objectClass=user))",
    "groups": "(objectCategory=group)",
    "computers": "(objectCategory=computer)",
    "ous": "(objectClass=organizationalUnit)",
    "all": "(|(&(objectCategory=person)(objectClass=user))(objectCategory=group)(objectCategory=computer)(objectClass=organizationalUnit))",
}
CHILD_CONTAINER_FILTER = "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))"
KIND_LABELS = {
    "users": "user",
    "groups": "group",
    "computers": "computer",
    "ous": "ou",
    "all": "object",
}


def build_directory_filter(kind: str, text: str = "") -> str:
    normalized_kind = kind.casefold() or "users"
    base_filter = KIND_FILTERS.get(normalized_kind)
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
