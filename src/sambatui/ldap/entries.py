from __future__ import annotations

from collections.abc import Mapping, Sequence

from sambatui.ldap.filters import KIND_LABELS
from sambatui.ldap.rows import DirectoryRow


def entry_to_directory_row(entry: object, kind: str = "all") -> DirectoryRow:
    attributes = getattr(entry, "entry_attributes_as_dict", {})
    attrs = normalize_entry_attributes(
        attributes if isinstance(attributes, Mapping) else {}
    )
    dn = str(getattr(entry, "entry_dn", ""))
    name = first_attr(attrs, "displayName", "cn", "name", "sAMAccountName") or dn
    row_kind = infer_kind(attrs, kind)
    summary = directory_summary(attrs)
    return DirectoryRow(
        dn=dn, kind=row_kind, name=name, summary=summary, attributes=attrs
    )


def normalize_entry_attributes(
    attributes: Mapping[str, object],
) -> dict[str, tuple[str, ...]]:
    return {
        str(key): normalize_attribute_values(value) for key, value in attributes.items()
    }


def normalize_attribute_values(value: object) -> tuple[str, ...]:
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
    return KIND_LABELS.get(requested_kind.casefold(), "object")


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
