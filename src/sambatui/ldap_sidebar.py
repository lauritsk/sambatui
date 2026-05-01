from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .ldap_directory import DirectoryRow


@dataclass(frozen=True)
class SidebarItem:
    label: str
    value: str
    action: str


def split_ldap_dn(dn: str) -> tuple[str, ...]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in dn:
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


def _dn_suffix_index(parts: Sequence[str], suffix: Sequence[str]) -> int:
    if not suffix or len(suffix) > len(parts):
        return -1
    start = len(parts) - len(suffix)
    for offset, part in enumerate(suffix):
        if parts[start + offset].casefold() != part.casefold():
            return -1
    return start


def _trailing_dc_index(parts: Sequence[str]) -> int:
    index = len(parts)
    while index > 0 and parts[index - 1].casefold().startswith("dc="):
        index -= 1
    return index if index < len(parts) else max(len(parts) - 1, 0)


def ldap_structure_nodes(
    rows: Sequence[DirectoryRow], base_dn: str
) -> list[tuple[str, str]]:
    base_parts = split_ldap_dn(base_dn)
    nodes: dict[str, tuple[str, ...]] = {}

    def add_node(parts: Sequence[str]) -> None:
        if parts:
            nodes[",".join(part.casefold() for part in parts)] = tuple(parts)

    if base_parts:
        add_node(base_parts)

    for row in rows:
        parts = split_ldap_dn(row.dn)
        if not parts:
            continue
        base_index = _dn_suffix_index(parts, base_parts)
        if base_index < 0:
            base_index = _trailing_dc_index(parts)
        add_node(parts[base_index:])
        for index in range(base_index):
            if index == 0 and row.kind not in {"ou", "container"}:
                continue
            rdn = parts[index].casefold()
            if rdn.startswith(("ou=", "cn=")):
                add_node(parts[index:])

    if not nodes:
        return []
    ordered = sorted(
        nodes.values(),
        key=lambda parts: tuple(part.casefold() for part in reversed(parts)),
    )
    shortest = min(len(parts) for parts in ordered)
    result: list[tuple[str, str]] = []
    for parts in ordered:
        depth = max(0, len(parts) - shortest)
        label = ",".join(parts) if depth == 0 else parts[0]
        result.append((f"{'  ' * depth}{label}", ",".join(parts)))
    return result


def ldap_structure_labels(rows: Sequence[DirectoryRow], base_dn: str) -> list[str]:
    return [label for label, _dn in ldap_structure_nodes(rows, base_dn)]


def ldap_sidebar_items(rows: Sequence[DirectoryRow], base_dn: str) -> list[SidebarItem]:
    if not base_dn:
        return [
            SidebarItem("No LDAP base DN — set connection or setup wizard", "", "empty")
        ]

    base_key = base_dn.casefold()
    return [
        SidebarItem(
            label,
            dn,
            "ldap_root" if dn.casefold() == base_key else "ldap_dn",
        )
        for label, dn in ldap_structure_nodes(rows, base_dn)
    ]


def active_ldap_sidebar_item(
    values: Mapping[str, str], base_dn: str
) -> SidebarItem | None:
    kind = values.get("kind", "")
    text = values.get("text", "")
    search_base_dn = values.get("search_base_dn", "") or values.get("base_dn", "")
    if kind == "all" and not text and search_base_dn.casefold() == base_dn.casefold():
        return SidebarItem(base_dn, base_dn, "ldap_root")
    if kind == "all" and not text and search_base_dn:
        return SidebarItem(search_base_dn, search_base_dn, "ldap_dn")
    if kind == "all" and text:
        return SidebarItem(text, search_base_dn or text, "ldap_dn")
    return None
