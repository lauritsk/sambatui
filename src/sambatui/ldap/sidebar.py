from __future__ import annotations

from collections.abc import Iterator, Mapping, MutableMapping, Sequence
from dataclasses import dataclass

from .dn import split_ldap_dn
from .rows import DirectoryRow


@dataclass(frozen=True)
class SidebarItem:
    label: str
    value: str
    action: str


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


def _node_key(parts: Sequence[str]) -> str:
    return ",".join(part.casefold() for part in parts)


def _add_node(
    nodes: MutableMapping[str, tuple[str, ...]], parts: Sequence[str]
) -> None:
    if parts:
        nodes[_node_key(parts)] = tuple(parts)


def _row_base_index(parts: Sequence[str], base_parts: Sequence[str]) -> int:
    base_index = _dn_suffix_index(parts, base_parts)
    if base_index >= 0:
        return base_index
    return _trailing_dc_index(parts)


def _row_structure_parts(
    row: DirectoryRow, base_parts: Sequence[str]
) -> Iterator[Sequence[str]]:
    parts = split_ldap_dn(row.dn)
    if not parts:
        return

    base_index = _row_base_index(parts, base_parts)
    yield parts[base_index:]
    for index in range(base_index):
        if index == 0 and row.kind not in {"ou", "container"}:
            continue
        if parts[index].casefold().startswith(("ou=", "cn=")):
            yield parts[index:]


def _sorted_nodes(nodes: Mapping[str, tuple[str, ...]]) -> list[tuple[str, ...]]:
    return sorted(
        nodes.values(),
        key=lambda parts: tuple(part.casefold() for part in reversed(parts)),
    )


def _structure_label(parts: Sequence[str], shortest: int) -> str:
    depth = max(0, len(parts) - shortest)
    label = ",".join(parts) if depth == 0 else parts[0]
    return f"{'  ' * depth}{label}"


def ldap_structure_nodes(
    rows: Sequence[DirectoryRow], base_dn: str
) -> list[tuple[str, str]]:
    base_parts = split_ldap_dn(base_dn)
    nodes: dict[str, tuple[str, ...]] = {}
    _add_node(nodes, base_parts)

    for row in rows:
        for parts in _row_structure_parts(row, base_parts):
            _add_node(nodes, parts)

    ordered = _sorted_nodes(nodes)
    if not ordered:
        return []

    shortest = min(len(parts) for parts in ordered)
    return [(_structure_label(parts, shortest), ",".join(parts)) for parts in ordered]


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
    if kind != "all":
        return None

    text = values.get("text", "")
    search_base_dn = values.get("search_base_dn", "") or values.get("base_dn", "")
    if text:
        return SidebarItem(text, search_base_dn or text, "ldap_dn")
    if search_base_dn.casefold() == base_dn.casefold():
        return SidebarItem(base_dn, base_dn, "ldap_root")
    if search_base_dn:
        return SidebarItem(search_base_dn, search_base_dn, "ldap_dn")
    return None
