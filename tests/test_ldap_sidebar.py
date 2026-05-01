from sambatui.ldap_directory import DirectoryRow
from sambatui.ldap_sidebar import (
    SidebarItem,
    active_ldap_sidebar_item,
    ldap_sidebar_items,
    ldap_structure_labels,
    ldap_structure_nodes,
    split_ldap_dn,
)


def directory_row(dn: str, kind: str = "user") -> DirectoryRow:
    return DirectoryRow(dn=dn, kind=kind, name="", summary="", attributes={})


def test_split_ldap_dn_keeps_escaped_commas() -> None:
    assert split_ldap_dn(r"CN=Doe\, Jane, OU=Users ,DC=example,DC=com") == (
        r"CN=Doe\, Jane",
        "OU=Users",
        "DC=example",
        "DC=com",
    )


def test_ldap_structure_nodes_falls_back_to_trailing_domain_components() -> None:
    nodes = ldap_structure_nodes(
        [directory_row("CN=Alice,OU=Users,DC=other,DC=com")],
        "DC=example,DC=com",
    )

    assert nodes == [
        ("DC=example,DC=com", "DC=example,DC=com"),
        ("DC=other,DC=com", "DC=other,DC=com"),
        ("  OU=Users", "OU=Users,DC=other,DC=com"),
    ]


def test_ldap_structure_labels_are_empty_without_rows_or_base() -> None:
    assert ldap_structure_labels([], "") == []


def test_ldap_sidebar_items_mark_root_and_child_actions() -> None:
    assert ldap_sidebar_items([], "") == [
        SidebarItem("No LDAP base DN — set connection or setup wizard", "", "empty")
    ]

    assert ldap_sidebar_items(
        [directory_row("OU=Servers,DC=example,DC=com", "ou")],
        "DC=example,DC=com",
    ) == [
        SidebarItem("DC=example,DC=com", "DC=example,DC=com", "ldap_root"),
        SidebarItem("  OU=Servers", "OU=Servers,DC=example,DC=com", "ldap_dn"),
    ]


def test_active_ldap_sidebar_item_tracks_root_child_and_text_search() -> None:
    base_dn = "DC=example,DC=com"

    assert active_ldap_sidebar_item(
        {"kind": "all", "text": "", "search_base_dn": base_dn}, base_dn
    ) == SidebarItem(base_dn, base_dn, "ldap_root")
    assert active_ldap_sidebar_item(
        {"kind": "all", "text": "", "search_base_dn": "OU=Users," + base_dn},
        base_dn,
    ) == SidebarItem("OU=Users," + base_dn, "OU=Users," + base_dn, "ldap_dn")
    assert active_ldap_sidebar_item(
        {"kind": "all", "text": "alice", "base_dn": base_dn}, base_dn
    ) == SidebarItem("alice", base_dn, "ldap_dn")
    assert active_ldap_sidebar_item({"kind": "users", "text": ""}, base_dn) is None
