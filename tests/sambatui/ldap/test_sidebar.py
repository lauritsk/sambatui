from hypothesis import given
from hypothesis import strategies as st

from sambatui.ldap.client import DirectoryRow
from sambatui.ldap.sidebar import (
    SidebarItem,
    active_ldap_sidebar_item,
    ldap_sidebar_items,
    ldap_structure_labels,
    ldap_structure_nodes,
    split_ldap_dn,
)


def directory_row(dn: str, kind: str = "user") -> DirectoryRow:
    return DirectoryRow(dn=dn, kind=kind, name="", summary="", attributes={})


RDN_VALUE = st.text(
    alphabet=st.characters(
        blacklist_characters=",\\\n\r", min_codepoint=33, max_codepoint=126
    ),
    min_size=1,
    max_size=20,
)
DOMAIN_LABEL = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
    min_size=1,
    max_size=12,
).filter(lambda value: value.isascii())
BASE_DN = st.lists(DOMAIN_LABEL, min_size=2, max_size=4).map(
    lambda labels: ",".join(f"DC={label}" for label in labels)
)


@given(RDN_VALUE, RDN_VALUE, RDN_VALUE, BASE_DN)
def test_split_ldap_dn_keeps_escaped_commas(
    first: str, second: str, ou: str, base_dn: str
) -> None:
    assert split_ldap_dn(rf"CN={first}\, {second}, OU={ou} ,{base_dn}") == (
        rf"CN={first}\, {second}",
        f"OU={ou}",
        *tuple(base_dn.split(",")),
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


@given(st.just([]), st.just(""))
def test_ldap_structure_labels_are_empty_without_rows_or_base(
    rows: list[DirectoryRow], base_dn: str
) -> None:
    assert ldap_structure_labels(rows, base_dn) == []


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


@given(BASE_DN, RDN_VALUE, RDN_VALUE)
def test_active_ldap_sidebar_item_tracks_root_child_and_text_search(
    base_dn: str, child: str, text: str
) -> None:
    child_dn = f"OU={child},{base_dn}"

    assert active_ldap_sidebar_item(
        {"kind": "all", "text": "", "search_base_dn": base_dn}, base_dn
    ) == SidebarItem(base_dn, base_dn, "ldap_root")
    assert active_ldap_sidebar_item(
        {"kind": "all", "text": "", "search_base_dn": child_dn},
        base_dn,
    ) == SidebarItem(child_dn, child_dn, "ldap_dn")
    assert active_ldap_sidebar_item(
        {"kind": "all", "text": text, "base_dn": base_dn}, base_dn
    ) == SidebarItem(text, base_dn, "ldap_dn")
    assert active_ldap_sidebar_item({"kind": "all", "text": ""}, base_dn) is None
    assert active_ldap_sidebar_item({"kind": "users", "text": ""}, base_dn) is None
