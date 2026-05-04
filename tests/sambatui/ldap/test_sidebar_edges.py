from __future__ import annotations

from sambatui.ldap.client import DirectoryRow
from sambatui.ldap.sidebar import ldap_structure_nodes
from sambatui.core.settings import ConnectionSettings


def test_ldap_sidebar_and_settings_exception_branches() -> None:
    rows = [DirectoryRow("", "user", "empty", "", {})]
    assert ldap_structure_nodes(rows, "") == []
    assert ldap_structure_nodes(
        [DirectoryRow("CN=Alice,DC=example,DC=com", "user", "Alice", "", {})], ""
    )
    assert ldap_structure_nodes([], "OU=Long,DC=example,DC=com") == [
        ("OU=Long,DC=example,DC=com", "OU=Long,DC=example,DC=com")
    ]
    settings = ConnectionSettings.from_lookup(
        lambda _key: (_ for _ in ()).throw(KeyError)
    )
    assert settings.server == ""
    assert settings.auth
