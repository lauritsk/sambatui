from __future__ import annotations

from sambatui.core.settings import ConnectionSettings
from sambatui.ldap.rows import DirectoryRow
from sambatui.ldap.sidebar import ldap_structure_nodes


def test_ldap_sidebar_and_settings_exception_branches() -> None:
    rows = [DirectoryRow("", "user", "empty", "", {"uSNChanged": ("17",)})]
    assert ldap_structure_nodes(rows, "") == []
    assert ldap_structure_nodes(
        [
            DirectoryRow(
                "CN=Alice,DC=example,DC=com",
                "user",
                "Alice",
                "",
                {"uSNChanged": ("17",)},
            )
        ],
        "",
    )
    assert ldap_structure_nodes([], "OU=Long,DC=example,DC=com") == [
        ("OU=Long,DC=example,DC=com", "OU=Long,DC=example,DC=com")
    ]
    settings = ConnectionSettings()
    assert settings.server == ""
    assert settings.auth
