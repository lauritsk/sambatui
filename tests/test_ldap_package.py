from __future__ import annotations

import pytest

from sambatui.ldap.config import parse_ldap_server
from sambatui.ldap.dn import ldap_dn_equal, split_ldap_dn


def test_ldap_package_facades_cover_split_modules() -> None:
    assert split_ldap_dn("CN=Alice,DC=example,DC=com") == (
        "CN=Alice",
        "DC=example",
        "DC=com",
    )
    assert ldap_dn_equal("DC=example,DC=com", "dc=example,dc=com") is True
    with pytest.raises(ValueError, match="port"):
        parse_ldap_server("ldap://dc01.example.com:0")
