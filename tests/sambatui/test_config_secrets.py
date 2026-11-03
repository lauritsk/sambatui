import pytest

from sambatui.ldap.types import LdapSearchConfig
from sambatui.samba.client import SambaToolConfig


@pytest.mark.parametrize("config_type", [LdapSearchConfig, SambaToolConfig])
def test_config_repr_omits_password(config_type) -> None:
    config = config_type(server="dc.example.com", password="sensitive-test-password")
    assert "sensitive-test-password" not in repr(config)
    assert "password=" not in repr(config)
    assert config.password == "sensitive-test-password"
