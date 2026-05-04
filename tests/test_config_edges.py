from __future__ import annotations

from pathlib import Path

import pytest

from sambatui import config as config_module
from sambatui.config import (
    _default_domain,
    password_file_permissions_too_open,
    password_file_warning,
    user_config_value_error,
)


def test_config_last_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    assert user_config_value_error("ldap_compatibility", "maybe") == (
        "LDAP compatibility must be on or off."
    )
    assert user_config_value_error("smart_days", "many") == (
        "Smart days must be a whole number."
    )
    assert user_config_value_error("server", "dc01") is None

    monkeypatch.setattr(config_module, "USER_CONFIG", {"domain": "example.com"})
    monkeypatch.delenv("SAMBATUI_DOMAIN", raising=False)
    assert _default_domain() == "example.com"

    assert password_file_permissions_too_open(Path("/definitely/missing")) is False

    error_path = Path("/secret/password")
    monkeypatch.setattr(
        Path, "stat", lambda _path: (_ for _ in ()).throw(OSError("denied"))
    )
    assert password_file_warning(error_path) == (
        "Cannot inspect password file /secret/password: denied"
    )
