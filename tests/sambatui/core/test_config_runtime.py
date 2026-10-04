from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from sambatui.core import config


def test_legacy_domain_and_zone_defaults_use_only_given_preferences(
    monkeypatch,
) -> None:
    monkeypatch.delenv("SAMBATUI_DOMAIN", raising=False)
    monkeypatch.delenv("SAMBATUI_ZONE", raising=False)
    monkeypatch.setattr(config, "USER_CONFIG", {"zone": "example.com"})
    assert config._default_domain() == "example.com"
    assert config._default_zone() == "example.com"
    monkeypatch.setattr(config, "USER_CONFIG", {"zone": "2.0.192.in-addr.arpa"})
    assert config._default_domain() == ""


@pytest.mark.parametrize("timeout,expected", [("invalid", 60), ("0", 1)])
def test_command_timeout_falls_back_or_clamps_without_loading_passwords(
    timeout, expected
) -> None:
    loaded = config.AppConfig.load(
        env={
            "SAMBATUI_AUTH": "password",
            "SAMBATUI_PASSWORD": "",
            "SAMBATUI_COMMAND_TIMEOUT": timeout,
        },
        preferences={},
    )
    assert loaded.command_timeout == expected
    assert loaded.password == ""


def test_password_permissions_check_opened_file_and_support_chmod_fallback(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "test-password"
    path.write_text("test-only\n", encoding="utf-8")
    path.chmod(0o644)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", lambda fd: SimpleNamespace(st_mode=0))
        with pytest.raises(OSError, match="not a regular file"):
            config.fix_password_file_permissions(path)
    with monkeypatch.context() as patch:
        patch.setattr(os, "getuid", lambda: -1)
        with pytest.raises(OSError, match="owned by the current user"):
            config.fix_password_file_permissions(path)
    with monkeypatch.context() as patch:
        patch.delattr(os, "fchmod", raising=False)
        config.fix_password_file_permissions(path)
    assert path.stat().st_mode & 0o777 == 0o600
