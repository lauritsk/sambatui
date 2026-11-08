from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from sambatui.core import config


@pytest.mark.parametrize(
    "zone,domain",
    [("example.com", "example.com"), ("2.0.192.in-addr.arpa", "")],
)
def test_domain_defaults_from_saved_forward_zone(zone: str, domain: str) -> None:
    loaded = config.AppConfig.load(
        env={"SAMBATUI_PASSWORD": ""},
        preferences={"zone": zone},
        ticket_checker=lambda: False,
    )
    assert loaded.domain == domain
    assert loaded.zone == zone


def test_runtime_paths_and_shared_kerberos_cache() -> None:
    loaded = config.AppConfig.load(
        env={"SAMBATUI_PASSWORD": "", "KRB5CCNAME": "FILE:/config/krb5cc"},
        preferences={},
        ticket_checker=lambda: False,
    )
    assert config.USER_CONFIG_PATH == Path("/config/config.toml")
    assert loaded.password_file == Path("/config/password")
    assert loaded.krb5_ccache == "FILE:/config/krb5cc"


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


def test_password_permissions_check_opened_file(tmp_path: Path, monkeypatch) -> None:
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
    config.fix_password_file_permissions(path)
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("opened_read_only", [True, False])
def test_read_only_secret_rechecks_mount_after_open(
    tmp_path: Path, monkeypatch, opened_read_only: bool
) -> None:
    path = tmp_path / "ad-password"
    path.write_text("mounted-secret\n", encoding="utf-8")
    path.chmod(0o444)
    monkeypatch.setattr(config, "SECRETS_DIR", tmp_path)
    monkeypatch.setattr(os, "getuid", lambda: -1)
    monkeypatch.setattr(
        os, "statvfs", lambda path: SimpleNamespace(f_flag=os.ST_RDONLY)
    )
    monkeypatch.setattr(
        os,
        "fstatvfs",
        lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY if opened_read_only else 0),
    )
    assert config.password_file_warning(path) is None
    assert config.read_password_file(path) == (
        "mounted-secret" if opened_read_only else ""
    )
    assert path.stat().st_mode & 0o777 == 0o444


def test_writable_secret_requires_private_permissions(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "ad-password"
    path.write_text("secret\n", encoding="utf-8")
    path.chmod(0o644)
    monkeypatch.setattr(config, "SECRETS_DIR", tmp_path)
    monkeypatch.setattr(os, "statvfs", lambda path: SimpleNamespace(f_flag=0))
    assert "permissions too open" in config.password_file_warning(path)
    assert config.read_password_file(path) == ""


def test_secret_mount_inspection_failure(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "ad-password"
    path.write_text("secret\n", encoding="utf-8")
    monkeypatch.setattr(config, "SECRETS_DIR", tmp_path)

    def fail_statvfs(path):
        raise OSError("mount unavailable")

    monkeypatch.setattr(os, "statvfs", fail_statvfs)
    assert "mount unavailable" in config.password_file_warning(path)
    assert config.read_password_file(path) == ""
