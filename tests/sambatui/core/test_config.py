import os
import stat
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sambatui.core import config as config_module
from sambatui.core.config import (
    detected_default_auth,
    fix_password_file_permissions,
    has_valid_kerberos_ticket,
    password_file_permissions_too_open,
    password_file_warning,
    read_password_file,
    write_private_text,
)


def test_password_file_warning_rejects_group_or_other_permissions(
    tmp_path: Path,
) -> None:
    path = tmp_path / "password"
    path.write_text("secret\n", encoding="utf-8")
    path.chmod(0o644)

    assert "Press p to fix and load" in (password_file_warning(path) or "")
    assert password_file_permissions_too_open(path)
    assert read_password_file(path) == ""

    fix_password_file_permissions(path)

    assert password_file_warning(path) is None
    assert not password_file_permissions_too_open(path)
    assert read_password_file(path) == "secret"


def test_write_private_text_creates_secret_file_without_group_access(
    tmp_path: Path,
) -> None:
    path = tmp_path / "nested" / "password"

    write_private_text(path, "secret\n")

    assert path.read_text(encoding="utf-8") == "secret\n"
    assert path.stat().st_mode & 0o077 == 0
    assert path.parent.stat().st_mode & 0o077 == 0


def test_write_private_text_removes_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "password"

    def broken_fdopen(
        file_descriptor: int, *_args: object, **_kwargs: object
    ) -> object:
        raise OSError(f"boom {file_descriptor}")

    monkeypatch.setattr(config_module.os, "fdopen", broken_fdopen)

    with pytest.raises(OSError, match="boom"):
        write_private_text(path, "secret\n")

    assert not path.exists()
    assert not list(tmp_path.glob(".password.*.tmp"))


def test_password_file_warning_rejects_symlink_directory_and_wrong_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.write_text("secret\n", encoding="utf-8")
    target.chmod(0o600)
    symlink = tmp_path / "password-link"
    symlink.symlink_to(target)
    assert (
        password_file_warning(symlink)
        == f"Password file must not be a symlink: {symlink}."
    )
    assert password_file_permissions_too_open(symlink) is False
    with pytest.raises(OSError, match="Refusing to chmod symlink"):
        fix_password_file_permissions(symlink)

    directory = tmp_path / "password-dir"
    directory.mkdir()
    assert password_file_warning(directory) == (
        f"Password file must be a regular file: {directory}."
    )
    with pytest.raises(OSError, match="not a regular file"):
        fix_password_file_permissions(directory)

    monkeypatch.setattr(config_module.os, "getuid", lambda: -1)
    assert password_file_warning(target) == (
        f"Password file must be owned by the current user: {target}."
    )


@pytest.mark.parametrize(
    ("mode", "uid"),
    [
        (stat.S_IFDIR | 0o600, os.getuid()),
        (stat.S_IFREG | 0o600, -1),
        (stat.S_IFREG | 0o644, os.getuid()),
    ],
)
def test_read_password_file_rechecks_opened_file_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int, uid: int
) -> None:
    path = tmp_path / "password"
    path.write_text("secret\n", encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.setattr(config_module, "password_file_warning", lambda _path: None)
    monkeypatch.setattr(
        config_module.os,
        "fstat",
        lambda _fd: os.stat_result((mode, 0, 0, 0, uid, 0, 0, 0, 0, 0)),
    )

    assert read_password_file(path) == ""


def test_kerberos_ticket_detection_uses_klist_s() -> None:
    calls: list[list[str]] = []

    def runner(cmd: list[str], **_kwargs: object) -> CompletedProcess[bytes]:
        calls.append(cmd)
        return CompletedProcess(cmd, 0)

    assert has_valid_kerberos_ticket(runner)
    assert calls == [["klist", "-s"]]

    def timeout_runner(cmd: list[str], **_kwargs: object) -> CompletedProcess[bytes]:
        raise TimeoutExpired(cmd, 2)

    assert not has_valid_kerberos_ticket(timeout_runner)


@given(
    st.one_of(st.none(), st.sampled_from(["password", "kerberos"])),
    st.one_of(st.none(), st.sampled_from(["password", "kerberos"])),
    st.booleans(),
)
def test_detected_default_auth_prefers_explicit_config_then_ticket(
    env_auth: str | None, config_auth: str | None, has_ticket: bool
) -> None:
    env = {"SAMBATUI_AUTH": env_auth} if env_auth else {}
    user_config = {"auth": config_auth} if config_auth else {}

    assert detected_default_auth(
        env=env,
        user_config=user_config,
        ticket_checker=lambda: has_ticket,
    ) == (env_auth or config_auth or ("kerberos" if has_ticket else "password"))
