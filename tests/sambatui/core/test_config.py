from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

import pytest

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
    assert not (tmp_path / ".password.tmp").exists()


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


def test_detected_default_auth_prefers_explicit_config_then_ticket() -> None:
    assert (
        detected_default_auth(
            env={"SAMBATUI_AUTH": "password"},
            user_config={},
            ticket_checker=lambda: True,
        )
        == "password"
    )
    assert (
        detected_default_auth(
            env={},
            user_config={"auth": "password"},
            ticket_checker=lambda: True,
        )
        == "password"
    )
    assert detected_default_auth(
        env={}, user_config={}, ticket_checker=lambda: True
    ) == ("kerberos")
    assert detected_default_auth(
        env={}, user_config={}, ticket_checker=lambda: False
    ) == ("password")
