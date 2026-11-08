from __future__ import annotations

import asyncio
import os
import socket
import tempfile
from pathlib import Path

import pytest
from hypothesis import settings

for name in tuple(os.environ):
    if name.startswith("SAMBATUI_"):
        del os.environ[name]
os.environ["SAMBATUI_AUTH"] = "password"

_TEST_CONFIG_DIR = Path(tempfile.mkdtemp(prefix="sambatui-tests-"))
os.environ["SAMBATUI_PASSWORD_FILE"] = str(_TEST_CONFIG_DIR / "password")
os.environ.pop("SAMBATUI_PASSWORD", None)


settings.register_profile(
    "sambatui",
    deadline=None,
    max_examples=100,
)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "sambatui"))


def _deny_external_io(*args: object, **kwargs: object) -> None:
    raise AssertionError("Tests must mock external network access and commands")


def _deny_dns_lookup(*args: object, **kwargs: object) -> None:
    raise socket.gaierror("External DNS resolution is disabled in tests")


@pytest.fixture(autouse=True)
def no_external_io(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    if request.node.get_closest_marker("samba"):
        return
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, _deny_external_io)
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        monkeypatch.setattr(socket, name, _deny_dns_lookup)
    if not request.node.get_closest_marker("local_process"):
        monkeypatch.setattr(asyncio, "create_subprocess_exec", _deny_external_io)
