from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest

from sambatui.samba.client import SambaCommandClient, SambaToolClient, SambaToolConfig
from sambatui.samba.execution import CommandResult, execute_command


def test_samba_client_implements_command_contract() -> None:
    client: SambaCommandClient = SambaToolClient(
        SambaToolConfig("dc.example.com", user="alice", password="secret")
    )
    assert client.authentication_error() is None
    env = client.execution_env()
    assert env is not None and env["PASSWD"] == "secret"
    assert client.status_command(["samba-tool", "--password=secret"]) == (
        "samba-tool --password=******"
    )


class Process:
    def __init__(
        self,
        code: int = 0,
        output: bytes = b"",
        *,
        slow: bool = False,
        cancelled: bool = False,
        already_exited: bool = False,
    ) -> None:
        self.returncode = code
        self.output = output
        self.slow = slow
        self.cancelled = cancelled
        self.already_exited = already_exited
        self.events: list[str] = []

    async def communicate(self) -> tuple[bytes, bytes]:
        self.events.append("communicate")
        if len(self.events) == 1:
            if self.cancelled:
                raise asyncio.CancelledError
            if self.slow:
                await asyncio.sleep(60)
        return self.output, b""

    def kill(self) -> None:
        self.events.append("kill")
        if self.already_exited:
            raise ProcessLookupError


def install_process(monkeypatch: pytest.MonkeyPatch, process: Process) -> None:
    async def create_process(*command: str, **kwargs: object) -> Process:
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)


@pytest.mark.parametrize(
    ("code", "output", "error"),
    [
        (0, b"ok", None),
        (3, b"\nfirst\nsecond", "first"),
        (7, b"", "exit 7"),
        (0, b"\xff", None),
    ],
)
def test_result_and_subprocess_arguments(
    monkeypatch: pytest.MonkeyPatch, code: int, output: bytes, error: str | None
) -> None:
    process = Process(code, output)
    command = ["samba-tool", "literal;not-a-shell-command"]
    env: Mapping[str, str] = {"PASSWD": "secret"}

    async def create_process(*args: str, **kwargs: object) -> Process:
        assert args == tuple(command)
        assert kwargs == {
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.STDOUT,
            "env": env,
        }
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    result = asyncio.run(execute_command(command, env=env, timeout=1))
    assert result == CommandResult(code, output.decode(errors="replace"), error)
    assert "secret" not in repr(result)
    assert process.events == ["communicate"]


@pytest.mark.parametrize("output", [b"", b"partial output"])
@pytest.mark.parametrize("already_exited", [False, True])
def test_timeout_reaps_process_and_preserves_output(
    monkeypatch: pytest.MonkeyPatch, output: bytes, already_exited: bool
) -> None:
    process = Process(output=output, slow=True, already_exited=already_exited)
    install_process(monkeypatch, process)
    result = asyncio.run(execute_command(["samba-tool"], env=None, timeout=0.001))
    message = "samba-tool timed out after 0.001 seconds"
    assert result == CommandResult(124, output.decode() or message, message)
    assert process.events == ["communicate", "kill", "communicate"]


@pytest.mark.parametrize("already_exited", [False, True])
def test_cancellation_reaps_process_and_propagates(
    monkeypatch: pytest.MonkeyPatch, already_exited: bool
) -> None:
    process = Process(cancelled=True, already_exited=already_exited)
    install_process(monkeypatch, process)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(execute_command(["samba-tool"], env=None, timeout=1))
    assert process.events == ["communicate", "kill", "communicate"]


def test_start_failure_is_a_result(monkeypatch: pytest.MonkeyPatch) -> None:
    async def create_process(*command: str, **kwargs: object) -> Process:
        raise FileNotFoundError("missing executable")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    result = asyncio.run(execute_command(["samba-tool"], env=None, timeout=1))
    assert result == CommandResult(
        127,
        "Cannot start samba-tool: missing executable",
        "Cannot start samba-tool: missing executable",
    )
