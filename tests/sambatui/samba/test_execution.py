from __future__ import annotations

import asyncio
import os
import signal
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from sambatui.samba.client import SambaCommandClient, SambaToolClient, SambaToolConfig
from sambatui.samba.execution import CommandResult, execute_command

pytestmark = pytest.mark.local_process


def test_samba_client_implements_command_contract() -> None:
    client: SambaCommandClient = SambaToolClient(
        SambaToolConfig("dc.example.com", user="alice", password="secret")
    )
    assert client.authentication_error() is None
    env = client.execution_env()
    assert env is not None and env["PASSWD"] == "secret"
    assert (
        client.status_command(["samba-tool", "--password=secret"])
        == "samba-tool --password=******"
    )


@pytest.mark.parametrize(
    ("code", "output", "error"),
    [
        (0, b"ok", None),
        (3, b"\nfirst\nsecond", "first"),
        (7, b"", "exit 7"),
        (0, b"\xff", None),
    ],
)
def test_real_child_results(code: int, output: bytes, error: str | None) -> None:
    command = [
        sys.executable,
        "-c",
        f"import os; os.write(1, {output!r}); raise SystemExit({code})",
    ]
    result = asyncio.run(execute_command(command, env=None, timeout=5))
    assert result == CommandResult(code, output.decode(errors="replace"), error)


def test_start_failure_and_subprocess_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = ["samba-tool", "literal;not-a-shell-command"]
    env = {"PASSWD": "secret"}

    async def create(*args: str, **kwargs: object) -> asyncio.subprocess.Process:
        assert list(args) == command
        assert kwargs == {
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.STDOUT,
            "env": env,
            "start_new_session": True,
        }
        raise FileNotFoundError("missing executable")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    result = asyncio.run(execute_command(command, env=env, timeout=1))
    assert result == CommandResult(
        127,
        "Cannot start samba-tool: missing executable",
        "Cannot start samba-tool: missing executable",
    )
    assert "secret" not in repr(result)


@pytest.mark.parametrize("output", [b"", b"partial output"])
def test_timeout_reaps_real_child_and_preserves_output(output: bytes) -> None:
    command = [
        sys.executable,
        "-c",
        f"import os,time; os.write(1, {output!r}); time.sleep(30)",
    ]
    result = asyncio.run(execute_command(command, env=None, timeout=1))
    message = "samba-tool timed out after 1 seconds"
    assert result == CommandResult(124, output.decode() or message, message)


def test_output_limit_kills_child_and_never_returns_success() -> None:
    command = [sys.executable, "-c", "import os; os.write(1, b'x' * 1000000)"]
    result = asyncio.run(
        execute_command(command, env=None, timeout=5, max_output_bytes=128)
    )
    assert result.code == 125
    assert result.output == "x" * 128
    assert result.error == "samba-tool output exceeded 128 bytes"
    with pytest.raises(ValueError, match="positive"):
        asyncio.run(execute_command(command, env=None, timeout=1, max_output_bytes=0))


def test_cancellation_kills_descendants_holding_output_pipe(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    command = [
        sys.executable,
        "-c",
        f"import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); open({str(ready)!r},'w').write(str(child.pid)); time.sleep(30)",
    ]

    async def scenario() -> None:
        task = asyncio.create_task(execute_command(command, env=None, timeout=10))
        try:
            for _ in range(250):
                if ready.exists() and ready.read_text():
                    break
                await asyncio.sleep(0.02)
            else:
                pytest.fail("child did not start")
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        child = Path(f"/proc/{ready.read_text()}/stat")
        # A killed orphan may briefly remain a zombie until the container init reaps it.
        assert not child.exists() or child.read_text().split()[2] == "Z"

    asyncio.run(scenario())


def test_repeated_cancellation_waits_for_reaping_even_after_exit_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_process = asyncio.create_subprocess_exec
    kill_group = os.killpg

    async def scenario() -> None:
        started, cleanup_started = asyncio.Event(), asyncio.Event()
        processes: list[asyncio.subprocess.Process] = []

        async def create(
            *args: str,
            stdout: int,
            stderr: int,
            env: Mapping[str, str] | None,
            start_new_session: bool,
        ) -> asyncio.subprocess.Process:
            process = await create_process(
                *args,
                stdout=stdout,
                stderr=stderr,
                env=env,
                start_new_session=start_new_session,
            )
            communicate = process.communicate
            processes.append(process)

            async def slow_cleanup() -> tuple[bytes, bytes]:
                cleanup_started.set()
                await asyncio.sleep(0.05)
                return await communicate()

            monkeypatch.setattr(process, "communicate", slow_cleanup)
            started.set()
            return process

        def raced_kill(pid: int, sig: int) -> None:
            kill_group(pid, sig)
            raise ProcessLookupError

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
        monkeypatch.setattr(os, "killpg", raced_kill)
        task = asyncio.create_task(
            execute_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                env=None,
                timeout=5,
            )
        )
        await started.wait()
        task.cancel()
        await cleanup_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert processes[0].returncode == -signal.SIGKILL

    asyncio.run(scenario())
