"""Bounded Samba subprocess execution, independent of Textual and UI state."""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass

MAX_OUTPUT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CommandResult:
    code: int
    output: str
    error: str | None = None


class OutputLimitExceeded(Exception):
    pass


async def execute_command(
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None,
    timeout: float,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> CommandResult:
    """Run without a shell; kill/reap the process group on failure or cancellation."""
    if max_output_bytes < 1:
        raise ValueError("Output limit must be positive.")
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
    except OSError as exc:
        message = f"Cannot start samba-tool: {exc}"
        return CommandResult(127, message, message)

    output = bytearray()
    # PIPE above always supplies stdout.
    stdout = process.stdout
    assert stdout is not None

    async def collect() -> None:
        while chunk := await stdout.read(65536):
            available = max_output_bytes - len(output)
            output.extend(chunk[:available])
            if len(chunk) > available:
                raise OutputLimitExceeded
        await process.wait()

    task = asyncio.create_task(collect())
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
    except (TimeoutError, OutputLimitExceeded, asyncio.CancelledError) as exc:
        task.cancel()
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        # Observe the reader, drain the remaining pipe buffer, and reap the child.
        # Repeated cancellation must not interrupt cleanup.
        completion = asyncio.gather(task, process.communicate(), return_exceptions=True)
        cancelled = isinstance(exc, asyncio.CancelledError)
        while not completion.done():
            try:
                await asyncio.shield(completion)
            except asyncio.CancelledError:
                cancelled = True
        if cancelled:
            raise asyncio.CancelledError from None
        if isinstance(exc, TimeoutError):
            code, message = 124, f"samba-tool timed out after {timeout} seconds"
        else:
            code, message = 125, f"samba-tool output exceeded {max_output_bytes} bytes"
        return CommandResult(code, output.decode(errors="replace") or message, message)

    text = output.decode(errors="replace")
    code = process.returncode or 0
    error = (
        next((line for line in text.splitlines() if line.strip()), f"exit {code}")
        if code
        else None
    )
    return CommandResult(code, text, error)
