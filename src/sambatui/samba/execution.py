"""Samba subprocess execution, independent of Textual and UI state."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CommandResult:
    code: int
    output: str
    error: str | None = None


async def execute_command(
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None,
    timeout: float,
) -> CommandResult:
    """Run without a shell; kill and reap the child on timeout or cancellation."""
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
    except OSError as exc:
        message = f"Cannot start samba-tool: {exc}"
        return CommandResult(127, message, message)

    try:
        output_bytes, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        with suppress(ProcessLookupError):
            process.kill()
        output_bytes, _ = await process.communicate()
        message = f"samba-tool timed out after {timeout} seconds"
        return CommandResult(
            124, output_bytes.decode(errors="replace") or message, message
        )
    except asyncio.CancelledError:
        with suppress(ProcessLookupError):
            process.kill()
        await process.communicate()
        raise

    output = output_bytes.decode(errors="replace")
    code = process.returncode or 0
    error = None
    if code != 0:
        error = next(
            (line for line in output.splitlines() if line.strip()), f"exit {code}"
        )
    return CommandResult(code, output, error)
