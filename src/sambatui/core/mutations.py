"""Single-owner write lifecycle shared by keyboard, palette, and guided actions."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine, Generator
from contextlib import contextmanager
from functools import wraps
from typing import Concatenate, Protocol

from .settings import ConnectionSettings


class MutationInProgress(RuntimeError):
    pass


class MutationGuard:
    def __init__(self) -> None:
        self._owner: asyncio.Task[object] | None = None
        self._snapshot: ConnectionSettings | None = None

    @property
    def active(self) -> bool:
        return self._owner is not None

    @property
    def snapshot(self) -> ConnectionSettings | None:
        if self._owner is not None and self._owner is asyncio.current_task():
            return self._snapshot
        return None

    @contextmanager
    def reserve(self, settings: ConnectionSettings) -> Generator[None]:
        owner = asyncio.current_task()
        if self._owner is not None:
            if self._owner is not owner:
                raise MutationInProgress(
                    "Another write is still in progress; wait before retrying."
                )
            yield
            return
        self._owner = owner
        self._snapshot = settings
        try:
            yield
        finally:
            self._snapshot = None
            self._owner = None

    async def run_thread[Result](self, operation: Callable[[], Result]) -> Result:
        """Cancellation cannot stop a thread: retain ownership until it settles."""
        if self.snapshot is None:
            raise RuntimeError("Writes require an active mutation reservation.")
        task = asyncio.create_task(asyncio.to_thread(operation))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Gather observes failures too, without replacing the caller's cancellation.
            completion = asyncio.gather(task, return_exceptions=True)
            while not completion.done():
                try:
                    await asyncio.shield(completion)
                except asyncio.CancelledError:
                    continue
            raise


class MutationHost(Protocol):
    mutations: MutationGuard

    def connection_settings(self) -> ConnectionSettings: ...

    def report_error(self, message: str) -> None: ...


def mutation_action[Host: MutationHost, **Params](
    method: Callable[Concatenate[Host, Params], Awaitable[None]],
) -> Callable[Concatenate[Host, Params], Coroutine[object, object, None]]:
    @wraps(method)
    async def guarded(self: Host, *args: Params.args, **kwargs: Params.kwargs) -> None:
        outermost = self.mutations.snapshot is None
        try:
            with self.mutations.reserve(self.connection_settings()):
                await method(self, *args, **kwargs)
        except MutationInProgress as exc:
            self.report_error(str(exc))
        except asyncio.CancelledError:
            if outermost:
                self.report_error(
                    "Write cancelled; cancellation does not undo server changes. "
                    "Refresh and check the outcome before retrying."
                )
            raise

    return guarded
