from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from collections.abc import Callable

import pytest

from sambatui.core.mutations import MutationGuard, mutation_action
from sambatui.core.settings import ConnectionSettings


class Host:
    def __init__(self) -> None:
        self.mutations = MutationGuard()
        self.settings = ConnectionSettings(server="original.example.com")
        self.errors: list[str] = []

    def connection_settings(self) -> ConnectionSettings:
        return self.mutations.snapshot or self.settings

    def report_error(self, message: str) -> None:
        self.errors.append(message)

    @mutation_action
    async def write(self, operation: Callable[[], None]) -> None:
        await self.mutations.run_thread(operation)

    @mutation_action
    async def nested_write(self, operation: Callable[[], None]) -> None:
        await self.write(operation)


def test_reservation_is_reentrant_and_freezes_connection_settings() -> None:
    async def scenario() -> None:
        host = Host()
        original = host.settings
        with host.mutations.reserve(original):
            host.settings = replace(original, server="new.example.com")
            assert host.connection_settings() is original
            with host.mutations.reserve(host.settings):
                assert host.connection_settings() is original
            await host.nested_write(lambda: None)
            assert host.mutations.active
        assert not host.mutations.active
        assert host.connection_settings().server == "new.example.com"
        assert host.errors == []

    asyncio.run(scenario())


@pytest.mark.parametrize("worker_fails", [False, True])
def test_cancelled_thread_keeps_reservation_until_completion(
    worker_fails: bool,
) -> None:
    async def scenario() -> None:
        host = Host()
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        release = threading.Event()
        completed = threading.Event()
        calls: list[str] = []

        def write() -> None:
            calls.append("write")
            loop.call_soon_threadsafe(started.set)
            assert release.wait(5), "test did not release the worker"
            completed.set()
            if worker_fails:
                raise ValueError("backend failed after cancellation")

        task = asyncio.create_task(host.nested_write(write))
        try:
            await asyncio.wait_for(started.wait(), timeout=5)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()  # Repeated cancellation must not release the guard either.
            await asyncio.sleep(0)
            assert host.mutations.active
            assert not task.done()
            assert not completed.is_set()
            await host.write(lambda: calls.append("overlapping write"))
            assert calls == ["write"]
            assert "still in progress" in host.errors[-1]
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert completed.is_set()
        assert not host.mutations.active
        assert sum("does not undo" in error for error in host.errors) == 1
        await host.write(lambda: calls.append("next write"))
        assert calls == ["write", "next write"]

    asyncio.run(scenario())


def test_cancelling_before_execution_does_not_start_a_write() -> None:
    async def scenario() -> None:
        host = Host()
        calls: list[str] = []
        task = asyncio.create_task(host.write(lambda: calls.append("write")))
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert calls == []
        assert not host.mutations.active
        assert host.errors == []
        with pytest.raises(RuntimeError, match="active mutation reservation"):
            await host.mutations.run_thread(lambda: None)

    asyncio.run(scenario())


def test_unexpected_worker_failure_propagates_and_releases_reservation() -> None:
    def fail() -> None:
        raise RuntimeError("programming error")

    async def scenario() -> None:
        host = Host()
        with pytest.raises(RuntimeError, match="programming error"):
            await host.write(fail)
        assert not host.mutations.active
        assert host.errors == []

    asyncio.run(scenario())
