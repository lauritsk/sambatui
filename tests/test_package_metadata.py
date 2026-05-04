from __future__ import annotations

from importlib import metadata, reload

import pytest

import sambatui


def test_package_version_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_version(_name: str) -> str:
        raise metadata.PackageNotFoundError

    monkeypatch.setattr(metadata, "version", missing_version)
    reloaded = reload(sambatui)
    assert reloaded.__version__ == "0.0.0"

    monkeypatch.undo()
    reload(sambatui)
