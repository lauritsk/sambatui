from __future__ import annotations

from contextlib import suppress


def pytest_configure() -> None:
    with suppress(ImportError, AttributeError):
        from pyasn1.codec.ber import encoder

        encoder.tagMap = encoder.TAG_MAP
        encoder.typeMap = encoder.TYPE_MAP
