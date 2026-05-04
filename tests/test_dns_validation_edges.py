from __future__ import annotations

import pytest

from sambatui import dns as dns_module
from sambatui.dns import validate_record


def test_dns_value_error_path_and_mx_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    assert validate_record("@", "MX", "10 bad space") is not None
    assert validate_record("@", "MX", "mail.example.com bad") is not None

    def raise_value_error(_rtype: str, _value: str) -> str | None:
        raise ValueError("bad rdata")

    monkeypatch.setattr(dns_module, "_record_value_error", raise_value_error)
    assert validate_record("www", "A", "192.0.2.1") == "bad rdata"
