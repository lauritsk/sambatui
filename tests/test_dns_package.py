from __future__ import annotations

import dns.exception
import pytest

from sambatui.dns import service
from sambatui.dns import validation as validation_module
from sambatui.dns.validation import validate_record as validate_record_impl


def test_dns_package_facades_cover_split_modules() -> None:
    assert service.parse_zones("ZoneName : example.com") == ["example.com"]
    assert service.valid_dns_name("example.com") is True
    assert service.ptr_target_for_name("host", "example.com") == "host.example.com"
    assert validate_record_impl("@", "A", "192.0.2.1") is None
    assert validate_record_impl("bad space", "A", "192.0.2.1") is not None
    assert validate_record_impl("@", "A", "") is not None


def test_dns_validation_impl_exception_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_dns_exception(_rtype: str, _value: str) -> str | None:
        raise dns.exception.SyntaxError("bad dns")

    monkeypatch.setattr(validation_module, "_record_value_error", raise_dns_exception)
    assert "bad dns" in (validate_record_impl("@", "A", "192.0.2.1") or "")

    def raise_value_error(_rtype: str, _value: str) -> str | None:
        raise ValueError("bad value")

    monkeypatch.setattr(validation_module, "_record_value_error", raise_value_error)
    assert validate_record_impl("@", "A", "192.0.2.1") == "bad value"
