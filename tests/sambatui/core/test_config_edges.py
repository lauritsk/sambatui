from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sambatui.core import config as config_module
from sambatui.core.config import (
    _default_domain,
    _safe_user_config_values,
    password_file_permissions_too_open,
    password_file_warning,
    user_config_value_error,
)

CONFIG_KEYS = st.sampled_from(
    [
        "server",
        "domain",
        "zone",
        "auth",
        "kerberos",
        "krb5_ccache",
        "configfile",
        "options",
        "auto_ptr",
        "ldap_base",
        "ldap_encryption",
        "ldap_compatibility",
        "smart_days",
        "smart_disabled_days",
        "smart_never_logged_days",
        "smart_max_rows",
        "last_zone",
        "user",
        "password_file",
        "unknown",
    ]
)


def test_config_last_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    assert user_config_value_error("ldap_compatibility", "maybe") == (
        "LDAP compatibility must be on or off."
    )
    assert user_config_value_error("smart_days", "many") == (
        "Smart days must be a whole number."
    )
    assert user_config_value_error("server", "dc01") is None

    monkeypatch.setattr(config_module, "USER_CONFIG", {"domain": "example.com"})
    monkeypatch.delenv("SAMBATUI_DOMAIN", raising=False)
    assert _default_domain() == "example.com"

    assert password_file_permissions_too_open(Path("/definitely/missing")) is False

    error_path = Path("/secret/password")
    monkeypatch.setattr(
        Path, "stat", lambda _path: (_ for _ in ()).throw(OSError("denied"))
    )
    assert password_file_warning(error_path) == (
        "Cannot inspect password file /secret/password: denied"
    )


@given(CONFIG_KEYS, st.one_of(st.text(), st.integers(), st.booleans(), st.none()))
def test_user_config_value_error_accepts_any_preference_value(
    key: str, value: object
) -> None:
    error = user_config_value_error(key, value)

    assert error is None or isinstance(error, str)


@given(
    st.dictionaries(
        CONFIG_KEYS,
        st.one_of(st.text(max_size=100), st.integers(), st.booleans(), st.none()),
        max_size=8,
    )
)
def test_safe_user_config_values_are_self_validating(
    values: dict[str, object],
) -> None:
    safe_values = _safe_user_config_values(values)

    assert config_module.user_config_validation_error(safe_values) is None
    assert set(safe_values) <= config_module.USER_CONFIG_KEYS
