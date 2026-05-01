from __future__ import annotations

import os
import subprocess
import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

USER_CONFIG_PATH = Path(
    os.getenv("SAMBATUI_USER_CONFIG", "~/.config/sambatui/config.toml")
).expanduser()
USER_CONFIG_KEYS = frozenset(
    {
        "server",
        "zone",
        "auth",
        "ldap_base",
        "ldap_encryption",
        "ldap_compatibility",
        "auto_ptr",
        "last_zone",
        "smart_days",
        "smart_disabled_days",
        "smart_never_logged_days",
        "smart_max_rows",
    }
)
CHOICE_VALUES = {
    "auth": frozenset({"password", "kerberos"}),
    "kerberos": frozenset({"off", "desired", "required"}),
    "ldap_encryption": frozenset({"off", "ldaps", "starttls"}),
    "auto_ptr": frozenset({"ask", "on", "off"}),
}
ON_VALUES = frozenset({"on"})
OFF_VALUES = frozenset({"off"})
INTEGER_RANGES = {
    "smart_days": (1, None),
    "smart_disabled_days": (1, None),
    "smart_never_logged_days": (1, None),
    "smart_max_rows": (1, 5000),
}
CHOICE_LABELS = {
    "auth": "password or kerberos",
    "kerberos": "off, desired, or required",
    "ldap_encryption": "off, ldaps, or starttls",
    "auto_ptr": "ask, on, or off",
}
FIELD_LABELS = {
    "auth": "Auth",
    "kerberos": "Kerberos",
    "ldap_encryption": "LDAP encryption",
    "ldap_compatibility": "LDAP compatibility",
    "auto_ptr": "Auto PTR",
    "smart_days": "Smart days",
    "smart_disabled_days": "Smart disabled days",
    "smart_never_logged_days": "Smart never-logged days",
    "smart_max_rows": "Smart max rows",
}
VALIDATED_USER_CONFIG_KEYS = (
    "auth",
    "kerberos",
    "ldap_encryption",
    "ldap_compatibility",
    "auto_ptr",
    "smart_days",
    "smart_disabled_days",
    "smart_never_logged_days",
    "smart_max_rows",
)


def load_user_config(path: Path = USER_CONFIG_PATH) -> dict[str, str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError, OSError, tomllib.TOMLDecodeError:
        return {}

    return _safe_user_config_values(data)


def _preference_value(value: Any) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    return ""


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def save_user_config(
    values: Mapping[str, Any], path: Path = USER_CONFIG_PATH
) -> dict[str, str]:
    safe_values = _safe_user_config_values(values)
    parent_exists = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not parent_exists:
        path.parent.chmod(0o700)
    content = "".join(
        f"{key} = {_toml_string(safe_values[key])}\n" for key in sorted(safe_values)
    )
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(path)
    return safe_values


def _safe_user_config_values(values: Mapping[str, Any]) -> dict[str, str]:
    safe_values: dict[str, str] = {}
    for key, value in values.items():
        normalized = _safe_user_config_value(key, value)
        if normalized:
            safe_values[key] = normalized
    return safe_values


def _safe_user_config_value(key: str, value: Any) -> str:
    normalized = _preference_value(value)
    if key not in USER_CONFIG_KEYS or not normalized:
        return ""
    if key == "ldap_compatibility":
        return _normalized_on_off(normalized)
    if key in CHOICE_VALUES:
        choice = normalized.casefold()
        return choice if choice in CHOICE_VALUES[key] else ""
    if key in INTEGER_RANGES:
        return normalized if _integer_value_error(key, normalized) is None else ""
    return normalized


def _normalized_on_off(value: str) -> str:
    normalized = value.casefold()
    if normalized in ON_VALUES:
        return "on"
    if normalized in OFF_VALUES:
        return "off"
    return ""


def user_config_value_error(key: str, value: Any) -> str | None:
    normalized = _preference_value(value)
    if not normalized or key not in USER_CONFIG_KEYS | frozenset({"kerberos"}):
        return None
    if key == "ldap_compatibility":
        if _normalized_on_off(normalized):
            return None
        return "LDAP compatibility must be on or off."
    if key in CHOICE_VALUES:
        if normalized.casefold() in CHOICE_VALUES[key]:
            return None
        return f"{FIELD_LABELS[key]} must be {CHOICE_LABELS[key]}."
    if key in INTEGER_RANGES:
        return _integer_value_error(key, normalized)
    return None


def user_config_validation_error(values: Mapping[str, Any]) -> str | None:
    for key in VALIDATED_USER_CONFIG_KEYS:
        error = user_config_value_error(key, values.get(key, ""))
        if error:
            return error
    return None


def _integer_value_error(key: str, value: str) -> str | None:
    minimum, maximum = INTEGER_RANGES[key]
    try:
        number = int(value)
    except ValueError:
        return f"{FIELD_LABELS[key]} must be a whole number."
    if number < minimum:
        return f"{FIELD_LABELS[key]} must be at least {minimum}."
    if maximum is not None and number > maximum:
        return f"{FIELD_LABELS[key]} must be at most {maximum}."
    return None


USER_CONFIG = load_user_config()


def _default(envvar: str, key: str, fallback: str) -> str:
    return os.getenv(envvar, USER_CONFIG.get(key, fallback))


def has_valid_kerberos_ticket(
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> bool:
    try:
        result = runner(
            ["klist", "-s"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except FileNotFoundError, OSError, subprocess.SubprocessError:
        return False
    return result.returncode == 0


def detected_default_auth(
    *,
    env: Mapping[str, str] = os.environ,
    user_config: Mapping[str, str] = USER_CONFIG,
    ticket_checker: Callable[[], bool] = has_valid_kerberos_ticket,
) -> str:
    explicit_auth = env.get("SAMBATUI_AUTH") or user_config.get("auth")
    if explicit_auth:
        return explicit_auth
    return "kerberos" if ticket_checker() else "password"


def password_file_permissions_too_open(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & 0o077)
    except FileNotFoundError:
        return False
    except OSError:
        return False


def fix_password_file_permissions(path: Path) -> None:
    path.chmod(0o600)


DEFAULT_SERVER = _default("SAMBATUI_SERVER", "server", "")
DEFAULT_ZONE = os.getenv(
    "SAMBATUI_ZONE", USER_CONFIG.get("zone") or USER_CONFIG.get("last_zone", "")
)
DEFAULT_USER = os.getenv("SAMBATUI_USER", "")
DEFAULT_AUTH = detected_default_auth()
DEFAULT_KERBEROS = os.getenv("SAMBATUI_KERBEROS", "off")
DEFAULT_KRB5_CCACHE = os.getenv("SAMBATUI_KRB5_CCACHE", "")
DEFAULT_CONFIGFILE = os.getenv("SAMBATUI_CONFIGFILE", "")
DEFAULT_OPTIONS = os.getenv("SAMBATUI_OPTIONS", "")
DEFAULT_LDAP_BASE = _default("SAMBATUI_LDAP_BASE", "ldap_base", "")
DEFAULT_LDAP_ENCRYPTION = _default(
    "SAMBATUI_LDAP_ENCRYPTION", "ldap_encryption", "ldaps"
)
DEFAULT_LDAP_COMPATIBILITY = _default(
    "SAMBATUI_LDAP_COMPATIBILITY", "ldap_compatibility", "off"
)
DEFAULT_AUTO_PTR = _default("SAMBATUI_AUTO_PTR", "auto_ptr", "ask")
DEFAULT_SMART_DAYS = _default("SAMBATUI_SMART_DAYS", "smart_days", "90")
DEFAULT_SMART_DISABLED_DAYS = _default(
    "SAMBATUI_SMART_DISABLED_DAYS", "smart_disabled_days", "180"
)
DEFAULT_SMART_NEVER_LOGGED_DAYS = _default(
    "SAMBATUI_SMART_NEVER_LOGGED_DAYS", "smart_never_logged_days", "30"
)
DEFAULT_SMART_MAX_ROWS = _default("SAMBATUI_SMART_MAX_ROWS", "smart_max_rows", "500")
DEFAULT_PASSWORD_FILE = Path(
    os.getenv("SAMBATUI_PASSWORD_FILE", "~/.config/sambatui/password")
).expanduser()


def password_file_warning(path: Path) -> str | None:
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"Cannot inspect password file {path}: {exc}"
    if mode & 0o077:
        return (
            f"Password file permissions too open: {path}. "
            f"Press p to fix and load, or run chmod 600 {path}."
        )
    return None


def read_password_file(path: Path = DEFAULT_PASSWORD_FILE) -> str:
    if password_file_warning(path):
        return ""
    try:
        return path.read_text(encoding="utf-8").splitlines()[0].strip()
    except FileNotFoundError, IndexError, OSError:
        return ""


DEFAULT_PASSWORD = os.getenv("SAMBATUI_PASSWORD", read_password_file())
