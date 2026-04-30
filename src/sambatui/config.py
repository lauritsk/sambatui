from __future__ import annotations

import os
import tomllib
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


def load_user_config(path: Path = USER_CONFIG_PATH) -> dict[str, str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError, OSError, tomllib.TOMLDecodeError:
        return {}
    return {
        key: _preference_value(value)
        for key, value in data.items()
        if key in USER_CONFIG_KEYS and _preference_value(value)
    }


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
    values: dict[str, str], path: Path = USER_CONFIG_PATH
) -> dict[str, str]:
    safe_values = {
        key: str(value).strip()
        for key, value in values.items()
        if key in USER_CONFIG_KEYS and str(value).strip()
    }
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


USER_CONFIG = load_user_config()


def _default(envvar: str, key: str, fallback: str) -> str:
    return os.getenv(envvar, USER_CONFIG.get(key, fallback))


DEFAULT_SERVER = _default("SAMBATUI_SERVER", "server", "")
DEFAULT_ZONE = os.getenv(
    "SAMBATUI_ZONE", USER_CONFIG.get("zone") or USER_CONFIG.get("last_zone", "")
)
DEFAULT_USER = os.getenv("SAMBATUI_USER", "")
DEFAULT_AUTH = _default("SAMBATUI_AUTH", "auth", "password")
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
        return f"Password file permissions too open: {path}. Run chmod 600 {path}."
    return None


def read_password_file(path: Path = DEFAULT_PASSWORD_FILE) -> str:
    if password_file_warning(path):
        return ""
    try:
        return path.read_text(encoding="utf-8").splitlines()[0].strip()
    except FileNotFoundError, IndexError, OSError:
        return ""


DEFAULT_PASSWORD = os.getenv("SAMBATUI_PASSWORD", read_password_file())
