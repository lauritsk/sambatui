from __future__ import annotations

import os
from pathlib import Path

DEFAULT_SERVER = os.getenv("SAMBATUI_SERVER", "")
DEFAULT_ZONE = os.getenv("SAMBATUI_ZONE", "")
DEFAULT_USER = os.getenv("SAMBATUI_USER", "")
DEFAULT_AUTH = os.getenv("SAMBATUI_AUTH", "password")
DEFAULT_KERBEROS = os.getenv("SAMBATUI_KERBEROS", "off")
DEFAULT_KRB5_CCACHE = os.getenv("SAMBATUI_KRB5_CCACHE", "")
DEFAULT_CONFIGFILE = os.getenv("SAMBATUI_CONFIGFILE", "")
DEFAULT_OPTIONS = os.getenv("SAMBATUI_OPTIONS", "")
DEFAULT_AUTO_PTR = os.getenv("SAMBATUI_AUTO_PTR", "off")
DEFAULT_LDAP_BASE = os.getenv("SAMBATUI_LDAP_BASE", "")
DEFAULT_LDAP_ENCRYPTION = os.getenv("SAMBATUI_LDAP_ENCRYPTION", "ldaps")
DEFAULT_LDAP_COMPATIBILITY = os.getenv("SAMBATUI_LDAP_COMPATIBILITY", "off")
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
