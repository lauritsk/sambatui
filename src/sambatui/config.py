from __future__ import annotations

import os
from pathlib import Path

DEFAULT_SERVER = os.getenv("SAMBATUI_SERVER", "")
DEFAULT_ZONE = os.getenv("SAMBATUI_ZONE", "")
DEFAULT_USER = os.getenv("SAMBATUI_USER", "")
DEFAULT_KERBEROS = os.getenv("SAMBATUI_KERBEROS", "off")
DEFAULT_AUTO_PTR = os.getenv("SAMBATUI_AUTO_PTR", "off")
DEFAULT_PASSWORD_FILE = Path(
    os.getenv("SAMBATUI_PASSWORD_FILE", "~/.config/sambatui/password")
).expanduser()


def read_password_file(path: Path = DEFAULT_PASSWORD_FILE) -> str:
    try:
        return path.read_text(encoding="utf-8").splitlines()[0].strip()
    except FileNotFoundError, IndexError, OSError:
        return ""


DEFAULT_PASSWORD = os.getenv("SAMBATUI_PASSWORD", read_password_file())
