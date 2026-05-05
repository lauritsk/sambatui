from __future__ import annotations

import os
import tempfile
from pathlib import Path

from hypothesis import settings

_TEST_CONFIG_DIR = Path(tempfile.mkdtemp(prefix="sambatui-tests-"))
os.environ["SAMBATUI_USER_CONFIG"] = str(_TEST_CONFIG_DIR / "config.toml")
os.environ["SAMBATUI_PASSWORD_FILE"] = str(_TEST_CONFIG_DIR / "password")
os.environ.pop("SAMBATUI_PASSWORD", None)


settings.register_profile(
    "sambatui",
    deadline=None,
    max_examples=100,
)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "sambatui"))
