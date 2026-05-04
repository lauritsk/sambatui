from __future__ import annotations

import os

from hypothesis import settings

settings.register_profile(
    "sambatui",
    deadline=None,
    max_examples=100,
)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "sambatui"))
