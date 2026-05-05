from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class DirectoryRow:
    dn: str
    kind: str
    name: str
    summary: str
    attributes: Mapping[str, Sequence[str]]
