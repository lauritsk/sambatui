from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DirectoryRow:
    dn: str
    kind: str
    name: str
    summary: str
    attributes: Mapping[str, Sequence[str]]

    @property
    def revision(self) -> str:
        values = self.attributes.get("uSNChanged", ())
        return values[0] if len(values) == 1 else ""
