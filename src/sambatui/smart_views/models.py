from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class SmartViewRow:
    severity: str
    object: str
    finding: str
    evidence: str
    suggested_action: str
    source: str
    fix_action: str = ""
    fix_label: str = ""
    fix_zone: str = ""
    fix_name: str = ""
    fix_rtype: str = ""
    fix_value: str = ""


@dataclass(frozen=True)
class SmartViewCheckResult:
    view_id: str
    label: str
    source: str
    rows: Sequence[SmartViewRow] = ()
    error: str = ""
