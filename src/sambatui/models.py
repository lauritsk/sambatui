from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DnsRow:
    name: str
    records: str
    children: str
    rtype: str
    value: str
    ttl: str
    raw: str
