from __future__ import annotations

import re

from .models import DnsRow

NAME_RE = re.compile(r"^\s*Name=(.*?), Records=(\d+), Children=(\d+)")
REC_RE = re.compile(r"^\s+([A-Z0-9_]+):\s*(.*?)(?:\s+\(flags=.*?ttl=(\d+)\))?\s*$")


def parse_records(output: str) -> list[DnsRow]:
    rows: list[DnsRow] = []
    current: tuple[str, str, str] | None = None

    for line in output.splitlines():
        name_match = NAME_RE.match(line)
        if name_match:
            display_name = name_match.group(1) or "@"
            current = display_name, name_match.group(2), name_match.group(3)
            if current[1] == "0":
                rows.append(
                    DnsRow(
                        current[0], current[1], current[2], "-", "", "", line.strip()
                    )
                )
            continue

        rec_match = REC_RE.match(line)
        if rec_match and current:
            value = rec_match.group(2).strip()
            rows.append(
                DnsRow(
                    name=current[0],
                    records=current[1],
                    children=current[2],
                    rtype=rec_match.group(1),
                    value=value,
                    ttl=rec_match.group(3) or "",
                    raw=line.strip(),
                )
            )
    return rows


def parse_zones(output: str) -> list[str]:
    zones: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        if "ZoneName" not in line:
            continue
        _, sep, value = line.partition(":")
        if not sep:
            continue
        zone = value.strip()
        if zone and zone not in seen:
            zones.append(zone)
            seen.add(zone)
    return zones
