from __future__ import annotations

import ipaddress
import re
from typing import cast

from .models import DnsRow

NAME_RE = re.compile(r"^\s*Name=(.*?), Records=(\d+), Children=(\d+)")
REC_RE = re.compile(r"^\s+([A-Z0-9_]+):\s*(.*?)(?:\s+\(flags=.*?ttl=(\d+)\))?\s*$")
LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


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
        if "ZoneName" not in line and "pszZoneName" not in line:
            continue
        _, sep, value = line.partition(":")
        if not sep:
            continue
        zone = value.strip()
        if zone and zone not in seen:
            zones.append(zone)
            seen.add(zone)
    return zones


def valid_dns_name(value: str, *, allow_at: bool = False) -> bool:
    if allow_at and value == "@":
        return True
    value = value.rstrip(".")
    if not value or len(value) > 253:
        return False
    labels = value.split(".")
    return all(LABEL_RE.fullmatch(label) for label in labels)


def ptr_target_for_name(name: str, zone: str) -> str:
    if name == "@":
        return zone
    if name.endswith("."):
        return name.rstrip(".")
    if "." in name:
        return name.rstrip(".")
    return f"{name}.{zone}"


def reverse_record_for_ipv4(ip_value: str, zones: list[str]) -> tuple[str, str] | None:
    try:
        ip = ipaddress.IPv4Address(ip_value)
    except ValueError:
        return None
    parts = str(ip).split(".")
    fqdn = ".".join(reversed(parts)) + ".in-addr.arpa"
    reverse_zones = [zone for zone in zones if zone.endswith(".in-addr.arpa")]
    matching_zones = [zone for zone in reverse_zones if fqdn.endswith(zone)]
    if matching_zones:
        best_zone = cast("str", max(matching_zones, key=len))
        ptr_name = fqdn[: -(len(best_zone) + 1)]
        return best_zone, ptr_name
    return ".".join(reversed(parts[:3])) + ".in-addr.arpa", parts[3]


def validate_record(
    name: str, rtype: str, value: str, *, require_value: bool = True
) -> str | None:
    rtype = rtype.upper()
    if not valid_dns_name(name, allow_at=True):
        return "Bad name. Use @ or DNS labels with letters, numbers, dash, underscore, dot."
    if not re.fullmatch(r"[A-Z0-9]+", rtype):
        return "Bad type. Example: A, AAAA, CNAME, PTR, TXT, MX, SRV."
    if require_value and not value:
        return "Value is required."
    if not value:
        return None

    try:
        match rtype:
            case "A":
                ipaddress.IPv4Address(value)
            case "AAAA":
                ipaddress.IPv6Address(value)
            case "CNAME" | "PTR" | "NS":
                if not valid_dns_name(value):
                    return f"{rtype} value must be a DNS name, e.g. host.example.com."
                if rtype == "CNAME":
                    try:
                        ipaddress.ip_address(value.rstrip("."))
                        return "CNAME value must be a hostname, not an IP address. Use A/AAAA for IPs."
                    except ValueError:
                        pass
            case "SRV":
                parts = value.split()
                if (
                    len(parts) != 4
                    or not all(part.isdigit() for part in parts[:3])
                    or not valid_dns_name(parts[3])
                ):
                    return "SRV value must be: priority weight port target.example.com."
            case "MX":
                parts = value.split()
                if len(parts) == 2 and parts[0].isdigit() and valid_dns_name(parts[1]):
                    return None
                if len(parts) == 2 and valid_dns_name(parts[0]) and parts[1].isdigit():
                    return None
                return "MX value must be: priority mail.example.com. (or mail.example.com. priority)"
    except ValueError as exc:
        return str(exc)
    return None
