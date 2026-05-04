from __future__ import annotations

from collections.abc import Iterable
import ipaddress

import dns.reversename


def ptr_target_for_name(name: str, zone: str) -> str:
    if name == "@":
        return zone
    if name.endswith(".") or "." in name:
        return name.rstrip(".")
    return f"{name}.{zone}"


def reverse_record_for_ipv4(
    ip_value: str, reverse_zones: Iterable[str] = ()
) -> tuple[str, str] | None:
    try:
        ip = ipaddress.IPv4Address(ip_value)
    except ValueError:
        return None

    reverse_name = dns.reversename.from_address(str(ip)).to_text().rstrip(".")
    zones: list[str] = [
        zone.rstrip(".") for zone in reverse_zones if zone.endswith(".in-addr.arpa")
    ]
    best_zone = best_matching_reverse_zone(reverse_name, zones)
    if best_zone:
        ptr_name = (
            "@" if reverse_name == best_zone else reverse_name[: -(len(best_zone) + 1)]
        )
        return best_zone, ptr_name

    labels = reverse_name.split(".")
    return ".".join(labels[1:]), labels[0]


def best_matching_reverse_zone(reverse_name: str, zones: Iterable[str]) -> str:
    matching_zones = [
        zone
        for zone in zones
        if reverse_name == zone or reverse_name.endswith(f".{zone}")
    ]
    return max(matching_zones, key=lambda zone: len(zone), default="")
