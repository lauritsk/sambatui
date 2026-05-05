from __future__ import annotations

from collections.abc import Iterable
import ipaddress

import dns.reversename

from .names import is_ipv4_reverse_zone, normalize_dns_name


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

    reverse_name = normalize_dns_name(dns.reversename.from_address(str(ip)).to_text())
    zones: list[str] = [
        normalize_dns_name(zone) for zone in reverse_zones if is_ipv4_reverse_zone(zone)
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
        normalized_zone
        for zone in zones
        if (normalized_zone := normalize_dns_name(zone))
        and (
            reverse_name == normalized_zone
            or reverse_name.endswith(f".{normalized_zone}")
        )
    ]
    return max(matching_zones, key=lambda zone: len(zone), default="")
