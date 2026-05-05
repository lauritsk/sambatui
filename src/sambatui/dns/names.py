from __future__ import annotations


def normalize_dns_name(value: str) -> str:
    return value.strip().rstrip(".").casefold()


def normalize_dns_value(value: str) -> str:
    return " ".join(value.strip().rstrip(".").casefold().split())


def is_ipv4_reverse_zone(value: str) -> bool:
    return normalize_dns_name(value).endswith(".in-addr.arpa")


def is_reverse_dns_zone(value: str) -> bool:
    normalized = normalize_dns_name(value)
    return normalized.endswith((".in-addr.arpa", ".ip6.arpa"))
