from __future__ import annotations

from collections.abc import Iterable
import ipaddress
import re
import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.reversename

from .models import DnsRow

NAME_RE = re.compile(r"^\s*Name=(.*?), Records=(\d+), Children=(\d+)")
REC_RE = re.compile(r"^\s+([A-Z0-9_]+):\s*(.*?)(?:\s+\(flags=.*?ttl=(\d+)\))?\s*$")
_LABEL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)
_LABEL_EDGE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
)


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


def valid_dns_name(value: str, *, allow_at: bool = False) -> bool:
    if value == "@":
        return allow_at

    text = value.rstrip(".")
    if not text or len(text) > 253:
        return False

    try:
        dns.name.from_text(value, origin=dns.name.root)
    except dns.exception.DNSException, UnicodeError, ValueError:
        return False

    return all(_valid_dns_label(label) for label in text.split("."))


def _valid_dns_label(label: str) -> bool:
    if not label or not label.isascii() or len(label) > 63:
        return False
    if label[0] not in _LABEL_EDGE_CHARS or label[-1] not in _LABEL_EDGE_CHARS:
        return False
    return all(char in _LABEL_CHARS for char in label)


def ptr_target_for_name(name: str, zone: str) -> str:
    if name == "@":
        return zone
    if name.endswith(".") or "." in name:
        return name.rstrip(".")
    return f"{name}.{zone}"


def _parse_rdata(rtype: str, value: str) -> None:
    dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.from_text(rtype),
        value,
        origin=dns.name.root,
    )


def _rdata_is_valid(rtype: str, value: str) -> bool:
    try:
        _parse_rdata(rtype, value)
    except dns.exception.DNSException:
        return False
    return True


def _valid_mx(value: str) -> bool:
    parts = value.split()
    if len(parts) != 2:
        return False
    if _rdata_is_valid("MX", value):
        return valid_dns_name(parts[1])
    if not parts[1].isdigit() or not valid_dns_name(parts[0]):
        return False
    return _rdata_is_valid("MX", f"{parts[1]} {parts[0]}")


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


def validate_record(
    name: str, rtype: str, value: str, *, require_value: bool = True
) -> str | None:
    rtype = rtype.upper()
    error = _record_shape_error(name, rtype, value, require_value=require_value)
    if error or not value:
        return error

    try:
        return _record_value_error(rtype, value)
    except dns.exception.DNSException as exc:
        return str(exc)
    except ValueError as exc:
        return str(exc)


def _record_shape_error(
    name: str, rtype: str, value: str, *, require_value: bool
) -> str | None:
    if not valid_dns_name(name, allow_at=True):
        return "Bad name. Use @ or DNS labels with letters, numbers, dash, underscore, dot."
    if not (rtype.isascii() and rtype.isalnum()):
        return "Bad type. Example: A, AAAA, CNAME, PTR, TXT, MX, SRV."
    if require_value and not value:
        return "Value is required."
    return None


def _record_value_error(rtype: str, value: str) -> str | None:
    match rtype:
        case "A" | "AAAA" | "TXT":
            _parse_rdata(rtype, value)
        case "CNAME" | "PTR" | "NS":
            return _dns_name_record_error(rtype, value)
        case "SRV":
            return _srv_record_error(value)
        case "MX":
            if not _valid_mx(value):
                return "MX value must be: priority mail.example.com. (or mail.example.com. priority)"
    return None


def _dns_name_record_error(rtype: str, value: str) -> str | None:
    if not valid_dns_name(value):
        return f"{rtype} value must be a DNS name, e.g. host.example.com."
    if rtype == "CNAME" and _is_ip_address(value):
        return "CNAME value must be a hostname, not an IP address. Use A/AAAA for IPs."
    _parse_rdata(rtype, value)
    return None


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.rstrip("."))
    except ValueError:
        return False
    return True


def _srv_record_error(value: str) -> str | None:
    parts = value.split()
    if (
        len(parts) != 4
        or not all(part.isdigit() for part in parts[:3])
        or not valid_dns_name(parts[3])
    ):
        return "SRV value must be: priority weight port target.example.com."
    _parse_rdata("SRV", value)
    return None
