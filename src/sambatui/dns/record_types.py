from __future__ import annotations

from dataclasses import dataclass

FormFieldSpec = tuple[str, str, str, str]


@dataclass(frozen=True)
class DnsRecordTypeSpec:
    rtype: str
    example: str
    fields: tuple[FormFieldSpec, ...]
    value_fields: tuple[str, ...]


DNS_RECORD_TYPE_SPECS: dict[str, DnsRecordTypeSpec] = {
    spec.rtype: spec
    for spec in (
        DnsRecordTypeSpec(
            "A",
            "192.0.2.10",
            (("IPv4 address", "address", "192.0.2.10", ""),),
            ("address",),
        ),
        DnsRecordTypeSpec(
            "AAAA",
            "2001:db8::10",
            (("IPv6 address", "address", "2001:db8::10", ""),),
            ("address",),
        ),
        DnsRecordTypeSpec(
            "CNAME",
            "host.example.com.",
            (("Canonical target", "target", "host.example.com.", ""),),
            ("target",),
        ),
        DnsRecordTypeSpec(
            "PTR",
            "host.example.com.",
            (("PTR target", "target", "host.example.com.", ""),),
            ("target",),
        ),
        DnsRecordTypeSpec(
            "TXT",
            "v=spf1 include:example.com ~all",
            (("TXT text", "text", "v=spf1 include:example.com ~all", ""),),
            ("text",),
        ),
        DnsRecordTypeSpec(
            "MX",
            "10 mail.example.com.",
            (
                ("Priority", "priority", "10", "10"),
                ("Mail exchanger", "target", "mail.example.com.", ""),
            ),
            ("priority", "target"),
        ),
        DnsRecordTypeSpec(
            "SRV",
            "0 100 389 dc01.example.com.",
            (
                ("Priority", "priority", "0", "0"),
                ("Weight", "weight", "100", "100"),
                ("Port", "port", "389", ""),
                ("Target", "target", "dc01.example.com.", ""),
            ),
            ("priority", "weight", "port", "target"),
        ),
        DnsRecordTypeSpec(
            "NS",
            "ns1.example.com.",
            (("Name server", "target", "ns1.example.com.", ""),),
            ("target",),
        ),
    )
}

SUPPORTED_DNS_RECORD_TYPES = tuple(DNS_RECORD_TYPE_SPECS)
SUPPORTED_DNS_RECORD_TYPES_TEXT = " / ".join(SUPPORTED_DNS_RECORD_TYPES)
SUPPORTED_DNS_RECORD_TYPES_CSV = ", ".join(SUPPORTED_DNS_RECORD_TYPES)


def dns_record_type_spec(rtype: str) -> DnsRecordTypeSpec | None:
    return DNS_RECORD_TYPE_SPECS.get(rtype.upper())
