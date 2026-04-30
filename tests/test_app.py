from sambatui.app import DnsRow, parse_records, parse_zones, validate_record


def test_parse_zones_deduplicates_zone_names() -> None:
    output = """
        pszZoneName                 : example.com
        ZoneName                    : 2.0.192.in-addr.arpa
        pszZoneName                 : example.com
    """

    assert parse_zones(output) == ["example.com", "2.0.192.in-addr.arpa"]


def test_parse_records_reads_records_and_empty_nodes() -> None:
    output = """
  Name=www, Records=1, Children=0
    A: 192.0.2.10 (flags=f0, serial=1, ttl=3600)
  Name=empty, Records=0, Children=1
    """

    assert parse_records(output) == [
        DnsRow("www", "1", "0", "A", "192.0.2.10", "3600", "A: 192.0.2.10 (flags=f0, serial=1, ttl=3600)"),
        DnsRow("empty", "0", "1", "-", "", "", "Name=empty, Records=0, Children=1"),
    ]


def test_validate_record_accepts_documentation_examples() -> None:
    assert validate_record("www", "A", "192.0.2.10") is None
    assert validate_record("alias", "CNAME", "www.example.com.") is None
    assert validate_record("@", "MX", "10 mail.example.com.") is None


def test_validate_record_rejects_bad_cname_ip() -> None:
    assert validate_record("alias", "CNAME", "192.0.2.10") == (
        "CNAME value must be a hostname, not an IP address. Use A/AAAA for IPs."
    )
