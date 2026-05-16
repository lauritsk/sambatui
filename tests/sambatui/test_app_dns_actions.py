import asyncio
import ipaddress

from hypothesis import given
from hypothesis import strategies as st

from sambatui.app import (
    DnsRow,
    SambatuiApp,
    parse_records,
    parse_zones,
    validate_record,
)
from textual.widgets import Button, Input, Static

from sambatui.dns.ptr import ptr_target_for_name, reverse_record_for_ipv4
from sambatui.dns.record_types import (
    DNS_RECORD_TYPE_SPECS,
    SUPPORTED_DNS_RECORD_TYPES,
    SUPPORTED_DNS_RECORD_TYPES_TEXT,
    dns_record_type_spec,
)
from sambatui.dns.validation import valid_dns_name
from sambatui.ui.screens import (
    FormScreen,
)

DNS_LABEL = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"))
    | st.sampled_from("_"),
    min_size=1,
    max_size=20,
).filter(lambda value: value[0].isalnum() and value[-1].isalnum() and value.isascii())
DNS_NAME = st.lists(DNS_LABEL, min_size=1, max_size=4).map(".".join)


@given(st.lists(DNS_NAME, min_size=1, max_size=8))
def test_parse_zones_deduplicates_zone_names(zones: list[str]) -> None:
    output = "\n".join(
        f"        pszZoneName                 : {zone}" for zone in [*zones, *zones]
    )

    assert parse_zones(output) == list(dict.fromkeys(zones))


def test_parse_records_reads_records_and_empty_nodes() -> None:
    output = """
  Name=www, Records=1, Children=0
    A: 192.0.2.10 (flags=f0, serial=1, ttl=3600)
  Name=empty, Records=0, Children=1
    """

    assert parse_records(output) == [
        DnsRow(
            "www",
            "1",
            "0",
            "A",
            "192.0.2.10",
            "3600",
            "A: 192.0.2.10 (flags=f0, serial=1, ttl=3600)",
        ),
        DnsRow("empty", "0", "1", "-", "", "", "Name=empty, Records=0, Children=1"),
    ]


@given(
    st.sampled_from(
        [
            ("www", "A", "192.0.2.10"),
            ("alias", "CNAME", "www.example.com."),
            ("@", "MX", "10 mail.example.com."),
        ]
    )
)
def test_validate_record_accepts_documentation_examples(
    record: tuple[str, str, str],
) -> None:
    assert validate_record(*record) is None


@given(
    st.sampled_from(
        [
            (
                rtype,
                {"name", "ttl"} | {field_id for _, field_id, _, _ in spec.fields},
            )
            for rtype, spec in DNS_RECORD_TYPE_SPECS.items()
        ]
    )
)
def test_guided_add_record_fields_are_type_specific(
    case: tuple[str, set[str]],
) -> None:
    rtype, expected = case
    app = SambatuiApp()

    assert {
        field_id for _, field_id, _, _ in app.add_record_type_fields(rtype)
    } == expected


def test_record_type_registry_covers_guided_fields_and_validation_hints() -> None:
    app = SambatuiApp()

    for rtype, spec in DNS_RECORD_TYPE_SPECS.items():
        assert rtype in SUPPORTED_DNS_RECORD_TYPES
        assert spec.fields
        assert dns_record_type_spec(rtype.lower()) == spec
        assert set(spec.value_fields) <= {field_id for _, field_id, _, _ in spec.fields}
        assert app.record_type_selection_error({"rtype": rtype.lower()}) is None

    assert validate_record("bad space", "BAD!", "value") == (
        "Bad name. Use @ or DNS labels with letters, numbers, dash, underscore, dot."
    )
    assert validate_record("www", "BAD!", "value") == (
        "Bad type. Example: A, AAAA, CNAME, PTR, TXT, MX, SRV, NS."
    )
    assert SUPPORTED_DNS_RECORD_TYPES_TEXT in str(
        app.update_record_fields(
            {"name": "www", "rtype": "NS", "value": "ns1.example.com."}
        )
    )


def test_guided_add_record_error_validates_ttl_and_duplicates() -> None:
    app = SambatuiApp()
    app.record_rows = [DnsRow("www", "1", "0", "A", "192.0.2.10", "3600", "raw")]

    assert (
        app.guided_add_record_error(
            "A", {"name": "www", "address": "192.0.2.10", "ttl": ""}
        )
        == "Duplicate record already exists in the loaded zone view."
    )
    assert (
        app.guided_add_record_error(
            "A", {"name": "www", "address": "192.0.2.11", "ttl": "bad"}
        )
        == "TTL must be whole seconds, e.g. 3600."
    )
    assert (
        app.guided_add_record_error(
            "MX",
            {"name": "@", "priority": "10", "target": "mail.example.com.", "ttl": ""},
        )
        is None
    )


def test_guided_add_preview_includes_command_and_ptr_suggestion() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test():
            app.query_one("#server", Input).value = "dc01.example.com"
            app.query_one("#zone", Input).value = "example.com"
            app.query_one("#user", Input).value = "admin"
            app.query_one("#password", Input).value = "secret"
            app.zones = ["example.com", "2.0.192.in-addr.arpa"]

            preview = app.add_record_preview("www", "A", "192.0.2.10", "300")

            assert "Record: www A 192.0.2.10" in preview
            assert "2.0.192.in-addr.arpa: 10 PTR www.example.com" in preview
            assert "Command preview: samba-tool dns add dc01.example.com" in preview
            assert "-U admin" in preview
            assert "secret" not in preview

    asyncio.run(run_app())


def test_form_screen_live_validation_disables_submit() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.push_screen(
                FormScreen(
                    "Validate",
                    "",
                    [("Value", "value", "ok", "bad")],
                    "Save",
                    lambda values: "Bad value" if values["value"] == "bad" else None,
                )
            )
            await pilot.pause()
            submit = app.screen.query_one("#submit", Button)
            error = app.screen.query_one("#form_error", Static)
            value = app.screen.query_one("#value", Input)

            assert submit.disabled
            assert str(error.render()) == "Bad value"

            value.value = "ok"
            await pilot.pause()

            assert not submit.disabled
            assert str(error.render()) == ""

    asyncio.run(run_app())


def test_setup_form_suggests_upn_domain_suffix() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.push_screen(
                FormScreen(
                    "First-run setup wizard",
                    "",
                    [
                        ("Domain", "domain", "example.com", "example.com"),
                        ("User", "user", "admin@example.com", ""),
                    ],
                    "Run checks",
                )
            )
            await pilot.pause()
            form = app.screen
            assert isinstance(form, FormScreen)
            domain = form.query_one("#domain", Input)
            user = form.query_one("#user", Input)
            user.focus()

            user.value = "alice"
            await pilot.pause()
            assert getattr(user, "_suggestion") == "alice@example.com"
            assert form.form_values()["user"] == "alice@example.com"

            await pilot.press("tab")
            await pilot.pause()
            assert user.value == "alice@example.com"
            assert getattr(user, "_suggestion") == ""

            user.focus()
            user.value = "alice"
            domain.value = "ad.example."
            await pilot.pause()
            assert getattr(user, "_suggestion") == "alice@ad.example"
            assert form.form_values()["user"] == "alice@ad.example"

            user.value = "alice@other.example"
            await pilot.pause()
            assert form.form_values()["user"] == "alice@other.example"

            user.value = r"EXAMPLE\alice"
            await pilot.pause()
            assert form.form_values()["user"] == r"EXAMPLE\alice"

    asyncio.run(run_app())


def test_validate_record_rejects_bad_cname_ip() -> None:
    assert validate_record("alias", "CNAME", "192.0.2.10") == (
        "CNAME value must be a hostname, not an IP address. Use A/AAAA for IPs."
    )


def test_validate_record_uses_dns_parser_for_supported_types() -> None:
    assert validate_record("_ldap._tcp", "SRV", "0 100 389 dc.example.com.") is None
    assert validate_record("@", "MX", "mail.example.com. 10") is None
    assert validate_record("www", "A", "999.0.2.10") is not None


@given(DNS_NAME)
def test_valid_dns_name_keeps_sambatui_label_policy(name: str) -> None:
    assert valid_dns_name(name)
    assert valid_dns_name(f"{name}.")
    assert not valid_dns_name(f"-{name}")
    assert not valid_dns_name(f"bad space.{name}")


@given(DNS_LABEL, DNS_NAME, DNS_NAME)
def test_ptr_target_for_name_uses_zone_for_relative_names(
    label: str, absolute_name: str, zone: str
) -> None:
    assert ptr_target_for_name(label, zone) == f"{label}.{zone}"
    assert ptr_target_for_name("@", zone) == zone
    assert ptr_target_for_name(f"{absolute_name}.", zone) == absolute_name


@given(st.ip_addresses(v=4))
def test_reverse_record_for_ipv4_prefers_longest_matching_zone(
    address: ipaddress.IPv4Address,
) -> None:
    octets = str(address).split(".")
    zone = f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
    zones = [zone, f"{octets[1]}.{octets[0]}.in-addr.arpa", "example.com"]

    assert reverse_record_for_ipv4(str(address), zones) == (zone, octets[3])


@given(st.ip_addresses(v=4))
def test_reverse_record_for_ipv4_falls_back_to_24_zone(
    address: ipaddress.IPv4Address,
) -> None:
    octets = str(address).split(".")

    assert reverse_record_for_ipv4(str(address), []) == (
        f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa",
        octets[3],
    )


def test_reverse_record_for_ipv4_accepts_case_and_trailing_dot_zones() -> None:
    assert reverse_record_for_ipv4(
        "192.0.2.10",
        ["example.com", "2.0.192.IN-ADDR.ARPA."],
    ) == ("2.0.192.in-addr.arpa", "10")


def test_reverse_record_for_ipv4_keeps_longest_normalized_match() -> None:
    assert reverse_record_for_ipv4(
        "192.0.2.10",
        ["0.192.IN-ADDR.ARPA.", "2.0.192.in-addr.arpa"],
    ) == ("2.0.192.in-addr.arpa", "10")


def test_reverse_record_for_ipv4_rejects_non_ipv4_values() -> None:
    assert reverse_record_for_ipv4("not-an-ip", []) is None
