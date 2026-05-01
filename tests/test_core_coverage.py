from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from ldap3 import NTLM, SIMPLE
from ldap3.core.exceptions import LDAPPackageUnavailableError

from sambatui.client import SambaToolClient, SambaToolConfig
from sambatui.config import (
    DEFAULT_AUTH,
    load_user_config,
    password_file_warning,
    read_password_file,
    save_user_config,
    user_config_validation_error,
)
from sambatui.dns import (
    parse_records,
    parse_zones,
    ptr_target_for_name,
    reverse_record_for_ipv4,
    valid_dns_name,
    validate_record,
)
from sambatui.ldap_directory import (
    DirectoryRow,
    LdapDirectoryClient,
    LdapSearchConfig,
    build_directory_filter,
    directory_summary,
    domain_to_base_dn,
    entry_to_directory_row,
    first_attr,
    gssapi_cred_store,
    infer_kind,
    ldap_connection_kwargs,
    ldap_server_tls,
    normalize_entry_attributes,
    parse_ldap_server,
)
from sambatui.remediation import actionable_error, bounded_int
from sambatui.settings import ConnectionSettings
from sambatui.smart_views import (
    ACCOUNTDISABLE,
    age_text,
    directory_object_name,
    dns_a_without_ptr,
    dns_duplicate_records,
    dns_fqdn,
    dns_ptr_without_a,
    ensure_utc,
    first_ad_datetime,
    ipv4_from_ptr_name,
    ldap_delete_candidate_users,
    ldap_is_disabled,
    ldap_stale_computers,
    ldap_users_without_groups,
    normalize_dns_value,
    normalized_now,
    parse_ad_datetime,
)
from sambatui.models import DnsRow


def dns_row(name: str, rtype: str, value: str) -> DnsRow:
    return DnsRow(name, "1", "0", rtype, value, "900", "raw")


def directory_row(
    *, kind: str = "user", name: str = "Alice", attrs: dict[str, tuple[str, ...]]
) -> DirectoryRow:
    return DirectoryRow(f"CN={name},DC=example,DC=com", kind, name, "", attrs)


def filetime_for(value: datetime) -> str:
    ad_epoch = datetime(1601, 1, 1, tzinfo=UTC)
    return str(int((value - ad_epoch).total_seconds() * 10_000_000))


class FakeEntry:
    entry_dn = "CN=Ops,DC=example,DC=com"
    entry_attributes_as_dict = {
        "cn": "Ops",
        "objectClass": ["top", "group"],
        "description": None,
        "member": {"CN=Alice,DC=example,DC=com"},
    }


def test_client_validation_redaction_and_status_edges() -> None:
    assert (
        SambaToolClient(SambaToolConfig("dc", auth_mode="token")).authentication_error()
        == "Auth must be password or kerberos."
    )
    assert (
        SambaToolClient(
            SambaToolConfig("dc", user="u", password="p", kerberos="bad")
        ).authentication_error()
        == "Kerberos must be off, desired, or required."
    )
    client = SambaToolClient(SambaToolConfig("dc", user="u", password="p"))
    assert client.dns_zone_command("query", "example.com", ["@", "ALL"])[3:6] == [
        "dc",
        "example.com",
        "@",
    ]
    assert SambaToolClient.redact_command(
        ["cmd", "--password=secret", "-U", "%pw", "-U", "alice"]
    ) == [
        "cmd",
        "--password=******",
        "-U",
        "******",
        "-U",
        "alice",
    ]
    long = SambaToolClient.status_command(["x" * 200], max_len=10)
    assert long == "x" * 9 + "…"


def test_config_password_file_missing_empty_and_os_errors(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert password_file_warning(missing) is None
    assert read_password_file(missing) == ""

    empty = tmp_path / "empty"
    empty.write_text("", encoding="utf-8")
    empty.chmod(0o600)
    assert read_password_file(empty) == ""

    directory = tmp_path / "directory"
    directory.mkdir()
    directory.chmod(0o600)
    assert read_password_file(directory) == ""


def test_user_config_persists_only_non_secret_preferences(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    saved = save_user_config(
        {
            "server": "dc01.example.com",
            "zone": "example.com",
            "last_zone": "example.com",
            "auth": "kerberos",
            "ldap_base": "DC=example,DC=com",
            "ldap_encryption": "starttls",
            "auto_ptr": "ask",
            "smart_days": "120",
            "smart_max_rows": "250",
            "password": "secret",
            "user": "admin",
        },
        path,
    )

    assert "password" not in saved
    assert "user" not in saved
    assert load_user_config(path) == saved
    assert "secret" not in path.read_text(encoding="utf-8")

    save_user_config({"server": "nested"}, tmp_path / "nested" / "config.toml")
    assert load_user_config(tmp_path / "nested" / "config.toml") == {"server": "nested"}

    path.write_text(
        'auto_ptr = true\nsmart_days = 120\nserver = ["bad"]\n',
        encoding="utf-8",
    )
    assert load_user_config(path) == {"auto_ptr": "on", "smart_days": "120"}
    path.write_text(
        'auth = "bad"\nldap_encryption = "plain"\nsmart_max_rows = 99999\nzone = "example.com"\n',
        encoding="utf-8",
    )
    assert load_user_config(path) == {"zone": "example.com"}
    assert save_user_config(
        {"auto_ptr": "always", "ldap_compatibility": "on", "smart_days": "0"},
        path,
    ) == {"ldap_compatibility": "on"}
    assert user_config_validation_error({"auth": "bad"}) == (
        "Auth must be password or kerberos."
    )
    assert user_config_validation_error({"smart_max_rows": "5001"}) == (
        "Smart max rows must be at most 5000."
    )
    path.write_text("invalid =", encoding="utf-8")
    assert load_user_config(path) == {}
    assert load_user_config(tmp_path / "missing.toml") == {}


def test_dns_parsing_and_validation_edges() -> None:
    assert parse_records("  Name=, Records=0, Children=0")[0].name == "@"
    assert parse_zones("ZoneName no colon\nOther: ignored") == []
    assert reverse_record_for_ipv4("192.0.2.10", ["10.2.0.192.in-addr.arpa"]) == (
        "10.2.0.192.in-addr.arpa",
        "@",
    )
    assert ptr_target_for_name("host.example.net", "example.com") == "host.example.net"
    assert not valid_dns_name("")
    assert not valid_dns_name("x" * 64 + ".example.com")
    assert not valid_dns_name("é.example.com")
    assert validate_record("bad space", "A", "192.0.2.10") is not None
    assert validate_record("www", "BAD-TYPE", "x") is not None
    assert validate_record("www", "A", "") == "Value is required."
    assert validate_record("www", "A", "", require_value=False) is None
    assert validate_record("ns", "NS", "ns1.example.com.") is None
    assert validate_record("ptr", "PTR", "bad space") is not None
    assert validate_record("srv", "SRV", "0 100 ldap.example.com.") is not None
    assert validate_record("@", "MX", "mail.example.com. 10") is None
    assert validate_record("@", "MX", "mail.example.com.") is not None


def test_ldap_config_validation_and_helpers() -> None:
    assert LdapSearchConfig(server="").validation_error() == "Enter LDAP server/DC."
    assert (
        LdapSearchConfig(server="dc", auth_mode="bad").validation_error()
        == "LDAP auth mode must be password or kerberos."
    )
    assert (
        LdapSearchConfig(server="ldaps://dc", encryption="off").validation_error()
        == "ldaps:// server URLs require LDAP encryption ldaps."
    )
    assert (
        LdapSearchConfig(server="dc", password="p", base_dn="DC=x").validation_error()
        == "LDAP search needs a username."
    )
    assert (
        LdapSearchConfig(server="dc", user="u", password="p").validation_error()
        == "Enter LDAP base DN, e.g. DC=example,DC=com."
    )

    assert domain_to_base_dn(" bad..example ") == ""
    with pytest.raises(ValueError, match="scheme"):
        parse_ldap_server("https://dc")
    with pytest.raises(ValueError, match="Enter LDAP server"):
        parse_ldap_server("")
    assert gssapi_cred_store("") is None
    assert (
        ldap_server_tls(LdapSearchConfig("dc", encryption="off", compatibility="on"))
        is None
    )
    assert ldap_server_tls(LdapSearchConfig("dc", compatibility="off")) is None


def test_ldap_filter_kwargs_and_entry_mapping() -> None:
    assert build_directory_filter("groups") == "(objectCategory=group)"
    with pytest.raises(ValueError, match="users, groups"):
        build_directory_filter("bad")

    simple = ldap_connection_kwargs(
        LdapSearchConfig("dc", user="alice", password="pw", base_dn="DC=x")
    )
    assert simple["authentication"] == SIMPLE
    ntlm = ldap_connection_kwargs(
        LdapSearchConfig("dc", user="EXAMPLE\\alice", password="pw", base_dn="DC=x")
    )
    assert ntlm["authentication"] == NTLM

    attrs = normalize_entry_attributes({"a": [1, None, "x"], "b": None, "c": 3})
    assert attrs == {"a": ("1", "x"), "b": (), "c": ("3",)}
    assert first_attr(attrs, "missing", "a") == "1"
    assert first_attr(attrs, "missing") == ""
    assert infer_kind({"objectClass": ("organizationalUnit",)}, "all") == "ou"
    assert infer_kind({"objectClass": ("unknown",)}, "computers") == "computer"

    row = entry_to_directory_row(FakeEntry(), "groups")
    assert row.kind == "group"
    assert row.name == "Ops"
    assert directory_summary({"memberOf": ("a", "b")}) == "memberOf=2"


def test_ldap_search_success_starttls_and_package_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeConnection:
        result = {"description": "ok", "message": ""}
        entries = [FakeEntry()]

        def __init__(self, server: object, **kwargs: object) -> None:
            captured["server"] = server
            captured["kwargs"] = kwargs
            self.unbound = False

        def start_tls(self) -> bool:
            captured["starttls"] = True
            return True

        def bind(self) -> bool:
            return True

        def search(self, base_dn: str, search_filter: str, **kwargs: object) -> bool:
            captured["search"] = (base_dn, search_filter, kwargs)
            return True

        def unbind(self) -> bool:
            captured["unbound"] = True
            return True

    monkeypatch.setattr("ldap3.Server", lambda *args, **kwargs: (args, kwargs))
    monkeypatch.setattr("ldap3.Connection", FakeConnection)

    rows = LdapDirectoryClient(
        LdapSearchConfig(
            "ldap://dc.example.com",
            user="alice",
            password="pw",
            base_dn="DC=example,DC=com",
            encryption="starttls",
        )
    ).search("groups", "ops")

    assert captured["starttls"] is True
    assert captured["unbound"] is True
    assert rows[0].kind == "group"
    assert "ops" in captured["search"][1]

    class KerberosConnection(FakeConnection):
        def bind(self) -> bool:
            raise LDAPPackageUnavailableError("missing gssapi")

    monkeypatch.setattr("ldap3.Connection", KerberosConnection)
    with pytest.raises(ValueError, match=r"Install sambatui\[kerberos\]"):
        LdapDirectoryClient(
            LdapSearchConfig(
                "dc.example.com",
                base_dn="DC=example,DC=com",
                auth_mode="kerberos",
            )
        ).search("users")


def test_ldap_search_starttls_and_search_result_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeConnection:
        entries: list[object] = []

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.result = {"description": "unwillingToPerform", "message": "no tls"}

        def start_tls(self) -> bool:
            return False

        def bind(self) -> bool:
            return True

        def search(self, *_args: object, **_kwargs: object) -> bool:
            self.result = {"description": "noSuchObject", "message": "bad base"}
            return False

        def unbind(self) -> bool:
            return True

    monkeypatch.setattr("ldap3.Server", lambda *_args, **_kwargs: object())
    monkeypatch.setattr("ldap3.Connection", FakeConnection)
    cfg = LdapSearchConfig(
        "ldap://dc.example.com",
        user="alice",
        password="pw",
        base_dn="DC=example,DC=com",
        encryption="starttls",
    )
    with pytest.raises(
        ValueError, match="LDAP StartTLS failed: unwillingToPerform: no tls"
    ):
        LdapDirectoryClient(cfg).search("users")

    class SearchFailConnection(FakeConnection):
        def start_tls(self) -> bool:
            return True

    monkeypatch.setattr("ldap3.Connection", SearchFailConnection)
    with pytest.raises(ValueError, match="LDAP search failed: noSuchObject: bad base"):
        LdapDirectoryClient(cfg).search("users")


def test_settings_branches_and_config_conversion(tmp_path: Path) -> None:
    values = {
        "server": "dc",
        "zone": "example.com",
        "user": "alice",
        "password": "",
        "auth": "",
        "kerberos": "",
        "krb5_ccache": "/tmp/ccache",
        "configfile": "/etc/samba/smb.conf",
        "options": "x=y; debug=1",
        "ldap_base": "",
        "ldap_encryption": "",
        "ldap_compatibility": "",
        "auto_ptr": "",
        "password_file": str(tmp_path / "pw"),
    }
    settings = ConnectionSettings.from_lookup(lambda key: values[key])
    assert settings.summary == f"dc · example.com · {DEFAULT_AUTH} auth"
    assert settings.needs_setup(lambda _path: "loaded") is False
    assert ConnectionSettings(server="", zone="z").needs_setup(lambda _path: "") is True
    assert (
        ConnectionSettings(server="s", zone="z", auth="kerberos").needs_setup(
            lambda _path: ""
        )
        is False
    )
    assert (
        ConnectionSettings(server="s", zone="z", user="").needs_setup(lambda _path: "")
        is True
    )
    assert (
        ConnectionSettings(server="s", zone="z", user="u").needs_setup(lambda _path: "")
        is True
    )

    samba = settings.samba_config()
    assert samba.configfile == "/etc/samba/smb.conf"
    assert samba.options == ("x=y", "debug=1")
    ldap = settings.ldap_config()
    assert ldap.base_dn == "DC=example,DC=com"
    assert settings.ldap_config("DC=override").base_dn == "DC=override"
    fields = settings.form_fields()
    assert fields[0][1] == "server"
    assert fields[-1][1] == "password_file"


def test_remediation_and_smart_view_edges() -> None:
    assert actionable_error("  ldap bind failed: nope  ") == (
        "ldap bind failed: nope Action: check credentials, UPN username format, encryption, or Kerberos ticket."
    )
    assert actionable_error("Already Action: done") == "Already Action: done"
    assert bounded_int("bad", 7) == 7
    assert bounded_int("0", 7, minimum=3) == 3
    assert bounded_int("99", 7, maximum=10) == 10

    assert dns_fqdn("@", "example.com.") == "example.com"
    assert dns_fqdn("host.example.net.", "example.com") == "host.example.net"
    assert normalize_dns_value(" Host.EXAMPLE.com.  ") == "host.example.com"
    assert ipv4_from_ptr_name("bad", "example.com") is None

    naive = datetime(2026, 1, 1)
    assert ensure_utc(naive).tzinfo == UTC
    assert normalized_now(naive).tzinfo == UTC
    assert parse_ad_datetime("0") is None
    assert parse_ad_datetime("000") is None
    assert parse_ad_datetime("20260101000000+0000") == datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_ad_datetime("20260101000000.000000+0000") == datetime(
        2026, 1, 1, tzinfo=UTC
    )
    assert parse_ad_datetime("not a date") is None
    assert age_text(None, datetime(2026, 1, 1, tzinfo=UTC)) == "unknown age"
    assert (
        age_text(datetime(2025, 12, 31, tzinfo=UTC), datetime(2026, 1, 1, tzinfo=UTC))
        == "1 day"
    )


def test_smart_dns_and_ldap_branch_edges() -> None:
    rows = {
        "example.com": [
            dns_row("badip", "A", "not-ip"),
            dns_row("host", "A", "192.0.2.10"),
        ],
    }
    findings = dns_a_without_ptr(rows)
    assert [finding.finding for finding in findings] == [
        "No loaded reverse zone for A record"
    ]

    ptr_rows = {
        "example.com": [dns_row("host", "A", "not-ip")],
        "2.0.192.in-addr.arpa": [dns_row("bad", "PTR", "host.example.com.")],
        "example.net": [dns_row("10", "PTR", "host.example.com.")],
    }
    assert dns_ptr_without_a(ptr_rows) == []
    assert dns_duplicate_records({"example.com": [dns_row("folder", "-", "")]}) == []

    now = datetime(2026, 4, 30, tzinfo=UTC)
    recent = filetime_for(now - timedelta(days=1))
    disabled = directory_row(attrs={"userAccountControl": ("not-int",)})
    assert ldap_is_disabled(disabled) is False
    assert directory_object_name(directory_row(name="Fallback", attrs={})) == "Fallback"
    assert first_ad_datetime(
        directory_row(attrs={"lastLogon": (recent,)}), "missing", "lastLogon"
    ) == now - timedelta(days=1)

    cleanup_rows = [
        directory_row(kind="group", attrs={"sAMAccountName": ("group",)}),
        directory_row(
            attrs={
                "sAMAccountName": ("changed",),
                "whenChanged": (filetime_for(now - timedelta(days=200)),),
                "userAccountControl": (str(ACCOUNTDISABLE),),
            }
        ),
        directory_row(
            attrs={
                "sAMAccountName": ("recent",),
                "whenCreated": (filetime_for(now - timedelta(days=1)),),
                "userAccountControl": ("512",),
            }
        ),
    ]
    assert [
        row.object for row in ldap_delete_candidate_users(cleanup_rows, now=now)
    ] == ["changed"]

    stale_rows = [
        directory_row(
            kind="computer",
            name="OLD$",
            attrs={"whenCreated": (filetime_for(now - timedelta(days=120)),)},
        ),
        directory_row(
            kind="computer",
            name="RECENTLOGON$",
            attrs={"lastLogonTimestamp": (filetime_for(now - timedelta(days=1)),)},
        ),
        directory_row(
            kind="computer",
            name="NEW$",
            attrs={"whenCreated": (filetime_for(now - timedelta(days=1)),)},
        ),
        directory_row(
            kind="computer",
            name="DISABLED$",
            attrs={"userAccountControl": (str(ACCOUNTDISABLE),)},
        ),
    ]
    assert [row.object for row in ldap_stale_computers(stale_rows, now=now)] == ["OLD$"]

    assert (
        ldap_users_without_groups(
            [
                directory_row(kind="group", attrs={}),
                directory_row(attrs={"userAccountControl": (str(ACCOUNTDISABLE),)}),
            ]
        )
        == []
    )
