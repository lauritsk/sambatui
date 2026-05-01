import ssl

import pytest
from ldap3 import GSSAPI, NONE, SASL
from ldap3.core.exceptions import LDAPSessionTerminatedByServerError

from sambatui.ldap_directory import (
    LdapDirectoryClient,
    LdapSearchConfig,
    build_directory_filter,
    domain_to_base_dn,
    entry_to_directory_row,
    gssapi_cred_store,
    ldap_connection_kwargs,
    ldap_server_get_info,
    ldap_server_tls,
    parse_ldap_server,
)


class FakeEntry:
    entry_dn = "CN=Alice Example,CN=Users,DC=example,DC=com"
    entry_attributes_as_dict = {
        "displayName": ["Alice Example"],
        "sAMAccountName": ["alice"],
        "userPrincipalName": ["alice@example.com"],
        "mail": ["alice@example.com"],
        "memberOf": [
            "CN=Domain Users,CN=Users,DC=example,DC=com",
            "CN=Helpdesk,CN=Users,DC=example,DC=com",
        ],
        "objectClass": ["top", "person", "organizationalPerson", "user"],
    }


def test_domain_to_base_dn_derives_active_directory_base() -> None:
    assert domain_to_base_dn("example.com.") == "DC=example,DC=com"


def test_parse_ldap_server_defaults_to_ldaps_port() -> None:
    settings = parse_ldap_server("dc01.example.com")

    assert settings.host == "dc01.example.com"
    assert settings.port == 636
    assert settings.use_ssl


def test_parse_ldap_server_accepts_explicit_starttls_port() -> None:
    settings = parse_ldap_server("ldap://dc01.example.com:389", "starttls")

    assert settings.host == "dc01.example.com"
    assert settings.port == 389
    assert not settings.use_ssl


def test_build_directory_filter_escapes_user_text() -> None:
    ldap_filter = build_directory_filter("users", "alice*")

    assert "(objectCategory=person)" in ldap_filter
    assert r"alice\2a" in ldap_filter


def test_search_config_accepts_kerberos_without_password() -> None:
    assert (
        LdapSearchConfig(
            server="ldap://dc01.example.com",
            base_dn="DC=example,DC=com",
            encryption="off",
            auth_mode="kerberos",
        ).validation_error()
        is None
    )


def test_search_config_accepts_legacy_compatibility_mode() -> None:
    config = LdapSearchConfig(
        server="dc01.example.com",
        user="EXAMPLE\\admin",
        password="secret",
        base_dn="DC=example,DC=com",
        compatibility="legacy",
    )

    assert config.validation_error() is None
    assert config.legacy_compatibility_enabled
    assert ldap_server_get_info(config) == NONE
    tls = ldap_server_tls(config)
    assert tls is not None
    assert tls.validate == ssl.CERT_NONE


def test_search_config_rejects_insecure_or_passwordless_bind() -> None:
    assert (
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
            encryption="plain",
        ).validation_error()
        == "LDAP encryption must be off, ldaps, or starttls."
    )
    assert (
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            base_dn="DC=example,DC=com",
        ).validation_error()
        == "LDAP search needs a password or auth mode kerberos."
    )
    assert (
        LdapSearchConfig(
            server="ldap://dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
            encryption="ldaps",
        ).validation_error()
        == "ldap:// server URLs require LDAP encryption starttls or off."
    )
    assert (
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
            compatibility="maybe",
        ).validation_error()
        == "LDAP compatibility must be on or off."
    )


def test_ldap_connection_kwargs_uses_sasl_gssapi_for_kerberos() -> None:
    kwargs = ldap_connection_kwargs(
        LdapSearchConfig(
            server="dc01.example.com",
            base_dn="DC=example,DC=com",
            auth_mode="kerberos",
            krb5_ccache="/tmp/krb5cc_test",
        )
    )

    assert kwargs["authentication"] == SASL
    assert kwargs["sasl_mechanism"] == GSSAPI
    assert "password" not in kwargs
    assert kwargs["cred_store"] == {"ccache": "FILE:/tmp/krb5cc_test"}


def test_search_passes_legacy_tls_to_ldap_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeConnection:
        result = {"description": "invalidCredentials", "message": "nope"}

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def bind(self) -> bool:
            return False

        def unbind(self) -> bool:
            return True

    def fake_server(*_args: object, **kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("ldap3.Connection", FakeConnection)
    monkeypatch.setattr("ldap3.Server", fake_server)

    client = LdapDirectoryClient(
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
            compatibility="on",
        )
    )

    with pytest.raises(ValueError, match="LDAP bind failed"):
        client.search("users")

    assert captured["get_info"] == NONE
    assert captured["tls"] is not None


def test_check_connection_binds_without_search(monkeypatch: pytest.MonkeyPatch) -> None:
    searched = False

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def bind(self) -> bool:
            return True

        def search(self, *_args: object, **_kwargs: object) -> bool:
            nonlocal searched
            searched = True
            return True

        def unbind(self) -> bool:
            return True

    monkeypatch.setattr("ldap3.Connection", FakeConnection)
    monkeypatch.setattr("ldap3.Server", lambda *_args, **_kwargs: object())

    client = LdapDirectoryClient(
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
        )
    )

    client.check_connection()

    assert not searched


def test_search_wraps_ldap_session_termination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeConnection:
        result = None

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def bind(self) -> bool:
            raise LDAPSessionTerminatedByServerError("session terminated by server")

        def unbind(self) -> bool:
            return True

    monkeypatch.setattr("ldap3.Connection", FakeConnection)
    monkeypatch.setattr("ldap3.Server", lambda *_args, **_kwargs: object())

    client = LdapDirectoryClient(
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
        )
    )

    with pytest.raises(
        ValueError,
        match="LDAP bind failed: session terminated by server",
    ):
        client.search("users")


def test_gssapi_cred_store_keeps_explicit_cache_type() -> None:
    assert gssapi_cred_store("DIR:/tmp/krb5cc_dir") == {"ccache": "DIR:/tmp/krb5cc_dir"}


def test_entry_to_directory_row_summarizes_common_ad_attributes() -> None:
    row = entry_to_directory_row(FakeEntry(), "users")

    assert row.name == "Alice Example"
    assert row.kind == "user"
    assert row.dn == "CN=Alice Example,CN=Users,DC=example,DC=com"
    assert "alice" in row.summary
    assert "memberOf=2" in row.summary
