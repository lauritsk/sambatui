import ssl
from urllib.parse import urlsplit

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from ldap3 import GSSAPI, LEVEL, MODIFY_DELETE, MODIFY_REPLACE, NONE, SASL
from ldap3.core.exceptions import LDAPSessionTerminatedByServerError

from sambatui.ldap.client import (
    LdapDirectoryClient,
    LdapSearchConfig,
    build_add_entry,
    build_directory_filter,
    domain_to_base_dn,
    entry_to_directory_row,
    gssapi_cred_store,
    ldap_connection_kwargs,
    ldap_dn_in_scope,
    ldap_server_get_info,
    ldap_server_tls,
    parse_ldap_server,
)


DNS_LABEL = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"))
    | st.sampled_from("_-"),
    min_size=1,
    max_size=20,
).filter(lambda value: value[0].isalnum() and value[-1].isalnum() and value.isascii())
DNS_NAME = st.lists(DNS_LABEL, min_size=1, max_size=5).map(".".join)
LDAP_KINDS = st.sampled_from(["ou", "user", "group", "computer"])
EDITABLE_ATTRS = st.sampled_from(
    ["description", "displayName", "mail", "telephoneNumber", "sAMAccountName"]
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


def test_search_config_accepts_ldap_compatibility_on() -> None:
    config = LdapSearchConfig(
        server="dc01.example.com",
        user="EXAMPLE\\admin",
        password="secret",
        base_dn="DC=example,DC=com",
        compatibility="on",
    )

    assert config.validation_error() is None
    assert config.compatibility_enabled
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


def test_client_search_raises_validation_error_before_connecting() -> None:
    client = LdapDirectoryClient(LdapSearchConfig(server="dc01.example.com"))

    with pytest.raises(ValueError, match="LDAP search needs a username"):
        client.search("users")


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


def test_search_passes_compatibility_tls_to_ldap_server(
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


def test_child_containers_searches_one_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class ContainerEntry:
        entry_dn = "CN=Users,DC=example,DC=com"
        entry_attributes_as_dict = {
            "cn": ["Users"],
            "objectClass": ["top", "container"],
        }

    class FakeConnection:
        entries = [ContainerEntry()]
        result = {}

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def bind(self) -> bool:
            return True

        def search(self, *args: object, **kwargs: object) -> bool:
            captured["args"] = args
            captured.update(kwargs)
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

    rows = client.child_containers()

    assert rows[0].dn == "CN=Users,DC=example,DC=com"
    assert rows[0].kind == "container"
    assert captured["args"] == (
        "DC=example,DC=com",
        "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))",
    )
    assert captured["search_scope"] == LEVEL


def test_modify_attributes_replaces_and_deletes_allowed_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections = []

    class FakeConnection:
        result = {}

        def __init__(self, *_args: object, **kwargs: object) -> None:
            self.kwargs = kwargs
            self.modified: tuple[str, object] | None = None
            connections.append(self)

        def bind(self) -> bool:
            return True

        def modify(self, dn: str, changes: object) -> bool:
            self.modified = (dn, changes)
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

    client.modify_attributes(
        "CN=Alice,DC=example,DC=com", {"displayName": "Alice A", "mail": ""}
    )

    assert connections[0].kwargs["read_only"] is False
    assert connections[0].modified == (
        "CN=Alice,DC=example,DC=com",
        {
            "displayName": [(MODIFY_REPLACE, ["Alice A"])],
            "mail": [(MODIFY_DELETE, [])],
        },
    )


def test_add_entry_builds_ad_user_defaults_and_escapes_rdn() -> None:
    dn, object_class, attributes = build_add_entry(
        "user",
        "CN=Users,DC=example,DC=com",
        "Doe, Jane",
        {"userPrincipalName": "jane@example.com", "description": ""},
    )

    assert dn == r"CN=Doe\, Jane,CN=Users,DC=example,DC=com"
    assert object_class == ("top", "person", "organizationalPerson", "user")
    assert attributes == {
        "userPrincipalName": "jane@example.com",
        "cn": "Doe, Jane",
        "sAMAccountName": "Doe, Jane",
    }


def test_add_entry_calls_ldap_add_writable_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections = []

    class FakeConnection:
        result = {}

        def __init__(self, *_args: object, **kwargs: object) -> None:
            self.kwargs = kwargs
            self.added: tuple[str, object, object] | None = None
            connections.append(self)

        def bind(self) -> bool:
            return True

        def add(self, dn: str, object_class: object, attributes: object) -> bool:
            self.added = (dn, object_class, attributes)
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

    dn = client.add_entry("ou", "DC=example,DC=com", "Servers", {})

    assert dn == "OU=Servers,DC=example,DC=com"
    assert connections[0].kwargs["read_only"] is False
    assert connections[0].added == (
        "OU=Servers,DC=example,DC=com",
        ("top", "organizationalUnit"),
        {"ou": "Servers"},
    )


def test_ldap_dn_in_scope_accepts_base_and_child_with_comma_whitespace() -> None:
    assert ldap_dn_in_scope("DC=example, DC=com", " DC=example,DC=com ")
    assert ldap_dn_in_scope("OU=Users, DC=example, DC=com", "DC=example,DC=com")
    assert not ldap_dn_in_scope("DC=evil,DC=com", "DC=example,DC=com")


@pytest.mark.parametrize(
    "dn", ["DC=example,DC=com", " DC=example,DC=com ", "DC=example, DC=com"]
)
def test_delete_entry_rejects_base_dn(dn: str) -> None:
    client = LdapDirectoryClient(
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
        )
    )

    with pytest.raises(ValueError, match="Refusing to delete LDAP base DN"):
        client.delete_entry(dn)


def test_delete_entry_calls_ldap_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    connections = []

    class FakeConnection:
        result = {}

        def __init__(self, *_args: object, **kwargs: object) -> None:
            self.kwargs = kwargs
            self.deleted = ""
            connections.append(self)

        def bind(self) -> bool:
            return True

        def delete(self, dn: str) -> bool:
            self.deleted = dn
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

    client.delete_entry("CN=Alice,DC=example,DC=com")

    assert connections[0].kwargs["read_only"] is False
    assert connections[0].deleted == "CN=Alice,DC=example,DC=com"


def test_modify_attributes_rejects_unlisted_attributes() -> None:
    client = LdapDirectoryClient(
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
        )
    )

    with pytest.raises(ValueError, match="LDAP attribute is not editable: memberOf"):
        client.modify_attributes("CN=Alice,DC=example,DC=com", {"memberOf": "x"})


def test_search_follows_paged_results_until_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PagedEntry:
        def __init__(self, index: int) -> None:
            self.entry_dn = f"CN=User {index},CN=Users,DC=example,DC=com"
            self.entry_attributes_as_dict = {
                "displayName": [f"User {index}"],
                "objectClass": ["top", "person", "user"],
            }

    connections = []

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.entries = []
            self.result = {}
            self.cookies = []
            connections.append(self)

        def bind(self) -> bool:
            return True

        def search(self, *_args: object, **kwargs: object) -> bool:
            cookie = kwargs.get("paged_cookie")
            self.cookies.append(cookie)
            if cookie is None:
                self.entries = [PagedEntry(1), PagedEntry(2)]
                next_cookie = b"next"
            else:
                self.entries = [PagedEntry(3), PagedEntry(4)]
                next_cookie = b""
            self.result = {
                "controls": {
                    "1.2.840.113556.1.4.319": {"value": {"cookie": next_cookie}}
                }
            }
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

    rows = client.search("users", max_entries=3)

    assert [row.name for row in rows] == ["User 1", "User 2", "User 3"]
    assert connections[0].cookies == [None, b"next"]


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


@given(st.text(), st.sampled_from(["off", "ldaps", "starttls", "", "BAD"]))
@settings(deadline=None)
def test_parse_ldap_server_never_raises_unexpected_exception(
    server: str, encryption: str
) -> None:
    try:
        settings = parse_ldap_server(server, encryption)
    except ValueError:
        return

    assert settings.host
    assert isinstance(settings.port, int)
    assert 0 < settings.port <= 65535


@given(
    st.sampled_from(["ldap", "ldaps"]),
    DNS_NAME,
    st.integers(min_value=1, max_value=65535),
)
def test_parse_ldap_server_preserves_valid_url_parts(
    scheme: str, host: str, port: int
) -> None:
    settings = parse_ldap_server(f" {scheme}://{host}:{port} ", "off")

    assert settings.host == host.casefold()
    assert settings.port == port
    assert settings.use_ssl is (scheme == "ldaps")


@given(
    LDAP_KINDS,
    DNS_NAME,
    DNS_NAME,
    st.dictionaries(EDITABLE_ATTRS, st.text(max_size=30), max_size=5),
)
def test_build_add_entry_sets_required_attributes(
    kind: str, parent_label: str, name: str, attributes: dict[str, str]
) -> None:
    parent_dn = f"OU={parent_label},DC=example,DC=com"
    dn, object_class, ldap_attributes = build_add_entry(
        kind, parent_dn, name, attributes
    )

    assert dn.endswith(parent_dn)
    assert object_class
    assert all(value != "" for value in ldap_attributes.values())
    if kind == "ou":
        assert ldap_attributes["ou"] == name
    else:
        assert ldap_attributes["cn"] == name
    if kind == "computer":
        assert str(ldap_attributes["sAMAccountName"]).endswith("$")


@given(st.text())
def test_parse_ldap_server_reports_bad_port_as_value_error(server: str) -> None:
    try:
        parsed_port = urlsplit(
            server.strip() if "://" in server else f"//{server.strip()}"
        ).port
    except ValueError:
        parsed_port = None

    try:
        parse_ldap_server(server)
    except ValueError:
        return

    assert parsed_port is None or 0 < parsed_port <= 65535
