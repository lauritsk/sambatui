from sambatui.ldap_directory import (
    LdapSearchConfig,
    build_directory_filter,
    domain_to_base_dn,
    entry_to_directory_row,
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


def test_search_config_rejects_insecure_or_passwordless_bind() -> None:
    assert (
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
            encryption="plain",
        ).validation_error()
        == "LDAP encryption must be ldaps or starttls."
    )
    assert (
        LdapSearchConfig(
            server="dc01.example.com",
            user="EXAMPLE\\admin",
            base_dn="DC=example,DC=com",
        ).validation_error()
        == "LDAP search needs a password. Kerberos LDAP bind is not implemented yet."
    )
    assert (
        LdapSearchConfig(
            server="ldap://dc01.example.com",
            user="EXAMPLE\\admin",
            password="secret",
            base_dn="DC=example,DC=com",
            encryption="ldaps",
        ).validation_error()
        == "ldap:// server URLs require LDAP encryption starttls."
    )


def test_entry_to_directory_row_summarizes_common_ad_attributes() -> None:
    row = entry_to_directory_row(FakeEntry(), "users")

    assert row.name == "Alice Example"
    assert row.kind == "user"
    assert row.dn == "CN=Alice Example,CN=Users,DC=example,DC=com"
    assert "alice" in row.summary
    assert "memberOf=2" in row.summary
