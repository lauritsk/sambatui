from sambatui.core.operations import (
    DnsAddOperation,
    DnsDeleteOperation,
    DnsUpdateOperation,
    LdapAddOperation,
)


def test_dns_operations_validate_and_build_stable_arguments() -> None:
    add = DnsAddOperation("example.com", "www", "A", "192.0.2.10")
    update = DnsUpdateOperation("example.com", "www", "A", "192.0.2.10", "192.0.2.11")
    delete = DnsDeleteOperation("example.com", "www", "A", "192.0.2.11")

    assert add.validation_error() is None
    assert add.command_args == ("www", "A", "192.0.2.10")
    assert update.validation_error() is None
    assert update.command_args == ("www", "A", "192.0.2.10", "192.0.2.11")
    assert delete.command_args == ("www", "A", "192.0.2.11")


def test_ldap_operations_copy_mutable_form_values() -> None:
    attributes = {"description": "before"}
    add = LdapAddOperation.create("user", "DC=example,DC=com", "Alice", attributes)
    attributes["description"] = "mutated"

    assert add.attribute_values == {"description": "before"}
