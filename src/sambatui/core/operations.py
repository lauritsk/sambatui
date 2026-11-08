from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from sambatui.dns.validation import validate_record


@dataclass(frozen=True)
class DnsAddOperation:
    zone: str
    name: str
    rtype: str
    value: str

    @property
    def command_args(self) -> tuple[str, ...]:
        return self.name, self.rtype, self.value

    def validation_error(self) -> str | None:
        return validate_record(self.name, self.rtype, self.value)


@dataclass(frozen=True)
class DnsUpdateOperation:
    zone: str
    name: str
    rtype: str
    old_value: str
    new_value: str

    @property
    def command_args(self) -> tuple[str, ...]:
        return self.name, self.rtype, self.old_value, self.new_value

    def validation_error(self) -> str | None:
        return validate_record(self.name, self.rtype, self.new_value)


@dataclass(frozen=True)
class DnsDeleteOperation:
    zone: str
    name: str
    rtype: str
    value: str

    @property
    def command_args(self) -> tuple[str, ...]:
        return self.name, self.rtype, self.value


@dataclass(frozen=True)
class LdapAddOperation:
    kind: str
    parent_dn: str
    name: str
    attributes: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(
        cls,
        kind: str,
        parent_dn: str,
        name: str,
        attributes: Mapping[str, str],
    ) -> LdapAddOperation:
        return cls(kind, parent_dn, name, tuple(attributes.items()))

    @property
    def attribute_values(self) -> dict[str, str]:
        return dict(self.attributes)
