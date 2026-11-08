"""Critical revision assertions reject stale writes and unsupported servers."""

from typing import cast

from ldap3.protocol.rfc4511 import And, Filter
from pyasn1.codec.ber.encoder import encode

ASSERTION_CONTROL_OID = "1.3.6.1.1.12"


def entry_assertion(
    revision: str, expected_flags: int | None = None
) -> tuple[str, bool, bytes]:
    if not revision.isascii() or not revision.isdecimal():
        raise ValueError("Missing or invalid LDAP revision; refresh before writing.")
    conditions = {"uSNChanged": revision}
    if expected_flags is not None:
        conditions["userAccountControl"] = str(expected_flags)
    conjunction = And()
    for index, (attribute, value) in enumerate(conditions.items()):
        condition = Filter()
        condition["equalityMatch"]["attributeDesc"] = attribute
        condition["equalityMatch"]["assertionValue"] = value
        conjunction[index] = condition
    assertion = Filter()
    assertion["and"] = conjunction
    return ASSERTION_CONTROL_OID, True, cast(bytes, encode(assertion))
