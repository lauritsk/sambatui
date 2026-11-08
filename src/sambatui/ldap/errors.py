"""Operational LDAP failures are distinct from invalid user input."""


class LdapOperationError(RuntimeError):
    """Connection, TLS, bind, search, or write failure reported by LDAP."""


class LdapConflictError(LdapOperationError):
    """Server state changed since it was inspected; refresh before retrying."""
