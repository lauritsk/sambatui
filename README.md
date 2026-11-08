# sambatui

Terminal UI for Samba Active Directory DNS and LDAP administration.
Requires Docker, [just](https://just.systems), and network access to your domain
controllers.

## Run

```sh
docker login dhi.io
just build
just run
```

Enter connection details in the setup wizard. Preferences, saved passwords, and
Kerberos tickets persist in the `sambatui-config` volume at `/config`.

**This tool can modify DNS records and directory entries. Review confirmations.**

## Configuration

Use the setup wizard, or edit a copy of `.env.example`:

```sh
cp .env.example .env
just run --env-file .env
```

Pass additional Docker options directly, such as `just run --dns 192.0.2.10`.
Host environment variables are not automatically forwarded. File paths refer to
locations inside the container.

Preferences are stored in `/config/config.toml`; the default password file is
`/config/password`. Read-only password files can be mounted under `/run/secrets`
and selected with `--env SAMBATUI_PASSWORD_FILE=/run/secrets/ad-password`.
Kerberos uses `FILE:/config/krb5cc` by default. Never commit credentials or `.env`.

LDAP requires certificate-verified LDAPS or StartTLS, including for Kerberos.
Plaintext LDAP and the `off` encryption setting are removed. For a private CA, mount its certificate
and pass `--env SSL_CERT_FILE=/config/dc-ca.pem`. The old `ldap_compatibility` /
`SAMBATUI_LDAP_COMPATIBILITY` bypass has been removed; it cannot disable verification.
LDAP Kerberos uses the selected cache's identity, not the password-auth username;
a missing explicit cache fails rather than falling back to the process default.
The pinned `cryptography` dependency supplies TLS channel binding.

## Write safety

Only one write flow can run at a time, including keyboard actions and guided
fixes. Each flow uses an immutable connection snapshot, so changing connection
settings cannot redirect an in-flight write. Target/credential changes immediately
invalidate loaded rows and selections, even if the subsequent refresh fails.
Late results from the old connection are discarded.

Cancelling a write does not undo server changes. LDAP worker threads are allowed
to finish before another write is accepted; inspect refreshed server state before
retrying. Writes are never automatically retried.

LDAP edits and deletes require the selected entry's `uSNChanged` revision in a
critical RFC 4528 assertion control. Account-disable fixes also assert the original
`userAccountControl`, preserving unrelated flags without a read/write race. Use an
individual DC endpoint: AD revisions are local to that DC.

**Compatibility limitation:** the tested Samba 4.22 server does not support RFC
4528. LDAP edits, deletes, and account-disable fixes therefore fail closed on that
server. Reads and adds remain available, as do DNS operations. There is no
unconditional-write fallback. Successful conditional-write responses and conflict
handling are covered by protocol tests, not claimed as live Samba capabilities.

Samba command output is limited to 16 MiB; overflow is an error, not a successful
partial result. Timeout/cancellation kills the command's process group and waits
for cleanup. DNS operands follow `--`, so a record value cannot become a CLI
option. Adds use Samba's default TTL: the nonworking custom-TTL field is removed
because `samba-tool dns add` has no `--ttl` option. Server-provided table values,
errors, and confirmation/form text are rendered literally, not as Rich markup.

Passwords retain leading/trailing whitespace and are omitted from configuration
object representations. Password files use the first line, excluding its line
ending.

## Development

- `just build`: type-check all application source, run tests with 100% configured line coverage, build, and smoke-test the image.
- `just test -q -k dns`: run selected tests.
- `just lint`: check Python style with the pinned development version of Ruff.

Docker tests provision a disposable, loopback-only Samba AD and exercise verified
LDAPS/StartTLS, password and Kerberos authentication, paging, adds, permission
failures, lost-response handling, refused unsupported conditional writes, and a
DNS add/query/update/delete lifecycle. No supplied AD credentials are used.
The build test step has no external network access. Filesystem ACL provisioning
is skipped; this is not SMB/GPO ACL validation. Samba server packages exist only
in development/test stages, never in the production image.

### Architecture boundaries

Textual controllers own UI state, confirmations, and notifications. Connection
settings live in the immutable `core/settings.py` model, not hidden widgets;
`core/mutations.py` owns the task-scoped write reservation and cancellation drain.
Samba command construction/authentication lives in `src/sambatui/samba/client.py`; subprocess
execution and cleanup live in `src/sambatui/samba/execution.py`, which returns a
typed result without importing the UI.

LDAP library objects stay behind the protocols in `ldap/types.py` and
`ldap/connection.py`. Add attributes and modify operations have separate types;
searches return typed entries that `ldap/entries.py` normalizes into directory
rows. `ldap_session` owns TLS, binding, and cleanup for every operation.
`LdapDirectoryClient` accepts a connection factory for testing without a server.

The `ty` gate covers every application module and selected boundary tests. UI
mixins declare their actual `SambatuiApp` host type using type-only imports,
without a catch-all attribute fallback, duplicated host protocols, or runtime
controller base. Backend protocols remain independent of Textual. Import helpers
from their defining modules; the old app/client re-export facades are removed.

Rebuild after source changes. Use `just build --no-cache` to bypass cached tests.
