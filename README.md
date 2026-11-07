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

## Development

- `just build`: type-check, run tests with 100% coverage, build, and smoke-test the image.
- `just test -q -k dns`: run selected tests.
- `just lint`: check Python style.

### Architecture boundaries

Textual controllers own UI state, confirmations, and notifications. Samba command
construction/authentication lives in `src/sambatui/samba/client.py`; subprocess
execution and cleanup live in `src/sambatui/samba/execution.py`, which returns a
typed result without importing the UI.

LDAP library objects stay behind the protocols in `ldap/types.py` and
`ldap/connection.py`. Add attributes and modify operations have separate types;
searches return typed entries that `ldap/entries.py` normalizes into directory
rows. `ldap_session` owns TLS, binding, and cleanup for every operation.
`LdapDirectoryClient` accepts a connection factory for testing without a server.

The `ty` gate currently covers the LDAP package, Samba client/runner, and their
typed boundary tests. The remaining Textual mixins are not yet part of this gate;
expand it as their implicit app dependencies are replaced with explicit contracts.

Rebuild after source changes. Use `just build --no-cache` to bypass cached tests.
