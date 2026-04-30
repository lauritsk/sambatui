# Sambatui

Textual terminal UI for managing Samba services.

Current functionality focuses on DNS records on Samba Active Directory domain
controllers. It wraps `samba-tool dns` with a table UI for zones, records,
search, sorting, bulk delete, and optional A-record PTR creation.

## Requirements

- Python 3.14+
- `samba-tool` available in `PATH`
- Network and credentials with permission to manage Samba AD DNS

## Install

From this checkout:

```sh
mise run sambatui
# or
uv run sambatui
```

After packaging/publishing:

```sh
uvx sambatui
# or
pipx install sambatui
sambatui
```

## Configure

No organisation-specific defaults are embedded. Enter connection values in the UI
or set environment variables:

```sh
SAMBATUI_SERVER=dc01.example.com \
SAMBATUI_ZONE=example.com \
SAMBATUI_USER='EXAMPLE\\administrator' \
SAMBATUI_AUTH=kerberos \
SAMBATUI_KERBEROS=required \
uv run sambatui
```

Optional variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `SAMBATUI_SERVER` | Samba AD DNS server/DC | empty |
| `SAMBATUI_ZONE` | Initial DNS zone | empty |
| `SAMBATUI_USER` | Samba username, often `DOMAIN\\user` | empty |
| `SAMBATUI_AUTH` | `password` or `kerberos` | `password` |
| `SAMBATUI_KERBEROS` | Passed to `--use-kerberos`; `kerberos` auth upgrades `off` to `required` | `off` |
| `SAMBATUI_KRB5_CCACHE` | Passed to `--use-krb5-ccache` | empty |
| `SAMBATUI_CONFIGFILE` | Passed to `--configfile` for an alternate `smb.conf` | empty |
| `SAMBATUI_OPTIONS` | Samba `--option` values separated by `;` | empty |
| `SAMBATUI_AUTO_PTR` | Add PTR for new A records (`on`/`off`) | `off` |
| `SAMBATUI_PASSWORD` | Password loaded into password field | empty |
| `SAMBATUI_PASSWORD_FILE` | Password file path | `~/.config/sambatui/password` |

## Use

- `z` or **Load DNS zones**: list zones, including reverse zones.
- `c` or **Discover DCs**: discover AD domain controllers via DNS SRV
  records and populate the server field.
- Select a zone: refresh records for that zone.
- `r`: refresh current zone (`dns query SERVER ZONE @ ALL`).
- `q`: query one name/type.
- `a`: add record.
- `u`: update selected record.
- `d`: delete selected records.
- `/`: search by name, type, or value.
- `n` / `t` / `e`: sort by name/type/value.
- `h` / `l`: focus zones/records.
- `j` / `k`, `g` / `G`: move.
- `Space`: toggle selected record.
- `v`, then `j`/`k`: visual range selection.

Destructive actions require confirmation.

## Authentication and passwords

Prefer Kerberos where possible. With an existing ticket (`kinit` or system login),
set `SAMBATUI_AUTH=kerberos`; Sambatui then omits the password from
`samba-tool` arguments and uses `--use-kerberos=required` unless overridden.

Password mode remains available for environments without Kerberos tickets. The
app cannot safely drive the interactive `samba-tool` password prompt. Provide a
password by:

1. Typing it into the password field.
2. Setting `SAMBATUI_PASSWORD` for the current process.
3. Using a password file:

   ```sh
   mkdir -p ~/.config/sambatui
   printf '%s\n' 'replace-with-your-password' > ~/.config/sambatui/password
   chmod 600 ~/.config/sambatui/password
   ```

You can also use **Save password** / **Load password** in the app. Password
files must be readable only by the owner (`chmod 600`) or Sambatui will refuse to
load them. Do not commit password files or `.env` files.

Password mode still passes credentials to `samba-tool` non-interactively. Prefer
Kerberos ticket mode on shared systems where process arguments may be visible to
other users.

## AD discovery

**Discover DCs** uses DNS SRV records already published by Active Directory:

- `_ldap._tcp.dc._msdcs.DOMAIN`
- `_kerberos._tcp.DOMAIN`

This is intentionally DNS-only for now: no LDAP bind, no direct AD writes, and no
extra AD dependency. Future LDAP discovery can be added behind the client seam if
DNS SRV discovery is not enough.

## Development

This project uses `mise` for tools/tasks and `uv` for Python dependencies.

```sh
mise trust
mise run install
mise run fix
mise run lint
mise run test
mise run build
mise run check
```

## Privacy

This repository should contain only generic examples (`example.com`,
`192.0.2.0/24`) and no real hostnames, domains, usernames, passwords, network
ranges, or internal notes.
