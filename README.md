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
SAMBATUI_KERBEROS=off \
uv run sambatui
```

Optional variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `SAMBATUI_SERVER` | Samba AD DNS server/DC | empty |
| `SAMBATUI_ZONE` | Initial DNS zone | empty |
| `SAMBATUI_USER` | Samba username, often `DOMAIN\\user` | empty |
| `SAMBATUI_KERBEROS` | Passed to `--use-kerberos` | `off` |
| `SAMBATUI_AUTO_PTR` | Add PTR for new A records (`on`/`off`) | `off` |
| `SAMBATUI_PASSWORD` | Password loaded into password field | empty |
| `SAMBATUI_PASSWORD_FILE` | Password file path | `~/.config/sambatui/password` |

## Use

- `z` or **Load DNS zones**: list zones, including reverse zones.
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

## Passwords

The app cannot safely drive the interactive `samba-tool` password prompt.
Provide a password by:

1. Typing it into the password field.
2. Setting `SAMBATUI_PASSWORD` for the current process.
3. Using a password file:

   ```sh
   mkdir -p ~/.config/sambatui
   printf '%s\n' 'replace-with-your-password' > ~/.config/sambatui/password
   chmod 600 ~/.config/sambatui/password
   ```

You can also use **Save password** / **Load password** in the app. Do not commit
password files or `.env` files.

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
