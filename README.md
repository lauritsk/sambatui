# sambatui

Textual terminal UI for managing Samba services.

Current functionality focuses on DNS records on Samba Active Directory domain
controllers. It wraps `samba-tool dns` with a table UI for zones, records,
search, sorting, bulk delete, and prompted A-record PTR creation. It also offers
read-only LDAP directory search for AD users, groups, computers, and OUs.

## Requirements

`sambatui` is a Python TUI that shells out to Samba's supported CLI. A regular
host install needs:

- Python 3.14+
- `samba-tool` available in `PATH`
- network access to the AD DNS/DC endpoint
- credentials allowed to manage Samba AD DNS
- Kerberos client config/tickets when using Kerberos auth
- LDAPS or StartTLS access when using LDAP directory search

Useful system packages by distro:

| Distro | Packages |
| --- | --- |
| Debian/Ubuntu | `sudo apt install samba-common-bin krb5-user bind9-dnsutils` |
| Fedora/RHEL/CentOS | `sudo dnf install samba-common-tools krb5-workstation bind-utils` |
| Arch Linux | `sudo pacman -S samba krb5 bind` |
| openSUSE | `sudo zypper install samba krb5-client bind-utils` |
| Alpine | `sudo apk add samba-dc krb5 bind-tools` |

Package names vary by release. After installing, verify:

```sh
command -v samba-tool
samba-tool --version
```

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

# Include optional Kerberos/GSSAPI support for LDAP search:
pipx install 'sambatui[kerberos]'
```

## Docker

The Docker image is the batteries-included option. It includes `sambatui`,
`samba-tool`, Kerberos client tools, DNS lookup tools, LDAP CLI tools, and
`smbclient`. You still provide network access, credentials, and any local AD
configuration.

Password mode example:

```sh
docker run --rm -it \
  -e SAMBATUI_SERVER=dc01.example.com \
  -e SAMBATUI_ZONE=example.com \
  -e SAMBATUI_USER='EXAMPLE\administrator' \
  -e SAMBATUI_PASSWORD='replace-with-your-password' \
  sambatui
```

Kerberos mode example using host config and ticket cache:

```sh
kinit administrator@EXAMPLE.COM
KRB5CCACHE_PATH=${KRB5CCNAME#FILE:}

docker run --rm -it \
  -e SAMBATUI_SERVER=dc01.example.com \
  -e SAMBATUI_ZONE=example.com \
  -e SAMBATUI_AUTH=kerberos \
  -e SAMBATUI_KERBEROS=required \
  -e KRB5CCNAME=/tmp/krb5cc \
  -v /etc/krb5.conf:/etc/krb5.conf:ro \
  -v "$KRB5CCACHE_PATH:/tmp/krb5cc:ro" \
  sambatui
```

If your environment needs a custom Samba config, mount it and point sambatui at
it:

```sh
docker run --rm -it \
  -e SAMBATUI_CONFIGFILE=/workspace/smb.conf \
  -v "$PWD/smb.conf:/workspace/smb.conf:ro" \
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
| `SAMBATUI_KRB5_CCACHE` | Passed to `--use-krb5-ccache`; also used as LDAP GSSAPI credential cache when Kerberos LDAP auth is active | empty |
| `SAMBATUI_CONFIGFILE` | Passed to `--configfile` for an alternate `smb.conf` | empty |
| `SAMBATUI_OPTIONS` | Samba `--option` values separated by `;` | empty |
| `SAMBATUI_LDAP_BASE` | Base DN for read-only LDAP search | derived from zone when possible |
| `SAMBATUI_LDAP_ENCRYPTION` | LDAP transport: `ldaps`, `starttls`, or `off` for Kerberos-only LDAP | `ldaps` |
| `SAMBATUI_LDAP_COMPATIBILITY` | Opt-in legacy LDAP mode (`on`/`off`) for old Samba/EL6-era servers | `off` |
| `SAMBATUI_PASSWORD` | Password loaded into password field | empty |
| `SAMBATUI_PASSWORD_FILE` | Password file path | `~/.config/sambatui/password` |

## Use

- `z` or **Load DNS zones**: list zones, including reverse zones.
- `c` or **Discover DCs**: discover AD domain controllers via DNS SRV
  records and populate the server field.
- `L`: search AD directory over read-only LDAP (`users`, `groups`, `computers`,
  `ous`, or `all`).
- Move through DNS, LDAP, or smart-view rows to update the details pane with
  wrapped context for the focused row.
- Select a zone: refresh records for that zone.
- `r`: refresh current zone (`dns query SERVER ZONE @ ALL`).
- `q`: query one name/type.
- `a`: add record.
- `u`: update selected record.
- `d`: delete selected records.
- `/`: search by name, type, or value.
- `n` / `t` / `e`: sort by name/type/value.
- `h` / `l` or `Tab` / `Shift+Tab`: focus zones/records.
- `j` / `k`, `gg` / `G`, `PageUp` / `PageDown`, `Ctrl+u` / `Ctrl+d`:
  move.
- `Enter`: activate the focused row (load a zone, or toggle a record selection).
- `Space`: toggle selected record.
- `v`, then `j`/`k`: visual range selection; `Esc` leaves visual mode, then
  clears selection/search.

Confirmations support `y` (yes), `n` or `Esc` (no). `Enter` uses the safe
default: yes for low-risk add confirmations, no for destructive changes,
deletes, and secret writes.

## Authentication and passwords

Prefer Kerberos where possible. With an existing ticket (`kinit` or system login),
set `SAMBATUI_AUTH=kerberos`; sambatui then omits the password from
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
files must be readable only by the owner (`chmod 600`) or sambatui will refuse to
load them. Do not commit password files or `.env` files.

Password mode still passes credentials to `samba-tool` non-interactively. Prefer
Kerberos ticket mode on shared systems where process arguments may be visible to
other users.

## AD discovery

**Discover DCs** uses DNS SRV records already published by Active Directory:

- `_ldap._tcp.dc._msdcs.DOMAIN`
- `_kerberos._tcp.DOMAIN`

Discovery remains DNS-only: no LDAP bind and no direct AD writes.

## LDAP directory search

`L` opens read-only AD directory search powered by Python `ldap3`. It searches a
base DN such as `DC=example,DC=com`. If `SAMBATUI_LDAP_BASE` is empty, the UI
proposes a base DN from the current DNS zone.

With `SAMBATUI_AUTH=password`, LDAP uses the configured username/password and
requires `ldaps` or `starttls`. Cleartext simple bind is intentionally
unsupported.

With `SAMBATUI_AUTH=kerberos`, LDAP uses SASL GSSAPI and the current Kerberos
ticket cache. Install the optional extra first:

```sh
pipx install 'sambatui[kerberos]'
kinit administrator@EXAMPLE.COM
SAMBATUI_AUTH=kerberos sambatui
```

Set `SAMBATUI_KRB5_CCACHE` to point GSSAPI at a non-default cache. For Kerberos
LDAP on port 389, set `SAMBATUI_LDAP_ENCRYPTION=off` or `starttls`.

For old Samba/EL6-era LDAP servers that only negotiate legacy TLS or fail schema
probing, set `SAMBATUI_LDAP_COMPATIBILITY=on` or use the LDAP compatibility field
in the UI. This mode is off by default because it relaxes TLS protocol/cipher
policy for LDAP/StartTLS and skips LDAP schema probing.

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
