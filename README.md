# sambatui

[![Check](https://github.com/lauritsk/sambatui/actions/workflows/check.yml/badge.svg)](https://github.com/lauritsk/sambatui/actions/workflows/check.yml)
[![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://www.python.org/)

A Textual terminal UI for Samba Active Directory DNS administration and read-only
LDAP directory browsing.

`sambatui` wraps Samba's supported `samba-tool` CLI in a keyboard-friendly TUI,
adds safe confirmations for write operations, and provides smart views for common
DNS and AD hygiene checks.

## Features

- Discover domain controllers from AD DNS SRV records.
- List DNS zones and browse records, including reverse zones.
- Add, update, query, sort, search, and bulk-delete DNS records.
- Create matching PTR records for A records when a reverse zone is available.
- Run DNS hygiene checks for duplicate records, missing PTRs, and orphan PTRs.
- Search AD users, groups, computers, and OUs over read-only LDAP.
- Run LDAP smart views for inactive users, stale computers, cleanup candidates,
  and users without secondary groups.
- Use password or Kerberos authentication, with preference persistence for
  non-secret settings.

> [!IMPORTANT]
> `sambatui` can change Samba AD DNS records. Review command previews and
> confirmations before applying destructive actions. LDAP features are read-only.

## Requirements

A normal host install needs:

- Python 3.14+
- `samba-tool` in `PATH`
- network access to a Samba AD DNS/domain controller endpoint
- credentials allowed to manage Samba AD DNS
- Kerberos client configuration and tickets when using Kerberos auth
- LDAPS or StartTLS access when using LDAP directory search

Useful system packages:

| Distro | Packages |
| --- | --- |
| Debian/Ubuntu | `sudo apt install samba-common-bin krb5-user bind9-dnsutils` |
| Fedora/RHEL/CentOS | `sudo dnf install samba-common-tools krb5-workstation bind-utils` |
| Arch Linux | `sudo pacman -S samba krb5 bind` |
| openSUSE | `sudo zypper install samba krb5-client bind-utils` |
| Alpine | `sudo apk add samba-dc krb5 bind-tools` |

Verify Samba tooling after installation:

```sh
command -v samba-tool
samba-tool --version
```

## Quick start

Run from a checkout:

```sh
uv run sambatui
```

Or run the published package:

```sh
uvx sambatui
```

For persistent installation:

```sh
pipx install sambatui
sambatui
```

Install optional Kerberos/GSSAPI support for LDAP search when needed:

```sh
pipx install 'sambatui[kerberos]'
```

## Docker

The Docker image includes `sambatui`, `samba-tool`, Kerberos tools, DNS lookup
tools, LDAP CLI tools, and `smbclient`. You still provide network access,
credentials, and any site-specific AD configuration.

Password mode:

```sh
docker run --rm -it \
  -e SAMBATUI_SERVER=dc01.example.com \
  -e SAMBATUI_ZONE=example.com \
  -e SAMBATUI_USER='EXAMPLE\administrator' \
  -e SAMBATUI_PASSWORD='replace-with-your-password' \
  sambatui
```

Kerberos mode using host config and ticket cache:

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

Custom Samba config:

```sh
docker run --rm -it \
  -e SAMBATUI_CONFIGFILE=/workspace/smb.conf \
  -v "$PWD/smb.conf:/workspace/smb.conf:ro" \
  sambatui
```

## Configuration

Enter connection values in the setup wizard or provide environment variables:

```sh
SAMBATUI_SERVER=dc01.example.com \
SAMBATUI_ZONE=example.com \
SAMBATUI_USER='EXAMPLE\administrator' \
SAMBATUI_AUTH=kerberos \
SAMBATUI_KERBEROS=required \
sambatui
```

| Variable | Purpose | Default |
| --- | --- | --- |
| `SAMBATUI_SERVER` | Samba AD DNS server/DC | empty |
| `SAMBATUI_ZONE` | Initial DNS zone | empty |
| `SAMBATUI_USER` | Samba/LDAP username. UPN form (`user@example.com`) is preferred for LDAP password binds. | empty |
| `SAMBATUI_AUTH` | `password` or `kerberos`; unset auto-detects a valid `klist -s` ticket | ticket => `kerberos`, else `password` |
| `SAMBATUI_KERBEROS` | Value passed to `samba-tool --use-kerberos` | `off` |
| `SAMBATUI_KRB5_CCACHE` | Kerberos credential cache for Samba/LDAP GSSAPI | empty |
| `SAMBATUI_CONFIGFILE` | Alternate `smb.conf` passed to `samba-tool --configfile` | empty |
| `SAMBATUI_OPTIONS` | Samba `--option` values separated by `;` | empty |
| `SAMBATUI_LDAP_BASE` | Base DN for LDAP search | derived from zone when possible |
| `SAMBATUI_LDAP_ENCRYPTION` | LDAP transport: `ldaps`, `starttls`, or `off` for Kerberos-only LDAP | `ldaps` |
| `SAMBATUI_LDAP_COMPATIBILITY` | Relaxed LDAP TLS/schema probing mode for legacy servers (`on`/`off`) | `off` |
| `SAMBATUI_AUTO_PTR` | PTR behavior after adding A records: `ask`, `on`, or `off` | `ask` |
| `SAMBATUI_SMART_DAYS` | Default stale/inactive smart-view threshold | `90` |
| `SAMBATUI_SMART_DISABLED_DAYS` | Disabled-user cleanup threshold | `180` |
| `SAMBATUI_SMART_NEVER_LOGGED_DAYS` | Never-logged-in user threshold | `30` |
| `SAMBATUI_SMART_MAX_ROWS` | Smart-view row limit | `500` |
| `SAMBATUI_PASSWORD` | Password loaded into the password field | empty |
| `SAMBATUI_PASSWORD_FILE` | Password file path | `~/.config/sambatui/password` |
| `SAMBATUI_USER_CONFIG` | Preference file path | `~/.config/sambatui/config.toml` |

`sambatui` stores non-secret preferences in `~/.config/sambatui/config.toml`.
Passwords, password-file contents, and usernames are not written there.
Precedence is environment variables, then saved preferences, then built-in
defaults.

## Using the TUI

Start with the setup wizard, then load zones or search LDAP from the command
palette.

| Key | Action |
| --- | --- |
| `Ctrl+P` | Open command palette |
| `w` | Run setup wizard |
| `z` | Load DNS zones |
| `c` | Discover domain controllers |
| `L` | Search AD directory over LDAP |
| `S` | Open smart-view picker |
| `8` from smart views | Run full health dashboard |
| `r` | Refresh current zone or rerun current smart view |
| `f` | Apply a guided smart-view fix when available |
| `q` | Query one DNS name/type |
| `a` | Add DNS record with guided picker and command preview |
| `u` | Update selected DNS record |
| `d` | Delete selected DNS records |
| `/` | Focus inline search; `Esc` clears it |
| `n` / `t` / `e` | Sort by name, type, or value |
| `h` / `l`, `Tab` / `Shift+Tab` | Move focus between zones and records |
| `j` / `k`, `gg` / `G`, `PageUp` / `PageDown` | Move through tables |
| `Space` | Toggle selected record |
| `v`, then `j`/`k` | Visual range selection |

Confirmations support `y` for yes and `n` or `Esc` for no. `Enter` uses the safe
default: yes for low-risk add confirmations, no for destructive changes,
deletes, and secret writes.

## Authentication

Prefer Kerberos where possible. With an existing ticket (`kinit` or system
login), `sambatui` auto-detects `klist -s` and defaults to Kerberos unless auth
is set explicitly. Kerberos mode omits the password from `samba-tool` arguments
and uses `--use-kerberos=required` unless overridden.

Password mode remains available for environments without Kerberos tickets. The
app cannot safely drive the interactive `samba-tool` password prompt, so provide
a password through the UI, `SAMBATUI_PASSWORD`, or a protected password file:

```sh
mkdir -p ~/.config/sambatui
printf '%s\n' 'replace-with-your-password' > ~/.config/sambatui/password
chmod 600 ~/.config/sambatui/password
```

> [!CAUTION]
> Password mode passes credentials to `samba-tool` non-interactively. Prefer
> Kerberos on shared systems where process arguments may be visible to other
> users. Never commit password files or `.env` files.

## LDAP directory search

LDAP search is read-only and uses Python `ldap3` against a base DN such as
`DC=example,DC=com`. If `SAMBATUI_LDAP_BASE` is empty, the UI proposes a base DN
from the current DNS zone.

- `SAMBATUI_AUTH=password` uses the configured username/password and requires
  `ldaps` or `starttls`; cleartext simple bind is intentionally unsupported.
- `SAMBATUI_AUTH=kerberos` uses SASL GSSAPI and the current Kerberos ticket
  cache. Install `sambatui[kerberos]` first.
- Set `SAMBATUI_LDAP_COMPATIBILITY=on` only for legacy servers that need relaxed
  TLS settings or fail schema probing.

## AD discovery

Domain controller discovery uses DNS SRV records already published by Active
Directory:

- `_ldap._tcp.dc._msdcs.DOMAIN`
- `_kerberos._tcp.DOMAIN`

Discovery is DNS-only: no LDAP bind and no AD writes.

## Privacy and safe examples

Examples use documentation-safe values such as `example.com` and
`dc01.example.com`. Do not put real hostnames, domains, usernames, passwords,
network ranges, or internal notes in public issues, docs, examples, or commits.

For contributor setup and release workflow, see [CONTRIBUTING.md](CONTRIBUTING.md).
To report a vulnerability, see [SECURITY.md](SECURITY.md).
