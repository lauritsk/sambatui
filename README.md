# sambatui

A Textual terminal UI for Samba Active Directory DNS administration and LDAP
browsing/management.

`sambatui` wraps Samba's `samba-tool` CLI for DNS changes and uses `ldap3` for
LDAP directory operations. It provides keyboard-driven views for DNS zones,
records, AD objects, and common DNS/LDAP hygiene findings.

## Features

- Discover domain controllers from AD DNS SRV records.
- List DNS zones and browse records, including reverse zones.
- Add, update, query, sort, search, and delete DNS records.
- Create matching PTR records for A records when a reverse zone is available.
- Find duplicate DNS records, missing PTRs, and orphan PTRs.
- Search AD users, groups, computers, and OUs over LDAP.
- Find inactive users, stale computers, cleanup candidates, and users without
  secondary groups.
- Add LDAP users, groups, computers, and OUs; edit allowlisted attributes; and
  delete selected LDAP entries after confirmation.
- Use password or Kerberos authentication.

> [!IMPORTANT]
> `sambatui` can modify Samba AD DNS records and LDAP directory entries. Review
> command previews and confirmation prompts before applying changes.

## Requirements

- Python 3.14+
- `samba-tool` in `PATH`
- Network access to a Samba AD DNS/domain controller endpoint
- Credentials allowed to manage the DNS records and LDAP objects you edit
- Kerberos client configuration and tickets when using Kerberos auth
- LDAPS or StartTLS access when using LDAP password binds

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

## Run

From a checkout:

```sh
uv run sambatui
```

From an installed package:

```sh
sambatui
```

Install optional Kerberos/GSSAPI support for LDAP search when needed:

```sh
pipx install 'sambatui[kerberos]'
```

## Configuration

Enter connection values in the setup wizard, or provide environment variables:

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
| `SAMBATUI_DOMAIN` | AD DNS domain used for setup, discovery, and LDAP defaults | empty, or saved non-reverse zone |
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

`sambatui` stores non-secret preferences, including connection settings and the
username, in `~/.config/sambatui/config.toml`. Passwords and password-file
contents are not written there. Environment variables override saved
preferences.

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| `Ctrl+P` | Open command palette |
| `w` | Run setup wizard |
| `z` | Load DNS zones |
| `c` | Discover domain controllers |
| `L` | Search AD directory over LDAP |
| `S` | Open DNS/LDAP findings picker |
| `1`-`7` | Open DNS/LDAP finding filters directly |
| `8` | Run full health dashboard |
| `r` | Refresh current zone or rerun current finding view |
| `f` | Apply a guided finding fix when available |
| `q` | Query one DNS name/type |
| `a` | Add DNS record with guided picker and command preview, or add an LDAP entry |
| `u` | Update selected DNS record or edit allowlisted LDAP attributes |
| `d` | Delete selected DNS records or selected LDAP entry |
| `m` | Load 200 more LDAP rows from the last LDAP search |
| `/` | Focus inline search; `Esc` clears it |
| `n` / `t` / `e` | Sort by name, type, or value |
| `h` / `l`, `Tab` / `Shift+Tab` | Move focus between zones and records |
| `j` / `k`, `gg` / `G`, `PageUp` / `PageDown` | Move through tables |
| `Space` | Toggle selected record |
| `v`, then `j`/`k` | Visual range selection |

Confirmations support `y` for yes and `n` or `Esc` for no. `Enter` uses the safe
default: yes for low-risk add confirmations, no for destructive changes,
deletes, and secret writes.

## Authentication notes

Kerberos mode uses an existing ticket and omits the password from `samba-tool`
arguments. With a valid `klist -s` ticket, `sambatui` defaults to Kerberos unless
authentication is set explicitly.

Password mode is available for environments without Kerberos tickets. Provide a
password through the UI, `SAMBATUI_PASSWORD`, or a protected password file:

```sh
mkdir -p ~/.config/sambatui
printf '%s\n' 'replace-with-your-password' > ~/.config/sambatui/password
chmod 600 ~/.config/sambatui/password
```

> [!CAUTION]
> Password mode passes credentials to `samba-tool` non-interactively. Prefer
> Kerberos on shared systems where process arguments may be visible to other
> users. Never commit password files or `.env` files.

## LDAP notes

LDAP search and entry management use a base DN such as `DC=example,DC=com`. If
`SAMBATUI_LDAP_BASE` is empty, the UI proposes a base DN from the configured AD
domain or current DNS zone.

- `SAMBATUI_AUTH=password` uses the configured username/password and requires
  `ldaps` or `starttls`; cleartext simple bind is intentionally unsupported.
- `SAMBATUI_AUTH=kerberos` uses SASL GSSAPI and the current Kerberos ticket
  cache. Install `sambatui[kerberos]` first.
- Set `SAMBATUI_LDAP_COMPATIBILITY=on` only for legacy servers that need relaxed
  TLS settings or fail schema probing.
