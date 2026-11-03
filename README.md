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

## Docker (recommended)

Docker packages the TUI, Python 3.15, `samba-tool`, Kerberos/GSSAPI support,
and DNS utilities together. The host only needs Docker and an interactive
terminal. Authenticate to Docker Hardened Images, build, and run:

```sh
docker login dhi.io
docker build -t sambatui:local .
./scripts/sambatui
```

Or use `just docker-build` and `just docker-run` for this disposable interactive
CLI.
The launcher attaches your terminal and removes the container when you quit.
The named volume `sambatui-config` preserves preferences at
`/home/app/.config/sambatui`. It runs as UID 1000 with a read-only root filesystem,
writable temporary storage, all capabilities dropped, and privilege escalation
disabled. Additional Docker run options can be passed to the launcher.

The Dockerfile uses digest-pinned `dhi.io/uv` on Debian 13. uv installs a
separate managed Python 3.15.2 and the locked application dependencies,
including the Kerberos extra. Samba keeps Debian's system Python; mixing Samba's
packages into a DHI Python image would replace its interpreter. The DHI `dev`
variant provides apt for Samba's OS dependencies. Compilers stay in the tested
build stage; test dependencies are removed before copying the release artifact.
This is a custom image based on DHI; uv's managed Python and additional packages
are not covered by the base image's hardening guarantees. Update the `UV_IMAGE`
tag and digest together when refreshing the base.

### Development and tests

Use `uv run sambatui` for source development, or rebuild the image to try changes
in Docker. BuildKit cache mounts reuse package downloads, and `uv sync --frozen`
installs from `uv.lock`. Docker Engine with BuildKit is required.

```sh
just docker-validate
just docker-build
```

`docker build -t sambatui:local .` runs the entire test suite and enforces the
project's 100% coverage threshold with network access disabled. The production
stage copies its Python and virtual environment from the tested stage only after
tests pass and uv removes development dependencies. A failing test stops the
build. BuildKit may reuse a successful test layer when its inputs are unchanged;
use `docker build --no-cache -t sambatui:local .` to rerun everything.

To check the installed production dependencies and start the TUI headlessly:

```sh
docker run --rm -i --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --tmpfs /tmp \
  --entrypoint python sambatui:local - < scripts/check-container.py
```

CI checks the Dockerfile, builds the tested image, and runs this smoke check.
Configure repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_PASSWORD`
for its DHI registry login.

### Updates and releases

Dependabot opens weekly grouped updates for uv dependencies and GitHub Actions,
and updates the digest-pinned DHI uv base. Actions are pinned to commit SHAs.
Python is pinned to 3.15.2 in `.python-version`; update that file when
refreshing Python. `requires-python` sets the supported minor version.

Set `DOCKERHUB_USERNAME` and `DOCKERHUB_PASSWORD` as both **Actions secrets** and
**Dependabot secrets** in GitHub repository settings. Dependabot needs its own
secrets to resolve DHI updates and run their CI. Use a read-only Docker Hub token
for DHI pulls. The local environment's credentials are separate from GitHub's.

After CI passes, pushing a `v*` tag publishes an image to
`ghcr.io/lauritsk/sambatui:<tag>` with an SBOM and build provenance. Only the
release job has package write permission; GHCR uses GitHub's built-in token.
For example, after publishing `v0.7.2`:

```sh
docker pull ghcr.io/lauritsk/sambatui:v0.7.2
SAMBATUI_IMAGE=ghcr.io/lauritsk/sambatui:v0.7.2 ./scripts/sambatui
```

GHCR packages inherit their configured visibility; authenticate to GHCR when
pulling a private package. The release workflow currently builds for Linux amd64.

### Connection settings

Enter your server and credentials in the setup wizard. Exported `SAMBATUI_*`
variables are forwarded to the container, along with terminal settings and
`KRB5CCNAME`. Host paths in those variables must refer to files mounted into
the container. For example:

```sh
export SAMBATUI_SERVER=dc01.example.com
export SAMBATUI_DOMAIN=example.com
export SAMBATUI_USER=administrator@example.com
export SAMBATUI_AUTH=password
./scripts/sambatui
```

Use `SAMBATUI_IMAGE` to select another locally built or published image, and
`SAMBATUI_DOCKER_VOLUME` to select a different preferences volume. No image
is published by this repository's build command. The launcher accepts additional
Docker run options before the image name, for example:

```sh
./scripts/sambatui --dns 192.0.2.10
```

The container must resolve your AD names and reach the domain controllers over
the required DNS, LDAP, Kerberos, and Samba RPC ports. Explicit `--dns` may be
needed for corporate DNS. Docker Desktop and host VPN combinations may require
additional routing configuration; verify access from inside the container.

### Private AD certificate authority

For LDAPS/StartTLS with a private CA, build a local derived image that installs
your CA into the system trust store. Create `Dockerfile.ad` alongside `ad-ca.crt`
(a PEM certificate):

```dockerfile
FROM sambatui:local
USER root
COPY ad-ca.crt /usr/local/share/ca-certificates/ad-ca.crt
RUN update-ca-certificates
USER app
```

```sh
docker build -f Dockerfile.ad -t sambatui:ad .
SAMBATUI_IMAGE=sambatui:ad ./scripts/sambatui
```

The repository's `.dockerignore` uses an allowlist. Before this derived build,
create `Dockerfile.ad.dockerignore` with:

```text
*
!Dockerfile.ad
!ad-ca.crt
```

This makes the CA available in its build context. Keep credentials out of image
layers.

### Kerberos in Docker

Mount your realm configuration and obtain a ticket inside the container. Store
the file cache in the preferences volume so it survives container recreation:

```sh
docker run --rm -it --entrypoint kinit \
  --mount type=volume,src=sambatui-config,dst=/home/app/.config/sambatui \
  --mount "type=bind,src=$PWD/krb5.conf,dst=/etc/krb5.conf,readonly" \
  -e KRB5CCNAME=FILE:/home/app/.config/sambatui/krb5cc \
  sambatui:local administrator@EXAMPLE.COM

export KRB5CCNAME=FILE:/home/app/.config/sambatui/krb5cc
export SAMBATUI_KRB5_CCACHE=FILE:/home/app/.config/sambatui/krb5cc
export SAMBATUI_AUTH=kerberos
export SAMBATUI_KERBEROS=required
./scripts/sambatui \
  --mount "type=bind,src=$PWD/krb5.conf,dst=/etc/krb5.conf,readonly"
```

Repeat `kinit` when the ticket expires. To remove the cached ticket, use the same
volume and `KRB5CCNAME` with `--entrypoint kdestroy`. An existing host FILE cache
can also be bind-mounted if UID 1000 can read it; host KEYRING/KCM caches are not
automatically accessible in a container. Password files and alternate `smb.conf`
files can be bind-mounted read-only and selected with the corresponding settings.

### Builds behind a TLS inspection proxy

The Dockerfile accepts an optional BuildKit certificate secret. Pass a PEM CA
bundle trusted by your proxy; it is mounted only during dependency installation:

```sh
docker build --secret id=proxy_ca,src=/path/to/proxy-ca-bundle.pem \
  -t sambatui:local .
```

Configure Docker's daemon and client proxy settings for your environment. Runtime
AD CA trust is configured separately as shown above.

## Native installation requirements

- Python 3.15+
- `samba-tool` in `PATH`
- Network access to a Samba AD DNS/domain controller endpoint
- Credentials allowed to manage the DNS records and LDAP objects you edit
- Kerberos client configuration and tickets when using Kerberos auth
- LDAPS or StartTLS access when using LDAP password binds

Useful system packages:

| Distro | Packages |
| --- | --- |
| Debian/Ubuntu | `sudo apt install samba-common-bin python3-samba krb5-user bind9-dnsutils` |
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
| `SAMBATUI_COMMAND_TIMEOUT` | Maximum seconds for one `samba-tool` command | `60` |
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
| `SAMBATUI_THEME` | Textual theme name; overrides `TEXTUAL_THEME` | `ansi-dark` (uses the terminal palette) |

`sambatui` stores non-secret preferences, including connection settings and the
username, in `~/.config/sambatui/config.toml`. Passwords and password-file
contents are not written there. Environment variables override saved
preferences. By default, the UI uses ANSI colors and the terminal's own
foreground and background. Set `SAMBATUI_THEME=textual-dark` (or another
Textual theme name) if you prefer a fixed palette.

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

Normal LDAPS and StartTLS connections verify the server certificate using the
system trust store. Install your AD CA certificate in that trust store when
using a private CA. Legacy compatibility mode explicitly disables certificate
verification and permits old TLS versions and weak ciphers; it remains available
for older AD servers on trusted networks. It is off by default.
