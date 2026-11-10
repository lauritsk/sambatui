# sambatui

Native Go terminal UI for Samba Active Directory DNS and LDAP administration.
The client needs **no Python, Docker, Samba installation, system GSSAPI, `klist`,
`samba-tool`, or helper processes**. It connects directly to your existing DC.
No telemetry or directory/credential uploads are added.

**This tool changes directory entries and DNS records. Review every confirmation.**

## Build, install, run

Use Go 1.26 or newer (validated with 1.27.3):

```sh
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/sambatui ./cmd/sambatui
./bin/sambatui
# Optional installation:
mkdir -p "$HOME/.local/bin"
install -m 755 bin/sambatui "$HOME/.local/bin/sambatui"
```

Enter an individual DC hostname, AD DNS domain/base DN, authentication and TLS
settings in **Ctrl+O**. Setup checks DNS management and LDAP TLS/binding. The
command palette (**Ctrl+P → discover**) finds LDAP/DC and Kerberos SRV records;
you still review the selected DC. Use a DC hostname, not a load-balanced alias:
LDAP revisions are DC-local. Trust the DC's CA through the operating system or
the **CA PEM file** setting. Certificate verification cannot be disabled.

```sh
./bin/sambatui -config /absolute/path/config.json
./bin/sambatui -check   # DNS zone enumeration + verified LDAP bind; no writes
./bin/sambatui -version
```

`sh scripts/release.sh v1.0.0` produces executable archives and SHA-256 checksums
under `dist/` for **Linux and macOS, amd64 and arm64**. They contain the executable,
README and license notices; Go is not required to run them. Linux executables
are statically linked. Windows is not a release target. Runtime interoperability
has been tested on Linux/amd64; other targets have only been cross-compiled.
A terminal, network connectivity, trusted CA certificates and (for Kerberos) its
configuration/tickets remain necessary data/environment, not helper programs.

## Features and keys

- DNS zone browsing and management queries, including nested names; A, AAAA,
  CNAME, PTR, TXT, MX, SRV and NS add/update/delete. Adds use Samba's 900-second
  default; updates preserve existing TTL, flags and aging metadata. The update
  sends old+new records in **one MS-DNSP request**, not delete followed by add.
- Guided type-specific forms, duplicate validation, batch deletion, and optional
  matching IPv4 PTR creation using the longest loaded reverse zone. No implicit
  zone creation; PTR changes are shown in the final write confirmation.
- LDAP users/groups/computers/OUs/all, escaped server search, container navigation,
  paging, complete ranged membership attributes, details/attributes, adds,
  conditional edits/deletes and account disable.
  Critical AD domain-scope controls keep searches within the selected naming
  context; referrals are never chased.
  Editable attributes are limited by object kind; base DN deletion is prohibited.
- DNS duplicate/CNAME conflicts, missing/mismatched forward/reverse records;
  inactive users, disabled cleanup candidates, never-used accounts, stale
  computers, users without secondary groups; a full health dashboard. Failed,
  incomplete and row-limited checks are not reported as clean. Guided fixes are
  intentionally limited to evidence-backed PTR adds and conditional disable.

| Key | Action |
| --- | --- |
| `z`, `l`, `q` | DNS zones, LDAP search, DNS name/type query |
| `1`–`8`, `h` | Findings/dashboard, findings picker |
| `Tab`, arrows or `j/k`, `Enter` | Pane focus, move, open/details |
| `PgUp/PgDn`, `Ctrl+U/D`, `g/G` | Page, half page, first/last |
| `/`, `s`, `Space`, `v`, `Esc` | Local filter, sort, select, range, clear |
| `a`, `u`/`e`, `d`, `f` | Add, edit, delete, guided fix |
| `r`, `m` | Refresh, load more (+200, up to 5000) |
| `Ctrl+O`, `Ctrl+P`, `?` | Connection setup, command palette, help |
| `p`, `P` | Load/save private password file |
| `Ctrl+C`, `R`, `Q` | Cancel/drain a write, reconcile uncertain outcome, quit |

Forms: **Tab/Enter** changes field; **Ctrl+U** clears it; **Ctrl+S** submits;
**Esc** cancels. Every write requires typing `yes` after reviewing its target
and complete preview. **PgUp/PgDn scroll long confirmation previews**. Row
information is available with Enter; help/details scroll with j/k.

## Configuration and authentication

Preferences are JSON in `os.UserConfigDir()/sambatui/config.json` (typically
`~/.config/sambatui/config.json` on Linux and
`~/Library/Application Support/sambatui/config.json` on macOS).
Use `-config` to choose another path. Preferences never include passwords or
tickets. Passwords are saved **only explicitly with P**, unencrypted, in a
separate owner-only file (`password` beside the configuration by default).

See [config.example.json](config.example.json). Shell environment values can
override preferences:

- `SAMBATUI_SERVER`, `SAMBATUI_DOMAIN`, `SAMBATUI_LDAP_BASE`, `SAMBATUI_ZONE`
- `SAMBATUI_AUTH=password|kerberos`, `SAMBATUI_USER`
- `SAMBATUI_PASSWORD_FILE`, or `SAMBATUI_PASSWORD` (less suitable for persistent use)
- `SAMBATUI_LDAP_ENCRYPTION=ldaps|starttls`, `SAMBATUI_CA_FILE`
- `SAMBATUI_DNS_PASSWORD_AUTH=ntlm|kerberos`
- `SAMBATUI_KRB5_CCACHE=FILE:/absolute/path`, `SAMBATUI_KRB5_CONFIG`
- `SAMBATUI_AUTO_PTR=off|ask|on`

Paths are native host paths; use absolute paths. Domain-derived base DNs can be
overridden explicitly.
Directory searches initially load 200 entries; smart views initially inspect
500. Both limits can be increased up to 5000. Timeouts (1–300 seconds), row limits
and smart-view thresholds (1–100000 days) are preferences;
thresholds can also be edited through the command palette.

### Authentication modes

**Password:** DNS uses sealed NTLMv2 RPC by default. Set `dns_password_auth` to
`kerberos` to acquire a DNS service ticket directly in Go with the supplied
password; use a realm-qualified UPN and a valid Kerberos configuration. There
is **no automatic Kerberos-to-NTLM downgrade**. LDAP uses SIMPLE for UPN/DN
usernames or SASL GSS-SPNEGO/NTLMv2 for `DOMAIN\user`, always inside verified TLS.
NTLM retains its MIC/extended session security and supplies TLS channel binding;
SASL message signing/sealing is not layered on top of TLS because Samba refuses it.

**Kerberos cache:** explicitly select a private MIT FILE-format v3/v4 cache.
`SAMBATUI_KRB5_CCACHE` overrides the configuration; `KRB5CCNAME` is used as a
configuration default only when no cache was selected. The selected cache's
identity—not the password username—is used for both protocols. Missing, malformed,
unsafe or explicitly selected nonexistent caches fail, never fall back to another
identity. Non-FILE cache stores (KEYRING/KCM/DIR) are not supported. The nonstandard
`KRB5_CCACHE` variable is refused for DNS Kerberos to prevent upstream ambient-cache
selection; use the explicit selector instead.

Tickets are frozen in memory when settings are loaded/applied. Replacing a cache
file cannot redirect a pending confirmation. After renewing tickets, reopen
Ctrl+O and apply the selected cache again. The client never invokes ticket tools
or writes/renews the cache. You can use an existing cache from your login/ticket
workflow; password mode requires no ticket executable or cache. LDAP Kerberos
supplies channel binding and verifies mutual authentication. Integrated TLS binds
fail closed for certificate signature algorithms without a supported endpoint
binding hash; ordinary verified SIMPLE binds do not need channel binding.

Password whitespace is significant, including leading/trailing spaces and tabs.
Password files use the **first line only, excluding LF and an optional preceding
CR**; later lines are ignored. Password/cache files must be regular, non-symlink,
owned by the current user, with no group/other permissions (`chmod 600`). Atomic
persistence uses mode 0600 and newly created directories use 0700. Do not commit
credentials or ticket files. In-memory credentials are not claimed to be zeroized.

## Write safety and server limitations

One write reservation spans the entire form/confirmation/worker lifetime.
Settings, selected DC and credentials are immutable snapshots. Connection changes
immediately invalidate loaded rows and selections; late reads are generation-tagged
and discarded. No write is automatically retried. Server/control text is escaped
for literal display, including terminal controls and bidi formatting characters.

**Cancellation is not rollback.** A canceled or unanswered write may have committed.
Sockets are closed and local workers drained; uncertain results block further
writes. A private `config.json.pending-write.json` intent journal survives crashes
and restart; it contains target/operation context, **not credentials**. Do not
delete it to retry. `R` reads the original target and requires explicit
reconciliation; reads alone cannot prove a remote operation has stopped. Only
acknowledge after establishing the outcome and that nothing is still pending.
After restart, load matching original endpoint/identity credentials to reconcile.
An exclusive per-configuration lock prevents overlapping client instances using
that configuration. Do not use separate configurations/processes to bypass it.

LDAP edits/deletes require the selected entry's `uSNChanged` in a **critical RFC
4528 assertion control**. Disable also asserts the original `userAccountControl`
and preserves unrelated flags. The same selected DC/session is used for capability
checking and the mutation; referrals and unconditional-write fallbacks are absent.

**Samba 4.22.11 does not advertise RFC 4528.** These conditional operations are
refused before dispatch on the tested server. Reads/adds and DNS operations work.
Successful conditional writes/conflicts are verified by protocol fakes and a BER
wire server, **not claimed as successful live Samba operations**.

## Development and verification

```sh
go install mvdan.cc/gofumpt@v0.12.0
gofumpt -w cmd internal integration
test -z "$(gofumpt -l cmd internal integration)"
go vet ./...
go test ./...                         # local fakes, no Docker/Python/DC needed
CGO_ENABLED=1 go test -race ./...      # race instrumentation needs a C compiler
CGO_ENABLED=0 go build ./cmd/sambatui
```

CI runs gofumpt, vet, tests and race checks directly; releases are executable
archives. The race detector requires a C compiler at build time, not at runtime.

Optional, explicitly isolated interoperability/PTY tests:

```sh
sh integration/run.sh
```

Only this opt-in test provisions a Samba server in a DHI-based Docker image with
`--network none`, no published ports, no host credentials or extra capabilities. Samba's own
provisioning/runtime dependencies live solely in that disposable **server** image.
It is not used to build or run the client or default tests. See
[integration/README.md](integration/README.md) for coverage and unverified
environments. Never run fixture provisioning on your host or point destructive
tests at a production directory.

### Code boundaries

`internal/tui` owns state/forms/confirmations; `config`, `lifecycle` and `journal`
own preferences, snapshots, serialization and recovery. `dnsdata` and `health`
are pure domain logic. `dnsrpc` implements direct MS-DNSP over authenticated/sealed
TCP RPC with endpoint mapping; ordinary DNS/dynamic updates are not substituted
for management RPC. `directory` owns TLS, LDAP paging, mutations and controls;
`auth` owns secret-safe cache/GSSAPI boundaries. `backend` connects these to the UI.
Dependencies are pinned in `go.mod`/`go.sum`; distributed notices are in
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
