# sambatui

Go terminal UI for Samba Active Directory DNS and LDAP administration.

Requires Go 1.26+ to build:

```sh
CGO_ENABLED=0 go build -o sambatui ./cmd/sambatui
./sambatui
```

Use **Ctrl+O** to configure an individual DC, authentication, and verified LDAP
TLS. **Ctrl+P** opens commands; **?** shows help. Use `-config PATH` for alternate
preferences. Use `-theme light` for a light terminal; non-empty `NO_COLOR`
disables colors. Focus and selection also have text markers. Narrow terminals
show one pane at a time (**Tab** switches); **!** retrieves the last error.
**Ctrl+Z** suspends/resumes unless a write is running.

The focused pane has a heavy border; `>` marks keyboard focus, `·` the active
navigation choice, and `*` batch selection. Tables fit their content; narrow screens
keep the focused pane. Forms use aligned rows or a stacked layout as space allows.
Use arrows for choice controls and the searchable command picker. Only the target
and a contextual footer remain outside the data panes.

**Writes require confirmation. Cancellation is not rollback.** Reconcile unknown
outcomes with **R**; never delete the pending-write journal to bypass recovery.
LDAP edits/deletes require server support for RFC 4528 assertion controls.

Samba can confuse a DNS subtree with the zone apex when their names match.
For these zones, complete enumeration uses the configured, certificate-verified
LDAP connection to the same DC. It never silently skips the affected records.

Configuration: [config.example.json](config.example.json).
Development: [STYLE.md](STYLE.md), `go test ./...`, or `go run ./cmd/dev check`.
Releases: `go run ./cmd/dev release --version v1.2.3 --output dist` (new directory).
Optional live tests: [integration/README.md](integration/README.md).
