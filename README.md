# sambatui

Go terminal UI for Samba Active Directory DNS and LDAP administration.

Requires Go 1.26+ to build:

```sh
CGO_ENABLED=0 go build -o sambatui ./cmd/sambatui
./sambatui
```

Use **Ctrl+O** to configure an individual DC, authentication, and verified LDAP
TLS. **Ctrl+P** opens commands; **?** shows help. Use `-config PATH` for alternate
preferences or `-check` to check connectivity/authentication without writes.

**Writes require confirmation. Cancellation is not rollback.** Reconcile unknown
outcomes with **R**; never delete the pending-write journal to bypass recovery.
LDAP edits/deletes require server support for RFC 4528 assertion controls.

Configuration: [config.example.json](config.example.json).
Development: [STYLE.md](STYLE.md), `go test ./...`, or `go run ./cmd/dev check`.
Releases: `go run ./cmd/dev release --version v1.2.3 --output dist` (new directory).
Optional live tests: [integration/README.md](integration/README.md).
