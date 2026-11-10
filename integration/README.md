# Disposable Samba interoperability tests (opt-in)

Run `go run ./cmd/dev integration` from the checkout root with Go and Docker. Neither Docker
nor any server provisioning tools are needed for the normal Go test suite,
build, installed executable or connection to an existing remote DC.

The runner:

1. Builds a **test-server-only** image from `integration/Dockerfile`, using
   `dhi.io/debian-base:trixie-debian13-dev` pinned by version and digest.
2. Cross-builds native Linux test binaries and the native client with
   `CGO_ENABLED=0` on the host.
3. Starts the server with `--network none`, no published ports, host credentials,
   host config mounts or extra capabilities. CPU, memory, process count and Docker
   logs are bounded. All server sockets are loopback-only.
4. Provisions `LAB.INVALID`, test-only users, a private TLS certificate and a
   reverse DNS zone inside that disposable container. Samba's upstream
   provisioning API and fixture ticket generation use the **server's** Python/
   Samba/Kerberos packages; none are invoked by the native client.
5. Copies only the native binaries into that network namespace, then executes
   the explicit fixture-only tests. They require both an opt-in variable and
   the fixture marker; there is no configurable production endpoint/credential.
6. Removes its uniquely owned container and temporary host binaries, including
   after failure or cancellation. Subprocess groups and readiness have deadlines;
   cleanup uses an independent deadline and reports failures instead of hiding them.

`SAMBATUI_TEST_SERVER_IMAGE` can select an already-built **server fixture** image
to avoid rebuilding it. This is not a fallback client image. Never run
`server.py` on a host; its guards refuse host provisioning or existing fixture state.
The fixture has a finite lifetime and bounded command/retry/shutdown budgets.
Its Python safety tests run at image build time without provisioning a domain.

## Live checks

Verified on Samba **4.22.11** in this environment:

- LDAP/DC and Kerberos SRV discovery against the actual fixture DNS server.
- Sealed MS-DNSP TCP RPC: password NTLMv2, password Kerberos without downgrade,
  explicit FILE-cache Kerberos; forward/reverse zone enumeration and descendant
  record enumeration.
- A/AAAA/CNAME/PTR/NS/MX/SRV/TXT add, read, single-request update and delete;
  canonical values and preserved nondefault TTL; denied writes and useful
  protocol errors.
- Certificate-verified LDAPS and StartTLS; untrusted CA/wrong hostname/wrong
  password rejected; whitespace-sensitive passwords preserved.
- LDAP SIMPLE, SASL NTLMv2 with channel binding and Kerberos with mutual
  authentication/channel binding. Selected-cache Reader identity is used even
  when the password username says Administrator and the source file is gone.
- Critical AD domain-scope searches and LDAP paging with opaque repeated server
  cookie handles; all entry-add kinds;
  permission errors; a real committed add with a deliberately lost reply is
  uncertain and is not retried.
- Unsupported conditional modify/delete/disable rejected before dispatch and
  original entry unchanged. **Samba does not advertise RFC 4528.** Successful
  conditional writes are not claimed as live Samba functionality.
- The actual static executable in a Go-driven pseudo-terminal: zones, optional
  matching PTR, DNS add/update/delete with confirmations, independent server
  state checks, LDAP view, health dashboard, help and clean quit.
- `sambatui -check` performs authenticated DNS enumeration and verified LDAP
  binding without writes.

## Deterministic default checks versus live claims

`go test ./...` defaults to local protocol fakes/loopback servers and skips all
of the above opt-in mutations. Native tests verify critical assertion bytes,
successful/stale/unsupported conditional responses, original UAC preservation,
TLS-binding bytes/MIC, cancellation/timeout socket cleanup, snapshots, secret
handling, write serialization/draining, durable uncertainty and UI transitions.

The fixture accepts correctly bound integrated authentication. Strict negative
channel-binding enforcement by other DC policies, Windows AD, multi-forest
referrals, large production directories and real-DC lost-response timing have
not been live-validated. Ranged membership retrieval has deterministic protocol
coverage, not a live large-group claim. No external/production DC is accessed by these tests.
