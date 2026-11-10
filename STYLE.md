# Style

Follow [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md):
safety first, then performance, then developer experience. Prefer simple,
explicit control flow and a small number of domain-specific abstractions.

## Go conventions

This is a Go adaptation, not a claim of literal TigerBeetle/Zig compliance.
The garbage collector, protocol libraries, interface callbacks and asynchronous
terminal runtime remain intentional dependencies. Snapshot values are copied on
purpose to freeze identity; mutable resources retain a single explicit owner.

Use Go's exported/unexported naming conventions and `gofumpt`. Use explicitly
sized integers for domain quantities and wire fields. Keep `int` for collection
indexes and APIs that require it; check bounds before converting between types.

Use descriptive names without abbreviations, including receivers and parameters.
Preserve established acronyms. Put units and qualifiers last. Distinguish indexes,
counts, and sizes, and make rounding and overflow behavior explicit.

## Assertions and errors

Assert arguments, preconditions, postconditions, and state invariants with
`internal/invariant.Require`, which remains enabled in every build. Seek at least
two independent substantive checks in nontrivial routines. For tiny pure helpers
and forwarding methods, use the caller/callee contracts and Go's type/bounds
checks rather than padding an assertion count. This deliberately adapts the
manifesto's numeric density target to Go. Pair assertions across producer/consumer
and persistence boundaries.

Panic for programmer errors. Return errors for invalid external input, remote
failures, and resource limits. Handle every error and explain intentionally
ignored errors. Never recover arbitrary application panics; contain malformed-data
panics only at narrow third-party decoder boundaries.

## Function shape and ownership

- Limit production functions to 70 lines, including nested callbacks.
- Limit source and comment lines to 100 columns.
- Do not use recursion.
- Keep sequencing and mutable state in the owning function. Extract helpers by
  responsibility, not arbitrary line counts. Keep leaf computations pure.
- Declare variables in the smallest useful scope. Avoid duplicated state.
- Give mutable state and resources explicit owners and lifetimes. Workers receive
  immutable snapshots rather than accessing another owner's live state.
- Validate asynchronous results against the state that requested them. Match both
  connection generation and request ID for reads; match the owning flow for writes.
  Reconciliation must also match the outstanding intent and latest inspection.
- Explain why decisions and invariants matter, not merely what the code does.

## Bounded work and memory

Give every loop, queue, buffer, and unit of remote work an explicit bound.
Document intentionally long-running loops and their shutdown conditions.
Keep limit values beside the code that enforces them, not in this guide.

Budget memory and preallocate bounded storage during initialization where
possible. Reuse buffers. Go's garbage collector does not excuse unbounded
allocation. Check input and aggregate limits before allocating, copying,
enqueuing, or persisting; audit dependency behavior rather than assuming it is
bounded. These are application-work budgets, not a fixed process heap quota:
Go and third-party wire decoders still allocate dynamically. A strict no-allocation
or zero-dependency implementation would require a different runtime and protocol
stack.

## External effects

Validate untrusted data at boundaries. Never report incomplete work as complete
success. Check persistence invariants before writing and after reading.

Make mutations explicit and reviewable. Preserve their original target and
identity throughout execution. Cancellation is not rollback; retain ownership
until work has settled. Reconcile partial or unknown outcomes before retrying.
Do not automatically retry non-idempotent operations.

Keep credentials out of logs and operational metadata. Make credential storage
explicit and protect it independently from ordinary application data.

## Performance and dependencies

Reason about network, disk, memory, and CPU costs before implementing a design.
Batch work, build reusable indexes, and avoid repeatedly copying growing data.
Make externally visible output deterministic. For example, DNS health checks
reuse the zone index to probe at most six IPv4 reverse-name suffixes per record,
rather than scanning up to 10000 zones for each of up to 100000 records.

Prefer the standard library and existing tools. Add dependencies only when their
benefit justifies their complexity, security, and maintenance costs. Pin versions,
review resource and error behavior, and remove unnecessary dependencies.

## Verification

Test valid and invalid states, both sides of resource boundaries, error paths,
failed persistence, partial effects, and cancellation. Use deterministic local
fakes without mistaking them for interoperability evidence.

Automate enforceable style rules. `integration/style_test.go` checks 70-line
production functions (including callbacks), 100-column source lines with four-column
tabs, syntactically infinite loops, and statically visible recursive call paths.
Interface dispatch and data-dependent work limits still require review.

Format code, run static analysis, execute tests, check concurrency with the race
detector, and verify builds before submitting:

```sh
gofumpt -w cmd internal integration
go vet ./...
CGO_ENABLED=0 go test ./...
CGO_ENABLED=1 go test -race ./... # Requires a C compiler.
CGO_ENABLED=0 go build ./cmd/sambatui
```

## Tooling and automation

TigerStyle applies to release tooling, integration fixtures, CI, Dockerfiles,
configuration and tests—not only the client. Host workflows belong in the existing
Go toolchain (`cmd/dev` and `internal/devtool`), not shell scripts or inline YAML
programs. Use named options, direct argument vectors, explicit environments,
subprocess deadlines and owned process groups. Cancellation must reap descendants;
cleanup failures must remain visible alongside the original error.

```sh
go run ./cmd/dev check
go run ./cmd/dev release --version v1.2.3 --output dist
go run ./cmd/dev integration
```

`check` requires `gofumpt`, a C compiler for race tests, and Python 3.9+ for
fixture-only safety tests. Normal `go test ./...` and the client need neither
Docker nor Python. Integration additionally requires Docker, only for the fixture.

Release builds stage the complete fixed artifact set, stream deterministic archives
and checksums, refuse existing destinations, and publish only after success. Never
include stale files through wildcards. Integration runs own one uniquely named
container with explicit CPU, memory, process, log, readiness and lifetime limits.
Cleanup uses a fresh deadline even after operation cancellation.

The only scripting-language exception is `integration/server.py`: Samba exposes
its server provisioning API through Python. It is disposable-server code, never
client code. Keep functions within 70 lines, source within 100 columns, subprocesses
bounded and provisioning guarded. Its standard-library safety tests run in
`dev check` and during the fixture image build; the base image is digest-pinned.
Go tests also check tooling
asset layout and CI action pins, job deadlines and shared command entrypoints.

The binary-only fixture runs interoperability/terminal tests; checkout-dependent
style checks run on the host, not inside the fixture.
