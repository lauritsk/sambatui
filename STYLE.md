# Style

Follow [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md):
safety first, then performance, then developer experience. Prefer simple,
explicit control flow and a small number of domain-specific abstractions.

## Go conventions

Use Go's exported/unexported naming conventions and `gofumpt`. Use explicitly
sized integers for domain quantities and wire fields. Keep `int` for collection
indexes and APIs that require it; check bounds before converting between types.

Use descriptive names without abbreviations, including receivers and parameters.
Preserve established acronyms. Put units and qualifiers last. Distinguish indexes,
counts, and sizes, and make rounding and overflow behavior explicit.

## Assertions and errors

Assert arguments, preconditions, postconditions, and state invariants. Maintain
an average of at least two meaningful assertions per production function; do not
pad the count with tautologies or checks already guaranteed by Go's type system.
Pair assertions across producer/consumer and persistence boundaries.

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
- Validate asynchronous results against the state that requested them.
- Explain why decisions and invariants matter, not merely what the code does.

## Bounded work and memory

Give every loop, queue, buffer, and unit of remote work an explicit bound.
Document intentionally long-running loops and their shutdown conditions.
Keep limit values beside the code that enforces them, not in this guide.

Budget memory and preallocate bounded storage during initialization where
possible. Reuse buffers. Go's garbage collector does not excuse unbounded
allocation. Check input and aggregate limits before allocating, copying,
enqueuing, or persisting; audit dependency behavior rather than assuming it is
bounded.

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
Make externally visible output deterministic.

Prefer the standard library and existing tools. Add dependencies only when their
benefit justifies their complexity, security, and maintenance costs. Pin versions,
review resource and error behavior, and remove unnecessary dependencies.

## Verification

Test valid and invalid states, both sides of resource boundaries, error paths,
failed persistence, partial effects, and cancellation. Use deterministic local
fakes without mistaking them for interoperability evidence.

Automate enforceable style rules. Format code, run static analysis, execute tests,
check concurrency with the race detector, and verify builds before submitting.
