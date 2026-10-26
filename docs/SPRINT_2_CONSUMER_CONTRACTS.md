# Sprint 2: borrowed-connection consumer contracts

Sprint 2 starts at committed Sprint 1 `33f5161becb6f66c7bc475d22d86a447f9281224`
on `codex/sprint-2-consumer-contracts`. It adds integration coverage and
interface guidance. **No transport implementation, build options, dependency
pins, package version, congestion policy or defaults changed.** The inherited
main-only fairness promotion hold from Sprint 1 remains.

## Exercised interface

The new `ConnectionDriver: consumer pressure...` case in
`tests/e2e/app_driver.zig` runs a real TLS/protected-packet Loopback twice:
client asks/server answers, then server asks/client answers. It proves:

- A real application-buffer allocation failure returns `OutOfMemory` before
  copying data or queueing a response. Retrying after the failure is resolved
  delivers the exact bytes once; neither receive credit nor FIN advanced on
  the failed callback.
- A one-byte send buffer and an outbox limited to one stream/six bytes create
  real staging pressure. `QueueFull` accepts no prefix; mapping ordinary
  pressure to a zero-byte callback result retains receive credit while the
  normal service pass flushes existing tails. Paused and partial readers then
  resume without duplicate bytes or premature clean ends.
- The owner advances its clock to an application cancellation deadline and
  resets/stops only that request. A real protected STREAM+FIN datagram held
  before cancellation arrives afterward. It neither resurrects the request
  nor produces a second/clean terminal callback; another request completes.
- A later request reuses the same connection. Both driver tables, outboxes
  and connection stream maps empty after cleanup; neither peer is closed or
  reports a refused stream.

The callback owns copying retained bytes and committing application effects
only after fallible work succeeds. The owner retains stream IDs across ticks,
not Stream pointers whose streams may be reaped. It owns application deadlines
and network/timer pumping; the borrowing driver owns neither. These rules are
also stated in the borrowing-driver section of `EMBEDDING.md`.

Existing lifetime tests are reused rather than duplicated: 20,000 bidi
request/reply streams plus 20,000 uni notes per owner role, with eight-entry
driver tables, and the greedy window cases (1, 2 and 16).

## Local verification

Stock mise Zig **0.17.0**, Darwin arm64, Debug/ReleaseSafe,
`COPYFILE_DISABLE=1`, builds limited to `-j2`. Durable command/exit/timing/log
records and exact source/compiler/package identities are under ignored
`benchmark-reports/sprint-2-2026-10-26/manifest.json`.

| Gate | Result |
|---|---|
| New pressure filter | 2/2 (one matching case containing both roles, plus the unnamed test-import root). |
| Borrowed-driver filter, Debug / Safe | 26/26 each: 20 library and 6 integration tests, including lifetime/window coverage. |
| Full Debug graph | 37/37 steps; changed integration binary 308/308. Other verified modules cached. |
| Full ReleaseSafe graph | 30/30 steps; changed integration binary 308/308. Other verified modules cached. |
| Benchmark fixtures / examples | 32/32 steps, cached fixture execution explicitly retained. |
| Native UDP echo | Exact stream/datagram payloads 24 and 4172 bytes; clean shutdown. |
| Consumer Debug / Safe | 11/11 steps each; executable ran with correct shared module identity. |
| Formatting / whitespace | Pass. |

The 16 known conformance skips remain in the cached Sprint 1 gate; this is
not a claim that they newly ran or disappeared. The initial new-test attempts
(name shadowing and a retained test Stream pointer) are retained as authored
fixture failures, corrected before the passing gates. No transport defect was
reproduced. Full fuzz, sanitizer, external interop and cross-platform gates
were not repeated for unchanged runtime source; their exact Sprint 1 evidence
is linked in the manifest.

## Package identity and handoff

The manifest verifies every runtime/build package file against the qualified
Sprint 1 archive. The existing Sprint 1 archive therefore remains the runtime
candidate for coordinated qmsg/qmesh stress. A new local archive,
`candidate/quic-zig-sprint-2.tar.gz`, contains the updated documentation and is
identified by its SHA256 in the manifest. Its consumer paths are hashed and
checked against the final worktree; no Zig package rehash is required for
SHA-verified local composition. No release or publication follows from this
local evidence, and no Sprint 2 commit was created.
