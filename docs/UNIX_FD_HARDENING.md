# Unix/FD correctness follow-up, 2026-10-11 UTC

The recommended correctness sprint is complete. The Zig fork's
`feat/evented-0.17` now contains ancillary ownership/address repair
`03263c1c4424c1252edb6b2e4a7d5aba752029d0` and Dispatch futex repair
`017b3e4966a26a33db3bb77a92405b60644df396`, both with the owner-selected
`Co-Authored-By: Codex` trailer. These fixes are **unreleased**; published
`0.17.0+fork.3bfc1a3ab` does not include them.

The [portable evidence record](UNIX_FD_HARDENING_EVIDENCE.json) includes
source/compiler/binary hashes, native runtime identities, expected failing
reproductions, passing checkpoints and log hashes. The evented
[ledger](EVENTED_BACKEND_EVIDENCE.json) gained
`unix_fd_hardening_2026_10_11`; earlier entries retain their values.
The fuller implementation/reproduction report lives in the adjacent
zigfork checkout's `docs/unix-fd-hardening-2026-10-11.md`.

## Before and after

| Defect | Before | After |
|---|---|---|
| Truncated SCM_RIGHTS | Darwin installed three descriptors while returning a truncated, uniterable message: FD count increased by three. Linux already closed undelivered rights but the old datagram path lacked CLOEXEC. | Darwin receives into a private buffer large enough to observe installed rights, closes descriptors in messages that cannot fit the caller's buffer, and returns only complete messages. All delivered descriptors are valid and CLOEXEC. Linux uses atomic `MSG_CMSG_CLOEXEC`. |
| Ancillary bounds/send failures | Oversized lengths reached casts; rejected rights could reach errno panic paths. | Lengths above signed 32-bit capacity fail before dereference. Invalid rights sends return `InvalidControlMessage`; the iterator bounds advertised headers. |
| Unix address encoding | Linux abstract names gained an extra NUL; pathname capacity was not native on Darwin. | Native pathname bounds reserve the terminator; Linux abstract bytes, including embedded/trailing NULs and full 108-byte names, round-trip unchanged through `getsockname`. |
| Dispatch timed futex allocation failure | Failure after cancellation registration resumed with a stale registration and an unlinked waiter node. | Link before allocation, drain cancellation ownership before a spurious wake, or let the queued callback remove/wake. Release waiter accounting before resuming. |

The futex injection runs four cancellation timings, 16 repetitions each
in Debug and ReleaseSafe. Every case proves exactly one wake, no remaining
registration/node/waiter count, later real timer and futex reuse, group reuse
and clean deinit. The injection is test-only; production retains direct
native timer allocation.

## Acceptance results

| Gate | Result |
|---|---|
| Darwin AArch64 full `test-feature.sh` | Debug and ReleaseSafe pass; Threaded, Dispatch and Kqueue FD accounting/CLOEXEC/cancellation/reuse, native address limits, injected futex failure and existing regressions. |
| Linux AArch64 full `test-feature.sh` | Debug and ReleaseSafe pass; Threaded streams/datagrams, low-level Uring datagrams, native Unix boundaries/abstract round trips and existing regressions. |
| QUIC `zig build test` | 37/37 steps; 2079/2095 tests pass, 16 skipped. |
| QUIC `zig build test -Drelease=true` | 30/30 steps; 2035/2051 tests pass, 16 skipped. The existing guard excludes 44 benchmark fixtures; the separate bench gate covers them. |
| `bench-test`, `bench-io-build` | 12/12 steps each. |
| Formatting/tooling | `test-fmt`, diff whitespace, shell syntax, ShellCheck and all 20 tooling tests pass. |

Native receive matrices include stream/datagram direct, async and timed
paths; capacities 0, 1, a short header, one-FD space and 2048 bytes; and
maximal rights messages (Darwin 254 FDs, Linux 253). Tests close every
returned descriptor and require FD count to return to baseline. Each
supported evented backend additionally cancels 16 receives, overwrites and
reuses the buffer/socket after the cancellation barrier, and receives a
valid CLOEXEC descriptor.

Darwin and the four QUIC gates use the freshly rebuilt
`0.17.0+fork.unix-audit` compiler from the final source, with the prior
patched LLVM 22.1.4 and assertions ON. This is a local audit instrument.
Linux uses the verified published CI compiler built with the stock LLVM
bundle, paired with the modified library: native source pairing, not a
rebuilt Linux compiler. The Linux full gate preceded one test strengthening
to explicitly assert descriptor validity; final Threaded/Uring ancillary
binaries were rebuilt and rerun in both modes, all four pass, with no
standard-library implementation changes. The final Darwin full gate uses
the strengthened test. Both test-source identities are retained in JSON.

## Integration and release boundaries

Darwin's `fcntl` CLOEXEC step follows `recvmsg` and is not atomic with an
unrelated concurrent exec. The caller still owns and must close every
delivered descriptor. Rights in undelivered control messages are closed
by the backend. Expanded std networking error sets may require downstream
exhaustive switches to be updated when adopting this source.

Raw socketpairs are a regression seam, not a new public Unix pair API.
Uring's public Unix/stream operations remain unsupported; low-level raw
Unix datagram coverage does not change that contract. Keep evented
registrations, buffers and descriptors alive through completion or the
cancellation barrier, and drain groups/futures before deinit.

Threaded, stock mise Zig 0.17.0, the verified QUIC v0.42.2 pin and downstream
pins remain unchanged. `capnp-zig` activation remains owner-led. No release
assembly, `build/stable` push, retag, default-toolchain change, benchmark
measurement or LLVM upstream submission occurred. The full upstream Zig
suite and new x86_64/BSD/WASI runtime coverage are not claimed.
The remote Linux VM was restored to **Stopped**.

Raw logs remain in `benchmark-reports/unix-fd-hardening-2026-10-11/` and
the compiler checkout's `build-release/unix-hardening/`; the committed
JSON retains their hashes and essential checkpoints.

| Work | Goal | Risk | Acceptance |
|---|---|---|---|
| **Publish and validate the hardened fork — recommended** | Deliver these source fixes for owner-led adoption. | Stock-bundle builds, platform coverage and downstream exhaustive error switches require exact-release validation. | Reviewed assembly, three-platform native gates, verified artifacts and each adopting owner's actual backend paths. |
| Linux Uring profiling | Explain the prior bulk gain and evaluate multiple event loops. | Depends on adoption; scheduling changes can affect fairness/cancellation. | Paired workload/profile evidence, exact completion, shutdown/cancel checks and full gates for any code change. |
