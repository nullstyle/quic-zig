# Sprint 4: fixed-runtime stack qualification

Sprint 4 qualifies committed Sprint 3 source
`43c2390557c47f48e6c28e07a31efdb2b6723478` on
`codex/sprint-4-stack-qualification`. It introduces no transport implementation,
public API, module-option, dependency-pin, package-version or default-policy
change. Stock Zig 0.17.0 and the Threaded backend remain the configuration.

The source/build subset is exactly `src/**`, `build.zig` and `build.zig.zon`:
124 files with canonical byte digest
`6fad282fb75f66f935381dfe84e4e5fcc6f66167cee6165ca978c81db984d5e5`.
The digest uses the composition checker's sorted path-length/path and
content-length/content encoding. It includes the Sprint 3 idle-cache repair
and its bidi/uni, duplicate-suppression and public stream-credit regressions.
Documentation and qualification records are separate from this runtime identity.

## Executed gates

The producer records under `benchmark-reports/sprint-4-2026-10-26/` retain
commands, timestamps, exits, logs, source and harness hashes, compiler identities,
dependency inputs and the final archive identity. The coordinated qmesh evidence
index records the complete stack checkpoint. Counts from cached tests stay
separate from newly executed tests.

| Gate | Evidence |
|---|---|
| Mac Debug / ReleaseSafe | 37/37 and 30/30 build steps; previously qualified results reused only after verifying the unchanged runtime identity. |
| Mac full C sanitizer | Fresh 37/37 steps; 2,076/2,092 tests passed, with 16 existing conformance skips. |
| Linux arm64 Debug / ReleaseSafe | Fresh container execution: 2,091/2,107 and 2,047/2,063 tests passed, respectively, with 16 existing conformance skips in each mode. |
| Linux full C sanitizer | Fresh 37/37 steps; 2,091/2,107 tests passed, with the same 16 skips. |
| Examples, benchmark fixtures and autodocs | 35/35 build steps. |
| Native Mac UDP | Exact 24-byte stream and 4,172-byte datagram echoes; exact 16 MiB upload with acknowledged FIN and clean shutdown. Throughput is informational. |
| Consumer module identity and modes | Out-of-tree Debug and ReleaseSafe binaries each run successfully; all six build-mode guard outcomes match the contract. |
| Windows x86-64 / Linux x86-musl | Existing cross-compilation recipes pass, including test-binary compilation. Neither foreign test binary executes on this Mac. |
| Linux coverage-guided fuzz | 50,000 inputs per site across 43 sites; 2,176,255 executions, 13,693 unique runs, 48,236 instrumented PCs and 6,008 covered PCs. The 1,935,000 execution floor and failure-marker checks pass. |
| Strict pinned quic-go interop | Client and server roles each execute handshake and transfer: four successful cells, zero failed, skipped or unsupported cells. |

Mac execution uses stock compiler SHA256
`1c5f706db0ed6d55451940f31dc05a6177d05696bc1fa5d853696d04c718b523`.
The Linux arm64 container uses stock compiler SHA256
`5165c9a2d17938a8173839b3adf81d025b558d38d9e9711237a6fa5b8d8bb3f7`.
The Linux compiler is independently checked inside the image; it is not the
Mac executable. The fuzz recipe enables LLVM and verifies coverage metadata
rather than trusting `zig build test --fuzz`'s exit status.

Interop builds a fresh candidate QNS endpoint with the existing Dockerfile,
uses runner `1d6f6554ac8e3b7c4cca0e3d40fd69f661420673` and the pinned quic-go
image digest from the hard-gate workflow. Endpoint source, image and executable
identities accompany the result files. The quic-go peer image is Linux amd64
under Docker's compatibility support; the candidate endpoint is Linux arm64.
These are local container tests, not hosted CI or physical-network evidence.

## Fairness disposition

The six held virtual-time fairness cells were freshly run against the fixed
candidate and a clean local Git archive of verified release v0.42.2
(`2aa5bae31b7eab42cf95a654ab9717248d6f2498`). The fairness entry point, algorithm
and SimNet sources are byte-identical. The common harness differs only in a
churn helper that these fairness cells do not call. Both lanes use stock
0.17.0, ReleaseSafe, identical fixed seeds and the same virtual measurement
windows. Every candidate result repeats the prior held observation exactly.

| Cell | Released Jain index | Fixed candidate |
|---|---:|---:|
| Two CUBIC flows | 1.0000 | 0.9916 |
| Two BBR flows | 0.9996 | 0.9992 |
| Four BBR flows | 0.9960 | 0.9951 |
| BBR with a staggered joiner | 0.9999 | 0.9996 |
| Mixed BBR/CUBIC, deep buffer | 0.8914 | 0.8233 |
| Mixed BBR/CUBIC, shallow buffer | 0.9691 | 0.9236 |

All six retain progress in every flow, utilization above 0.5 and Jain above
0.5. Those are broad machinery checks, not a maintained numeric promotion
criterion. `bench-compare` has no fairness metric; its default 10% headline
tolerance therefore cannot accept these share changes. The cause and
acceptance of the inherited main-only difference remain unresolved. Prior
RTT-eligibility and handshake-confirmation controls excluded only those two
hypotheses.

Local runtime and consumer-contract qualification can pass while the
**promotion hold remains**. Keep the current controller defaults and policies;
an explicit fairness review or approved acceptance criterion is still required
before treating this comparison as promotion evidence.

## Migration and package handoff

There is no QUIC API, toolchain or backend migration for this source candidate.
The Sprint 3 correction restores prompt transmission when a failed stream
open queues `STREAMS_BLOCKED` or public code queues `MAX_STREAMS`. Applications
retain their existing owner loop and deadlines; an application sleep is not a
transport repair.

Every parent in one binary must select the same QUIC source and pass the same
`{target, release, sanitize-c = "trap"}` options. Import `quic` and `boringssl`
from that one dependency instance. For local composition, identify the candidate
archive by its recorded SHA256, verify the extracted files against the frozen
source, and run the out-of-tree consumer with the packaged source. Its retained
version string, 0.42.2, does not identify an unpublished archive.

The published release guidance remains v0.42.2. Existing qmsg/qmesh v0.37.2 pins
stay unchanged and remain an immutable negative control for the inherited
idle-cache defect; that correctness control is separate from the v0.42.2
fairness comparison. This sprint authorizes no release, publication or pin move.
Native Windows, native Linux x86-64, hosted tier-1 CI and physical-network
behavior remain outside these local results.

## Follow-up recommendation

| Problem | Proposed work | Goal | Scope and risk | Validation |
|---|---|---|---|---|
| **Recommended: inherited mixed-share promotion hold** | Isolate the main-only fairness difference against v0.42.2, then review an explicit acceptance criterion. | Explain the changed shares before promotion. | Bounded source controls first; changing congestion policy can trade fairness, latency and throughput. | The same six deterministic cells, exact source/options, per-flow bytes and shares; full gates for any resulting transport change. |
| Hosted platform evidence is absent for this source | Run the existing tier-1 workflows when remote execution is authorized. | Obtain native Windows and Linux x86-64 evidence. | Keep local/container/cross results separate; no release or pin move follows automatically. | Exact-commit job logs, test counts and the interop evidence line. |
