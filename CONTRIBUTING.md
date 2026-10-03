# Contributing to quic-zig

Thanks for your interest in quic-zig.

quic-zig is pre-1.0. It is a QUIC transport library for embedding,
interop work, and implementation research; 0.x releases may include
breaking API changes.

## Local Setup

The repository pins its toolchain with [`mise`](https://mise.jdx.dev/).

```sh
mise install
zig build
```

`zig build` produces the QNS endpoint and the external interop helper.

## Tests

```sh
zig build test
zig build conformance
zig build conformance -Dconformance-filter='RFC9000'
zig build bench
```

`zig build test` runs unit, integration, conformance, QNS endpoint, and
deterministic fuzz-smoke coverage. `zig build conformance` runs the
auditor-facing RFC corpus directly. `zig build bench` runs the
microbenchmark harness.

### Cross-platform code

If you touch anything platform-conditional — sockopts, cmsg layouts,
the UDP loops — also run:

```sh
just check-windows
```

Windows is tier-1 and release-gating, but only CI can run it natively,
so a break there costs a full round trip. Note that a bare
`zig build -Dtarget=x86_64-windows` is **not** sufficient: it builds
the library and examples without ever compiling the test binaries, so
platform-specific code reachable only from a test compiles nowhere
locally. That exact gap turned the windows-latest leg red during
0.11.0 — `std.c.cmsghdr` is `void` on Windows, and the new GSO/GRO
helpers were pulled in by their own tests. The recipe compiles the
test binaries too; a host that cannot execute the resulting binaries
is expected and ignored.

## Fuzzing

Fuzz targets live inline next to the code they exercise, as
`test "fuzz: ..."` blocks driving `std.testing.fuzz`. They run in two
modes:

- **Smoke (every commit).** `zig build test` executes each fuzz target
  against its seed `.corpus` (and a default input). This is part of the CI
  gate (`.github/workflows/test.yml`), so a seed that panics or trips a
  safety check fails the build like any other test.
- **Deep, coverage-guided (Linux).** Run `tools/fuzz-gate.sh $ITERS`
  (`just fuzz` / `mise run fuzz`), which is exactly what CI runs weekly on
  Linux (`.github/workflows/fuzz.yml`). It wraps
  `zig build test -Duse-llvm=true --fuzz=$ITERS` and judges the run on
  its log and coverage header, because the command's own exit status
  says nothing (see "Toolchain caveats"). The fuzzer gives every
  `std.testing.fuzz` site in the unfiltered test binary its own budget.
  Limit mode is single-instance (see caveats), so it saturates one core;
  give it a large `$ITERS` and let it run.
- **Pre-release gate.** Before a release is tagged, a completed green run
  of `.github/workflows/rc-fuzz.yml` must exist for the release commit.
  Default budget is `50000` per site (40 sites as of 2026-10-02, so ~2M
  executions; the gate counts the sites itself with
  `grep -rho 'std\.testing\.fuzz(' src --include='*.zig' | wc -l` rather
  than trusting this sentence). Unlike the weekly fuzz job, this gate is
  blocking. Anyone — maintainer, contributor, or an agent session — can
  dispatch it (`gh workflow run rc-fuzz.yml --ref <ref>`) and tag on
  green; the gate is about the evidence existing, not about who pushes
  the button.

  It used to be `1M` (~5 hours) and that was the wrong trade. Measured
  on the pinned toolchain: coverage is 8.81% at 39k executions and 9.48%
  at 37.1M — **0.67 percentage points for ~950x the work**, with unique
  runs plateauing near 12.5k. A blocking gate that costs half a day
  buys under a point of coverage and, empirically, means releases don't
  get tagged at all (v0.8.0 and v0.9.0 both shipped untagged). Deep
  exploration belongs to the weekly `fuzz.yml` job at `1M` per target
  (~37M executions, ~5 hours — the largest budget that fits GitHub's 6-hour
  job cap; this line used to say `10M`, which would be ~50 hours and was
  never actually runnable), which runs regardless of the release calendar.

  What the release gate is for, and still does at `50000`: prove the fuzz
  harness is genuinely instrumented on this commit, and catch a failing
  site or corpus regression before a tag. It trusts none of that to the
  exit status, which has fooled it twice. An uninstrumented run executes
  the whole budget and looks green — that is how the gate produced no
  signal for two weeks before 0.10.0. And a run with a *failing site*
  exits 0 as well: from v0.14.0 through v0.21.1 every gate run — eight
  of them — logged one (a stale invariant in the CID-lifecycle harness),
  stopped at a fraction of its budget, and passed. `tools/fuzz-gate.sh` now fails the run on
  the failing-site log line, on a run count below 90% of sites x budget,
  and on a missing or zero-`pcs_len` coverage file, and prints the
  coverage numbers either way. Raise the budget for an RC or 1.0 if you
  want more; the default is tuned for "tag a 0.x release in half an hour".

### Regression corpus

There is no separate corpus directory: seed inputs are committed inline in
each target's `.corpus` array. When deep fuzzing finds a crash, **minimize
the input and add it to that target's `.corpus`** — it then runs on every
`zig build test` and is gated by CI, turning a one-off finding into
permanent per-commit regression coverage.

Where the failing input is: the log line names `.zig-cache/f/crash`, but
on Zig 0.17.0 that file is cut to a multiple of 512 bytes — empty for
most harness inputs — because the runner does not flush its last buffer.
The whole input is still in the instance's input file,
`.zig-cache/f/in0`: a 20-byte header (the input length is the
little-endian `u32` at offset 16), then the input. Both fuzz workflows
upload all of `.zig-cache/f`.

How a seed is encoded: with no fuzzer attached, `std.testing.Smith` reads
every integer draw (`value`, `valueRangeAtMost`, ...) as one 8-byte
little-endian word, and every `bytes` draw as raw bytes, in the order the
harness draws them; `slice` reads a 4-byte length first. A seed for a
parser is therefore just the bytes (see `src/wire/varint.zig`); a seed
for a state-machine harness is easier to read built at comptime from the
operations it encodes (see `cid_limit_seed` in
`src/Connection/_tests_fuzz.zig`).

A harness invariant that lists the *allowed* outcomes of a handler (close
codes, event reasons) needs a seed for each outcome the handler can
produce. Otherwise only the deep fuzzer exercises the list, and it goes
stale silently the day the handler changes — which is how the CID
harness's close-code set outlived the code it described.

Corpus hygiene: seeds are protocol bytes, never secrets. Do not paste a
real key, token, or ticket into a `.corpus` entry — synthesize the shape
you need (the crypto targets derive keys from fixed test secrets in the
harness itself).

### Toolchain caveats

Measured on Zig 0.17.0 unless a bullet says otherwise. Re-measure when the
toolchain moves: two of these described a bug that a later Zig fixed, and
the note outlived the bug.

- **`zig build test --fuzz` exits 0 when a site fails, and stops there.**
  The only trace is a log line, `error: test '...' exited with code 1;
  input saved to '.zig-cache/f/crash'`. The run also ends at the failing
  site, and the site order changes from run to run, so the sites after it
  get none of their budget. `tools/fuzz-gate.sh` exists because of this;
  never gate anything on the bare command.
- **Per-site fuzz binaries work again; none exist yet.** On
  0.17.0-dev.1158, a test binary built with a filter
  (`addTest(.filters = ...)`) aborted the build runner with "reached
  unreachable code" as soon as it ran under `--fuzz`
  (ziglang/zig#25352), which is why there is no per-site or `-j<N>`
  parallel fuzz step. On 0.17.0 a filtered binary fuzzes cleanly (probe:
  three sites, one selected by filter, full budget). Limit mode
  (`--fuzz=N`) is still single-instance (`n_instances = 1`); only forever
  mode (`--fuzz`) uses every core.
- **macOS deep-fuzzing works.** On 0.17.0-dev.1158 the coverage-guided
  runtime aborted on macOS. On 0.17.0, `tools/fuzz-gate.sh 1000` completes
  on aarch64-macOS with real coverage (verified: 49,770 runs, 1,908
  unique, 3405/40622 PCs = 8.38%). Re-check before assuming a platform
  gap, and prefer Linux only for long runs, since that is what CI does.
- **x86_64 needs `-Duse-llvm=true`.** Only the LLVM backend emits the
  sancov sections the fuzzer reads, and x86_64 defaults to the self-hosted
  backend: an x86_64-linux `-ffuzz` test binary has 0 sancov sections by
  default and 2 with `-fllvm`. `tools/fuzz-gate.sh` passes the flag; the
  build.zig comment on `use-llvm` has the history.
- **Do not add `-ffuzz` / `Module.fuzz` by hand.** `--fuzz` already sets
  the compilation-level flag on the *root* module, and every
  `std.testing.fuzz` site lives in `src/`, which is the root module of
  `zig build test`. Forcing the per-module flag instead instruments
  `quic` where it is a non-root *dependency* (`tests/`,
  `tests/conformance.zig`, `interop/`, the `examples/` targets), and those
  binaries' test runners are compiled with `builtin.fuzz == false`, so the
  seven `export fn runner_*` hooks in Zig's `lib/compiler/test_runner.zig`
  are never emitted while `lib/fuzzer.zig` still links — 7 undefined
  symbols, on Linux and macOS alike. It looks like a platform bug and is
  not one.
- **Verify a deep-fuzz run was real** rather than trusting exit status.
  `tools/fuzz-gate.sh` does it for you and prints the numbers. To read a
  coverage file by hand: a populated one is large (~330 KB here); a
  24-byte one is a header with `pcs_len = 0`, i.e. the truncated-artifact
  flake below, not a run with no instrumentation:

  ```sh
  python3 -c 'import struct,glob
  for f in glob.glob(".zig-cache/v/*"):
      b=open(f,"rb").read(); n,u,p=struct.unpack("<QQQ",b[:24])
      print(f, len(b), f"n_runs={n:,} unique_runs={u:,} pcs_len={p}")'
  ```
- Long Linux limit-mode runs have occasionally left an empty-PC coverage
  metadata file in `.zig-cache/v` and failed with "corrupted coverage file
  ... pcs_len was zero" (seen on 0.17-dev builds; not re-observed on
  0.17.0 yet, and not ruled out). `tools/fuzz-gate.sh` treats only that
  runner metadata failure as retryable: it deletes `.zig-cache/v` and
  reruns once. A failing site in either attempt, or a repeated coverage
  failure, still fails the gate.

## Interop

The external interop wrapper drives the official
[`quic-interop-runner`](https://github.com/quic-interop/quic-interop-runner).

```sh
zig build external-interop -- runner --dry-run
zig build external-interop -- runner --build-image
zig build external-interop -- runner --clients quic-go --tests H,D
zig build external-interop -- runner --role client --servers quic-go --tests H,D
```

See [interop/README.md](https://github.com/nullstyle/quic-zig/blob/main/interop/README.md) for the full command surface
and generated-artifact locations.

## Releases

Downstream projects pin quic-zig by version and hash; these rules exist
so the version string never lies to them. They constrain the *releases*,
not the maintainer's time: every mechanical step here (dispatching the
fuzz gate, prepping the changelog, tagging, pushing) is expected to be
driven by tooling or agent sessions. The only step that requires the
maintainer is the decision to cut a release; a session told "cut X.Y.0"
should be able to run the rest end-to-end. (v0.8.0 and v0.9.0 predate
this policy and shipped untagged — that's recorded as closed in
RELEASE_READINESS.md, not an open item.)

- **Every release gets a tag** (`vX.Y.Z`), including hardening and patch
  releases. Only tagged commits are advertised as consumable — a bare
  commit SHA between tags carries no compatibility promise. (Release
  tags additionally wait for the rc-fuzz gate above and the platform
  tiers in [docs/RELEASE_READINESS.md](https://github.com/nullstyle/quic-zig/blob/main/docs/RELEASE_READINESS.md).)
- **Any breaking change to the public surface bumps the manifest
  version** — pre-1.0 that means the minor (`0.x` → `0.(x+1)`) — in the
  same change that lands the break, using a `-dev` pre-release suffix
  (e.g. `0.10.0-dev`) until the release-prep commit finalizes it. A
  consumer pinning an untagged commit then at least sees the bump in
  the package hash instead of a silent same-version surface change.
- **Breaking changes go under `### Changed (BREAKING)`** in
  CHANGELOG.md, with a migration note. A `minimum_zig_version` bump is
  a breaking change: consumers pin their own toolchain, and a floor
  move is exactly as build-breaking for them as an API rename.
- **When a config field's meaning changes incompatibly, rename it**
  (or add a new field and deprecate the old one) so consumers get a
  compile error, not a silent behavior change. Avoid `?T` where `null`
  would have to mean both "not configured" and "feature off" — spell
  the states out in a union/enum, as `Server.RateLimit` and
  `Server.EarlyData` do. Prefer making a dangerous configuration
  unrepresentable over catching it with a runtime `InvalidConfig`
  check; `docs/API_STABILITY.md` carries the full rule.

## File layout: hubs, siblings, and leaves

The two big aggregates (`Connection` in `src/Connection.zig`, `Server`
in `src/Server.zig`) are composed across files using the same
hub-and-spokes idiom as Zig's standard library (`std/fs.zig` and
friends back-import `std.zig` while it forward-imports them; Zig's
lazy per-decl resolution makes the mutual import well-formed, and
`usingnamespace` no longer exists as an alternative). The canonical
per-file ownership map lives at the top of `src/Connection.zig`.

Rules that keep the seam clean:

1. **Hub files own the struct**: fields, construction, lifecycle,
   public API, and thin delegating thunks. Method bodies live in
   sibling free-function files taking the hub type (`*Connection`,
   `*Server`) as their first argument.
2. **A sibling's back-import may reach only hub-owned things**: the
   hub type, its nested `Type.X` API, and constants/helpers whose
   semantics belong to the hub (e.g. `max_tracked_cids_per_slot`
   sizes `Server.Slot`'s own array). If the thing you're reaching is
   declared in — or conceptually belongs to — another sibling, rule 3
   applies instead.
3. **Sibling-to-sibling needs are direct imports**, never
   round-tripped through the hub's namespace or a hub method thunk.
   Mark such decls `// INTERNAL: pub for direct sibling import
   (<file>)`.
4. **Hub-independent helpers live in leaf files** with no back-import
   (example: `src/Server/wire_peek.zig` — pure byte-in/value-out wire
   peeking). A leaf that imports the hub is not a leaf; if a helper
   needs the hub, it belongs in a sibling method file.
5. **Thunk retention** (established in 95a4472): a hub method thunk
   is kept only if it has callers in tests, examples, bench, the QNS
   endpoint, or `src/` outside the hub's own directory — or is
   documented embedder API. Sibling-only thunks are demoted to direct
   free-function calls.

An unreferenced alias to a nonexistent decl compiles silently (lazy
analysis) and detonates on first use — when you delete a decl, grep
for aliases to it rather than trusting the build.

Mechanical restyle commits (whole-file de-indents, rename-only moves)
are listed in `.git-blame-ignore-revs`; run `git config
blame.ignoreRevsFile .git-blame-ignore-revs` once locally and `git
blame` skips them (GitHub's blame UI honors the file automatically).

## Style

- Keep one logical change per commit.
- Prefer existing module boundaries and helper APIs.
- Keep tests proportional to risk. Shared behavior, public APIs, and
  protocol invariants deserve focused regression coverage.
- Use RFC references in tests and comments when the behavior is driven by
  normative text.
- Keep public docs stable and usage-oriented. Investigation notes, local
  matrix snapshots, and scratch output should stay out of tracked docs.

## Pull Requests

Pull requests should include:

- A concise summary of behavior changed.
- The tests or interop commands run.
- Any known gaps or follow-up work.
- Notes about public API or wire-format compatibility when relevant.
