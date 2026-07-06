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

## Fuzzing

Fuzz targets live inline next to the code they exercise, as
`test "fuzz: ..."` blocks driving `std.testing.fuzz`. They run in two
modes:

- **Smoke (every commit).** `zig build test` executes each fuzz target
  against its seed `.corpus` (and a default input). This is part of the CI
  gate (`.github/workflows/test.yml`), so a seed that panics or trips a
  safety check fails the build like any other test.
- **Deep, coverage-guided (Linux).** Run `zig build test --fuzz=$ITERS`
  (`just fuzz` / `mise run fuzz`), which is exactly what CI runs weekly on
  Linux (`.github/workflows/fuzz.yml`). The fuzzer rotates across every
  `std.testing.fuzz` site in the unfiltered test binary. It is
  single-instance (see caveats), so it saturates one core; give it a large
  `$ITERS` and let it run.
- **Pre-release gate.** Before tagging a release candidate, RC-prep release,
  or final 1.0 release, manually run `.github/workflows/rc-fuzz.yml` with the
  default `1M` iteration budget or higher. Unlike the weekly fuzz job, this
  workflow is blocking and must be green before tagging.

### Regression corpus

There is no separate corpus directory: seed inputs are committed inline in
each target's `.corpus` array. When deep fuzzing finds a crash, **minimize
the input and add it to that target's `.corpus`** — it then runs on every
`zig build test` and is gated by CI, turning a one-off finding into
permanent per-commit regression coverage.

Corpus hygiene: seeds are protocol bytes, never secrets. Do not paste a
real key, token, or ticket into a `.corpus` entry — synthesize the shape
you need (the crypto targets derive keys from fixed test secrets in the
harness itself).

### Toolchain caveats

- **Only the unfiltered binary can be fuzzed.** On 0.17.0-dev.1158, a test
  binary built with a filter (`addTest(.filters = ...)`) aborts the
  build-runner with "reached unreachable code" as soon as it runs under
  `--fuzz`, while the unfiltered `zig build test --fuzz` runs cleanly
  (confirmed on Linux: unfiltered exits 0 with 750k+ runs; a single
  filtered site exits 1 on the same tree). So there is deliberately no
  per-site or `-j<N>` parallel fuzz step — those all rely on filtered
  binaries. Deep fuzzing is single-instance (n_instances = 1;
  ziglang/zig#25352) until upstream fixes filtered-binary fuzzing or lifts
  the instance cap.
- On macOS the `std.testing.fuzz` coverage-guided runtime aborts even the
  unfiltered binary (reproduced with a trivial standalone test on
  0.17.0-dev.1158 — a platform gap, not a target bug). Deep-fuzz on Linux
  or a Linux container; the smoke run works everywhere.

## Interop

The external interop wrapper drives the official
[`quic-interop-runner`](https://github.com/quic-interop/quic-interop-runner).

```sh
zig build external-interop -- runner --dry-run
zig build external-interop -- runner --build-image
zig build external-interop -- runner --clients quic-go --tests H,D
zig build external-interop -- runner --role client --servers quic-go --tests H,D
```

See [interop/README.md](interop/README.md) for the full command surface
and generated-artifact locations.

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
