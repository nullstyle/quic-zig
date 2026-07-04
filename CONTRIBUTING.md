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
- **Deep, coverage-guided (Linux).** CI runs `zig build test --fuzz=$ITERS`
  weekly on Linux (`.github/workflows/fuzz.yml`). Run it locally the same
  way, optionally narrowing to one site:
  `zig build test --fuzz=1M --test-filter "fuzz: open1Rtt"`.

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

- The parallel breadth step `zig build fuzz -j<N>` (one binary per site)
  currently aborts under the Zig fuzz coordinator ("reached unreachable
  code") on both Linux and macOS — an upstream limitation
  (ziglang/zig#25352, hard-coded `n_instances = 1`). Use the
  single-instance `zig build test --fuzz` path above for deep runs until it
  is resolved.
- On macOS the `std.testing.fuzz` coverage-guided runtime aborts even
  single-instance (reproduced with a trivial standalone test on
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
