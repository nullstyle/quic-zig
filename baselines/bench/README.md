# Committed benchmark baselines

Tracked reference points for `zig build bench-compare`. Each file is a
benchmark JSON report (the `bench/report.zig` schema, v3+) captured on a
named machine class; the filename is the machine class:

- `github-ubuntu-x64.json` — GitHub-hosted `ubuntu-latest` runners; what
  `.github/workflows/benchmark.yml` compares against (advisory).
- `<local-machine>.json` — optional developer baselines for same-machine
  A/B during perf work (name them after `BENCH_MACHINE_ID`).

Comparisons are only meaningful within a machine class — never compare a
laptop run against the CI baseline.

## Comparing

```sh
zig build bench -- --json /tmp/new.json --samples 9
zig build bench-compare -- --baseline baselines/bench/github-ubuntu-x64.json --new /tmp/new.json --advisory
```

A regression requires the new median to be worse than baseline by more
than the tolerance (default 10%) AND by more than 3x the baseline's MAD
(the noise floor). Direction is metric-aware: ns/op regresses upward,
MB/s and handshakes/sec regress downward.

## Refreshing

Refreshing a baseline is a deliberate act tied to a commit that
legitimately moves a number — never a drive-by. Policy (see the sprint
verification protocol): the commit that changes performance updates the
baseline in the same commit, with before/after medians in its message.

```sh
just bench-baseline-refresh          # runs 3x, keeps the element-wise best-of-median run
```

The recipe runs the suite three times at `--samples 9` and keeps the run
whose total median is lowest (least-loaded pass), then writes it over
the local machine-class file. Inspect the diff before committing; raw
reports stay untracked (`benchmark-reports/` is gitignored).
