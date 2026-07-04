#!/usr/bin/env bash
#
# Deep coverage-guided fuzzing across every fuzz site.
#
# Each site runs as its OWN `zig build fuzz-<label> --fuzz=N` process, so
# each fuzz coordinator is single-instance — the same topology as
# `zig build test --fuzz`, which is the path CI uses and the only one
# proven to work. Parallelism comes from running separate processes here,
# NOT from `zig build fuzz -j<N>`: that multiplexes N sites through one
# build-runner fuzz coordinator, which aborts upstream ("reached
# unreachable code"; ziglang/zig#25352, hard-coded n_instances = 1) on both
# Linux and macOS. See CONTRIBUTING.md "Fuzzing".
#
# NOTE: the std.testing.fuzz coverage runtime aborts on macOS regardless of
# topology (a platform gap). Run this on Linux, as CI does.
#
# Usage: scripts/fuzz-parallel.sh [ITERS] [JOBS]
#   ITERS  per-site fuzz budget passed to --fuzz (default: 1M)
#   JOBS   number of sites to fuzz concurrently (default: CPU count)
set -euo pipefail

ITERS="${1:-1M}"
JOBS="${2:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

cd "$(dirname "$0")/.."

# Enumerate the per-site steps (fuzz-<label>) that build.zig registers.
SITES="$(zig build --help 2>/dev/null | awk '/^  fuzz-/{print $1}')"
if [ -z "$SITES" ]; then
  echo "no fuzz-<label> steps found — is build.zig registering per-site steps?" >&2
  exit 1
fi
COUNT="$(printf '%s\n' "$SITES" | wc -l | tr -d ' ')"

echo "fuzzing $COUNT sites at --fuzz=$ITERS, $JOBS concurrent processes"
echo "(each site is its own single-instance coordinator; Ctrl-C to stop)"

# One `zig build` process per site, JOBS at a time. xargs exits non-zero if
# any site's process does (e.g. a crash), which is the intended gate signal.
printf '%s\n' "$SITES" \
  | xargs -P "$JOBS" -I {} zig build {} --fuzz="$ITERS"
