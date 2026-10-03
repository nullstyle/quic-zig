#!/usr/bin/env bash
set -uo pipefail

# One definition of "a real, clean deep-fuzz run", shared by the
# pre-release gate (.github/workflows/rc-fuzz.yml), the weekly job
# (.github/workflows/fuzz.yml), and `just fuzz` / `mise run fuzz`.
#
# The exit status of `zig build test --fuzz` is not evidence of anything:
#
#   - It is 0 when a fuzz site FAILS. The only trace is a log line,
#     "error: test '...' exited with code 1; input saved to
#     '.zig-cache/f/crash'". Every CI fuzz run this project made between
#     2026-08-16 and 2026-10-02 logged that line for a stale harness
#     invariant and reported success, weekly job and release gate alike.
#   - A failing site also ends the run on the spot, and the site order
#     changes per run, so the sites after it get no budget (one release
#     gate ran 203,673 of ~2M executions and passed).
#   - It is 0 when the binary carries no coverage instrumentation: the
#     run executes its whole budget, collects zero program counters, and
#     looks green (the pre-0.10.0 failure, see build.zig `-Duse-llvm`).
#
# So this script reads the evidence instead: the log for a failing site,
# and the coverage file's own header for instrumentation and run count.
# Measured on Zig 0.17.0; re-measure when the toolchain moves.
#
# usage: tools/fuzz-gate.sh <per-site budget> [log file]
#   budget   what `--fuzz=` takes: a plain integer, or a K / M suffix
#   log      where the fuzzer output is kept (default: fuzz-gate.log)
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    printf 'usage: %s <per-site budget, e.g. 50000 or 1M> [log file]\n' "$0" >&2
    exit 2
fi
iters=$1
log=${2:-fuzz-gate.log}

budget=${iters%[KkMm]}
case "$budget" in
    "" | *[!0-9]*)
        printf 'error: budget must be an integer with an optional K or M suffix, got "%s"\n' "$iters" >&2
        exit 2
        ;;
esac
case "$iters" in
    *[Kk]) budget=$((budget * 1000)) ;;
    *[Mm]) budget=$((budget * 1000000)) ;;
esac

# Count the sites instead of trusting a number in a comment.
sites=$(grep -rho 'std\.testing\.fuzz(' src --include='*.zig' | wc -l | tr -d ' ')
if [ "$sites" -eq 0 ]; then
    printf 'error: found no std.testing.fuzz sites under src/ (run from the repo root)\n' >&2
    exit 2
fi

run_fuzz() {
    zig build test -Duse-llvm=true --fuzz="$iters" 2>&1 | tee -a "$log"
    return "${PIPESTATUS[0]}"
}

# The coverage file accumulates across runs when it is kept, which would
# let an earlier run's counts satisfy this one's floor. The corpus
# (.zig-cache/f) is deliberately left alone: it is what makes a later
# run start where an earlier one stopped.
rm -rf .zig-cache/v
rm -f .zig-cache/f/crash
: > "$log"

status=0
run_fuzz || status=$?

# Long limit-mode runs can leave a coverage file with an empty PC table
# and die with "pcs_len was zero". That is runner metadata, not a
# finding, so it earns exactly one retry on a clean coverage directory.
if [ "$status" -ne 0 ] && grep -q "corrupted coverage file .*pcs_len was zero" "$log"; then
    echo "::warning::Zig fuzz coverage metadata was corrupted; retrying once with a clean coverage directory"
    rm -rf .zig-cache/v
    status=0
    run_fuzz || status=$?
fi

failed=0
if [ "$status" -ne 0 ]; then
    echo "::error::zig build test --fuzz exited with status $status"
    failed=1
fi

# Checked across both attempts on purpose: a retry must not launder a
# failing site out of the first one.
site_failure='exited with code|terminated with signal|input saved to'
if grep -Eq "$site_failure" "$log" || [ -e .zig-cache/f/crash ]; then
    echo "::error::a fuzz site failed (zig build exits 0 regardless):"
    grep -E "$site_failure" "$log" | sort -u
    echo "The input is in .zig-cache/f/ (CONTRIBUTING.md \"Regression corpus\" says where and what to do with it)."
    failed=1
fi

# Always print the coverage numbers, including after a failure: that is
# when it matters most whether the run was instrumented and how far it got.
min_runs=$((sites * budget * 9 / 10))
python3 - "$sites" "$budget" "$min_runs" <<'PY' || failed=1
import glob, struct, sys

sites, budget, min_runs = (int(a) for a in sys.argv[1:4])
files = sorted(glob.glob(".zig-cache/v/*"))
if not files:
    sys.exit("::error::no coverage file was produced; the fuzz run did not report coverage")
bad = False
total_runs = 0
for f in files:
    b = open(f, "rb").read()
    if len(b) < 24:
        print(f"::error::{f} is {len(b)} bytes, too short to hold a coverage header")
        bad = True
        continue
    n_runs, unique_runs, pcs_len = struct.unpack("<QQQ", b[:24])
    total_runs += n_runs
    print(f"{f}: {len(b)} bytes n_runs={n_runs:,} unique_runs={unique_runs:,} pcs_len={pcs_len}")
    if pcs_len == 0:
        print(f"::error::{f} reports pcs_len=0 — the binary ran with NO coverage instrumentation, so this run proves nothing")
        bad = True
if total_runs < min_runs:
    print(f"::error::only {total_runs:,} executions for {sites} sites x {budget:,} (floor {min_runs:,}): the run stopped early")
    bad = True
if bad:
    sys.exit(1)
print(f"coverage verified: instrumented, {total_runs:,} executions across {sites} sites (floor {min_runs:,})")
PY

exit "$failed"
