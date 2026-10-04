#!/bin/sh
# The build-mode contract of the quic package, as a consumer sees it.
# Runs the consumer smoke's configure-time guard (`zig build check`:
# nothing is compiled) for each way to pass a mode, in each mode.
#
#   wiring     application mode   quic-zig must build in
#   release    Debug              Debug
#   release    ReleaseSafe        ReleaseSafe
#   release    ReleaseFast        ReleaseSafe
#   optimize   Debug              Debug
#   optimize   ReleaseSafe        ReleaseSafe
#   optimize   ReleaseFast        REFUSED (the build must stop)
#
# Why it exists: through 0.24.0 `optimize` was not an option of the
# package, Zig reported it and went on, and quic-zig was built in Debug
# inside release builds. The CI step that could have seen it printed
# `error: invalid option: "optimize"` in every run and passed. So this
# script also fails on that line.
#
# usage: sh tools/consumer-smoke/check-modes.sh   (from anywhere)
set -u
cd "$(dirname "$0")" || exit 1
ZIG="${ZIG:-zig}"
failures=0
log="$(mktemp)"

run() { # <wiring> <mode> <expect: ok|refused>
    wiring="$1"; mode="$2"; expect="$3"
    "$ZIG" build check "-Dwiring=$wiring" "-Doptimize=$mode" > "$log" 2>&1
    code=$?
    if grep -q 'invalid option' "$log"; then
        echo "FAIL  wiring=$wiring mode=$mode: the build reported an invalid option"
        failures=$((failures + 1))
    elif [ "$expect" = ok ] && [ "$code" -ne 0 ]; then
        echo "FAIL  wiring=$wiring mode=$mode: exit $code"
        grep -m1 -E 'panic|error' "$log"
        failures=$((failures + 1))
    elif [ "$expect" = refused ] && [ "$code" -eq 0 ]; then
        echo "FAIL  wiring=$wiring mode=$mode: the build was not refused"
        failures=$((failures + 1))
    elif [ "$expect" = refused ] && ! grep -q 'ReleaseFast/ReleaseSmall are unsupported' "$log"; then
        echo "FAIL  wiring=$wiring mode=$mode: stopped, but not with the build-mode message"
        grep -m1 -E 'panic|error' "$log"
        failures=$((failures + 1))
    else
        echo "ok    wiring=$wiring mode=$mode ($expect)"
    fi
}

run release Debug ok
run release ReleaseSafe ok
run release ReleaseFast ok
run optimize Debug ok
run optimize ReleaseSafe ok
run optimize ReleaseFast refused

rm -f "$log"
if [ "$failures" -ne 0 ]; then
    echo "check-modes: $failures of 6 failed"
    exit 1
fi
echo "check-modes: 6 of 6 as expected"
