set shell := ["bash", "-euo", "pipefail", "-c"]

qns_image := env_var_or_default("QUIC_ZIG_IMAGE", "quic-zig-qns:local")
runner_dir := env_var_or_default("RUNNER_DIR", "../quic-interop-runner")
interop_clients := env_var_or_default("CLIENTS", "quic-go,ngtcp2,quiche")
interop_servers := env_var_or_default("SERVERS", "quic-go,ngtcp2,quiche")
interop_tests := env_var_or_default("TESTS", "H,D")
remote_host := env_var_or_default("REMOTE_HOST", "root@quic-zig-interop")
remote_dir := env_var_or_default("REMOTE_DIR", "/root/quic-interop-runner")
remote_python := env_var_or_default("REMOTE_PYTHON", "/root/quic-interop-runner/.venv/bin/python3")
remote_image := env_var_or_default("REMOTE_IMAGE", "ghcr.io/nullstyle/quic-zig-qns:latest")
mainstream_impls := env_var_or_default("MAINSTREAM_IMPLS", "quic-go,ngtcp2,quiche,picoquic,aioquic,msquic,neqo,quinn,s2n-quic,lsquic,xquic")
feature_clients := env_var_or_default("FEATURE_CLIENTS", "quic-go,ngtcp2,quiche")
feature_tests := env_var_or_default("FEATURE_TESTS", "handshake,transfer,chacha20,retry,resumption,zerortt,multiplexing,keyupdate,longrtt")

default:
    @just --list

check-tools:
    @command -v zig >/dev/null || { echo "missing zig"; exit 1; }
    @echo "tools ok: $(zig version)"

# Run the full quic-zig test suite (currently: smoke).
test:
    zig build test

# Deep coverage-guided fuzzing (single-instance, unfiltered). ITERS = input
# budget. The fuzzer rotates across all sites in the unfiltered test binary.
# -Duse-llvm matches CI: the self-hosted x86_64 backend emits no sancov.
fuzz iters="1M":
    zig build test -Duse-llvm=true --fuzz={{iters}}

# Compile-only check against a tier-1 platform we can't run locally.
#
# `zig build -Dtarget=...` alone is NOT this check: it builds the
# library and examples but never compiles the test binaries, so
# platform-specific code reachable only from a test is invisible to
# it. That gap shipped a broken windows-latest leg once already (the
# GSO/GRO cmsg helpers, whose `std.c.cmsghdr` is `void` on Windows).
# The `run test` steps are expected to fail here — a macOS or Linux
# host cannot execute a Windows binary — so only compile errors count.
check-windows:
    #!/usr/bin/env bash
    set -uo pipefail
    zig build -Dtarget=x86_64-windows --summary all || exit 1
    echo "--- test binaries: compile-only ---"
    # The only tolerated error is the host refusing to run a foreign
    # binary; anything else is a real compile failure.
    errs=$(zig build test -Dtarget=x86_64-windows 2>&1 \
        | grep "error:" | grep -v "unable to execute binaries")
    if [ -n "$errs" ]; then
        echo "$errs"
        echo "WINDOWS COMPILE ERRORS (above)"
        exit 1
    fi
    echo "windows cross-compile clean"

clean:
    rm -rf .zig-cache zig-out

# Refresh the local benchmark baseline: 3 runs at --samples 9, keep the
# least-loaded pass (lowest sum of medians), write it to
# baselines/bench/<machine>.json. Inspect the diff before committing.
bench-baseline-refresh machine=`hostname -s`:
    mkdir -p benchmark-reports
    for i in 1 2 3; do zig build bench -- --samples 9 --json "benchmark-reports/baseline-candidate-$i.json"; done
    python3 -c "$(printf '%s\n' \
        'import json, sys' \
        'cands = [json.load(open(f"benchmark-reports/baseline-candidate-{i}.json")) for i in (1, 2, 3)]' \
        'best = min(cands, key=lambda r: sum(b.get("median_ns_per_op", b.get("ns_per_op", 0.0)) for b in r["benchmarks"]))' \
        'json.dump(best, open("baselines/bench/{{machine}}.json", "w"), indent=1)' \
        'print("wrote baselines/bench/{{machine}}.json")')"

# Build the local QNS image from this checkout.
interop-build-image:
    zig build external-interop -- build-image --image "{{qns_image}}"

# Run quic-zig as a QNS server against external clients.
interop:
    zig build external-interop -- runner --role server --runner-dir "{{runner_dir}}" --image "{{qns_image}}" --clients "{{interop_clients}}" --tests "{{interop_tests}}"

# Run quic-zig as a QNS client against external servers.
interop-client:
    zig build external-interop -- runner --role client --runner-dir "{{runner_dir}}" --image "{{qns_image}}" --servers "{{interop_servers}}" --tests "{{interop_tests}}"

interop-both: interop interop-client

interop-features:
    CLIENTS=quic-go TESTS=H,D,C,S,R,Z,M just interop

interop-loss:
    CLIENTS=quic-go TESTS=loss just interop

interop-loss-client:
    SERVERS=quic-go TESTS=transferloss,blackhole just interop-client

interop-loss-both: interop-loss interop-loss-client

# Goodput measurement cells (runner reports Mbps in result.json).
interop-goodput:
    CLIENTS=quic-go,quiche,ngtcp2 TESTS=G just interop

# Refresh and inspect the published QNS image on a remote runner host.
interop-remote-pull:
    ssh "{{remote_host}}" 'docker pull {{remote_image}}'
    ssh "{{remote_host}}" 'docker image inspect {{remote_image}} >/dev/null'

interop-remote-mainstream: interop-remote-pull
    ssh -t "{{remote_host}}" 'cd {{remote_dir}} && {{remote_python}} run.py -i quic-zig -s {{mainstream_impls}} -c {{mainstream_impls}} -t handshake,transfer'

interop-remote-features: interop-remote-pull
    ssh -t "{{remote_host}}" 'cd {{remote_dir}} && {{remote_python}} run.py -s quic-zig -c {{feature_clients}} -t {{feature_tests}}'

interop-remote-matrix: interop-remote-pull
    ssh -t "{{remote_host}}" 'cd {{remote_dir}} && {{remote_python}} run.py -i quic-zig -j /tmp/quic-zig-matrix.json -l logs/quic-zig-full-matrix'
