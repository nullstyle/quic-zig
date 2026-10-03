#!/bin/sh
set -eu

# Toolchain pin agreement lint. The Zig toolchain is named in four places
# (listed in mise.toml). When they disagree, CI, the QNS image, and
# downstream consumers build with different compilers than the tree was
# tested with — main sat red for eleven days in 2026-09 on exactly that,
# while the QNS image kept building green on an older compiler.
#
# usage: check-zig-pins.sh [--online]
#   --online  also compare the Dockerfile's per-arch SHA-256 with the
#             digests ziglang.org publishes for the pinned release. A
#             version bump without a digest bump otherwise presents as
#             "every mirror is unusable", which reads like a mirror outage.
online=0
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--online" ]; }; then
    printf 'usage: %s [--online]\n' "$0" >&2
    exit 2
fi
if [ "$#" -eq 1 ]; then online=1; fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dockerfile="$root/interop/qns/Dockerfile"

zon_floor() {
    sed -n 's/^ *\.minimum_zig_version = "\(.*\)",$/\1/p' "$1"
}
docker_arg() {
    sed -n "s/^ARG $1=\(.*\)\$/\1/p" "$dockerfile"
}

mise_pin=$(sed -n 's/^zig = "\(.*\)"$/\1/p' "$root/mise.toml")
if [ -z "$mise_pin" ]; then
    printf 'FAIL: could not read the zig pin from mise.toml\n' >&2
    exit 1
fi

status=0
check() {
    if [ -z "$2" ]; then
        printf 'FAIL: could not read the Zig version from %s\n' "$1" >&2
        status=1
    elif [ "$2" != "$mise_pin" ]; then
        printf 'FAIL: %s names Zig %s, but mise.toml pins %s\n' "$1" "$2" "$mise_pin" >&2
        status=1
    fi
}

check 'build.zig.zon minimum_zig_version' "$(zon_floor "$root/build.zig.zon")"
check 'tools/consumer-smoke/build.zig.zon minimum_zig_version' "$(zon_floor "$root/tools/consumer-smoke/build.zig.zon")"
check 'interop/qns/Dockerfile ZIG_VERSION' "$(docker_arg ZIG_VERSION)"

if [ "$online" -eq 1 ] && [ "$status" -eq 0 ]; then
    index=$(mktemp "${TMPDIR:-/tmp}/zig-index.XXXXXX")
    trap 'rm -f "$index"' EXIT HUP INT TERM
    curl -fsSL --retry 3 -o "$index" https://ziglang.org/download/index.json
    for pair in "x86_64-linux ZIG_SHA256_X86_64" "aarch64-linux ZIG_SHA256_AARCH64"; do
        # shellcheck disable=SC2086 # deliberate split into target + ARG name
        set -- $pair
        published=$(python3 -c 'import json, sys
index = json.load(open(sys.argv[1]))
print(index.get(sys.argv[2], {}).get(sys.argv[3], {}).get("shasum", ""))' "$index" "$mise_pin" "$1")
        pinned=$(docker_arg "$2")
        if [ -z "$published" ]; then
            printf 'FAIL: ziglang.org publishes no %s digest for Zig %s\n' "$1" "$mise_pin" >&2
            status=1
        elif [ "$published" != "$pinned" ]; then
            printf 'FAIL: Dockerfile %s is %s, ziglang.org publishes %s for %s\n' "$2" "$pinned" "$published" "$1" >&2
            status=1
        fi
    done
fi

if [ "$status" -eq 0 ]; then
    printf 'zig pins agree: %s\n' "$mise_pin"
fi
exit "$status"
