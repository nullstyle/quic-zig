#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s <package-url>\n' "$0" >&2
    exit 2
fi

# `zig fetch` also writes a recompressed copy to the global package cache.
# On the current 0.17 development series, URL fetches can retain the
# downloaded archive's top-level directory inside that recompressed copy.
# A later `zig build` strips only the cache archive's own root, sees no
# build.zig.zon, and reports an unrelated-looking N-V hash mismatch.
#
# Hash calculation is a one-shot operation, so isolate and discard its cache
# instead of risking the package cache used by normal builds.
cache_dir=$(mktemp -d "${TMPDIR:-/tmp}/quic-zig-fetch.XXXXXX")
trap 'rm -rf "$cache_dir"' EXIT HUP INT TERM

if ! command -v mise >/dev/null 2>&1; then
    printf 'error: mise is required to select the project Zig toolchain\n' >&2
    exit 1
fi

mise exec -- env ZIG_GLOBAL_CACHE_DIR="$cache_dir" zig fetch "$1"
