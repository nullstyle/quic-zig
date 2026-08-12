FROM martenseemann/quic-network-simulator-endpoint:latest AS build

ARG TARGETPLATFORM
# Pinned to a 0.17.0-dev master tarball because mise.toml tracks Zig master
# and HEAD uses 0.17-only forms; tagged 0.16.0 is no longer ABI-compatible.
# Keep this in step with `mise.toml` — that is the compiler `zig build`
# actually runs, so a stale pin here builds the image with a *different*
# compiler than the tree was tested with, and a locally-green checkout can
# produce a red or unrepresentative interop image. (This previously said
# to track `build.zig.zon`'s `minimum_zig_version`, which is a floor, not
# the toolchain; following it had already let this drift a version behind.)
# Dev tarballs live under /builds/ (no per-version subdirectory), unlike
# tagged releases which are served from /download/<version>/.
#
# ziglang.org keeps only the CURRENT master dev tarball, so any pin here
# 404s there the moment upstream master moves on. That is not a
# hypothetical: it happened, and it turned this image — and the interop
# gate that builds it — red, while the rest of CI stayed green purely
# because jdx/mise-action restores a warm cache and never re-downloads.
# The Docker jobs, having no such cache, were the canary rather than the
# cause.
#
# Tracking current master (as this pin now does) makes the tarball
# available again but does not make it durable; it only restarts the
# same clock. So the fetch below does not trust any single source: it
# walks the Zig project's own community mirror list and pins the exact
# bytes. The digests were verified locally against Zig's well-known
# minisign public key
# (RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U), so the
# check needs no signing tooling in the image and still fails closed on
# a bad mirror as well as a missing one.
ARG ZIG_VERSION=0.17.0-dev.1683+5ceec001b
ARG ZIG_SHA256_X86_64=e6e5c7e0834626bded90cd786d148bebf211dc80b013afefd631472b57b41f77
ARG ZIG_SHA256_AARCH64=b18bd9c61b751ec64982359f85c3d4aec3347f4988b9edbfc15a14c055452eee

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils cmake ninja-build clang git python3 perl \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETPLATFORM" in \
        "linux/arm64") zig_arch="aarch64-linux"; zig_sha="$ZIG_SHA256_AARCH64" ;; \
        *) zig_arch="x86_64-linux"; zig_sha="$ZIG_SHA256_X86_64" ;; \
    esac \
    && tarball="zig-${zig_arch}-${ZIG_VERSION}.tar.xz" \
    && for base in \
            "https://ziglang.org/builds" \
            "https://zig.squirl.dev" \
            "https://pkg.hexops.org/zig" \
            "https://zigmirror.com"; do \
        echo "trying ${base}/${tarball}" \
        && curl -fsSL --retry 3 --max-time 300 "${base}/${tarball}" -o /tmp/zig.tar.xz \
        && echo "${zig_sha}  /tmp/zig.tar.xz" | sha256sum -c - \
        && break \
        || { rm -f /tmp/zig.tar.xz; echo "  ...unusable, next mirror"; }; \
    done \
    && echo "${zig_sha}  /tmp/zig.tar.xz" | sha256sum -c - \
    && mkdir -p /opt/zig \
    && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
    && rm /tmp/zig.tar.xz \
    && /opt/zig/zig version | grep -qx "$ZIG_VERSION"

ENV PATH="/opt/zig:${PATH}"

COPY quic-zig /src/quic-zig

# Pre-populate the zig package cache from the host's
# ~/.cache/zig/p/ if the wrapper staged it. Without this, the build
# step below tries to fetch boringssl-zig over HTTPS from
# github.com — which is flaky enough during interop iteration that
# transient `HttpConnectionClosing` errors abort the matrix run.
# When the staged cache is absent (e.g. fresh checkout), zig falls
# back to the URL fetch.
COPY zig-cache-p/ /root/.cache/zig/p/

WORKDIR /src/quic-zig
# Build for the architecture's baseline CPU. Without this, Zig defaults to
# native and BoringSSL can compile hardware checks as compile-time true on the
# build host, then SIGILL on a less capable deployment CPU.
RUN zig build qns-endpoint -Doptimize=ReleaseSafe -Dcpu=baseline

FROM martenseemann/quic-network-simulator-endpoint:latest

WORKDIR /
COPY --from=build /src/quic-zig/zig-out/bin/qns-endpoint /qns-endpoint
COPY quic-zig/interop/qns/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
