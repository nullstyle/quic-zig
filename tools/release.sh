#!/bin/sh
# usage: tools/release.sh <X.Y.Z> [--no-gates] [--dry-run]
#
# The fast-gate release (CONTRIBUTING.md, "Releases", since 2026-10-07):
# the gates a tag needs BEFORE it are the fast ones, about five minutes
# on a warm cache: the full suite, the Windows and the 32-bit compile
# checks. Then the version moves in build.zig.zon and README.md, the
# CHANGELOG section is checked, "Release vX.Y.Z" is committed, tagged,
# and pushed with the tag, rc-fuzz is dispatched, and the CI run ids
# and the package hash are printed. The five CI gates (test, rc-fuzz,
# quic-go-interop, QNS Image, pin-lint) then prove the tag within the
# hour, each read at its evidence line; a red one is answered with a
# patch tag, never a moved tag. The slow local checks (mutants, bench
# cells, the wide interop matrix) are the engineer's call per change,
# before or after the tag, and go in the release record either way.
#
# Preconditions: HEAD descends from the remote's main; the tree is clean
# but for CHANGELOG.md, README.md and build.zig.zon; CHANGELOG.md has
# "## [X.Y.Z] - <date>"; the tag does not exist. Run under the pinned
# toolchain: `mise exec -- sh tools/release.sh 0.33.0`. The commit
# message comes from $QUIC_ZIG_RELEASE_MESSAGE (a file) when set.
# --no-gates skips the gates (for a docs-only patch whose suite just
# ran); --dry-run stops before the commit and restores the two files.
set -eu

version=${1:?usage: tools/release.sh <X.Y.Z> [--no-gates] [--dry-run]}
shift
gates=1
dry=0
for a in "$@"; do
    case "$a" in
        --no-gates) gates=0 ;;
        --dry-run) dry=1 ;;
        *) printf 'unknown argument: %s\n' "$a" >&2; exit 2 ;;
    esac
done
case "$version" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) printf 'version must be X.Y.Z, got %s\n' "$version" >&2; exit 2 ;;
esac
tag="v$version"
remote=${QUIC_ZIG_REMOTE:-https://github.com/nullstyle/quic-zig.git}
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

echo "== release $tag: preconditions"
git fetch -q "$remote" main
if ! git merge-base --is-ancestor FETCH_HEAD HEAD; then
    printf 'HEAD does not descend from %s main: merge or rebase first\n' "$remote" >&2
    exit 1
fi
dirty=$(git status --porcelain | grep -v -E '^ M (CHANGELOG\.md|README\.md|build\.zig\.zon)$' || true)
if [ -n "$dirty" ]; then
    printf 'the tree is not clean (only CHANGELOG.md, README.md and build.zig.zon may be modified):\n%s\n' "$dirty" >&2
    exit 1
fi
if ! grep -q "^## \[$version\] - " CHANGELOG.md; then
    printf 'CHANGELOG.md has no "## [%s] - <date>" section: write the entry first\n' "$version" >&2
    exit 1
fi
if git tag -l "$tag" | grep -q .; then
    printf 'the tag %s exists\n' "$tag" >&2
    exit 1
fi
old=$(sed -n 's/^    \.version = "\(.*\)",$/\1/p' build.zig.zon)
if [ -z "$old" ]; then
    echo 'build.zig.zon has no .version line in the expected form' >&2
    exit 1
fi
printf '   %s -> %s on %s\n' "$old" "$version" "$(git rev-parse --short HEAD)"

if [ "$gates" = 1 ]; then
    echo "== the fast gates: the full suite, the Windows and 32-bit compile checks"
    zig build test --summary all
    just check-windows
    just check-x86
else
    echo "== gates skipped (--no-gates)"
fi

echo "== the bump"
sed -i.bak "s/^    \\.version = \"$old\",\$/    .version = \"$version\",/" build.zig.zon
# The three pin mentions in the README and nothing else.
sed -i.bak \
    -e "s/current tag (\`v$old\` as of this writing)/current tag (\`$tag\` as of this writing)/" \
    -e "s|archive/refs/tags/v$old\\.tar\\.gz|archive/refs/tags/$tag.tar.gz|" \
    -e "s/git+https:\\/\\/…#v$old\`/git+https:\\/\\/…#$tag\`/" \
    README.md
rm -f build.zig.zon.bak README.md.bak
mentions=$(grep -c "$tag" README.md || true)
printf '   README.md mentions %s %s times (expected 3)\n' "$tag" "$mentions"
git diff --stat

if [ "$dry" = 1 ]; then
    echo "== dry run: no commit, tag or push; the two bumped files restored"
    git checkout -- build.zig.zon README.md
    exit 0
fi

echo "== commit, tag, push"
git add CHANGELOG.md README.md build.zig.zon
if [ -n "${QUIC_ZIG_RELEASE_MESSAGE:-}" ]; then
    git commit -q -F "$QUIC_ZIG_RELEASE_MESSAGE"
else
    git commit -q -m "Release $tag"
fi
git tag -a "$tag" -m "$tag"
git push -q "$remote" HEAD:main
git push -q "$remote" "$tag"
git ls-remote "$remote" main "$tag^{}"
if command -v gh >/dev/null 2>&1; then
    gh workflow run rc-fuzz.yml --ref main || echo "   rc-fuzz not dispatched: run 'gh workflow run rc-fuzz.yml --ref main'"
    gh run list --limit 6 --json databaseId,name,status,headSha --jq '.[] | "   \(.databaseId) \(.name) \(.status) \(.headSha[0:7])"' || true
else
    echo "   gh missing: dispatch rc-fuzz by hand (gh workflow run rc-fuzz.yml --ref main)"
fi

echo "== the package hash (a throwaway cache)"
sh tools/fetch-package-hash.sh "https://github.com/nullstyle/quic-zig/archive/refs/tags/$tag.tar.gz"

echo "== done: $tag is out. Read the five gates at the evidence line within the hour; a red one is a patch tag."
