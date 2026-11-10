#!/bin/sh
# Build the release assets with GoReleaser (pinned in tools/go.mod) and copy them to OUTDIR.
#
#   tools/release-build.sh vX.Y.Z [OUTDIR]     (default OUTDIR: release)
#
# OUTDIR gets the 12 assets - 6 unversioned raw binaries (azpgaad-<os>-<arch>[.exe]) and
# 6 versioned tarballs - and the script prints "sha256  file" for each on stdout.
# Reproducible: the same commit and tag give identical hashes on any host (see
# .goreleaser.yaml). OUTDIR must be git-ignored or outside the work tree: an untracked
# file in the work tree would change the binaries' vcs.modified stamp.
# Long options where macOS (BSD) tools have them too; rm, mkdir and cp stay short.
set -o errexit -o nounset

[ $# -ge 1 ] || { echo "usage: $0 vX.Y.Z [OUTDIR]" >&2; exit 2; }
tag=$1
out=${2:-release}

cd "$(dirname "$0")/.."
root=$(pwd)

# GoReleaser takes the version from a git tag on HEAD. The release workflow builds before
# the real tag exists (it's created when the draft release is published), so create a
# local lightweight tag if it's missing and remove it again afterwards. Never pushed.
created_tag=
cleanup() {
	if [ -n "$created_tag" ]; then git -C "$root" tag --delete "$created_tag" >/dev/null; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ! git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null; then
	# Lightweight and unsigned (tag.gpgSign would make it an annotated tag needing a message).
	git -c tag.gpgSign=false tag "$tag"
	created_tag=$tag
elif [ "$(git rev-parse "$tag^{commit}")" != "$(git rev-parse HEAD)" ]; then
	echo "$0: tag $tag exists but isn't HEAD; check it out first (git checkout $tag)" >&2
	exit 1
fi

GORELEASER_CURRENT_TAG=$tag go tool -modfile=tools/go.mod goreleaser release --snapshot --clean >&2

rm -rf "$out"
mkdir -p "$out"
cp dist/azpgaad_*.tar.gz "$out"/
# Raw binaries: dist/azpgaad_<os>_<arch>_<variant>/azpgaad[.exe] -> azpgaad-<os>-<arch>[.exe]
for dir in dist/azpgaad_*_*_*/; do
	target=${dir#dist/azpgaad_}
	target=${target%/}
	os=${target%%_*}
	arch=${target#*_}
	arch=${arch%%_*}
	exe=
	if [ "$os" = windows ]; then exe=.exe; fi
	cp "$dir/azpgaad$exe" "$out/azpgaad-$os-$arch$exe"
done

cd "$out"
set -- azpgaad*
[ $# -eq 12 ] || { echo "$0: expected 12 assets, got $#: $*" >&2; exit 1; }
# One format everywhere: "<hash>  <file>" (sha256sum on Windows marks binary mode as "*file").
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum azpgaad*
else
	shasum --algorithm 256 azpgaad*
fi | sed 's/ \*/  /'
