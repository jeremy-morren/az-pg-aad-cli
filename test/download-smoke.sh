#!/bin/sh
# Smoke test for download.sh, run by CI inside each test container.
#
#   test/download-smoke.sh DOWNLOAD_SH EXPECT
#
# EXPECT is the variant this environment must pick: xz, br, gz or raw. 
# For "raw", download.sh runs with a PATH holding only the tools it needs, so no
# decompressor is found.
#
# AZPGAAD_BASE_URL must point at a server laid out like GitHub releases:
#   latest/download/<assets>            all variants (raw, .xz, .br, .gz)
#   rawonly/latest/download/<assets>    raw binaries only (exercises the 404 fallback)
# (download.sh always fetches the latest release, so the raw-only and missing
# cases use other base URLs: <base>/rawonly and <base>/missing.)
# The binaries must report AZPGAAD_TEST_VERSION (default v0.0.0-ci) from --version.
# Short options for coreutils and grep: BusyBox (Alpine) has no long forms for them.

set -o errexit -o nounset

script=$1
expect=$2
want=${AZPGAAD_TEST_VERSION:-v0.0.0-ci}
: "${AZPGAAD_BASE_URL:?AZPGAAD_BASE_URL must be set}"

fail() {
	echo "FAIL: $*" >&2
	if [ -f "$log" ]; then sed 's/^/  | /' "$log" >&2; fi
	exit 1
}
ok() { echo "ok: $*"; }

work=$(mktemp -d)
log=$work/log
trap 'rm -rf "$work"' EXIT
sh_bin=$(command -v sh)

dl_path=$PATH
if [ "$expect" = raw ]; then
	mkdir "$work/bin"
	for t in curl uname mktemp mkdir chmod mv rm; do
		p=$(command -v "$t") || fail "$t not found"
		ln -s "$p" "$work/bin/$t"
	done
	dl_path=$work/bin
	for t in xz xzcat brotli gzip; do
		if (PATH=$dl_path && command -v "$t" >/dev/null 2>&1); then
			fail "$t is still reachable on the stripped PATH"
		fi
	done
fi

# dl ARGS...: run download.sh from a file, stderr to $log.
dl() { PATH=$dl_path "$sh_bin" "$script" "$@" 2>"$log"; }
# dl_at BASE ARGS...: same, against another release base URL.
dl_at() {
	base=$1
	shift
	AZPGAAD_BASE_URL=$base PATH=$dl_path "$sh_bin" "$script" "$@" 2>"$log"
}

case $expect in
	raw) pattern='downloading .*/azpgaad-[a-z]*-[a-z0-9]*$' ;;
	xz | br | gz) pattern="downloading .*/azpgaad-[a-z]*-[a-z0-9]*\\.$expect\$" ;;
	*) fail "unknown EXPECT: $expect" ;;
esac

check_bin() { # FILE: executable and reports the expected version
	[ -x "$1" ] || fail "$1 missing or not executable"
	v=$("$1" --version) || fail "$1 --version failed"
	case $v in *"$want"*) ;; *) fail "$1 --version printed '$v', want '$want'" ;; esac
}
check_only() { # DIR NAME: DIR holds exactly NAME (no temp files left behind)
	c=$(ls -A "$1")
	[ "$c" = "$2" ] || fail "$1 contains '$c', want only '$2'"
}

# 1. Default output path, latest release.
mkdir "$work/t1"
(cd "$work/t1" && dl) || fail "default run failed"
grep -q "$pattern" "$log" || fail "expected a .$expect download"
if grep -q 'falling back' "$log"; then fail "unexpected raw fallback"; fi
check_bin "$work/t1/azpgaad"
check_only "$work/t1" azpgaad
ok "latest release, default ./azpgaad, picked $expect"

# 2. The documented pipe form, a missing parent directory.
# shellcheck disable=SC2002 # mirrors `curl ... | sh -s -- ...`
cat "$script" | PATH=$dl_path "$sh_bin" -s -- --output "$work/t2/a/b/azpgaad" 2>"$log" ||
	fail "piped run failed"
grep -q "$pattern" "$log" || fail "expected a .$expect download"
grep -q "/latest/download/" "$log" || fail "expected the latest-release URL"
check_bin "$work/t2/a/b/azpgaad"
check_only "$work/t2/a/b" azpgaad
ok "piped into sh -s --, nested --output"

# 3. Overwrite an existing file; --output naming an existing directory.
dl --output "$work/t2/a/b/azpgaad" || fail "overwrite failed"
check_bin "$work/t2/a/b/azpgaad"
mkdir "$work/t3"
dl --output "$work/t3/" || fail "--output DIR failed"
check_bin "$work/t3/azpgaad"
check_only "$work/t3" azpgaad
ok "overwrite, --output DIR"

# 4. Compressed asset missing (404) -> raw fallback.
mkdir "$work/t4"
dl_at "$AZPGAAD_BASE_URL/rawonly" --output "$work/t4/azpgaad" || fail "raw-only release failed"
if [ "$expect" != raw ]; then
	grep -q 'falling back' "$log" || fail "expected the 404 fallback to raw"
fi
check_bin "$work/t4/azpgaad"
check_only "$work/t4" azpgaad
ok "compressed asset 404 -> raw fallback"

# 5. Failures leave nothing behind and exit non-zero.
mkdir "$work/t5"
if dl_at "$AZPGAAD_BASE_URL/missing" --output "$work/t5/azpgaad"; then fail "missing release succeeded"; fi
grep -q 'not found' "$log" || fail "expected a 'not found' error"
check_only "$work/t5" ''
if dl --version v1.2.3; then fail "--version (removed option) was accepted"; fi
if dl --bogus-flag; then fail "unknown flag succeeded"; fi
if ! command -v gh >/dev/null 2>&1; then
	if dl --output "$work/t5/azpgaad" --require-attestation; then fail "--require-attestation without gh succeeded"; fi
	grep -q 'gh' "$log" || fail "expected an error naming gh"
	check_only "$work/t5" ''
fi
ok "failures exit non-zero and leave no files"

echo "PASS ($expect)"
