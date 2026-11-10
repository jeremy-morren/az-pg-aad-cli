#!/bin/sh
# Download the azpgaad binary for this machine.
# No install step, no PATH changes, no root: the binary is written to the path you choose.
#
#   curl --fail --silent --show-error --location https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.sh | sh -s -- [options]
#
# Options:
#   --output PATH          where to write the binary (default: ./azpgaad, or
#                          ./azpgaad.exe on Windows; an existing directory gets
#                          that name inside it)
#   --require-attestation  fail unless the build-provenance attestation can be
#                          verified (needs the GitHub CLI, gh, on PATH)
#
# Always the latest release. On Windows (Git Bash, MSYS2, Cygwin) the Windows
# build is downloaded.
#
# The smallest variant this machine can decompress is fetched (.xz, then .br,
# then .gz, else the raw binary). If gh is on PATH, the binary is checked
# against the release's build-provenance attestation (no login needed).
#
# Requires curl. POSIX sh: works with dash, bash, busybox ash and zsh.
# Defensive quoting: every expansion is "${quoted}", including command substitutions,
# so paths and command output containing spaces can't be split or globbed.
# Long options wherever every target has them (curl, brotli, set -o). uname, mkdir, mktemp,
# rm, mv, xz and gzip keep short options: the BusyBox (Alpine) and macOS (BSD) versions
# have no long forms for them.

set -o errexit -o nounset

REPO="jeremy-morren/az-pg-aad-cli"
# AZPGAAD_BASE_URL is a test-only override of the release base URL.
BASE_URL="${AZPGAAD_BASE_URL:-https://github.com/${REPO}/releases}"
BASE_URL="${BASE_URL%/}"

say() { printf 'azpgaad: %s\n' "${*}" >&2; }
die() { say "error: ${*}"; exit 1; }

usage() {
	cat >&2 <<'EOF'
usage: download.sh [--output PATH] [--require-attestation]
EOF
}

output=""
require_attestation="false"

while [ "${#}" -gt 0 ]; do
	case "${1}" in
		--output | -o)
			[ "${#}" -ge 2 ] || die "${1} needs a value"
			output="${2}"
			shift 2
			;;
		--output=*)
			output="${1#*=}"
			shift
			;;
		--require-attestation)
			require_attestation="true"
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			usage
			die "unknown argument: ${1}"
			;;
	esac
done

output_given="false"
if [ -n "${output}" ]; then output_given="true"; fi

command -v curl >/dev/null 2>&1 || die "curl is required but was not found on PATH"

# --- platform ---------------------------------------------------------------
uname_s="$(uname -s)"
case "${uname_s}" in
	Linux) os="linux" ;;
	Darwin) os="darwin" ;;
	MINGW* | MSYS* | CYGWIN* | Windows_NT) os="windows" ;;
	*) die "unsupported operating system: ${uname_s}" ;;
esac
uname_m="$(uname -m)"
case "${uname_m}" in
	x86_64 | amd64) arch="amd64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) die "unsupported architecture: ${uname_m}" ;;
esac
# On ARM64 Windows, `uname -m` says x86_64 even with Git for Windows' native ARM64 build:
# the MSYS2 base layer (bash, uname) is still x64, running emulated. Look for any ARM64 signal:
# - `uname -s` (MSYS2 appends -ARM64 on ARM64 hosts, e.g. MINGW64_NT-10.0-26200-ARM64)
# - MSYSTEM (CLANGARM64 in Git for Windows' ARM64 build)
# - MSYSTEM_CARCH, PROCESSOR_ARCHITEW6432, PROCESSOR_ARCHITECTURE (not reliable: bash is sometimes run emulated)
# If none is found the amd64 build is used, which still runs on ARM64 Windows under x64 emulation.
if [ "${os}" = "windows" ]; then
	case "${uname_s} ${MSYSTEM:-} ${MSYSTEM_CARCH:-} ${PROCESSOR_ARCHITEW6432:-} ${PROCESSOR_ARCHITECTURE:-}" in
		*ARM64* | *aarch64* | *arm64*) arch="arm64" ;;
	esac
fi
# An x86_64 shell under Rosetta reports x86_64 on Apple silicon.
if [ "${os}" = "darwin" ] && [ "${arch}" = "amd64" ] &&
	[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = "1" ]; then
	arch="arm64"
fi

# Windows executables need the .exe suffix to run
exe=""
if [ "${os}" = "windows" ]; then exe=".exe"; fi
asset="azpgaad-${os}-${arch}${exe}"
release_url="${BASE_URL}/latest/download"

# --- output path and temp dir -------------------------------------------------
if [ "${output_given}" = "false" ]; then
	output="./azpgaad${exe}"
elif [ -d "${output}" ]; then
	output="${output%/}/azpgaad${exe}"
fi
case "${output}" in
	*/*) out_dir="${output%/*}" ;;
	*) out_dir="." ;;
esac
[ -n "${out_dir}" ] || out_dir="/"
mkdir -p "${out_dir}" || die "cannot create directory ${out_dir}"

work=""
cleanup() {
	if [ -n "${work}" ]; then rm -rf "${work}"; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Next to the target, so the final rename is atomic and a failed run never leaves a half-written binary behind.
work="$(mktemp -d "${out_dir}/.azpgaad.XXXXXX")" || die "cannot create a temporary directory in ${out_dir}"

# fetch URL FILE: 0 on success, 2 on HTTP 404, exits on any other failure.
fetch() {
	fetch_status="$(curl --silent --show-error --location --retry 3 --output "${2}" --write-out '%{http_code}' "${1}")" ||
		die "download failed: ${1}"
	case "${fetch_status}" in
		2??) return 0 ;;
		404) return 2 ;;
		*) die "download failed (HTTP ${fetch_status}): ${1}" ;;
	esac
}

# --- download -------------------------------------------------------------------
if command -v xz >/dev/null 2>&1; then
	decompressor="xz" ext="xz"
elif command -v xzcat >/dev/null 2>&1; then
	decompressor="xzcat" ext="xz"
elif command -v brotli >/dev/null 2>&1; then
	decompressor="brotli" ext="br"
elif command -v gzip >/dev/null 2>&1; then
	decompressor="gzip" ext="gz"
else
	decompressor="" ext=""
fi

bin="${work}/azpgaad${exe}"
if [ -n "${decompressor}" ]; then
	say "downloading ${release_url}/${asset}.${ext}"
	rc=0
	fetch "${release_url}/${asset}.${ext}" "${work}/download" || rc="${?}"
	if [ "${rc}" -eq 0 ]; then
		# A separate step, not a pipe: sh has no pipefail,
		# so a failure in the middle of a pipeline would go unnoticed.
		case "${decompressor}" in
			xz) xz -dc <"${work}/download" >"${bin}" ;;
			xzcat) xzcat <"${work}/download" >"${bin}" ;;
			brotli) brotli --decompress --stdout <"${work}/download" >"${bin}" ;;
			gzip) gzip -dc <"${work}/download" >"${bin}" ;;
		esac || die "${decompressor} failed to decompress ${asset}.${ext}"
		rm -f "${work}/download"
	else
		say "${asset}.${ext} not found; falling back to the uncompressed binary"
		decompressor=""
	fi
fi
if [ -z "${decompressor}" ]; then
	say "downloading ${release_url}/${asset}"
	rc=0
	fetch "${release_url}/${asset}" "${bin}" || rc="${?}"
	[ "${rc}" -eq 0 ] || die "not found: ${release_url}/${asset} (no release yet, or no build for ${os}/${arch}?)"
fi
[ -s "${bin}" ] || die "downloaded binary is empty"
chmod 755 "${bin}"

# --- provenance ----------------------------------------------------------------
# Opportunistic: if github cli not available and --require-attestation is not specified, skip the attestation verification.
# Does not require github cli to be installed
if command -v gh >/dev/null 2>&1; then
	bundle="${work}/attestation.sigstore.jsonl"
	rc=0
	fetch "${release_url}/attestation.sigstore.jsonl" "${bundle}" || rc="${?}"
	if [ "${rc}" -eq 0 ]; then
		say "verifying build provenance with gh attestation verify"
		gh attestation verify "${bin}" --repo "${REPO}" --bundle "${bundle}" >&2 ||
			die "attestation verification FAILED for ${asset} - do not use this binary"
	elif [ "${require_attestation}" = "true" ]; then
		die "--require-attestation: this release has no attestation.sigstore.jsonl"
	else
		say "note: this release has no attestation bundle; provenance not checked"
	fi
elif [ "${require_attestation}" = "true" ]; then
	die "--require-attestation: the GitHub CLI (gh) is needed to verify the attestation but is not on PATH"
else
	say "note: gh not found; skipping build-provenance check (see README to verify manually)"
fi

# --- sanity check and install ---------------------------------------------------
installed_version="$("${bin}" --version)" || die "the downloaded binary failed to run (${bin} --version)"
mv -f "${bin}" "${output}" || die "cannot write ${output}"
say "saved azpgaad ${installed_version} to ${output}"
