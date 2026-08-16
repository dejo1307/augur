#!/bin/sh
# install.sh — install the latest augur release.
#
#   curl -fsSL https://raw.githubusercontent.com/dejo1307/augur/main/install.sh | sh
#
# Installs to ~/.local/bin by default; override with AUGUR_INSTALL_DIR.
# Set AUGUR_VERSION to pin a version instead of taking the latest.

# POSIX sh, and `set -eu` rather than `set -euo pipefail`.
#
# Not a style preference. An install script published as a one-liner gets piped
# to whatever shell the reader typed, and on Debian and Ubuntu `sh` is dash,
# which has no `pipefail` — so a bash-only `set -o pipefail` aborts the script on
# line 5 with "Illegal option" before it does anything. That is not hypothetical:
# it is how enola's installer failed in this repository's own CI.
#
# Nothing here needs pipefail. The one pipeline that matters (resolving the
# version) is followed by an explicit emptiness check, which is a better test
# than an exit status anyway.
set -eu

REPO="dejo1307/augur"

die() { echo "error: $*" >&2; exit 1; }

# --- Detect platform -------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *)      die "unsupported OS: $OS (see https://github.com/${REPO}/releases)" ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *)             die "unsupported architecture: $ARCH" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar  >/dev/null 2>&1 || die "tar is required"

# --- Resolve version -------------------------------------------------------
VERSION="${AUGUR_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')"
fi
VERSION="${VERSION#v}"
[ -n "$VERSION" ] || die "could not determine the latest version — is there a published release?"

BASE="augur-${VERSION}-${OS}-${ARCH}"
ASSET="${BASE}.tar.gz"
SHAFILE="${BASE}.sha256"
DL="https://github.com/${REPO}/releases/download/v${VERSION}"

echo "==> Downloading augur v${VERSION} for ${OS}/${ARCH} ..."

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if ! curl -fsSL -o "$TMPDIR/$ASSET" "${DL}/${ASSET}"; then
  echo "No prebuilt binary for ${OS}/${ARCH} in augur v${VERSION}." >&2
  echo "Available downloads: https://github.com/${REPO}/releases/tag/v${VERSION}" >&2
  exit 1
fi
curl -fsSL -o "$TMPDIR/$SHAFILE" "${DL}/${SHAFILE}"

# --- Verify ----------------------------------------------------------------
# Not optional. This script pipes a downloaded binary straight onto your PATH,
# and the checksum is the only thing standing between that and whatever the
# network handed back.
echo "==> Verifying checksum ..."
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMPDIR" && sha256sum -c "$SHAFILE")
elif command -v shasum >/dev/null 2>&1; then
  (cd "$TMPDIR" && shasum -a 256 -c "$SHAFILE")
else
  die "neither sha256sum nor shasum is available; refusing to install unverified"
fi

echo "==> Extracting ..."
tar xzf "$TMPDIR/$ASSET" -C "$TMPDIR"
[ -f "$TMPDIR/$BASE" ] || die "archive did not contain the expected binary ($BASE)"

# --- Install ---------------------------------------------------------------
INSTALL_DIR="${AUGUR_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"
install -m 755 "$TMPDIR/$BASE" "$INSTALL_DIR/augur"

echo "==> augur v${VERSION} installed to ${INSTALL_DIR}/augur"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "${INSTALL_DIR} is not on your PATH. Add it:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac

echo ""
echo "Try it:  augur --help"
