#!/bin/sh
# Install the latest shellvibe release binary for this platform.
#
# Usage:
#   ./install.sh                 # latest release, into ~/.local/bin
#   SHELLVIBE_INSTALL_DIR=/usr/local/bin ./install.sh
set -eu

repo="Qrzysztof/shellvibe"
dest="${SHELLVIBE_INSTALL_DIR:-${HOME}/.local/bin}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) target="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64 | Linux-arm64) target="aarch64-unknown-linux-gnu" ;;
  Darwin-x86_64) target="x86_64-apple-darwin" ;;
  Darwin-arm64) target="aarch64-apple-darwin" ;;
  *)
    echo "shellvibe: unsupported platform: $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

url="https://github.com/${repo}/releases/latest/download/shellvibe-${target}-rust-stable.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

curl -fsSL "${url}" | tar -xz -C "${tmp}"
mkdir -p "${dest}"
install -m 0755 "${tmp}/shellvibe" "${dest}/shellvibe"
echo "installed shellvibe to ${dest}/shellvibe"