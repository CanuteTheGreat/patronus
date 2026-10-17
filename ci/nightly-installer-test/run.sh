#!/usr/bin/env bash
# One entry point for the nightly installer test, used verbatim by
# .forgejo/workflows/nightly-realistic-installer-test.yml (runs-on: kvm-x86_64)
# and for local reproduction on any x86_64 host with /dev/kvm:
#   docker run --rm --device /dev/kvm --memory 12g --cpus 4 -v "$PWD:/src" -w /src \
#     ubuntu:24.04 ci/nightly-installer-test/run.sh
# Builds the real patronus-install (static musl), the unattended Alpine media,
# then boots/installs/reboots a real x86_64 VM under KVM (vm_orchestrate.py).
set -euo pipefail
cd "$(dirname "$0")/../.."
HERE=ci/nightly-installer-test
WORK="${CI_WORKDIR:-/tmp/patronus-vm-test}"
ALPINE_VER=3.20.3
ALPINE_BRANCH=v3.20
ISO_NAME="alpine-extended-${ALPINE_VER}-x86_64.iso"
SUDO=""; [ "$(id -u)" = 0 ] || SUDO=sudo

echo "::group::host deps"
need=()
for b in qemu-system-x86_64:qemu-system-x86 qemu-img:qemu-utils xorriso:xorriso musl-gcc:musl-tools curl:curl python3:python3 sha256sum:coreutils; do
  command -v "${b%%:*}" >/dev/null || need+=("${b#*:}")
done
[ -e /usr/share/OVMF/OVMF_CODE_4M.fd ] || [ -e /usr/share/OVMF/OVMF_CODE.fd ] || need+=(ovmf)
if [ ${#need[@]} -gt 0 ]; then
  $SUDO apt-get update -qq
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq --no-install-recommends "${need[@]}" ca-certificates build-essential
fi
if ! command -v cargo >/dev/null; then
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
  . "$HOME/.cargo/env"
fi
rustup target add x86_64-unknown-linux-musl
echo "::endgroup::"

echo "::group::unit-test + build patronus-install (x86_64 musl)"
cargo test --release --target x86_64-unknown-linux-musl -p patronus-installer
cargo build --release --target x86_64-unknown-linux-musl -p patronus-installer
echo "::endgroup::"

rm -rf "$WORK"; mkdir -p "$WORK/artifact"
A="$WORK/artifact"
cp target/x86_64-unknown-linux-musl/release/patronus-install "$A/patronus-install"
"$HERE/build_apkovl.sh" "$A/patronus-install" "$HERE/answer.toml" "$HERE/patronus-ci.start" "$A/patronus.apkovl.tar.gz"

echo "::group::Alpine Extended ${ALPINE_VER} x86_64 ISO"
CACHE="${ALPINE_ISO_CACHE:-$HOME/.cache/patronus-ci}"; mkdir -p "$CACHE"
BASE="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/x86_64"
curl -fsSL -o "$CACHE/$ISO_NAME.sha256" "$BASE/$ISO_NAME.sha256"
if ! (cd "$CACHE" && sha256sum -c --status "$ISO_NAME.sha256" 2>/dev/null); then
  curl -fL --retry 3 -o "$CACHE/$ISO_NAME" "$BASE/$ISO_NAME"
  (cd "$CACHE" && sha256sum -c "$ISO_NAME.sha256")
fi
echo "::endgroup::"

"$HERE/iso_remaster.sh" "$CACHE/$ISO_NAME" "$A/patronus.apkovl.tar.gz" "$A/install.iso"
CI_WORKDIR="$WORK" python3 -u "$HERE/vm_orchestrate.py" "$A/install.iso"
