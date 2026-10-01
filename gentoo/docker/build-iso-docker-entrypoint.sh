#!/bin/bash
# Entrypoint for the Patronus ISO Docker builder container.
#
# Runs inside patronus-iso-builder:latest (Gentoo stage3 + catalyst).
# The repo is bind-mounted read-only at /build/patronus; this script
# stages a writable working copy, cross-builds patronus-install natively
# for the container's x86_64 arch (NOT the host's -- building it on an
# arm64 host via `cargo build` would produce an arm64 binary, which is
# useless on the x86_64 LiveCD), overlays the fresh binary onto a
# writable copy of root_overlay, renders the catalyst specs against the
# container's own paths, and runs the two-stage catalyst LiveCD build.

set -euo pipefail

REPO_SRC="/build/patronus"
WORK="/build/work"
CATALYST_SRC="${REPO_SRC}/gentoo/catalyst"
VERSION="${VERSION:-0.1.0}"
TIMESTAMP="${TIMESTAMP:-$(date +%Y%m%d)}"
OUTPUT_DIR="/output"

echo "============================================"
echo "  Patronus ISO build (in-container)"
echo "  Version: ${VERSION}  Timestamp: ${TIMESTAMP}"
echo "============================================"

mkdir -p "${WORK}" "${OUTPUT_DIR}"

echo "[1/5] Staging writable source tree..."
rm -rf "${WORK}/src"
cp -a "${REPO_SRC}" "${WORK}/src"

echo "[2/5] Building patronus-install (native x86_64 in container)..."
cd "${WORK}/src"
export CARGO_PROFILE_RELEASE_OPT_LEVEL=3
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export RUSTFLAGS="-C target-cpu=x86-64"
cargo build -p patronus-installer --release
INSTALLER_BIN="${WORK}/src/target/release/patronus-install"
if [[ ! -f "${INSTALLER_BIN}" ]]; then
    echo "Error: patronus-install binary not found after cargo build" >&2
    exit 1
fi
command -v file >/dev/null 2>&1 && file "${INSTALLER_BIN}" || true

echo "[3/5] Preparing writable root_overlay with fresh installer..."
ROOT_OVERLAY="${WORK}/root_overlay"
rm -rf "${ROOT_OVERLAY}"
cp -a "${CATALYST_SRC}/root_overlay" "${ROOT_OVERLAY}"
install -D -m 0755 "${INSTALLER_BIN}" "${ROOT_OVERLAY}/usr/bin/patronus-install"

echo "[3.5/5] Fetching Gentoo stage3 seed tarball (if not already cached)..."
# catalyst's livecd-stage1 spec builds FROM a seed stage3 it expects to
# find under /var/tmp/catalyst/builds/default/<source_subpath>.tar.xz --
# catalyst does not fetch this itself, so we have to stage it first.
SEED_DIR="/var/tmp/catalyst/builds/default"
mkdir -p "${SEED_DIR}"
SEED_NAME="stage3-amd64-openrc-latest"
SEED_TARBALL="${SEED_DIR}/${SEED_NAME}.tar.xz"
if [[ ! -f "${SEED_TARBALL}" ]]; then
    LATEST_TXT_URL="https://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3-amd64-openrc.txt"
    REL_PATH="$(wget -q -O- "${LATEST_TXT_URL}" | grep -E '^[0-9]+T[0-9]+Z/stage3-amd64-openrc-.*\.tar\.xz' | awk '{print $1}')"
    if [[ -z "${REL_PATH}" ]]; then
        echo "Error: could not resolve latest stage3-amd64-openrc path from ${LATEST_TXT_URL}" >&2
        exit 1
    fi
    SEED_URL="https://distfiles.gentoo.org/releases/amd64/autobuilds/${REL_PATH}"
    echo "Downloading seed stage3: ${SEED_URL}"
    wget -q -O "${SEED_TARBALL}" "${SEED_URL}"
else
    echo "Seed stage3 already cached at ${SEED_TARBALL}"
fi

echo "[3.6/5] Building portage snapshot squashfs for catalyst..."
# catalyst's "snapshot_treeish: HEAD" expects a pre-built squashfs at
# /var/tmp/catalyst/snapshots/gentoo-<treeish>.sqfs. Its own `catalyst -s`
# snapshot mechanism expects a local gentoo.git clone (which we don't have
# -- we used emerge-webrsync instead, a full checkout at /var/db/repos/gentoo),
# so build the squashfs directly from that tree rather than via git-archive.
SNAPSHOT_DIR="/var/tmp/catalyst/snapshots"
SNAPSHOT_FILE="${SNAPSHOT_DIR}/gentoo-HEAD.sqfs"
mkdir -p "${SNAPSHOT_DIR}"
if [[ ! -f "${SNAPSHOT_FILE}" ]]; then
    tar2sqfs "${SNAPSHOT_FILE}" -q -f -j1 -c gzip < <(tar -C /var/db/repos/gentoo -cf - .)
else
    echo "Snapshot squashfs already exists at ${SNAPSHOT_FILE}"
fi

echo "[4/5] Rendering catalyst specs..."
SPEC_DIR="${WORK}/specs"
mkdir -p "${SPEC_DIR}"

render_spec() {
    local src="$1" dst="$2"
    sed \
        -e "s/@TIMESTAMP@/${TIMESTAMP}/g" \
        -e "s/@VERSION@/${VERSION}/g" \
        -e "s#/home/canutethegreat/files/repos/mine/patronus#${REPO_SRC}#g" \
        -e "s#/home/canutethegreat/patronus#${REPO_SRC}#g" \
        "${src}" > "${dst}"
}

render_spec "${CATALYST_SRC}/livecd-stage1.spec" "${SPEC_DIR}/livecd-stage1.spec"
render_spec "${CATALYST_SRC}/livecd-stage2.spec" "${SPEC_DIR}/livecd-stage2.spec"

# Point root_overlay at the writable copy carrying the freshly built binary
# (the read-only repo mount can't be overlaid directly).
sed -i "s#^livecd/root_overlay:.*#livecd/root_overlay: ${ROOT_OVERLAY}#" \
    "${SPEC_DIR}/livecd-stage2.spec"

echo "--- rendered livecd-stage1.spec ---"
cat "${SPEC_DIR}/livecd-stage1.spec"
echo "--- rendered livecd-stage2.spec ---"
cat "${SPEC_DIR}/livecd-stage2.spec"

echo "[5/5] Running catalyst (stage1 -> stage2)..."
catalyst -f "${SPEC_DIR}/livecd-stage1.spec"
catalyst -f "${SPEC_DIR}/livecd-stage2.spec"

echo "Collecting ISO output..."
ISO_SRC="$(find /var/tmp/catalyst/builds -maxdepth 2 -iname '*.iso' -newer "${SPEC_DIR}/livecd-stage2.spec" | head -1)"
if [[ -z "${ISO_SRC}" ]]; then
    ISO_SRC="$(find /var/tmp/catalyst/builds -maxdepth 2 -iname '*.iso' | head -1)"
fi
if [[ -z "${ISO_SRC}" ]]; then
    echo "Error: no ISO found under /var/tmp/catalyst/builds" >&2
    exit 1
fi

ISO_DST="${OUTPUT_DIR}/patronus-${VERSION}-amd64-${TIMESTAMP}.iso"
cp -f "${ISO_SRC}" "${ISO_DST}"
echo "ISO copied to ${ISO_DST}"
