#!/usr/bin/env bash
# Installed-image gate: the image hook (gentoo/live-iso/project/overlay/usr/libexec/project-image-packages) must record the PLAIN atom
# `net-firewall/patronus` in @world, never `net-firewall/patronus::patronus-image`. A repository-qualified world entry pins the package to the
# image-local repository (deleted after the image build), and every later upgrade from another repository or binhost (the web UI updater,
# `emerge -u`) became a slot conflict on a real install.
#
# The test runs the real hook in the CI base image (Portage tree pre-synced) with a dummy payload, then resolves an upgrade that only a
# SECOND repository offers and requires that it resolves without a conflict.
#
# Usage: ci/test-image-world-atom.sh [base-image]    (docker; the image needs a Portage tree, otherwise the test skips)
#        HOOK=/path/to/older/project-image-packages ci/test-image-world-atom.sh   # run another hook version (negative control)
set -euo pipefail
cd "$(dirname "$0")/.."
IMG=${1:-${BASE_IMAGE:-git.canutethegreat.com/canutethegreat/patronus-ci-base:latest}}
cid=$(docker create "$IMG" sleep infinity)
trap 'docker rm -fv "$cid" >/dev/null 2>&1 || true' EXIT
docker start "$cid" >/dev/null
# the job container reaches the daemon over a socket: bind mounts would name host paths, so copy the inputs in
docker exec "$cid" mkdir -p /src
tar cf - gentoo ci/test-image-world-atom-inner.sh | docker cp - "$cid":/src
if [ -n "${HOOK:-}" ]; then
  docker cp "$HOOK" "$cid":/src/hook-under-test
  hook_env=(-e HOOK=/src/hook-under-test)
else
  hook_env=()
fi
docker exec "${hook_env[@]}" -e CONTROL="${CONTROL:-}" "$cid" bash /src/ci/test-image-world-atom-inner.sh
