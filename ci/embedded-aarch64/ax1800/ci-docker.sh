#!/bin/bash
# ci-docker.sh up|build|qemu|down <openrc|systemd>: the CI side of the GL-AX1800 image job, run in the job container on
# an arm64 runner whose job containers get the host's docker socket (docker_host: automount). The builder image
# (Dockerfile.builder, tagged by its content hash) and a per-variant cache volume live on the host; the source goes into a
# sibling builder container with `docker cp` (a -v bind of the job's checkout would resolve on the host, not here).
#   up     build/reuse the builder image, start the container, copy the checkout in
#   build  ci-build.sh for this variant: host tests, patronus-cli, (systemd), userland, assemble, NAND budget
#   qemu   qemu-gate.sh for this variant (QEMU aarch64 virt; TCG on hosts without KVM)
#   rollback  rollback-gate.sh: the image's boot rollback under a real U-Boot (good image confirms, bad images revert)
#   down   copy summaries/results/serial logs out to ./ci-out, remove the container
set -euo pipefail
CMD=${1:?usage: ci-docker.sh up|build|qemu|rollback|down <openrc|systemd>}; V=${2:?variant}
case "$V" in openrc|systemd) ;; *) echo "variant must be openrc or systemd"; exit 2;; esac
H=ci/embedded-aarch64/ax1800
IMG=pembed-ax1800-builder:$(sha256sum "$H/Dockerfile.builder" | cut -c1-12)
C=pax1800-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$V
SHA=${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo local)}
case "$CMD" in
up)
  docker image inspect "$IMG" >/dev/null 2>&1 || docker build -q -t "$IMG" -f "$H/Dockerfile.builder" "$H"
  docker volume create "pembed-ax1800-cache-$V" >/dev/null
  docker rm -f "$C" >/dev/null 2>&1 || true
  docker run -d --name "$C" --memory=6g --memory-swap=6g --cpus=3 -v "pembed-ax1800-cache-$V:/cache" "$IMG" sleep 14400 >/dev/null
  docker exec "$C" mkdir -p /w /out
  tar --exclude=./.git -cf - . | docker exec -i "$C" sh -c 'mkdir -p /w/src && tar -xf - -C /w/src'
  echo "builder $IMG, container $C" ;;
build)
  # the release signing key goes in through stdin into a 0600 file (never on a command line or in the container's env), ci-build.sh
  # reads and deletes it after assemble.sh; no key = assemble.sh refuses to make an unsigned image
  if [ -n "${RELEASE_SIGNING_KEY:-}" ]; then printf '%s\n' "$RELEASE_SIGNING_KEY" | docker exec -i "$C" sh -c 'umask 077; cat > /w/.release-signing-key'; fi
  docker exec -e VARIANTS="$V" -e SOURCE_REV="$SHA" -e TAG="ci-$(echo "$SHA" | cut -c1-8)" "$C" bash /w/src/$H/ci-build.sh ;;
qemu)
  docker exec -e VIRT_KERNEL=/out/stock/virt-kernel.bin -e UNIT_DIR=/out/unit -e RESULTS=/out/qemu-$V "$C" \
    sh -c "bash /w/src/$H/qemu-gate.sh $V \$(ls -d /out/images/$V/*/ | head -1)" ;;
rollback)
  docker exec -e VIRT_KERNEL=/out/stock/virt-kernel.bin -e UNIT_DIR=/out/unit -e RESULTS=/out/rb-$V "$C" \
    sh -c "bash /w/src/$H/rollback-gate.sh $V \$(ls -d /out/images/$V/*/ | head -1)" ;;
down)
  mkdir -p ci-out
  docker exec "$C" sh -c 'cd /out && tar cf - summary.txt images/*/*/sizes.txt images/*/*/nand-budget.txt images/*/*/sha256sums images/*/*/sha256sums.asc qemu-* rb-*/results.txt rb-*/serial-* build-patronus-cli.log 2>/dev/null' | tar xf - -C ci-out 2>/dev/null || true
  docker rm -f "$C" >/dev/null 2>&1 || true
  ls -R ci-out | head -40 ;;
*) echo "unknown command $CMD"; exit 2 ;;
esac
