#!/usr/bin/env bash
# Lane D (LAN services) netlab, OpenRC or systemd path:
#
#   ci/netlab/lan-services.sh openrc|systemd [patronus-cli patronus-web]
#
# Runs ci/netlab/lan-services-test.sh inside a capped Gentoo container
# (ci/netlab/gentoo-lan.Dockerfile: real stage3 + kea, dnsmasq, radvd,
# unbound, chrony from Gentoo's binhost) with the shipped binaries (default:
# target/debug, as built by ci/netlab/run.sh) and the shipped OpenRC
# scripts / systemd units from gentoo/net-firewall/patronus/files.
#
# - openrc: the container runs `sleep`; OpenRC's rc-service drives the
#   daemons (the docker-friendly softlevel setup, as on any OpenRC container).
# - systemd: the container's PID 1 is systemd (in a private cgroup
#   namespace whose cgroup2 view is remounted read-write; still capped, not
#   --privileged), and systemctl drives the daemons.
#
# The container's own network namespace is the router; the test builds
# client namespaces + a bridge inside it.
set -euo pipefail
cd "$(dirname "$0")/../.."

INIT=${1:?usage: lan-services.sh openrc|systemd [patronus-cli patronus-web]}
CLI=${2:-target/debug/patronus-cli}
WEB=${3:-target/debug/patronus-web}
case "$INIT" in openrc|systemd) ;; *) echo "bad init $INIT"; exit 2 ;; esac

REG=git.canutethegreat.com/canutethegreat/patronus-netlab-lan
HASH=$(sha256sum ci/netlab/gentoo-lan.Dockerfile | cut -c1-12)
IMAGE=$REG:$INIT-$HASH
LOGGED_IN=
if [ -n "${REGISTRY_PUSH_TOKEN:-}" ] && echo "$REGISTRY_PUSH_TOKEN" | \
     docker login git.canutethegreat.com -u CanuteTheGreat --password-stdin >/dev/null 2>&1; then
  LOGGED_IN=1
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  if docker pull "$IMAGE" >/dev/null 2>&1; then
    echo "--- pulled $IMAGE"
  else
    echo "--- building $IMAGE (Gentoo stage3 + binhost packages)"
    n=1
    until docker build --build-arg INIT="$INIT" -t "$IMAGE" -f ci/netlab/gentoo-lan.Dockerfile ci/netlab; do
      [ $n -ge 3 ] && { echo "image build failed"; exit 1; }
      n=$((n+1)); sleep 20
    done
    if [ -n "$LOGGED_IN" ]; then
      docker push "$IMAGE" >/dev/null 2>&1 || echo "::warning::push of $IMAGE failed (next run rebuilds)"
    fi
  fi
fi
[ -n "$LOGGED_IN" ] && { docker logout git.canutethegreat.com >/dev/null 2>&1 || true; }

C=${NETLAB_NAME:-netlab-lan-$INIT-${GITHUB_RUN_ID:-local}-$$}
OUT=$(mktemp -d)
cleanup() {
  # NETLAB_KEEP=1 leaves the container up for debugging (docker exec -it $C bash)
  if [ -n "${NETLAB_KEEP:-}" ]; then echo "--- kept container $C"; else docker rm -f -v "$C" >/dev/null 2>&1 || true; fi
  rm -rf "$OUT"
}
trap cleanup EXIT

cp "$CLI" "$OUT/patronus-cli"
cp "$WEB" "$OUT/patronus-web"
cp ci/netlab/lan-services-test.sh "$OUT/"
cp gentoo/net-firewall/patronus/files/patronus-{applyd,web,firewall}.{service,initd} "$OUT/"

COMMON=(--cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN
        --security-opt apparmor=unconfined --security-opt systempaths=unconfined
        --memory 2g --memory-swap 2g --cpus 2 --hostname router)
if [ "$INIT" = systemd ]; then
  # systemd needs a writable cgroup2 tree. Keep the container in its own
  # cgroup namespace (never hand it the host's tree) and remount that
  # namespace's view read-write (CAP_SYS_ADMIN + apparmor=unconfined, still
  # not --privileged) before exec'ing systemd as PID 1.
  docker run -d --name "$C" "${COMMON[@]}" --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock -e container=docker "$IMAGE" \
    /bin/sh -c 'mount -o remount,rw /sys/fs/cgroup 2>/dev/null \
      || { umount /sys/fs/cgroup; mount -t cgroup2 cgroup2 /sys/fs/cgroup; }; exec /sbin/init' >/dev/null
  for i in $(seq 1 60); do
    st=$(docker exec "$C" systemctl is-system-running 2>/dev/null || true)
    case "$st" in running|degraded) break ;; esac
    sleep 1
  done
  echo "--- systemd in the container: $st"
else
  # --init: a real PID 1 reaps the daemons OpenRC stops; under a bare
  # `sleep` they stay zombies and start-stop-daemon reports "refused to stop".
  docker run -d --init --name "$C" "${COMMON[@]}" "$IMAGE" sleep infinity >/dev/null
fi
docker exec "$C" mkdir -p /t
docker cp "$OUT/." "$C:/t/"
set +e
docker exec "$C" bash /t/lan-services-test.sh "$INIT"
rc=$?
set -e
if [ $rc -ne 0 ]; then
  echo "===== diagnostics ($INIT)"
  docker exec "$C" bash -c 'for f in /etc/kea/kea-dhcp4.conf /etc/dnsmasq.conf /etc/unbound/unbound.conf /etc/radvd.conf /etc/chrony/chrony.conf /var/log/patronus/*.log /t/*.log; do [ -f "$f" ] && { echo "--- $f"; tail -60 "$f"; }; done' || true
  if [ "$INIT" = systemd ]; then
    docker exec "$C" journalctl --no-pager -n 120 || true
  fi
fi
exit $rc
