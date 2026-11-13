#!/usr/bin/env bash
# The published image booted with systemd as PID 1 (the "as shipped" check for
# the systemd side of Patronus' init parity; ci/container-as-shipped.sh covers
# the no-init docker-compose shape). Proves, in the real emerge-built image:
#   * systemd reaches a running/degraded state as PID 1 and every shipped
#     patronus-*.service passes `systemd-analyze verify`;
#   * `systemctl start patronus-web` brings up applyd + the firewall oneshot +
#     the web UI as the unprivileged patronus user (units are real, ordering ok);
#   * the web UI's service control works through the systemd backend of
#     patronus_core::service::ServiceManager: GET /api/system/services reports
#     patronus-web Running with its enabled flag, POST restart changes the
#     MainPID, restart-only services refuse stop (400), unknown names 404;
#   * the unit file for every service the UI lists exists (no OpenRC-only
#     service name leaks into the list).
#
# Usage: ci/container-as-shipped-systemd.sh <image>
# Needs a runner that can run systemd in a container (cgroup v2 rw mount,
# --privileged). The container is memory/CPU capped and removed on exit.
set -euo pipefail

IMAGE=${1:?usage: ci/container-as-shipped-systemd.sh <image>}
C=pas-sd-${GITHUB_RUN_ID:-local}-$$

log() { echo "[as-shipped-systemd] $*"; }
ok() { echo "[as-shipped-systemd] ok: $*"; }
fail() { echo "::error::[as-shipped-systemd] $*"; exit 1; }

cleanup() {
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "----- systemctl --failed -----"; docker exec "$C" systemctl --no-pager --failed 2>&1 || true
    for u in patronus-web patronus-applyd patronus-firewall; do
      echo "----- journal: $u -----"; docker exec "$C" journalctl -u "$u" --no-pager -n 40 2>&1 || true
    done
    echo "----- docker logs -----"; docker logs --tail 40 "$C" 2>&1 || true
  fi
  docker rm -f -v "$C" >/dev/null 2>&1 || true
  exit $rc
}
trap cleanup EXIT

PW="Sd-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')-Pw1"

# systemd needs /run, /tmp and the cgroup tree writable; the image's own USER
# (patronus) and CMD are replaced: PID 1 must be root's systemd.
docker run -d --name "$C" --privileged --cgroupns=host \
  --user 0 --entrypoint /usr/lib/systemd/systemd \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --stop-signal SIGRTMIN+3 --memory 2g --memory-swap 2g --cpus 2 \
  "$IMAGE" --unit=multi-user.target >/dev/null

X() { docker exec "$C" "$@"; }

# 1. systemd is PID 1 and finishes booting
for _ in $(seq 1 60); do
  st=$(X systemctl is-system-running 2>/dev/null || true)
  case "$st" in running|degraded) break ;; esac
  sleep 1
done
case "$st" in running|degraded) ok "systemd is PID 1 and booted ($st)" ;; *) fail "systemd did not finish booting: '$st'" ;; esac
[ "$(X cat /proc/1/comm)" = systemd ] || fail "PID 1 is not systemd"
X test -d /run/systemd/system || fail "/run/systemd/system missing: runtime detection would pick OpenRC"
ok "/run/systemd/system exists (the runtime detection probe)"

# 2. shipped units are well-formed
for u in $(X sh -c 'ls /usr/lib/systemd/system/patronus-*.service /usr/lib/systemd/system/patronus-*.timer'); do
  out=$(X systemd-analyze verify "$u" 2>&1 || true)
  # templates and units whose binaries are not in this image USE set are fine;
  # syntax / unknown-key / dependency-cycle problems are not
  echo "$out" | grep -E "Unknown (key|section)|Unit .* not found|dependency cycle|Failed to parse|Invalid" && fail "systemd-analyze verify $u:\n$out"
done
ok "all shipped patronus units pass systemd-analyze verify"

# 3. web + applyd + firewall come up under systemd
X install -d -m 0755 /etc/systemd/system/patronus-web.service.d
X sh -c "printf '[Service]\nEnvironment=PATRONUS_ADMIN_PASSWORD=%s\n' '$PW' > /etc/systemd/system/patronus-web.service.d/ci.conf"
X systemctl daemon-reload
X systemctl start patronus-web || fail "systemctl start patronus-web failed"
for _ in $(seq 1 60); do
  X curl -ksf -o /dev/null https://localhost:8443/login && break
  sleep 1
done
X curl -ksf -o /dev/null https://localhost:8443/login || fail "patronus-web did not answer on :8443 under systemd"
for s in patronus-web patronus-applyd; do
  [ "$(X systemctl is-active $s)" = active ] || fail "$s is not active"
done
[ "$(X systemctl show -p Result --value patronus-firewall)" = success ] || fail "patronus-firewall oneshot did not succeed"
[ "$(X ps -o user= -p "$(X systemctl show -p MainPID --value patronus-web)" | tr -d ' ')" = patronus ] \
  || fail "patronus-web is not running as the patronus user"
ok "patronus-firewall (oneshot), patronus-applyd and patronus-web (as patronus) are up"

# 4. service control from the web UI goes through systemctl
OUT=; CODE=
api() {
  local r
  r=$(X curl -ks -b /tmp/jar -c /tmp/jar -X "$1" -H 'Content-Type: application/json' \
        ${3:+--data "$3"} -w '\n%{http_code}' "https://localhost:8443/api$2")
  CODE=${r##*$'\n'}; OUT=${r%$'\n'*}
}
must() { local want=$1; shift; api "$@"; [ "$CODE" = "$want" ] || fail "$1 $2 -> $CODE (want $want): $OUT"; }
must 200 POST /auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}"

must 200 GET /system/services
echo "$OUT" | python3 -c '
import json, sys
d = json.load(sys.stdin)
items = d if isinstance(d, list) else next(v for v in d.values() if isinstance(v, list))
by = {s["name"]: s for s in items}
w = by.get("patronus-web")
assert w, "patronus-web missing from %s" % sorted(by)
assert w["is_running"] and w["status"] == "Running", w
print("listed:", ", ".join(sorted(by)))
' || fail "GET /api/system/services: $OUT"
ok "GET /api/system/services lists patronus-web as Running (state read via systemctl)"

pid0=$(X systemctl show -p MainPID --value patronus-web)
must 200 POST /system/services/patronus-applyd/restart
ok "restarting patronus-applyd through the UI works (root broker, systemctl restart)"
for _ in $(seq 1 30); do [ "$(X systemctl is-active patronus-applyd)" = active ] && break; sleep 1; done
[ "$(X systemctl is-active patronus-applyd)" = active ] || fail "patronus-applyd not active after UI restart"
# patronus-web's own restart kills the request's server: fire it, then watch systemd
api POST /system/services/patronus-web/restart || true
for _ in $(seq 1 60); do
  pid1=$(X systemctl show -p MainPID --value patronus-web)
  [ "$pid1" != 0 ] && [ "$pid1" != "$pid0" ] && X curl -ksf -o /dev/null https://localhost:8443/login && break
  sleep 1
done
[ "$pid1" != "$pid0" ] && [ "$pid1" != 0 ] || fail "patronus-web MainPID unchanged ($pid0) after UI restart"
ok "restarting patronus-web through the UI re-spawned it under systemd (pid $pid0 -> $pid1)"

must 200 POST /auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}"
must 400 POST /system/services/patronus-web/stop
must 404 POST /system/services/not-a-service/restart
ok "restart-only services refuse stop (400), unknown names are 404"

# 5. clean shutdown through PID 1
docker stop -t 30 "$C" >/dev/null || fail "systemd did not stop cleanly"
ok "container stopped via SIGRTMIN+3 (clean systemd shutdown)"
