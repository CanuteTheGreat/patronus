#!/bin/sh
# hwsim-lock.sh: sourced by every script that loads mac80211_hwsim (ci/netlab/wifi-hwsim.sh,
# ci/embedded-aarch64/ax1800/tests/xbss-hwsim.sh). The module is host-global and CI job containers each have their own
# /tmp, so a flock on a file does not exclude a run in another job container: one run's rmmod then pulled the radios
# out of a second run (hostapd kept a dead radio, the coordination re-check never saw its neighbour, the job ran into
# its time limit). The mutex is a docker network of a fixed name: its creation is atomic on the host's docker daemon
# and visible to every job container that has the docker socket.
# Settings (all overridable): HWSIM_DOCKER (docker command, default "docker"), HWSIM_LOCK_NAME, HWSIM_STALE_MIN (a lock
# older than this belongs to a run that died without cleanup: removed), HWSIM_WAIT_MIN (longest wait for the lock).
# The lock label also records the holder's job container (its hostname = the short container id); when that container
# no longer exists (cancelled/killed run whose EXIT trap never ran) the lock is removed at once instead of after
# HWSIM_STALE_MIN. The default wait (65 min) is longer than the stale limit (60 min) on purpose: a waiter must outlast
# the longest legitimate holder (the Wi-Fi job, 60 min limit) or a leaked lock, otherwise it fails a green tree red
# (xbss-hwsim 2026-11-19 gave up after 20 min).
hwsim_lock_take() {
  _d=${HWSIM_DOCKER:-docker}; _n=${HWSIM_LOCK_NAME:-patronus-hwsim-lock}
  _stale=$(( ${HWSIM_STALE_MIN:-60} * 60 )); _wait=$(( ${HWSIM_WAIT_MIN:-65} * 60 )); _t0=$(date +%s)
  while ! $_d network create --label "patronus.hwsim-lock=$(date +%s)" --label "patronus.hwsim-holder=$(hostname)" "$_n" >/dev/null 2>&1; do
    _h=$($_d network inspect -f '{{index .Labels "patronus.hwsim-holder"}}' "$_n" 2>/dev/null)
    case "$_h" in
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
        if [ "$_h" != "$(hostname)" ] && ! $_d container inspect "$_h" >/dev/null 2>&1; then
          echo "removing the mac80211_hwsim lock of the dead job container $_h"; $_d network rm "$_n" >/dev/null 2>&1; continue; fi;;
    esac
    _ts=$($_d network inspect -f '{{index .Labels "patronus.hwsim-lock"}}' "$_n" 2>/dev/null)
    if [ -n "$_ts" ] && [ "$_ts" -gt 0 ] 2>/dev/null && [ $(( $(date +%s) - _ts )) -gt "$_stale" ]; then
      echo "removing the stale mac80211_hwsim lock ($(( ($(date +%s) - _ts) / 60 )) min old)"; $_d network rm "$_n" >/dev/null 2>&1; continue; fi
    [ $(( $(date +%s) - _t0 )) -gt "$_wait" ] && { echo "another mac80211_hwsim run still holds the host lock $_n after $((_wait / 60)) min: refusing"; return 1; }
    echo "another mac80211_hwsim run holds the host lock: waiting"; sleep 15
  done
  HWSIM_LOCK_HELD=1; }
hwsim_lock_drop() {
  [ "${HWSIM_LOCK_HELD:-}" = 1 ] || return 0
  ${HWSIM_DOCKER:-docker} network rm "${HWSIM_LOCK_NAME:-patronus-hwsim-lock}" >/dev/null 2>&1; HWSIM_LOCK_HELD=; }

# --- stale module left by a killed run -------------------------------------------------------------------------------
# A job that is cancelled or times out is killed with `docker kill`, which skips its EXIT trap: the container dies (the
# radios come back to the host's init namespace) but mac80211_hwsim stays loaded, and every later run waited the full
# lock time for a module nobody uses (patronus embedded-aarch64 run 25389, 2026-11-23: 65 min, then "still loaded").
# Once the host lock is ours, a loaded module is a LEFTOVER when ALL of these hold, and only then it is unloaded:
#   - its use count (/proc/modules) is 0,
#   - every hwsim phy has its interfaces in the host's initial network namespace (a phy moved into a container has none
#     there) and every such interface carries one of this repo's test names (HWSIM_STALE_NAMES, a space separated list of
#     shell patterns; default wl24-* wl5-* wsta*),
#   - no hostapd / wpa_supplicant / iw / iwd process exists on the host or in any container (HWSIM_STALE_PROCS).
# Anything else (a count above 0, a radio inside a container, a foreign interface name, a live process, a phy with no
# interface at all, a phy of another driver is ignored) means the module is in use: the caller keeps waiting.
# The probe needs the host's network and pid namespaces, so from a job container it runs in a throw-away sibling
# (`docker run --net=host --pid=host`, script on stdin; /proc/modules is kernel-global). HWSIM_STALE_DIRECT=1 runs it in
# place (host tests, fake roots HWSIM_PROC / HWSIM_SYS). Exit 0 = stale, prints the reason otherwise.
HWSIM_PROBE_SRC='
PROC=${HWSIM_PROC:-/proc}; SYS=${HWSIM_SYS:-/sys}
NAMES=${HWSIM_STALE_NAMES:-"wl24-* wl5-* wsta*"}; PROCS=${HWSIM_STALE_PROCS:-"hostapd wpa_supplicant iw iwd"}
line=$(grep "^mac80211_hwsim " "$PROC/modules" 2>/dev/null) || { echo "not loaded"; exit 2; }
set -- $line
[ "${3:-x}" = 0 ] || { echo "use count ${3:-?}"; exit 1; }
nphy=0
for ph in "$SYS"/class/ieee80211/*; do
  [ -e "$ph" ] || continue
  dev=$(readlink "$ph/device" 2>/dev/null); case "${dev##*/}" in hwsim*) ;; *) continue;; esac
  nphy=$((nphy + 1)); p=${ph##*/}; nif=0
  for n in "$SYS"/class/net/*; do
    [ -L "$n/phy80211" ] || continue
    t=$(readlink "$n/phy80211" 2>/dev/null); [ "${t##*/}" = "$p" ] || continue
    nif=$((nif + 1)); nm=${n##*/}; ok=0
    for pat in $NAMES; do case "$nm" in $pat) ok=1;; esac; done
    [ $ok = 1 ] || { echo "$p has interface $nm, not a test name"; exit 1; }
  done
  [ $nif -gt 0 ] || { echo "$p has no interface in the host namespace (moved into a container?)"; exit 1; }
done
[ $nphy -gt 0 ] || { echo "no hwsim phy visible"; exit 1; }
for c in "$PROC"/[0-9]*/comm; do
  [ -r "$c" ] || continue
  read -r cm < "$c" 2>/dev/null || continue
  for pr in $PROCS; do [ "$cm" = "$pr" ] && { echo "process $cm ${c%/comm}"; exit 1; }; done
done
echo "stale: use count 0, $nphy phys with test interface names in the host namespace, no wireless process"
exit 0'
hwsim_stale_probe() {
  if [ "${HWSIM_STALE_DIRECT:-0}" = 1 ]; then printf '%s\n' "$HWSIM_PROBE_SRC" | sh -s; return; fi
  printf '%s\n' "$HWSIM_PROBE_SRC" | ${HWSIM_DOCKER:-docker} run --rm -i --net=host --pid=host \
    -e HWSIM_STALE_NAMES -e HWSIM_STALE_PROCS "${HWSIM_PROBE_IMAGE:-${KMOD_IMAGE:-${IMAGE:-debian:trixie}}}" sh -s 2>&1
}
# hwsim_wait_free UNLOAD_CMD: with the host lock held, return once mac80211_hwsim is not loaded. A leftover (see above)
# is unloaded with UNLOAD_CMD; a module in use is waited for up to HWSIM_WAIT_MIN, then exit 1 is returned.
hwsim_wait_free() {
  _unl=$1; _w=$(( ${HWSIM_WAIT_MIN:-65} * 60 )); _t=$(date +%s); _tries=0
  while grep '^mac80211_hwsim ' "${HWSIM_PROC:-/proc}/modules" >/dev/null 2>&1; do
    _why=$(hwsim_stale_probe 2>&1) && _rc=0 || _rc=$?
    if [ $_rc = 0 ] && [ $_tries -lt 3 ]; then
      _tries=$((_tries + 1))
      if $_unl; then echo "stale mac80211_hwsim from a killed run: unloaded ($_why)"; continue; fi
      echo "stale mac80211_hwsim from a killed run: unload failed, retrying"; sleep 2; continue
    fi
    [ $(( $(date +%s) - _t )) -gt "$_w" ] && { echo "mac80211_hwsim still loaded after $((_w / 60)) min (another user?): refusing"; return 1; }
    echo "mac80211_hwsim is loaded by another run: waiting (${_why:-no reason})"; sleep "${HWSIM_POLL_SEC:-20}"
  done
  return 0; }

# --- skip policy and scenario accounting (bash; sourced by ci/netlab/wifi-hwsim.sh and xbss-hwsim.sh) -------------------
# A Wi-Fi job that cannot load mac80211_hwsim proves nothing, so in CI it FAILS: it is routed to the hwsim-x86_64 runner
# lane (rw-man-02/03, declared in redweek-devops runners-expected.json) whose kernel package ships the module, and a
# host without it is an error, never a green SKIP (the job used to "pass" on rw-man-01, whose 6.8 kernel has none, and the
# Wi-Fi code went unproven for weeks). HWSIM_ALLOW_SKIP=1 turns that back into a SKIP for a developer box without the module.
HWSIM_RUN=0; HWSIM_EXEC=0; HWSIM_SKIPPED=0; HWSIM_FAILED=0; HWSIM_CHECKS=0; HWSIM_FAILED_LIST=
hwsim_skip_or_fail() { # REASON
  if [ "${HWSIM_ALLOW_SKIP:-0}" = 1 ]; then echo "SKIP wifi-hwsim: $1 (HWSIM_ALLOW_SKIP=1)"; exit 0; fi
  echo "FAIL wifi-hwsim: $1 on $(hostname) (kernel $(uname -r)). This job needs a runner of the hwsim-x86_64 lane; set HWSIM_ALLOW_SKIP=1 only for a local run." >&2
  exit 1; }
# hwsim_run NAME CMD...: run one scenario, stream its output, and count it as EXECUTED only when it exited 0, printed no
# line starting with SKIP and produced at least one check line (ok - ... / PASS...).
hwsim_run() {
  local name=$1 f rc checks; shift
  f=$(mktemp); HWSIM_RUN=$((HWSIM_RUN + 1))
  echo "=== HWSIM scenario $HWSIM_RUN: $name"
  if "$@" 2>&1 | tee "$f"; then rc=0; else rc=${PIPESTATUS[0]}; fi   # survives set -e/pipefail in the caller
  checks=$(grep -c -E '^(ok - |PASS)' "$f" || true)
  if [ "$rc" != 0 ]; then HWSIM_FAILED=$((HWSIM_FAILED + 1)); HWSIM_FAILED_LIST="$HWSIM_FAILED_LIST $name"; echo "--- HWSIM $name: FAILED (rc=$rc)"
  elif grep -q -E '^SKIP' "$f"; then HWSIM_SKIPPED=$((HWSIM_SKIPPED + 1)); HWSIM_FAILED_LIST="$HWSIM_FAILED_LIST $name(skipped)"; echo "--- HWSIM $name: SKIPPED"
  elif [ "$checks" -lt 1 ]; then HWSIM_FAILED=$((HWSIM_FAILED + 1)); HWSIM_FAILED_LIST="$HWSIM_FAILED_LIST $name(no checks)"; echo "--- HWSIM $name: ran but printed no check line"
  else HWSIM_EXEC=$((HWSIM_EXEC + 1)); HWSIM_CHECKS=$((HWSIM_CHECKS + checks)); echo "--- HWSIM $name: EXECUTED ($checks checks)"; fi
  rm -f "$f"; }
# hwsim_summary: one line the job log can be audited by; returns non-zero unless every scenario executed.
hwsim_summary() {
  echo "HWSIM SUMMARY: host=$(hostname) kernel=$(uname -r) scenarios=$HWSIM_RUN executed=$HWSIM_EXEC skipped=$HWSIM_SKIPPED failed=$HWSIM_FAILED checks=$HWSIM_CHECKS${HWSIM_FAILED_LIST:+ problems:$HWSIM_FAILED_LIST}"
  [ "$HWSIM_RUN" -ge 1 ] && [ "$HWSIM_EXEC" = "$HWSIM_RUN" ] && return 0
  [ "${HWSIM_ALLOW_SKIP:-0}" = 1 ] && [ "$HWSIM_FAILED" = 0 ] && [ "$HWSIM_EXEC" -ge 1 ] && return 0
  return 1; }
