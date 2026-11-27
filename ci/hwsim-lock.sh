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

# --- skip policy and scenario accounting (bash; sourced by ci/netlab/wifi-hwsim.sh and xbss-hwsim.sh) -------------------
# A Wi-Fi job that cannot load mac80211_hwsim proves nothing, so in CI it FAILS: it is routed to the hwsim-x86_64 runner
# lane (the CI host, declared in the runner inventory) whose kernel package ships the module, and a
# host without it is an error, never a green SKIP (the job used to "pass" on the CI host, whose 6.8 kernel has none, and the
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
