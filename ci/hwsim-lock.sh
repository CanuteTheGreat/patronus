#!/bin/sh
# hwsim-lock.sh: sourced by every script that loads mac80211_hwsim (ci/netlab/wifi-hwsim.sh,
# ci/embedded-aarch64/ax1800/tests/xbss-hwsim.sh). The module is host-global and CI job containers each have their own
# /tmp, so a flock on a file does not exclude a run in another job container: one run's rmmod then pulled the radios
# out of a second run (hostapd kept a dead radio, the coordination re-check never saw its neighbour, the job ran into
# its time limit). The mutex is a docker network of a fixed name: its creation is atomic on the host's docker daemon
# and visible to every job container that has the docker socket.
# Settings (all overridable): HWSIM_DOCKER (docker command, default "docker"), HWSIM_LOCK_NAME, HWSIM_STALE_MIN (a lock
# older than this belongs to a run that died without cleanup: removed), HWSIM_WAIT_MIN (longest wait for the lock).
hwsim_lock_take() {
  _d=${HWSIM_DOCKER:-docker}; _n=${HWSIM_LOCK_NAME:-patronus-hwsim-lock}
  _stale=$(( ${HWSIM_STALE_MIN:-60} * 60 )); _wait=$(( ${HWSIM_WAIT_MIN:-20} * 60 )); _t0=$(date +%s)
  while ! $_d network create --label "patronus.hwsim-lock=$(date +%s)" "$_n" >/dev/null 2>&1; do
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
