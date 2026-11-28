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

# --- the host-global module: load, record the loader, reclaim a stale leftover, unload (all under the lock) -----------
# A run that dies without its EXIT trap (cancelled job, killed container) leaves mac80211_hwsim loaded, and every later
# run then waited the full HWSIM_WAIT_MIN for a module nobody uses. A leftover is reclaimed only when it is PROVABLY idle
# (hwsim_module_busy finds nothing alive); anything doubtful is left alone, because radios are host-global and an
# rmmod pulls them out from under a running hostapd/wpa_supplicant of some other job. Callers hold the lock (hwsim_lock_take).
# Settings: HWSIM_KMOD_IMAGE (image of the throw-away privileged sibling that sees /lib/modules, default debian:trixie),
# HWSIM_LOADER_NAME (record network), HWSIM_SYSROOT/HWSIM_PROCROOT + HWSIM_PROBE_LOCAL=1 (probe a fake tree, for the unit test).
HWSIM_LOADED=
hwsim_module_loaded() { grep '^mac80211_hwsim ' "${HWSIM_PROCROOT:-/proc}/modules" >/dev/null 2>&1; }
# The probe runs in the HOST's pid+net namespaces (a throw-away container), because a job container has its own sysfs.
# Live = any of: use count != 0; a radio (platform device hwsimN) that the host namespace does not see any more (it was
# moved into a container's namespace: that container is using it); a radio's netdev with carrier (an unattended wlan0 that the host merely set UP is NOT live); a hostapd/ap-steer process, or a
# wpa_supplicant/iwd whose command line names a radio's netdev, in any pid namespace (a host's own wpa_supplicant that
# manages real Wi-Fi is not live). Prints the reason and exits 1 when live, exits 0 when idle.
HWSIM_PROBE_SH='
P=${HWSIM_PROCROOT:-/proc}; S=${HWSIM_SYSROOT:-/sys}
rc=$(awk '"'"'$1=="mac80211_hwsim"{print $3}'"'"' "$P/modules" 2>/dev/null)
[ -n "$rc" ] && [ "$rc" != 0 ] && { echo "module use count $rc"; exit 1; }
nr=0; for d in "$S"/bus/platform/drivers/mac80211_hwsim/hwsim[0-9]*; do [ -e "$d" ] && nr=$((nr+1)); done
nv=0
NAMES=; for p in "$S"/class/ieee80211/*; do [ -e "$p" ] || continue
  case $(readlink -f "$p/device" 2>/dev/null) in *hwsim*) nv=$((nv+1));; esac
  for n in "$p"/device/net/*; do [ -d "$n" ] || continue; NAMES="$NAMES ${n##*/}"
    [ "$(cat "$n/carrier" 2>/dev/null)" = 1 ] && { echo "radio netdev ${n##*/} has carrier (an AP is beaconing or a station is associated)"; exit 1; }
  done
done
[ "$nv" -lt "$nr" ] && { echo "$((nr-nv)) of $nr radios are in another network namespace (in use)"; exit 1; }
for c in "$P"/[0-9]*/comm; do [ -r "$c" ] || continue; d=${c%/comm}; k=$(cat "$c" 2>/dev/null)
  case $k in
    hostapd|ap-steer) echo "$k is running (pid ${d##*/})"; exit 1;;
    wpa_supplicant|iwd) for n in $NAMES; do tr "\\0" " " < "$d/cmdline" 2>/dev/null | grep -F -e "$n" >/dev/null && { echo "$k (pid ${d##*/}) is bound to $n"; exit 1; }; done;;
  esac
done
exit 0'
# hwsim_module_busy: 0 (and the reason on stdout) when something may still be using the module, 1 when it is provably idle.
hwsim_module_busy() {
  _d=${HWSIM_DOCKER:-docker}; _why=
  # a running container of one of the four scripts (xbss-/bandsteer-/steer-hwsim-<pid>, hwsim-<pid>); NOT any container with
  # "hwsim" in its name: a waiting CI job's own container is called after the job and often contains it
  _run=$($_d ps -q --filter 'name=^/?(xbss-hwsim|bandsteer-hwsim|steer-hwsim|hwsim)-[0-9]+$' 2>/dev/null | head -n 1)
  if [ -n "$_run" ]; then echo "a running hwsim test container exists ($_run)"; return 0; fi
  _h=$($_d network inspect -f '{{index .Labels "patronus.hwsim-loader-holder"}}' "${HWSIM_LOADER_NAME:-patronus-hwsim-loader}" 2>/dev/null)
  if [ -n "$_h" ] && [ "$_h" != "$(hostname)" ] && $_d container inspect "$_h" >/dev/null 2>&1; then
    echo "the loader's job container $_h still exists"; return 0; fi
  if [ "${HWSIM_PROBE_LOCAL:-0}" = 1 ]; then _why=$(sh -c "$HWSIM_PROBE_SH" 2>&1); _r=$?
  else _why=$($_d run --rm --pid=host --net=host -e HWSIM_PROCROOT -e HWSIM_SYSROOT "${HWSIM_KMOD_IMAGE:-debian:trixie}" sh -c "$HWSIM_PROBE_SH" 2>&1); _r=$?; fi
  if [ "$_r" != 0 ]; then echo "${_why:-probe failed (rc=$_r)}"; return 0; fi   # a probe that cannot run counts as busy
  return 1; }
# hwsim_modctl load RADIOS | unload: directly (root, or sudo on the host) or, from an unprivileged CI job container, through
# a throw-away privileged sibling that sees the host's /lib/modules.
hwsim_modctl() {
  _d=${HWSIM_DOCKER:-docker}; _s=; [ "$(id -u)" = 0 ] || _s=sudo
  _cmd="rmmod mac80211_hwsim"; [ "$1" = load ] && _cmd="modprobe mac80211_hwsim radios=${2:-3}"
  if $_s $_cmd >/dev/null 2>&1; then return 0; fi
  $_d run --rm --privileged -v /lib/modules:/lib/modules:ro "${HWSIM_KMOD_IMAGE:-debian:trixie}" sh -c \
    "command -v modprobe >/dev/null || (apt-get update -qq >/dev/null && apt-get install -y -qq kmod >/dev/null); $_cmd" >/dev/null 2>&1; }
# hwsim_claim_module WAIT_MIN: make sure the module is NOT loaded, so this run can load its own. A leftover that
# hwsim_module_busy calls idle is unloaded at once; a busy one is waited for up to WAIT_MIN minutes, then refused.
hwsim_claim_module() {
  _wm=${1:-0}; _t0=$(date +%s)
  while hwsim_module_loaded; do
    if _why=$(hwsim_module_busy); then
      [ $(( $(date +%s) - _t0 )) -ge $(( _wm * 60 )) ] && { echo "mac80211_hwsim is loaded and in use ($_why): refusing to touch it"; return 1; }
      echo "mac80211_hwsim is loaded and in use ($_why): waiting"; sleep 20; continue; fi
    echo "mac80211_hwsim is loaded but idle (a leftover; loader record: $(hwsim_loader_show)): unloading it"
    hwsim_modctl unload || { echo "could not unload the leftover mac80211_hwsim"; return 1; }
    hwsim_loader_clear; sleep 1
  done
  return 0; }
# hwsim_loader_show: the recorded loader (who/where/when), or "none".
hwsim_loader_show() {
  _l=$(${HWSIM_DOCKER:-docker} network inspect -f '{{index .Labels "patronus.hwsim-loader-script"}}@{{index .Labels "patronus.hwsim-loader-holder"}} since {{index .Labels "patronus.hwsim-loader-time"}}' \
    "${HWSIM_LOADER_NAME:-patronus-hwsim-loader}" 2>/dev/null) && [ -n "$_l" ] && echo "$_l" || echo none; }
hwsim_loader_clear() { ${HWSIM_DOCKER:-docker} network rm "${HWSIM_LOADER_NAME:-patronus-hwsim-loader}" >/dev/null 2>&1 || true; }
# hwsim_load RADIOS SCRIPT: load the module and record the loader (a docker network, like the lock, so it outlives this
# job container); sets HWSIM_LOADED=1. Returns non-zero when the module cannot be loaded (callers skip or fail).
hwsim_load() {
  hwsim_loader_clear
  hwsim_modctl load "$1" || return 1
  HWSIM_LOADED=1
  ${HWSIM_DOCKER:-docker} network create --label "patronus.hwsim-loader-script=${2:-unknown}" --label "patronus.hwsim-loader-holder=$(hostname)" \
    --label "patronus.hwsim-loader-time=$(date -u +%Y-%m-%dT%H:%M:%SZ)" --label "patronus.hwsim-loader-radios=$1" \
    "${HWSIM_LOADER_NAME:-patronus-hwsim-loader}" >/dev/null 2>&1 || { echo "::error::could not record the mac80211_hwsim loader" >&2; return 1; }; }
# hwsim_unload: unload ONLY a module this run loaded (never one a neighbour loaded), and drop the record.
hwsim_unload() {
  [ -n "$HWSIM_LOADED" ] || return 0
  hwsim_modctl unload || { sleep 3; hwsim_modctl unload || echo "::warning::could not unload mac80211_hwsim"; }
  hwsim_loader_clear; HWSIM_LOADED=; }

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
