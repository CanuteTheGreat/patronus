#!/usr/bin/env bash
# Real-host proof of the leftover-module logic in ci/hwsim-lock.sh, run against the four scripts that load
# mac80211_hwsim (xbss-hwsim, bandsteer-hwsim, steer-hwsim, ci/netlab/wifi-hwsim). Run it ON a host of the hwsim lane
# (x86_64, docker, sudo, the module), from a checkout, inside a leased work dir:
#   agent-workdir run hwsim-live -- ci/hwsim-live-safety-test.sh [leftover|live|all]
# It takes the REAL host lock for its whole run (so no other run loads or unloads the module meanwhile) and runs the
# scripts under test with a PRIVATE lock/record name, so they can take "their" lock. Needs the module to be unloaded at
# the start, and leaves it unloaded.
#  leftover: the module is left loaded by a pretend dead run (loader recorded, nothing using it); each script must say
#            it is an idle leftover, unload it, run to the end and leave the module unloaded.
#  live:     (a) radios moved into a running container, (b) a hostapd bound to a radio in the host namespace; each script
#            must REFUSE (non-zero, "in use"), the module must stay loaded with all radios and the daemon alive.
set -euo pipefail
cd "$(dirname "$0")/.."
MODE=${1:-all}
DOCKER=${DOCKER:-docker}; export HWSIM_DOCKER=$DOCKER
IMG=${HWSIM_KMOD_IMAGE:-debian:trixie}
. ci/hwsim-lock.sh
fails=0
ok() { echo "ok - $*"; }
bad() { echo "FAIL - $*"; fails=$((fails + 1)); }
mods() { grep -c '^mac80211_hwsim ' /proc/modules || true; }
radios() { ls /sys/bus/platform/drivers/mac80211_hwsim 2>/dev/null | grep -c '^hwsim[0-9]' || true; }

echo "=== host $(hostname), kernel $(uname -r): taking the real host lock (waits for other runs)"
HWSIM_WAIT_MIN=${HWSIM_WAIT_MIN:-120} hwsim_lock_take || exit 1
CT=lt-$$
cleanup() {
  $DOCKER rm -fv "$CT-ns" "$CT-ap" "$CT-wifi" >/dev/null 2>&1 || true
  sleep 1; if [ "${CLEAN_START:-}" = 1 ] && [ "$(mods)" != 0 ]; then HWSIM_LOADED=1; hwsim_unload; fi   # only what this run loaded
  $DOCKER network rm "${HWSIM_LOCK_NAME}" "${HWSIM_LOADER_NAME}" >/dev/null 2>&1 || true
  unset HWSIM_LOCK_NAME HWSIM_LOADER_NAME; hwsim_lock_drop; echo "=== real lock dropped, module loaded: $(mods)"
}
trap cleanup EXIT
[ "$(mods)" = 0 ] || { echo "mac80211_hwsim is loaded at the start (someone's): not touching it"; exit 1; }
CLEAN_START=1
# the scripts under test use a private lock and loader record, the real lock stays ours
export HWSIM_LOCK_NAME=patronus-hwsim-lock-lt$$ HWSIM_LOADER_NAME=patronus-hwsim-loader-lt$$

# the four scripts; refuse runs must end quickly (HWSIM_WAIT_MIN=0 HWSIM_MODULE_WAIT_MIN=0)
$DOCKER run -d --name "$CT-wifi" "$IMG" sleep infinity >/dev/null
$DOCKER exec "$CT-wifi" mkdir -p /t
$DOCKER exec -i "$CT-wifi" sh -c 'cat > /t/stub.sh' <<'EOF'
echo "ok - stub scenario sees $(ls /sys/class/ieee80211 | wc -l) radios"
EOF
declare -A CMD=(
  [steer]="SOFT_CYCLES=2 HARD_RUNS=2 NIGHT=0 bash ci/embedded-aarch64/ax1800/tests/steer-hwsim.sh"
  [bandsteer]="CYCLES=1 bash ci/embedded-aarch64/ax1800/tests/bandsteer-hwsim.sh"
  [xbss]="SCENARIOS=acs bash ci/embedded-aarch64/ax1800/tests/xbss-hwsim.sh"
  [wifi-hwsim]="HWSIM_CONTAINER=$CT-wifi HWSIM_SCENARIOS=stub.sh HWSIM_RADIOS=3 bash ci/netlab/wifi-hwsim.sh"
)
ORDER=${LT_ORDER:-"steer bandsteer xbss wifi-hwsim"}
mkleft() { # a pretend dead run: module loaded, loader recorded, nothing uses it, no one holds a lock
  HWSIM_LOADED=; hwsim_load 3 "pretend-dead-run" || { echo "cannot load the module"; exit 1; }; HWSIM_LOADED=; }

if [ "$MODE" = leftover ] || [ "$MODE" = all ]; then
  for s in $ORDER; do
    echo; echo "=== LEFTOVER $s: module left loaded by a dead run (loader: $(hwsim_loader_show))"
    mkleft; [ "$(mods)" = 1 ] && [ "$(radios)" = 3 ] || { bad "$s: could not stage the leftover"; continue; }
    rc=0; env HWSIM_WAIT_MIN=0 HWSIM_MODULE_WAIT_MIN=0 bash -c "${CMD[$s]}" > "$TMPDIR/lt-$s.log" 2>&1 || rc=$?
    sed 's/^/    | /' "$TMPDIR/lt-$s.log" | grep -E 'idle|leftover|unload|refus|in use|HWSIM SUMMARY|^    \| (ok - |PASS|FAIL|SKIP)|moved into' | head -20
    grep -q 'loaded but idle' "$TMPDIR/lt-$s.log" && ok "$s: detected the idle leftover" || bad "$s: did not report an idle leftover"
    [ "$rc" = 0 ] && ok "$s: ran to the end (rc=0)" || bad "$s: rc=$rc"
    [ "$(mods)" = 0 ] && ok "$s: module unloaded afterwards" || { bad "$s: module still loaded afterwards"; hwsim_modctl unload || true; }
    $DOCKER network rm "$HWSIM_LOADER_NAME" >/dev/null 2>&1 || true
  done
fi

refuse_all() { # TAG: every script must refuse, and the radios/daemon must survive
  local tag=$1 s rc r0 ; r0=$(radios)
  for s in $ORDER; do
    rc=0; env HWSIM_WAIT_MIN=0 HWSIM_MODULE_WAIT_MIN=0 bash -c "${CMD[$s]}" > "$TMPDIR/lt-$s.log" 2>&1 || rc=$?
    grep -E 'in use|refus' "$TMPDIR/lt-$s.log" | head -2 | sed "s/^/    [$tag $s] /"
    [ "$rc" != 0 ] && grep -q 'in use' "$TMPDIR/lt-$s.log" && ok "$tag/$s: refused (rc=$rc)" || bad "$tag/$s: did not refuse (rc=$rc)"
    grep -q 'unloading it' "$TMPDIR/lt-$s.log" && bad "$tag/$s: tried to unload a live module"
    [ "$(mods)" = 1 ] && [ "$(radios)" = "$r0" ] && ok "$tag/$s: module and all $r0 radios still there" || bad "$tag/$s: module or radios gone"
  done
}

if [ "$MODE" = live ] || [ "$MODE" = all ]; then
  echo; echo "=== LIVE (a): radios in use inside a running container (no hwsim in its name, no daemon)"
  hwsim_load 3 "live-radios-test" || exit 1
  $DOCKER run -d --name "$CT-ns" --cap-add NET_ADMIN "$IMG" sleep infinity >/dev/null
  PID=$($DOCKER inspect -f '{{.State.Pid}}' "$CT-ns")
  $DOCKER run --rm --net=host --pid=host --cap-add NET_ADMIN "$IMG" sh -c \
    "apt-get update -qq >/dev/null && apt-get install -y -qq iw >/dev/null 2>&1; for p in \$(ls /sys/class/ieee80211); do iw phy \$p set netns $PID || exit 1; done"
  [ "$($DOCKER exec "$CT-ns" sh -c 'ls /sys/class/ieee80211 | wc -l')" = 3 ] && ok "3 radios live inside $CT-ns" || bad "radios did not move"
  refuse_all ns
  [ "$($DOCKER exec "$CT-ns" sh -c 'ls /sys/class/ieee80211 | wc -l')" = 3 ] && ok "the container still owns its 3 radios" || bad "container lost radios"
  $DOCKER rm -fv "$CT-ns" >/dev/null; sleep 1
  hwsim_unload; [ "$(mods)" = 0 ] || bad "could not clean up (a)"

  echo; echo "=== LIVE (b): a hostapd bound to a radio in the host namespace"
  hwsim_load 3 "live-hostapd-test" || exit 1
  $DOCKER run -d --name "$CT-ap" --net=host --privileged "$IMG" sh -c '
    apt-get update -qq >/dev/null && apt-get install -y -qq hostapd iw >/dev/null 2>&1
    P=$(ls /sys/class/ieee80211 | head -n 1); IF=ltap0; iw phy $P interface add $IF type managed
    printf "interface=$IF\ndriver=nl80211\nssid=lt-live\nhw_mode=g\nchannel=6\n" > /tmp/h.conf
    exec hostapd /tmp/h.conf' >/dev/null
  for i in $(seq 40); do $DOCKER logs "$CT-ap" 2>&1 | grep -q 'AP-ENABLED' && break; sleep 3; done
  $DOCKER logs "$CT-ap" 2>&1 | grep -q 'AP-ENABLED' && ok "hostapd serves ssid lt-live on a hwsim radio" || { bad "hostapd did not start"; $DOCKER logs "$CT-ap" 2>&1 | head -25; }
  refuse_all hostapd
  $DOCKER logs "$CT-ap" 2>&1 | tail -1 | grep -q 'AP-DISABLED\|died' && bad "hostapd was disturbed" || ok "hostapd still running, undisturbed"
  [ "$($DOCKER inspect -f '{{.State.Running}}' "$CT-ap")" = true ] && ok "hostapd container still running" || bad "hostapd container died"
  $DOCKER rm -fv "$CT-ap" >/dev/null; sleep 1
  hwsim_unload; [ "$(mods)" = 0 ] || bad "could not clean up (b)"
fi
echo
[ "$fails" = 0 ] && echo "PASS hwsim-live-safety-test ($MODE) on $(hostname)" || { echo "$fails check(s) FAILED"; exit 1; }
