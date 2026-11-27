#!/usr/bin/env bash
# Host-side unit test of the Wi-Fi job's skip policy (ci/hwsim-lock.sh): a green run needs every scenario EXECUTED; a
# SKIP, a missing module or a scenario that prints no check line fails unless HWSIM_ALLOW_SKIP=1. Pure bash, no radios.
set -euo pipefail
cd "$(dirname "$0")/.."
fails=0
t() { # NAME EXPECTED_RC SCRIPT_BODY
  local out rc=0; out=$(HWSIM_ALLOW_SKIP="${ALLOW:-0}" bash -c "set -euo pipefail; . ci/hwsim-lock.sh; $3" 2>&1) || rc=$?
  if [ "$rc" = "$2" ]; then echo "ok - $1"; else echo "FAIL - $1: rc=$rc want $2"; echo "$out" | sed 's/^/    /'; fails=$((fails + 1)); fi
}
t "all scenarios executed -> green" 0 'hwsim_run a bash -c "echo ok - x"; hwsim_run b bash -c "echo PASS b"; hwsim_summary'
t "summary counts them" 0 'hwsim_run a bash -c "echo ok - x"; hwsim_summary | grep -F "executed=1" >/dev/null || exit 9'
t "a failing scenario -> red" 1 'hwsim_run a bash -c "echo ok - x; exit 3"; hwsim_summary'
t "a SKIP line -> red" 1 'hwsim_run a bash -c "echo SKIP: need 4 radios"; hwsim_summary'
t "no check line -> red" 1 'hwsim_run a bash -c "echo nothing"; hwsim_summary'
t "no scenario at all -> red" 1 'hwsim_summary'
t "missing module -> red" 1 'hwsim_skip_or_fail "this kernel has no mac80211_hwsim"'
ALLOW=1 t "missing module with HWSIM_ALLOW_SKIP=1 -> skip" 0 'hwsim_skip_or_fail "this kernel has no mac80211_hwsim"'
ALLOW=1 t "SKIP only with HWSIM_ALLOW_SKIP=1 and nothing executed -> red" 1 'hwsim_run a bash -c "echo SKIP: x"; hwsim_summary'
# leaked-module reclaim (hwsim_reclaim_leaked): fake docker prints the radio state, a fake /proc/modules says loaded
LM=$(mktemp); echo 'mac80211_hwsim 139264 0 - Live 0x0' > "$LM"; NM=$(mktemp); echo 'mac80211 1912832 0 - Live 0x0' > "$NM"
export HWSIM_RECHECK_S=0
rc_t() { # NAME WANT_UNLOAD(0/1) MODULES STATE
  local out; out=$(HWSIM_PROC_MODULES=$3 bash -c "set -euo pipefail; . ci/hwsim-lock.sh; fake() { echo '$4'; }; HWSIM_DOCKER=fake
    unl() { echo UNLOADED; }; hwsim_reclaim_leaked img unl" 2>&1) || { echo "FAIL - $1: rc!=0"; fails=$((fails + 1)); return; }
  local got=0; grep -F UNLOADED <<<"$out" >/dev/null && got=1
  if [ "$got" = "$2" ]; then echo "ok - $1"; else echo "FAIL - $1: unloaded=$got want $2"; echo "$out" | sed 's/^/    /'; fails=$((fails + 1)); fi; }
rc_t "leaked module, all radios idle in the host netns -> unloaded" 1 "$LM" "3 3"
rc_t "module in use (radios moved into a container) -> left alone" 0 "$LM" "4 0"
rc_t "partly moved radios -> left alone" 0 "$LM" "4 2"
rc_t "module not loaded -> nothing" 0 "$NM" "3 3"
rc_t "unreadable state -> left alone" 0 "$LM" ""
rm -f "$LM" "$NM"
[ "$fails" = 0 ] || { echo "$fails hwsim policy test(s) failed"; exit 1; }
echo "PASS hwsim-policy-test"
