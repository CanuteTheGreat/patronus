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
[ "$fails" = 0 ] || { echo "$fails hwsim policy test(s) failed"; exit 1; }
echo "PASS hwsim-policy-test"
