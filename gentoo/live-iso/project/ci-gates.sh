# Patronus gates beyond the shared QEMU matrix (SOURCED by common/ci-run.sh after the matrix; $ISO, $EVI, $HERE, $ARCH, with_deadline,
# failed_list, failed_step and fail() are in scope).
#
# installed-firstrun (vmtest, x86_64): the installed image, driven through its own web API -- package-owned product files, the setup
# wizard with the default "DHCP from the ISP" WAN (200 + a dhcpcd client for the WAN port), a wizard that fails half-way (one readable
# sentence, nothing applied), then LAN pool + reservation + static WAN, a REBOOT, and: dnsmasq running, a second machine on the LAN gets
# the reserved address, the static default route is back, the system dhcpcd does not manage the Patronus ports. Both inits run the same
# scenarios (tools/vmtest/scenarios/*.py never name a service manager).
# installed-pfsense-import (vmtest, x86_64): a config.xml written by the scenario (WAN/LAN/OPT + VLAN, alias, rules, port forward,
# reservation, host override, one unmappable section) -- the CLI plan writes nothing, web plan + apply, kernel state, REBOOT.
# installed-lagg-vlan (vmtest, x86_64): an answer file with an 802.3ad bond and WAN / LAN / management on VLANs of it. At the FIRST boot,
# with nobody at the console, the web UI (443 + the 80 redirect) and SSH answer on the management VLAN and nowhere else, the bond has
# the switch as its LACP partner, the WAN VLAN gets its lease from a fake ISP, and cutting one member keeps the box reachable.
# aarch64 runs under TCG with no time left in the job (see ci-matrix.sh), so the gates are x86_64 only.
vmtest_gate() {   # NAME SCENARIO DEADLINE
  local name=$1 scenario=$2 deadline=$3 rc
  echo "::group::vmtest $name"
  REPO_ROOT=$(cd "$HERE/../../.." && pwd)
  ( cd "$REPO_ROOT/tools/vmtest" && VMTEST_CACHE=${VMTEST_CACHE:-/tmp/vmtest-cache} with_deadline "$deadline" \
      python3 -u -m vmtest run "scenarios/$scenario" --arg iso="$ISO" --out "$EVI/$name" ) 2>&1 | tee "$EVI/test-$name.log" | tail -40
  rc=${PIPESTATUS[0]}
  echo "::endgroup::"
  find "$EVI/$name" \( -name '*.qcow2' -o -name '*.raw' -o -name answers.img \) -delete 2>/dev/null || true
  if [ "$rc" != 0 ]; then
    failed_list="$failed_list $name"
    [ -z "$failed_step" ] && fail "vmtest-$name" "$(grep -E '^(\[FAIL\]|FAILED)' "$EVI/test-$name.log" | head -1)"
  fi
}
if [ "$ARCH" = x86_64 ]; then
  vmtest_gate installed-firstrun installed_firstrun.py 5400
  vmtest_gate installed-pfsense-import installed_pfsense_import.py 4200
  vmtest_gate installed-lagg-vlan installed_lagg_vlan.py 5400
fi
