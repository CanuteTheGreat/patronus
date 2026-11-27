# Patronus gates beyond the shared QEMU matrix (SOURCED by common/ci-run.sh after the matrix; $ISO, $EVI, $HERE, $ARCH, with_deadline,
# failed_list, failed_step and fail() are in scope).
#
# installed-firstrun (vmtest, x86_64): the installed image, driven through its own web API -- package-owned product files, the setup
# wizard with the default "DHCP from the ISP" WAN (200 + a dhcpcd client for the WAN port), a wizard that fails half-way (one readable
# sentence, nothing applied), then LAN pool + reservation + static WAN, a REBOOT, and: dnsmasq running, a second machine on the LAN gets
# the reserved address, the static default route is back, the system dhcpcd does not manage the Patronus ports.
# installed-lagg-vlan (vmtest, x86_64): an answer file with an 802.3ad bond and WAN / LAN / management on VLANs of it. At the FIRST boot,
# with nobody at the console, the web UI (443 + the 80 redirect) and SSH answer on the management VLAN and nowhere else, the bond has
# the switch as its LACP partner, the WAN VLAN gets its lease from a fake ISP, and cutting one member keeps the box reachable.
# Both inits run the same scenarios (tools/vmtest/scenarios/*.py never name a service manager).
# aarch64 runs under TCG with no time left in the job (see ci-matrix.sh), so the gates are x86_64 only.
if [ "$ARCH" = x86_64 ]; then
  REPO_ROOT=$(cd "$HERE/../../.." && pwd)
  for name in installed-firstrun installed-lagg-vlan; do
    echo "::group::vmtest $name"
    ( cd "$REPO_ROOT/tools/vmtest" && VMTEST_CACHE=${VMTEST_CACHE:-/tmp/vmtest-cache} with_deadline 5400 \
        python3 -u -m vmtest run "scenarios/${name//-/_}.py" --arg iso="$ISO" --out "$EVI/$name" ) 2>&1 | tee "$EVI/test-$name.log" | tail -40
    rc=${PIPESTATUS[0]}
    echo "::endgroup::"
    find "$EVI/$name" \( -name '*.qcow2' -o -name '*.raw' -o -name answers.img \) -delete 2>/dev/null || true
    if [ "$rc" != 0 ]; then
      failed_list="$failed_list $name"
      [ -z "$failed_step" ] && fail "vmtest-$name" "$(grep -E '^(\[FAIL\]|FAILED)' "$EVI/test-$name.log" | head -1)"
    fi
  done
fi
