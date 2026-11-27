#!/usr/bin/env bash
# Lane J (UI): the TFTP server page driven in a real browser (ci/tftp-page-e2e.py, Playwright + Firefox) against the
# shipped patronus-web in the netlab router: menu entry, every setting, the client networks table and the file manager
# on the page, phone width in the light and dark scheme, a refused root shown on the page, then through the page only:
# switch the server on, upload a file with the file chooser, fetch it with a real TFTP client (curl, from the LAN client's
# namespace where the script runs), add and delete a client network, delete the file, switch the server off. Needs
# Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing). The
# protocol behaviour behind it is proven by lane-j-tftp.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-tftp-ui.db
rm -f "$DB" "$NL_T/nl-jar"
rm -rf /var/lib/patronus/tftp
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/tftp-page-e2e.py" ] || { echo "SKIP lane-j-tftp-ui: ci/tftp-page-e2e.py was not copied next to the scenarios"; exit 0; }
export PATH="$NL_T:$PATH"
nl_kill_daemons

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api PUT /interfaces/$NL_LAN_IF "{\"role\":\"lan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$NL_RTR_LAN/24\"],\"ipv6_mode\":\"none\",\"force\":true}"
[ "$NL_CODE" = 200 ] || nl_fail "LAN address: $NL_CODE $(cat "$NL_OUT")"
nl_ok "booted with the LAN address the page serves on"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_TFTP_HOST="$NL_RTR_LAN" \
      "$PW/bin/python" "$NL_T/tftp-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the TFTP page e2e failed (exit $rc)"
n=$(grep -c '^PASS:' <<<"$out" || true)
nl_ok "TFTP page driven in Firefox: $n checks passed"
nl_web_stop
nl_kill_daemons
pkill -f '[t]ftp run' || true
echo "ALL TFTP UI CHECKS PASSED"
