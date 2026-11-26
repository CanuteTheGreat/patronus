#!/usr/bin/env bash
# Lane N (UI): System > Import driven in a real browser (ci/import-page-e2e.py, Playwright + Firefox) from the netlab
# LAN client against the shipped patronus-web: a pfSense config.xml is previewed (nothing written), imported and
# applied (kernel + nftables checked here), then a second file that moves the LAN address is imported: the answer is
# lost with the old address, the page must name the new one, and the router really moved.
# Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing); the
# importer itself is proven by crates/patronus-import's tests and the web route test config_import_*.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-import-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/import-page-e2e.py" ] || nl_fail "ci/import-page-e2e.py was not copied next to the scenarios (ci/netlab/run.sh)"

# a pfSense box with the netlab addresses: em0 = WAN (static), em1 = LAN; one alias and one LAN rule
pf_xml() { # FILE LAN_ADDRESS
  cat >"$1" <<EOF
<?xml version="1.0"?>
<pfsense>
  <version>23.3</version>
  <system><hostname>fw-imported</hostname><domain>example.lan</domain><timezone>Europe/Amsterdam</timezone></system>
  <interfaces>
    <wan><enable/><if>em0</if><descr>WAN</descr><ipaddr>$NL_RTR_WAN</ipaddr><subnet>24</subnet></wan>
    <lan><enable/><if>em1</if><descr>LAN</descr><ipaddr>$2</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <aliases><alias><name>web_ports</name><type>port</type><address>80 443</address></alias></aliases>
  <filter>
    <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><network>lan</network></source><destination><any/><port>web_ports</port></destination><descr>LAN web out</descr></rule>
  </filter>
</pfsense>
EOF
}
pf_xml "$NL_T/imp-same.xml" "$NL_RTR_LAN"
MOVED=192.168.51.1
pf_xml "$NL_T/imp-moved.xml" "$MOVED"
MAPS="em0=$NL_WAN_IF,em1=$NL_LAN_IF"

nl_write_installer_toml
nl_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_web_start "$DB"; nl_login
nl_ok "booted; the LAN client reaches the web UI at $NL_UI"

e2e() { # FILE EXPECT LAN
  C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_BROWSER=firefox E2E_APPLY=1 E2E_EXPECT="$2" \
    E2E_LAN="$3" "$PW/bin/python" "$NL_T/import-page-e2e.py" "$1" "$MAPS" 2>&1
}
out=$(e2e "$NL_T/imp-same.xml" applied "$NL_RTR_LAN") && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the import page e2e failed (exit $rc)"
nl_ok "config.xml previewed, imported and applied in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
nft_out=$(R nft list ruleset)
# the imported alias is a port set, the imported LAN rule matches it (rules carry no description comment)
grep -E 'tcp dport @alias_web_ports_ports .*accept' >/dev/null <<<"$nft_out" ||
  { R nft list chain inet patronus forward; nl_fail "the imported LAN rule is not in the kernel ruleset"; }
grep -E 'elements = \{ 80, 443 \}' >/dev/null <<<"$nft_out" ||
  { R nft list set inet patronus alias_web_ports_ports; nl_fail "the imported alias web_ports is not a kernel set of 80, 443"; }
grep -E "iifname \"$NL_LAN_IF\" tcp dport \{ 22, 8443 \} accept" >/dev/null <<<"$nft_out" ||
  nl_fail "anti-lockout on the LAN port is missing after the import"
addr=$(R ip -4 -br addr show dev "$NL_LAN_IF")
grep -F "$NL_RTR_LAN/24" >/dev/null <<<"$addr" || nl_fail "LAN address changed by an import that keeps it: $addr"
nl_ok "kernel: imported alias + rule loaded, anti-lockout kept on $NL_LAN_IF, LAN still $NL_RTR_LAN"

out=$(e2e "$NL_T/imp-moved.xml" moved "$MOVED") && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the moved-address import e2e failed (exit $rc)"
addr=$(R ip -4 -br addr show dev "$NL_LAN_IF")
grep -F "$MOVED/24" >/dev/null <<<"$addr" || nl_fail "the second import did not move the LAN address: $addr"
nl_ok "an import that moves the LAN address: applied ($MOVED), the page named the new address"
echo "PASS lane-n-import-ui"
