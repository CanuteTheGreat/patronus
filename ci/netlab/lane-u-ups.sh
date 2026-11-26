#!/usr/bin/env bash
# Lane U: UPS monitoring through NUT (USE=ups). A dummy-ups driver replays a script that mimics a UPS losing
# mains power (online -> on battery -> low battery). The UPS page is enabled over the API; Patronus must render
# its own NUT configuration, start the driver, upsd and upsmon under the supervisor, report the live readings
# (API), raise the power events, and make upsmon run the *configured* shutdown command when the battery is low.
# The shutdown command here writes a marker file: the router is never powered off. Netserver mode must listen on
# the LAN address only and open the NUT port on the LAN only; a daemon restart (reboot) brings it all back.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-u-ups.db
DEV=/tmp/nl-ups.dev
MARK=/tmp/nl-ups-shutdown.marker
CMD=/usr/local/bin/nl-ups-shutdown
rm -f "$DB" "$NL_T/nl-jar" "$MARK"
nl_write_installer_toml
nl_kill_daemons upsmon upsd dummy-ups

command -v upsd >/dev/null && command -v upsmon >/dev/null || nl_fail "NUT is not installed in the netlab image"
DRV=$(find /lib/nut /usr/lib/nut /usr/libexec/nut -name dummy-ups 2>/dev/null || true); DRV=$(printf "%s\n" "$DRV" | sed -n 1p)
[ -n "$DRV" ] || nl_fail "dummy-ups driver not found"

cat > "$DEV" <<'DEVEOF'
device.type: ups
ups.mfr: Eaton
ups.model: Eaton 3S 700
ups.status: OL CHRG
ups.load: 18
battery.charge: 100
battery.charge.low: 20
battery.runtime: 2610
battery.voltage: 13.6
input.voltage: 231.0
output.voltage: 230.0
TIMER 12
ups.status: OB DISCHRG
battery.charge: 71
battery.runtime: 1180
input.voltage: 0.0
TIMER 12
ups.status: OB DISCHRG LB
battery.charge: 14
battery.runtime: 150
TIMER 600
DEVEOF
chmod 644 "$DEV"
printf '#!/bin/sh\ndate +%%s > %s\n' "$MARK" > "$CMD"; chmod 755 "$CMD"

# the dummy script starts the clock when the driver starts, so the page is configured first and enabled last
nl_boot "$DB"
nl_web_start "$DB"; nl_login

echo "=== before it is enabled: honest status, nothing running"
nl_api_ok "status off" GET /v1/ups
[ "$(nl_json "$NL_OUT" 'd["enabled"]')" = False ] && [ "$(nl_json "$NL_OUT" 'd["reading"]')" = None ] || nl_fail "off status: $(cat "$NL_OUT")"
pgrep -x upsd >/dev/null && nl_fail "upsd runs before UPS monitoring is enabled"
nl_api_ok "alias" GET /ups
[ "$(nl_json "$NL_OUT" 'd["enabled"]')" = False ] || nl_fail "the /api/ups alias differs"
nl_ok "off: no reading, no daemons (/api/v1/ups and the /api/ups alias agree)"

echo "=== validation"
nl_api_code "shell metacharacters in the shutdown command" 400 PUT /svc/ups '{"shutdown_command":"/bin/x; reboot"}'
nl_api_code "unknown driver" 400 PUT /svc/ups '{"driver":"rm -rf"}'
nl_api_code "snmp without host" 400 PUT /svc/ups '{"enabled":true,"driver":"snmp-ups","snmp_community":"communitystr"}'
nl_api_code "charge threshold needs usbhid-ups" 400 PUT /svc/ups '{"enabled":true,"driver":"dummy-ups","port":"/tmp/x.dev","shutdown_policy":"charge_below"}'
nl_ok "unsafe command, unknown driver, incomplete SNMP and an impossible policy are refused (400)"

echo "=== enable: dummy-ups driver, standalone"
nl_api_ok "enable" PUT /svc/ups "{\"enabled\":true,\"mode\":\"standalone\",\"driver\":\"dummy-ups\",\"port\":\"$DEV\",\"shutdown_command\":\"$CMD $MARK\",\"poll_secs\":2}"
nl_wait 20 pgrep -x upsd || nl_fail "upsd did not start"
nl_wait 20 pgrep -x upsmon || nl_fail "upsmon did not start"
nl_wait 20 pgrep -f dummy-ups || nl_fail "the driver did not start"
nl_ok "driver, upsd and upsmon running under the supervisor"
CONF=/var/lib/patronus/net/nut
grep -q '^MODE=standalone' $CONF/nut.conf && grep -q 'LISTEN 127.0.0.1 3493' $CONF/upsd.conf && ! grep -q '0.0.0.0' $CONF/upsd.conf \
  || { cat $CONF/*.conf; nl_fail "generated NUT config is not standalone on loopback"; }
grep -q "SHUTDOWNCMD \"$CMD $MARK\"" $CONF/upsmon.conf || { cat $CONF/upsmon.conf; nl_fail "upsmon.conf lacks the configured shutdown command"; }
[ "$(stat -c %a $CONF/upsd.users)" = 640 ] || nl_fail "upsd.users is not 0640: $(stat -c %a $CONF/upsd.users)"
nl_ok "config rendered by Patronus: standalone, loopback only, configured SHUTDOWNCMD, upsd.users 0640"
nl_api GET /svc/ups
grep -q 'password' "$NL_OUT" && { grep -Eq '"monitor_password":"\*+"' "$NL_OUT" || nl_fail "the monitor password is returned by the API"; }
PW=$(sed -n 's/.*password = //p' $CONF/upsd.users | head -1)
[ -n "$PW" ] && ! grep -qF "$PW" "$NL_OUT" || nl_fail "the generated monitor password leaks through GET /api/svc/ups"
nl_ok "the generated monitor password is not returned by the API"

echo "=== live readings follow the UPS"
seen=""
for _ in $(seq 1 90); do
  # the marker is read BEFORE the state: state only moves forward, so a marker seen with a state that is not
  # low_battery means the shutdown command ran too early
  early=no; [ -e "$MARK" ] && early=yes
  nl_api GET /v1/ups
  st=$(nl_json "$NL_OUT" 'd["state"]')
  if [ "$early" = yes ] && [ "$st" != low_battery ]; then nl_fail "shutdown marker exists while the UPS state is $st (before low battery)"; fi
  case " $seen " in *" $st "*) ;; *) seen="$seen $st"; echo "  state: $st ($(nl_json "$NL_OUT" 'd["reading"] and d["reading"]["charge_pct"]')%) marker=$early";; esac
  [ "$st" = low_battery ] && break
  sleep 1
done
case "$seen" in *online*on_battery*low_battery*) ;; *) nl_fail "states seen:$seen (want online, on_battery, low_battery in order)";; esac
nl_ok "the API reported:$seen; the shutdown marker did not exist in any state before low_battery"
python3 - "$NL_OUT" <<'PY' || nl_fail "low-battery reading is wrong"
import json, sys
d = json.load(open(sys.argv[1]))
r = d["reading"]
assert d["installed"] and d["enabled"] and d["mode"] == "standalone", d
assert r["state"] == "low_battery" and "LB" in r["flags"], r
assert r["charge_pct"] == 14 and r["runtime_secs"] == 150 and r["model"] == "Eaton 3S 700", r
kinds = [e["kind"] for e in d["events"]]
assert "ups_on_battery" in kinds and "ups_low_battery" in kinds, kinds
PY
nl_ok "reading matches the UPS (charge 14%, 150 s left, Eaton 3S 700); events ups_on_battery and ups_low_battery were raised"
nl_api GET "/v1/ups/history?hours=1"
[ "$(nl_json "$NL_OUT" 'len([s for s in d["samples"] if s["state"]=="on_battery"])')" -ge 1 ] || nl_fail "no on-battery sample in the history: $(cat "$NL_OUT")"
nl_ok "history holds on-battery samples"

echo "=== low battery: upsmon runs the configured shutdown command"
nl_wait 40 test -s "$MARK" || { tail -20 /var/log/syslog 2>/dev/null; nl_fail "the shutdown command did not run on low battery"; }
nl_ok "SHUTDOWNCMD ran (marker $(cat "$MARK")); the router was not powered off"

echo "=== the UPS page and the event log"
nl_web GET /svc/ups
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "UPS page: $NL_CODE"
nl_api GET "/events?kind=ups_low_battery"
grep -q ups_low_battery "$NL_OUT" || nl_fail "the event log lacks ups_low_battery: $(cat "$NL_OUT")"
nl_ok "UPS page renders; ups_low_battery is in the event log"

echo "=== netserver mode: LAN address only, port open on the LAN only"
rm -f "$MARK"
nl_api_ok "netserver" PUT /svc/ups '{"mode":"netserver","listen_iface":"@lan"}'
nl_wait 20 grep -q "LISTEN $NL_RTR_LAN 3493" $CONF/upsd.conf || { cat $CONF/upsd.conf; nl_fail "upsd.conf does not listen on the LAN address"; }
! grep -q '0.0.0.0' $CONF/upsd.conf || nl_fail "upsd listens on a wildcard"
nl_assert_nft_has "iifname \"$NL_LAN_IF\" tcp dport 3493 accept"
nl_wait 30 C upsc "ups@$NL_RTR_LAN" battery.charge || { C upsc "ups@$NL_RTR_LAN" 2>&1 | head -5; nl_fail "a LAN client cannot read the UPS from $NL_RTR_LAN:3493"; }
OUTC=$(C upsc "ups@$NL_RTR_LAN" 2>/dev/null)
case "$OUTC" in *"battery.charge:"*"ups.status:"*) ;; *) nl_fail "upsc from the LAN lacks readings: $OUTC";; esac
nl_ok "a LAN-namespace client runs upsc ups@$NL_RTR_LAN and gets the readings (port 3493 on the LAN address)"
if C timeout 6 upsc "ups@$NL_RTR_WAN" ups.status >/dev/null 2>&1; then nl_fail "NUT answers on the WAN address (seen from the LAN client)"; fi
if ISP timeout 6 upsc "ups@$NL_RTR_WAN" ups.status >/dev/null 2>&1; then nl_fail "NUT answers a client on the WAN side"; fi
if ISP timeout 4 python3 -c "import socket; socket.create_connection(('$NL_RTR_WAN',3493),3)" 2>/dev/null; then nl_fail "port 3493 accepts a connection from the WAN side"; fi
nl_ok "upsc against the WAN address fails from the WAN side and from the LAN client; nothing listens or accepts there"

echo "=== reboot: the boot apply brings the monitoring back"
nl_web_stop
nl_kill_daemons upsmon upsd dummy-ups
nl_boot "$DB"
nl_wait 20 pgrep -x upsd || nl_fail "upsd not started by the boot apply"
nl_wait 20 pgrep -x upsmon || nl_fail "upsmon not started by the boot apply"
nl_assert_nft_has "tcp dport 3493 accept"
nl_ok "after reboot: driver, upsd, upsmon and the firewall rule are back"

echo "=== disable: everything stops, the rule goes"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/ups '{"enabled":false}'
# killed daemons stay as zombies in this init-less container: only live processes count
nut_gone() { local n; n=$(ps -eo stat=,comm= | awk '$1 !~ /^Z/ && ($2=="upsd" || $2=="upsmon" || $2=="dummy-ups")'); [ -z "$n" ]; }
nl_wait 20 nut_gone || { ps -eo pid,stat,comm,args | grep -E 'ups[dm]|dummy' ; nl_fail "NUT daemons still running"; }
nl_assert_nft_lacks "tcp dport 3493"
nl_api_ok "status" GET /v1/ups
[ "$(nl_json "$NL_OUT" 'd["reading"]')" = None ] || nl_fail "a reading is still shown while disabled"
nl_ok "disabled: daemons stopped, firewall rule gone, no reading"
nl_web_stop
nl_kill_daemons upsmon upsd dummy-ups
echo "ALL UPS CHECKS PASSED"
