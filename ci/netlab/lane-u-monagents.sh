#!/usr/bin/env bash
# Lane U: optional monitoring agents (USE=zabbix-agent, USE=telegraf) and the typed /metrics settings.
#
# HONEST HEADER: no Zabbix agent 2 / Telegraf package exists in the netlab image's apt archive (Telegraf has none, Debian/Ubuntu
# ship Zabbix 6 agents but not agent 2 7.x), and the real daemons are proven on Gentoo by the ebuild + the applier tests. So this
# scenario installs STAND-IN binaries named zabbix_agent2 and telegraf (a tiny python TCP/HTTP listener that reads the config
# Patronus generated, binds the address in it, records its argv and a copy of the config). What this lane proves for real:
#   - the page/API -> generated config -> supervised daemon chain (argv, files, restart only on change, stop when disabled),
#   - the daemon listens where the config says (the LAN address), the LAN client reaches it and the WAN side cannot: the stand-in
#     binds 0.0.0.0 on purpose (STANDIN_BIND_ALL=1), so ONLY the generated firewall rules keep the WAN out,
#   - the Zabbix UserParameter helper (`patronus zabbix-item`) answers from the metrics snapshot the web UI writes,
#   - the typed /metrics settings (switch, allowed source network, scrape token) with real HTTPS requests.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-u-monagents.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_kill_daemons zabbix_agent2 telegraf
rm -rf /var/lib/patronus-monagent /tmp/nl-standin-*
BIN=/usr/local/bin

cat > "$BIN/standin-agent.py" <<'PY'
#!/usr/bin/env python3
# STAND-IN for zabbix_agent2 / telegraf (see the lane header): listens where the generated config says.
import os, re, socket, sys, threading
name = os.path.basename(sys.argv[0])
argv = sys.argv[1:]
log = "/tmp/nl-standin-%s.log" % name
open(log, "w").write("argv: %s\nuid: %d\n" % (" ".join(argv), os.getuid()))
conf = None
for i, a in enumerate(argv):
    if a in ("-c", "--config") and i + 1 < len(argv):
        conf = argv[i + 1]
text = open(conf).read() if conf else ""
open("/tmp/nl-standin-%s.conf" % name, "w").write(text)
if name == "zabbix_agent2":
    ip = re.search(r"^ListenIP=(.*)$", text, re.M).group(1)
    port = int(re.search(r"^ListenPort=(\d+)$", text, re.M).group(1))
else:
    m = re.search(r'^\s*listen = "(.*):(\d+)"', text, re.M)
    if not m:
        threading.Event().wait()  # a push output: nothing listens
    ip, port = m.group(1).strip("[]"), int(m.group(2))
if os.environ.get("STANDIN_BIND_ALL"):
    ip = "::" if ":" in ip else "0.0.0.0"
s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port)); s.listen(8)
while True:
    c, _ = s.accept()
    try:
        c.recv(1024); c.sendall(b"HTTP/1.0 200 OK\r\n\r\nstand-in " + name.encode() + b"\n")
    finally:
        c.close()
PY
for n in zabbix_agent2 telegraf; do ln -sf "$BIN/standin-agent.py" "$BIN/$n"; done
chmod +x "$BIN/standin-agent.py"

export STANDIN_BIND_ALL=1
export PATRONUS_MONAGENT_SNAPSHOT_SECS=2
nl_boot "$DB"
nl_web_start "$DB"; nl_login

lan_get() { C curl -s -m 4 "http://$NL_RTR_LAN:$1/" >"$NL_OUT" 2>&1; }
wan_get() { ISP curl -s -m 4 "http://$NL_RTR_WAN:$1/" >"$NL_OUT" 2>&1; }

echo "=== nothing listens before the pages are switched on"
if lan_get 10050; then nl_fail "something answers on 10050 with the agent off"; fi
nl_ok "agents off: no listener"

echo "=== Zabbix agent: validation, then enable"
nl_api_code "enable without a server" 400 PUT /svc/zabbix '{"enabled":true}'
nl_api_code "bad PSK" 400 PUT /svc/zabbix '{"psk":"not-hex-not-hex-not-hex-not-hex-zz"}'
nl_api_code "remote commands cannot be switched on" 400 PUT /svc/zabbix '{"remote_commands":"on"}'
nl_api_code "bad server" 400 POST /svc/zabbix/servers '{"host":"a;b"}'
nl_ok "bad PSK, remote commands and a bad server name are refused (400)"
nl_api_ok "server" POST /svc/zabbix/servers '{"host":"zbx.example.net"}'
PSK=00112233445566778899aabbccddeeff
nl_api_ok "enable" PUT /svc/zabbix "{\"enabled\":true,\"hostname\":\"lab-router\",\"psk\":\"$PSK\",\"psk_identity\":\"lab-psk\"}"
nl_wait 10 pgrep -x zabbix_agent2 || nl_fail "the Zabbix agent did not start"
nl_wait 10 lan_get 10050 || nl_fail "the LAN client cannot reach the Zabbix agent on $NL_RTR_LAN:10050"
nl_ok "LAN client reaches the agent: $(cat "$NL_OUT")"
CONF=/var/lib/patronus-monagent/zabbix/zabbix_agent2.conf
for want in "Server=zbx.example.net" "Hostname=lab-router" "ListenIP=$NL_RTR_LAN" "ListenPort=10050" "DenyKey=system.run\\[\\*\\]" "TLSPSKIdentity=lab-psk" "TLSConnect=psk"; do
  grep -q "^$want" "$CONF" || { cat "$CONF"; nl_fail "zabbix_agent2.conf lacks $want"; }
done
if grep -q "$PSK" "$CONF"; then nl_fail "the PSK is inside the agent config instead of its own 0640 file"; fi
[ "$(stat -c %a /var/lib/patronus-monagent/zabbix/psk.key)" = 640 ] || nl_fail "psk.key is not mode 0640"
[ "$(tr -d '\n' < /var/lib/patronus-monagent/zabbix/psk.key)" = "$PSK" ] || nl_fail "psk.key does not hold the key"
nl_ok "config: server, host name, LAN listen address, remote commands denied, TLS PSK in its own 0640 file"
grep -q "^argv: .*-f -c $CONF" /tmp/nl-standin-zabbix_agent2.log || { cat /tmp/nl-standin-zabbix_agent2.log; nl_fail "agent started with the wrong command line"; }
nl_ok "daemon command line: $(sed -n 1p /tmp/nl-standin-zabbix_agent2.log)"
nl_api GET /svc/zabbix
grep -q "$PSK" "$NL_OUT" && nl_fail "the PSK is returned by the API"
nl_ok "the API shows the key masked only"

echo "=== firewall: the LAN reaches it, the WAN does not (the listener is bound to every address on purpose)"
nl_assert_nft_has "iifname \"$NL_LAN_IF\" tcp dport 10050 accept"
nl_assert_nft_lacks "iifname \"$NL_WAN_IF\" tcp dport 10050"
if wan_get 10050; then nl_fail "the WAN side reached the agent: $(cat "$NL_OUT")"; fi
nl_ok "WAN side cannot reach the agent (only the firewall stands in the way)"

echo "=== no restart without a change"
PID1=$(pgrep -x zabbix_agent2 | head -1)
nl_api_ok "same settings again" PUT /svc/zabbix '{"hostname":"lab-router"}'
sleep 1
PID2=$(pgrep -x zabbix_agent2 | head -1)
[ "$PID1" = "$PID2" ] || nl_fail "the agent was restarted without a configuration change ($PID1 -> $PID2)"
nl_api_ok "new host name" PUT /svc/zabbix '{"hostname":"lab-router2"}'
nl_wait 10 grep -q "^Hostname=lab-router2" "$CONF" || nl_fail "config not updated"
nl_wait 10 lan_get 10050 || nl_fail "agent not back after a config change"
nl_ok "unchanged settings keep the process; a changed one restarts it with the new config"

echo "=== Zabbix UserParameter helper reads the metrics snapshot the web UI writes"
nl_wait 20 test -s /var/lib/patronus-monagent/metrics.prom || nl_fail "the web UI did not write the metrics snapshot"
V=$(R "$P" --db "$DB" zabbix-item firewall.rules) || nl_fail "patronus zabbix-item firewall.rules failed"
case "$V" in ''|*[!0-9]*) nl_fail "firewall.rules is not a number: $V";; esac
nl_ok "patronus zabbix-item firewall.rules = $V"
R "$P" --db "$DB" zabbix-item gateway.discovery | grep '"data"' >/dev/null || nl_fail "gateway.discovery is not JSON"
if R "$P" --db "$DB" zabbix-item system.run id >"$NL_OUT" 2>&1; then nl_fail "an unknown key was answered"; fi
nl_ok "unknown keys are refused"

echo "=== Telegraf: prometheus_client on the LAN"
nl_api_code "bad url" 400 PUT /svc/telegraf '{"url":"http://x\"y"}'
nl_api_code "bad output" 400 PUT /svc/telegraf '{"output":"exec"}'
nl_api_ok "enable" PUT /svc/telegraf '{"enabled":true,"output":"prometheus_client"}'
nl_wait 10 lan_get 9273 || nl_fail "the LAN client cannot reach Telegraf's scrape port"
nl_ok "LAN client reaches Telegraf on $NL_RTR_LAN:9273: $(cat "$NL_OUT")"
TCONF=/var/lib/patronus-monagent/telegraf/telegraf.conf
grep -q "listen = \"$NL_RTR_LAN:9273\"" "$TCONF" || { cat "$TCONF"; nl_fail "telegraf.conf does not listen on the LAN address"; }
nl_assert_nft_has "iifname \"$NL_LAN_IF\" tcp dport 9273 accept"
nl_assert_nft_lacks "iifname \"$NL_WAN_IF\" tcp dport 9273"
if wan_get 9273; then nl_fail "the WAN side reached the Telegraf scrape port"; fi
nl_ok "WAN side cannot reach the scrape port"
python3 - "$TCONF" <<'PY' || nl_fail "telegraf.conf is not valid TOML"
import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
assert d["outputs"]["prometheus_client"][0]["metric_version"] == 2, d
PY
nl_ok "telegraf.conf parses as TOML"

echo "=== Telegraf: a push output has no listener and its token stays out of the API"
nl_api_ok "influx" PUT /svc/telegraf '{"output":"influxdb_v2","url":"https://influx.example:8086","token":"tok-0123456789abcd","organization":"home","bucket":"router"}'
lan_closed() { ! lan_get "$1"; }
nl_wait 10 lan_closed 9273 || nl_fail "9273 still answers after switching to a push output"
nl_assert_nft_lacks "tcp dport 9273"
nl_api GET /svc/telegraf
grep -q "tok-0123456789abcd" "$NL_OUT" && nl_fail "the Telegraf token is returned by the API"
nl_ok "token masked, 9273 closed again"

echo "=== /metrics follows its typed settings"
metrics_code() { C curl -sk -m 6 -o /dev/null -w '%{http_code}' "$@" "$NL_UI/metrics"; }
[ "$(metrics_code)" = 401 ] || nl_fail "/metrics without a login or token is not 401"
nl_api_ok "token" PUT /svc/metrics '{"token":"scrape-token-0123"}'
[ "$(metrics_code -H 'Authorization: Bearer scrape-token-0123')" = 200 ] || nl_fail "the scrape token does not open /metrics"
[ "$(metrics_code -H 'Authorization: Bearer scrape-token-0124')" = 401 ] || nl_fail "a wrong token opens /metrics"
nl_api_ok "source" PUT /svc/metrics '{"allowed_source":"203.0.113.0/24"}'
[ "$(metrics_code -H 'Authorization: Bearer scrape-token-0123')" = 403 ] || nl_fail "a source outside the allowed network still reads /metrics"
nl_api_ok "source ok" PUT /svc/metrics "{\"allowed_source\":\"192.168.50.0/24\"}"
[ "$(metrics_code -H 'Authorization: Bearer scrape-token-0123')" = 200 ] || nl_fail "the LAN source is refused"
nl_api_ok "off" PUT /svc/metrics '{"enabled":false}'
[ "$(metrics_code -H 'Authorization: Bearer scrape-token-0123')" = 404 ] || nl_fail "/metrics still served while switched off"
nl_ok "token, allowed source and the switch all act on real HTTPS requests"
nl_api_ok "on again" PUT /svc/metrics '{"enabled":true}'

echo "=== reboot: both agents come back"
nl_web_stop
nl_kill_daemons zabbix_agent2 telegraf
nl_boot "$DB"
nl_wait 10 lan_get 10050 || nl_fail "the Zabbix agent is not back after a reboot"
nl_ok "after a reboot the boot apply restarts the Zabbix agent and its firewall rule"

echo "=== disable: the listener, its firewall rule and the key are gone"
nl_web_start "$DB"; nl_login
nl_api_ok "off" PUT /svc/zabbix '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -x zabbix_agent2 && ! pgrep -x telegraf' || nl_fail "an agent is still running"
nl_assert_nft_lacks "tcp dport 10050"
[ ! -e /var/lib/patronus-monagent/zabbix/psk.key ] || nl_fail "the PSK file outlived the feature"
nl_api_ok "off" PUT /svc/telegraf '{"enabled":false}'
[ ! -e "$TCONF" ] || nl_fail "telegraf.conf (it carries a token) outlived the feature"
nl_ok "everything cleaned up"
nl_web_stop
echo "ALL MONITORING AGENT CHECKS PASSED"
