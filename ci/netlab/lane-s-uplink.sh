#!/usr/bin/env bash
# Lane s, part d: uplink health history, multi-probe and SLA. Runs INSIDE the
# capped netlab container (ci/netlab/run.sh) as root with the shipped binaries.
#
#   client ---- rtr-lan [ rtr ] rtr-wan  ---- isp  (203.0.113.1) ---- inet 198.51.100.10 / DNS .53
#                             rtr-wan2 ---- isp2 (100.64.0.1)  ---- inet (via 192.0.2.10)
#
# Gateways WAN1 (tier 1) and WAN2 (tier 2) in group FAILOVER (trigger
# loss_latency); the gateway monitor runs in the root `patronus applyd`.
# Proves, with real traffic and tc netem on the ISP side:
#  - history: samples of every gateway are written (state, RTT, loss), the
#    SLA numbers and hourly bars come from them
#  - latency: 300 ms of delay turns WAN1 `latency` (sample + event), the
#    group fails over to WAN2, availability stays 100 % but quality drops;
#    removing the delay brings it back
#  - loss: 100 % packet loss turns WAN1 `down`: gateway_down event, an outage
#    in the outage list, availability < 100 %, traffic moves to WAN2
#  - multi-probe: a DNS probe through WAN1 (its target pinned to WAN1 with a
#    host route even while WAN2 carries the default) works; when the ISP's DNS
#    dies while ping still works the uplink is `degraded` (not down), an
#    uplink_probe_failed event is recorded and signed-webhooked, routing does
#    not change; recovery raises uplink_probe_recovered
#  - a CRITICAL probe feeds failover: DNS dead + ping fine -> WAN1 down, the
#    default route and the LAN client move to WAN2; DNS back -> traffic returns
#  - an SLA target raises uplink_sla_breach
#  - reboot: history and probe configuration survive; probes run again
set -eu
. "$(dirname "$0")/lib.sh"

T=/t/lanes-uplink
rm -rf "$T"; mkdir -p "$T"
DB=$T/config.db
export NO_COLOR=1 CLICOLOR=0 PATRONUS_INIT=direct PATRONUS_NET_DIR=$T/net PATRONUS_RUN_DIR=$T/run
export PATRONUS_APPLYD_SOCKET=$T/applyd.sock PATRONUS_GATEWAY_STATUS=$T/gateway-status.json
export PATRONUS_UPLINK_TICK_SECS=2 PATRONUS_UPLINK_SAMPLE_SECS=3 PATRONUS_IPDB_REFRESH=0
ISP2() { ip netns exec nl-isp2 "$@"; }
APPLYD_PID=

dump() {
  echo "--- debug: rtr routes"; R ip -4 route 2>/dev/null || true; R ip -4 route show proto 252 2>/dev/null || true
  echo "--- debug: gateway status"; cat "$PATRONUS_GATEWAY_STATUS" 2>/dev/null || true; echo
  for f in "$T/applyd.log" "$NL_T/nl-web.log"; do [ -f "$f" ] && { echo "--- $f"; tail -30 "$f"; }; done
  true
}
fail() { dump; nl_fail "$*"; }

second_wan() {
  ip netns del nl-isp2 2>/dev/null || true
  ip netns add nl-isp2; ip -n nl-isp2 link set lo up
  ip link add rtr-wan2 netns nl-rtr type veth peer name up0 netns nl-isp2
  ip link add down1 netns nl-isp2 type veth peer name inet1 netns nl-inet
  ISP2 ip addr add 100.64.0.1/24 dev up0; ISP2 ip link set up0 up
  ISP2 ip addr add 192.0.2.1/24 dev down1; ISP2 ip link set down1 up
  ISP2 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  ISP2 ip route add 198.51.100.0/24 via 192.0.2.10
  INET ip addr add 192.0.2.10/24 dev inet1; INET ip link set inet1 up
  INET ip route add 100.64.0.0/24 via 192.0.2.1
  R ip link set rtr-wan2 up
}
applyd_start() {
  env PATRONUS_DB="$DB" RUST_LOG=info ip netns exec nl-rtr "$P" --db "$DB" applyd \
      --socket "$PATRONUS_APPLYD_SOCKET" --group nogroup >>"$T/applyd.log" 2>&1 &
  APPLYD_PID=$!
  for _ in $(seq 1 40); do [ -S "$PATRONUS_APPLYD_SOCKET" ] && return 0; sleep 0.25; done
  fail "patronus applyd did not create its socket"
}
applyd_stop() {
  [ -n "$APPLYD_PID" ] && kill "$APPLYD_PID" 2>/dev/null
  wait "$APPLYD_PID" 2>/dev/null || true
  APPLYD_PID=
  rm -f "$PATRONUS_APPLYD_SOCKET"
}
cleanup() { nl_web_stop; applyd_stop; nl_down; ip netns del nl-isp2 2>/dev/null || true; }
trap cleanup EXIT

jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
must() { local want=$1; shift; nl_api "$@"; [ "$NL_CODE" = "$want" ] || fail "$1 $2 -> $NL_CODE (want $want): $(cat "$NL_OUT")"; }
who() { C curl -s --max-time 4 "http://$NL_WWW/" | awk '{print $3}'; }
wait_for() { # DESC SECONDS CMD...
  local d=$1 n=$2; shift 2
  for _ in $(seq 1 $((n * 2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out after ${n}s waiting for: $d"
}
default_via() { R ip -4 route show table 4250 proto 253; }
via_is() { default_via | grep "$1" >/dev/null; }
# status helpers (GET /api/uplinks/status)
gw() { # NAME EXPR -> evaluates EXPR with g = that gateway of /api/uplinks/status
  nl_api GET /uplinks/status >/dev/null
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); g=[x for x in d["gateways"] if x["name"]==sys.argv[2]][0]; print(eval(sys.argv[3]))' "$NL_OUT" "$1" "$2"
}
gw_is() { [ "$(gw "$1" 'g["state"]')" = "$2" ]; }
probe_ok() { [ "$(gw WAN1 'len(g["probes"]) > 0 and g["probes"][0]["ok"] and g["probes"][0]["rtt_ms"] is not None')" = True ]; }
probe_failing() { [ "$(gw WAN1 'len(g["probes"]) > 0 and not g["probes"][0]["ok"]')" = True ]; }
event_count() { nl_api GET "/events?kind=$1" >/dev/null; jget 'len(d)'; }
wait_event() { # KIND (polls /api/events for up to 60 s)
  for _ in $(seq 1 60); do [ "$(event_count "$1")" -ge 1 ] && return 0; sleep 1; done
  fail "no $1 event: $(cat "$NL_OUT")"
}
health_has() { # EXPR over s = a WAN1 sample of /api/uplinks/health
  nl_api GET "/uplinks/health?since=1h&points=400&gateway=WAN1" >/dev/null
  [ "$(jget "any($1 for s in d[\"samples\"])")" = True ]
}
sla() { nl_api GET "/uplinks/sla?window=1h&gateway=WAN1" >/dev/null; jget "$1"; }

# --- 1. boot, two uplinks, gateways, failover group ----------------------------
nl_up; second_wan
nl_write_installer_toml
nl_apply "$DB" || { cat "$NL_OUT"; fail "boot apply"; }
applyd_start
nl_web_start "$DB"
nl_login
must 200 PUT /interfaces/rtr-wan2 '{"role":"opt1","ipv4_mode":"static","ipv4":["100.64.0.2/24"],"gateway4":"100.64.0.1"}'
must 201 POST /routing/gateways '{"name":"WAN1","interface":"@wan","latency_threshold":100}'
must 201 POST /routing/gateways '{"name":"WAN2","interface":"@opt1","monitor_ip":"192.0.2.10"}'
must 201 POST /routing/groups '{"name":"FAILOVER","members":"WAN1:1, WAN2:2","trigger":"loss_latency"}'
must 200 PUT /routing/default '{"ipv4":"FAILOVER"}'
wait_for "WAN1 online" 20 gw_is WAN1 online
wait_for "WAN2 online" 20 gw_is WAN2 online
via_is 'via 203.0.113.1 dev rtr-wan' || fail "default via WAN1: $(default_via)"
[ "$(who)" = "$NL_RTR_WAN" ] || fail "LAN should leave via WAN1"
nl_ok "two uplinks online, FAILOVER (trigger loss_latency) carries the traffic on WAN1"

# --- 2. history is written ------------------------------------------------------
enough() { nl_api GET "/uplinks/health?since=1h&points=400&gateway=WAN1" >/dev/null && [ "$(jget 'len(d["samples"])')" -ge 3 ]; }
wait_for "three samples of WAN1" 40 enough
nl_api GET "/uplinks/sla?window=1h"
[ "$(jget 'sorted(x["gateway"] for x in d["sla"])')" = "['WAN1', 'WAN2']" ] || fail "sla gateways: $(cat "$NL_OUT")"
[ "$(jget 'all(x["availability_pct"] == 100.0 for x in d["sla"])')" = True ] || fail "healthy uplinks must be 100 %: $(cat "$NL_OUT")"
nl_api GET "/uplinks/health?since=1h&points=400&gateway=WAN1"
[ "$(jget 'all(s["state"] == "online" and s["rtt_ms"] is not None for s in d["samples"])')" = True ] || fail "baseline samples: $(cat "$NL_OUT")"
nl_ok "history: samples of both uplinks recorded (state + RTT), SLA 100 % while healthy"
nl_web GET /insights
[ "$NL_CODE" = 200 ] && grep -q 'uplink-cards' "$NL_OUT" || fail "insights page: $NL_CODE"

# --- 3. latency ----------------------------------------------------------------
cat > "$T/hook.py" <<'PY'
import http.server, json, sys
LOG = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length', 0))).decode()
        with open(LOG, 'a') as f:
            f.write(json.dumps({'sig': self.headers.get('X-Patronus-Signature'),
                                'event': self.headers.get('X-Patronus-Event'), 'body': body}) + '\n')
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
http.server.HTTPServer((sys.argv[2], 9100), H).serve_forever()
PY
: > "$T/hook.log"
nl_bg INET python3 "$T/hook.py" "$T/hook.log" 0.0.0.0
for _ in $(seq 1 40); do INET sh -c "exec 3<>/dev/tcp/$NL_WWW/9100" 2>/dev/null && break; sleep 0.25; done
must 201 POST /system/hooks "{\"name\":\"uplink-alerts\",\"url\":\"http://$NL_WWW:9100/hook\",\"secret\":\"s3cret-value\",\"kinds\":\"uplink_probe_failed, uplink_probe_recovered, uplink_sla_breach, uplink_sla_ok, gateway_down\"}"

ISP tc qdisc add dev up0 root netem delay 300ms || fail "tc netem is not available in this kernel"
wait_for "WAN1 latency" 40 gw_is WAN1 latency
nl_ok "300 ms of delay: WAN1 is 'latency' (round trip $(gw WAN1 'g["rtt_ms"]') ms)"
wait_for "default moved to WAN2 (latency trigger)" 20 via_is 'via 100.64.0.1 dev rtr-wan2'
[ "$(who)" = 100.64.0.2 ] || fail "after the latency failover the LAN should leave via WAN2"
nl_ok "group trigger loss_latency: the slow uplink is left, LAN traffic follows to WAN2"
wait_for "a latency sample" 30 health_has 's["state"] == "latency" and s["rtt_ms"] > 250'
wait_event gateway_degraded
ISP tc qdisc del dev up0 root
wait_for "WAN1 online again" 40 gw_is WAN1 online
wait_for "default back on WAN1" 20 via_is 'via 203.0.113.1 dev rtr-wan'
[ "$(sla 'd["sla"][0]["availability_pct"]')" = 100.0 ] || fail "latency is not an outage: $(cat "$NL_OUT")"
[ "$(sla 'd["sla"][0]["degraded_minutes"] >= 1')" = True ] || fail "latency must show as degraded in the SLA: $(cat "$NL_OUT")"
[ "$(sla 'd["sla"][0]["quality_pct"] < 100')" = True ] || fail "quality must drop: $(cat "$NL_OUT")"
nl_ok "latency history: availability stays 100 %, quality below 100 %, degraded samples counted; delay removed -> back on WAN1"

# --- 4. loss -------------------------------------------------------------------
ISP tc qdisc add dev up0 root netem loss 100%
wait_for "WAN1 down" 40 gw_is WAN1 down
wait_event gateway_down
wait_for "default on WAN2" 20 via_is 'via 100.64.0.1 dev rtr-wan2'
wait_for "an outage in the history" 30 health_has 's["state"] == "down"'
nl_api GET "/uplinks/outages?window=1h&gateway=WAN1"
[ "$(jget 'len(d["outages"]) >= 1 and d["outages"][-1]["ongoing"]')" = True ] || fail "outage list: $(cat "$NL_OUT")"
nl_ok "100 % loss: WAN1 down, gateway_down event, ongoing outage listed, traffic on WAN2"
ISP tc qdisc del dev up0 root
wait_for "WAN1 online again" 40 gw_is WAN1 online
wait_for "default back on WAN1" 20 via_is 'via 203.0.113.1 dev rtr-wan'
[ "$(sla 'd["sla"][0]["availability_pct"] < 100')" = True ] || fail "an outage must lower the availability: $(cat "$NL_OUT")"
[ "$(sla 'd["sla"][0]["down_minutes"] >= 1')" = True ] || fail "down samples: $(cat "$NL_OUT")"
nl_api GET "/uplinks/sla?window=1h&gateway=WAN1&series=1"
[ "$(jget 'len(d["series"]["WAN1"]) >= 1 and d["series"]["WAN1"][-1]["down_minutes"] >= 1')" = True ] || fail "hourly SLA series: $(cat "$NL_OUT")"
nl_api GET "/uplinks/outages?window=1h&gateway=WAN1"
[ "$(jget 'len(d["outages"]) >= 1 and not d["outages"][-1]["ongoing"]')" = True ] || fail "the outage should have ended: $(cat "$NL_OUT")"
nl_ok "after recovery: availability < 100 %, down samples in the hourly series, the outage is closed"

# --- 5. multi-probe: DNS through WAN1 -------------------------------------------
nl_api POST /uplinks/probes '{"gateway":"WAN1","kind":"dns","target":"198.51.100.53","name":"www.example.test"}'
[ "$NL_CODE" = 201 ] || fail "add probe: $NL_CODE $(cat "$NL_OUT")"
PID=$(jget 'd["id"]')
must 400 POST /uplinks/probes '{"gateway":"WAN1","kind":"dns","target":"198.51.100.53","name":"www.example.test"}'
must 400 POST /uplinks/probes '{"gateway":"NOPE","kind":"tcp","target":"198.51.100.10","port":80}'
R ip -4 route show proto 252 | grep '198.51.100.53 via 203.0.113.1 dev rtr-wan' >/dev/null || fail "probe target not pinned to WAN1: $(R ip -4 route show proto 252)"
nl_ok "DNS probe added; its target 198.51.100.53 is pinned to WAN1 (host route, proto 252), bad probes refused (400)"
wait_for "the DNS probe answers through WAN1" 40 probe_ok
nl_ok "DNS probe through rtr-wan: ok, $(gw WAN1 'g["probes"][0]["rtt_ms"]') ms"
INET nft add table inet nlb; INET nft "add chain inet nlb in { type filter hook input priority 0; }"; INET nft "add rule inet nlb in udp dport 53 drop"
wait_for "the DNS probe fails" 60 probe_failing
[ "$(gw WAN1 'g["state"]')" = online ] || fail "ping still works: WAN1 must stay online, is $(gw WAN1 'g["state"]')"
via_is 'via 203.0.113.1 dev rtr-wan' || fail "a non-critical probe must not move the default route: $(default_via)"
wait_event uplink_probe_failed
nl_api GET "/events?kind=uplink_probe_failed"
[ "$(jget 'd[-1]["subject"]')" = WAN1 ] && [ "$(jget 'd[-1]["severity"]')" = warning ] || fail "probe event: $(cat "$NL_OUT")"
wait_for "a degraded sample (ping fine, dns dead)" 30 health_has 's["state"] == "online" and s["dns_failed"] and s["degraded"]'
[ "$(sla 'd["sla"][0]["degraded_minutes"] >= 2')" = True ] || fail "degraded samples: $(cat "$NL_OUT")"
nl_ok "ISP DNS dead, ping fine: WAN1 stays online but degraded, uplink_probe_failed (warning) recorded, routing unchanged"
for _ in $(seq 1 30); do grep -q uplink_probe_failed "$T/hook.log" && break; sleep 1; done
python3 - "$T/hook.log" <<'PY' || fail "webhook delivery/signature"
import hmac, hashlib, json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
d = [l for l in lines if l['event'] == 'uplink_probe_failed']
assert d, lines
l = d[0]
want = 'sha256=' + hmac.new(b's3cret-value', l['body'].encode(), hashlib.sha256).hexdigest()
assert l['sig'] == want, (l['sig'], want)
b = json.loads(l['body'])
assert b['subject'] == 'WAN1' and 'dns' in b['detail'] and 'www.example.test' in b['detail'], b
PY
nl_ok "the same event went through the signed webhook (HMAC-SHA256 valid)"
INET nft delete table inet nlb
wait_for "the DNS probe recovers" 60 probe_ok
wait_event uplink_probe_recovered
nl_ok "DNS back: probe ok again, uplink_probe_recovered recorded"

# --- 6. a CRITICAL probe feeds failover ----------------------------------------
must 200 PUT "/uplinks/probes/$PID" '{"gateway":"WAN1","kind":"dns","target":"198.51.100.53","name":"www.example.test","critical":true}'
INET nft add table inet nlb; INET nft "add chain inet nlb in { type filter hook input priority 0; }"; INET nft "add rule inet nlb in udp dport 53 drop"
wait_for "WAN1 down because of the critical probe" 90 gw_is WAN1 down
R ping -c1 -W2 -I rtr-wan 203.0.113.1 >/dev/null || fail "the ISP router must still answer ping (that is the point)"
gw WAN1 'g["detail"]' | grep 'critical dns probe' >/dev/null || fail "detail: $(gw WAN1 'g["detail"]')"
wait_for "default on WAN2" 20 via_is 'via 100.64.0.1 dev rtr-wan2'
[ "$(who)" = 100.64.0.2 ] || fail "the LAN client should have failed over to WAN2"
nl_ok "critical DNS probe failing while ping answers: WAN1 down ('$(gw WAN1 'g["detail"]')'), default and LAN client moved to WAN2"
INET nft delete table inet nlb
wait_for "WAN1 online again" 90 gw_is WAN1 online
wait_for "default back on WAN1" 20 via_is 'via 203.0.113.1 dev rtr-wan'
[ "$(who)" = "$NL_RTR_WAN" ] || fail "LAN should be back on WAN1"
nl_ok "DNS back: WAN1 recovers and carries the traffic again"

# --- 7. SLA target -> alert -----------------------------------------------------
must 200 PUT /uplinks/settings '{"sla_target":99.99}'
wait_event uplink_sla_breach
nl_api GET "/events?kind=uplink_sla_breach"
[ "$(jget 'd[-1]["subject"]')" = WAN1 ] || fail "sla breach event: $(cat "$NL_OUT")"
for _ in $(seq 1 30); do grep -q uplink_sla_breach "$T/hook.log" && break; sleep 1; done
grep -q uplink_sla_breach "$T/hook.log" || fail "the SLA breach was not sent to the webhook"
must 200 PUT /uplinks/settings '{"sla_target":0}'
nl_ok "SLA target 99.99 %: uplink_sla_breach for WAN1 in the event log and the webhook"

# --- 8. reboot: history and probe configuration survive -------------------------
before=$(sla 'd["sla"][0]["samples"]')
nl_web_stop; applyd_stop
rm -f "$PATRONUS_GATEWAY_STATUS"
nl_up; second_wan
nl_apply "$DB" || { cat "$NL_OUT"; fail "reboot apply"; }
R ip -4 route show proto 252 | grep '198.51.100.53 via 203.0.113.1 dev rtr-wan' >/dev/null || fail "boot apply did not pin the probe target: $(R ip -4 route show proto 252)"
applyd_start
nl_web_start "$DB"; nl_login
must 200 GET /uplinks/probes
[ "$(jget 'len(d["rows"]) == 1 and d["rows"][0]["critical"]')" = True ] || fail "probe configuration lost: $(cat "$NL_OUT")"
[ "$(sla 'd["sla"][0]["samples"]')" -ge "$before" ] || fail "history lost across the reboot"
wait_for "WAN1 online after the reboot" 40 gw_is WAN1 online
wait_for "the probe runs again after the reboot" 40 probe_ok
nl_ok "reboot: samples ($before before) and the critical probe survive; the probe pin is rebuilt by patronus apply and the probe answers"
echo "lane-s-uplink: all checks passed"
