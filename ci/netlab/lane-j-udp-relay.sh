#!/usr/bin/env bash
# Lane J: UDP broadcast relay (USE=udp-relay). A LAN client sends real UDP
# broadcasts (255.255.255.255 and the directed 192.168.50.255); a listener on a
# second segment (OPT1, "IoT", namespace nl-iot) is the only one that can
# receive them if the router repeats them. A broadcast never crosses a router
# by itself, so every check first proves the negative.
#   - multi-port rules on ONE interface: rule 1 = @lan -> @opt1 ports 137,138
#     (original source kept), rule 2 = @lan -> @opt1 port 1900 (source = the
#     router's own OPT1 address); a port with no rule (9999) stays home
#   - the relayed copy keeps the payload and the sender's UDP port
#   - a reverse rule (@opt1 -> @lan, same port) must not loop: each side sees
#     exactly one copy of each datagram
#   - validation refuses DHCP ports, bad lists, bad interfaces (400)
#   - firewall: no hole is opened for it
#   - survives a reboot apply; disabling stops it
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-udp-relay.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_kill_daemons
IOT_RTR=10.60.0.1
IOT_DEV=10.60.0.20

iot_up() {
  ip netns del nl-iot 2>/dev/null || true
  ip netns add nl-iot; ip -n nl-iot link set lo up
  ip link add rtr-iot netns nl-rtr type veth peer name iot0 netns nl-iot
  R ip addr add $IOT_RTR/24 dev rtr-iot; R ip link set rtr-iot up
  ip -n nl-iot addr add $IOT_DEV/24 dev iot0; ip -n nl-iot link set iot0 up
}

cat > "$NL_T/nl-bcast.py" <<'PY'
# nl-bcast.py send SRC DST PORT SPORT PAYLOAD
# nl-bcast.py listen SECONDS PORT[,PORT...]   (prints "port src sport payload")
import select, socket, sys, time
if sys.argv[1] == "send":
    src, dst, port, sport, payload = sys.argv[2:7]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((src, int(sport)))
    s.sendto(payload.encode(), (dst, int(port)))
else:
    end = time.time() + float(sys.argv[2])
    socks = []
    for p in sys.argv[3].split(","):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", int(p)))
        socks.append(s)
    print("listening", flush=True)
    while time.time() < end:
        r, _, _ = select.select(socks, [], [], 0.3)
        for s in r:
            d, a = s.recvfrom(9000)
            print(s.getsockname()[1], a[0], a[1], d.decode(), flush=True)
PY

# on_iot "payload-list"...: listener on the IoT segment while the LAN client sends
# bcast_iot DST PORT SPORT PAYLOAD -> $NL_T/iot.txt
bcast_iot() {
  : > "$NL_T/iot.txt"
  ip netns exec nl-iot python3 "$NL_T/nl-bcast.py" listen 4 137,138,1900,9999,5000 >"$NL_T/iot.txt" 2>&1 &
  local lp=$!
  nl_wait 5 grep -q listening "$NL_T/iot.txt" || true
  C python3 "$NL_T/nl-bcast.py" send $NL_CLIENT "$1" "$2" "$3" "$4"
  sleep 1.5
  kill $lp 2>/dev/null; wait $lp 2>/dev/null || true
}
# bcast_lan: a device on the IoT segment broadcasts; a listener on the LAN hears it
lan_hears=/tmp/lan-hears.txt
bcast_lan() { # DST PORT SPORT PAYLOAD
  : > "$lan_hears"
  C python3 "$NL_T/nl-bcast.py" listen 4 137,5000 >"$lan_hears" 2>&1 &
  local lp=$!
  sleep 0.5
  ip netns exec nl-iot python3 "$NL_T/nl-bcast.py" send $IOT_DEV "$1" "$2" "$3" "$4"
  sleep 1.5
  kill $lp 2>/dev/null; wait $lp 2>/dev/null || true
}
count() { local n; n=$(grep -c "$2" "$1" || true); echo "$n"; }

nl_up; iot_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_web_start "$DB"; nl_login
nl_api_ok "OPT1 on the IoT port" PUT /interfaces/rtr-iot "{\"role\":\"opt1\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$IOT_RTR/24\"]}"

echo "=== without the relay, a broadcast stays on its own segment"
bcast_iot 255.255.255.255 137 4137 "before-relay"
[ "$(count "$NL_T/iot.txt" before-relay)" = 0 ] || nl_fail "broadcast crossed with no relay: $(cat "$NL_T/iot.txt")"
nl_ok "no relay: nothing arrives on the IoT segment"

echo "=== validation"
nl_api_code "DHCP port" 400 POST /svc/udp-relay/rules '{"iface":"@lan","ports":"67","targets":"@opt1"}'
nl_api_code "port range through DHCP" 400 POST /svc/udp-relay/rules '{"iface":"@lan","ports":"60-70","targets":"@opt1"}'
nl_api_code "bad port" 400 POST /svc/udp-relay/rules '{"iface":"@lan","ports":"137,x","targets":"@opt1"}'
nl_api_code "bad target" 400 POST /svc/udp-relay/rules '{"iface":"@lan","ports":"137","targets":"@opt1;x"}'
nl_api_code "no target" 400 POST /svc/udp-relay/rules '{"iface":"@lan","ports":"137"}'
nl_api_code "enable without rules" 400 PUT /svc/udp-relay '{"enabled":true}'
if R pgrep -f 'udp-relay run' >/dev/null 2>&1; then nl_fail "relay started although the change was refused"; fi
nl_ok "DHCP ports, bad lists/interfaces and an empty relay are refused (400), nothing started"

echo "=== enable: two rules on @lan (multi-port per interface) + a reverse rule"
nl_api_ok "rule 1" POST /svc/udp-relay/rules '{"iface":"@lan","ports":"137,138","targets":"@opt1","description":"NetBIOS"}'
nl_api_ok "rule 2" POST /svc/udp-relay/rules '{"iface":"@lan","ports":"1900","targets":"@opt1","spoof":false,"description":"SSDP"}'
nl_api_ok "rule 3" POST /svc/udp-relay/rules '{"iface":"@opt1","ports":"5000","targets":"@lan"}'
nl_api_ok "rule 4 (also lan->opt1 5000: a loop if relays were relayed)" POST /svc/udp-relay/rules '{"iface":"@lan","ports":"5000","targets":"@opt1"}'
nl_api_ok "enable" PUT /svc/udp-relay '{"enabled":true}'
nl_wait 10 pgrep -f 'udp-relay run' || { tail -20 "$NL_T/nl-web.log"; nl_fail "relay daemon did not start"; }
CONF=/var/lib/patronus/net/udp-relay.json
python3 - "$CONF" <<'PY' || { cat "$CONF"; nl_fail "generated relay config is wrong"; }
import json, sys
c = json.load(open(sys.argv[1]))
by = {(r["src"], tuple(map(tuple, r["ports"]))): r for r in c["rules"]}
assert by[("rtr-lan", ((137, 137), (138, 138)))]["dst"] == ["rtr-iot"], c
assert by[("rtr-lan", ((1900, 1900),))]["spoof"] is False, c
assert by[("rtr-iot", ((5000, 5000),))]["dst"] == ["rtr-lan"], c
PY
nl_ok "relay running with a multi-port rule list on rtr-lan"
nl_assert_nft_lacks "udp dport 137" "udp dport 1900"

echo "=== real broadcasts"
bcast_iot 255.255.255.255 137 4137 "nb-all-ones"
grep -x "137 $NL_CLIENT 4137 nb-all-ones" "$NL_T/iot.txt" >/dev/null \
  || { cat "$NL_T/iot.txt"; nl_fail "255.255.255.255:137 was not relayed with its source address and port kept"; }
nl_ok "limited broadcast to 137 arrives on the IoT segment, source $NL_CLIENT:4137 kept"
bcast_iot 192.168.50.255 138 4138 "nb-directed"
grep -x "138 $NL_CLIENT 4138 nb-directed" "$NL_T/iot.txt" >/dev/null \
  || { cat "$NL_T/iot.txt"; nl_fail "directed broadcast to 138 was not relayed"; }
nl_ok "LAN directed broadcast to 138 arrives (second port of the same rule)"
bcast_iot 255.255.255.255 1900 4190 "ssdp-own-src"
grep -x "1900 $IOT_RTR 4190 ssdp-own-src" "$NL_T/iot.txt" >/dev/null \
  || { cat "$NL_T/iot.txt"; nl_fail "rule 2 (spoof off) must use the router's OPT1 address as source"; }
nl_ok "second rule on the same interface: 1900 relayed with the router's own source address"
bcast_iot 255.255.255.255 9999 4999 "no-rule-port"
[ "$(count "$NL_T/iot.txt" no-rule-port)" = 0 ] || nl_fail "port 9999 has no rule but was relayed"
nl_ok "a port with no rule is not relayed"
bcast_iot 255.255.255.255 5000 4500 "loop-probe"
n=$(count "$NL_T/iot.txt" loop-probe)
[ "$n" = 1 ] || { cat "$NL_T/iot.txt"; nl_fail "loop-probe arrived $n times on the IoT side (want exactly 1)"; }
sleep 1; echo "--- LAN side for loop-probe: a relayed copy must not come back"
: > "$lan_hears"
C python3 "$NL_T/nl-bcast.py" listen 3 5000 >"$lan_hears" 2>&1 &
lp=$!; sleep 0.5
bcast_iot 255.255.255.255 5000 4501 "loop-probe-2"
wait $lp 2>/dev/null || true
back=$(grep -c "loop-probe-2" "$lan_hears" || true)
# the only LAN-side sighting allowed is the client's own original (it sent it from the LAN, the listener is a different socket in the same netns)
[ "$back" -le 1 ] || { cat "$lan_hears"; nl_fail "relayed copy looped back to the LAN ($back sightings)"; }
nl_ok "no relay loop: one copy on the IoT side, none re-relayed back"
bcast_lan 255.255.255.255 137 4237 "iot-to-lan-no-rule"
[ "$(count "$lan_hears" iot-to-lan-no-rule)" = 0 ] || nl_fail "137 from OPT1 relayed to the LAN with no such rule"
nl_ok "relay is per direction: OPT1 -> LAN on 137 stays home"
bcast_lan 255.255.255.255 5000 4300 "iot-to-lan-5000"
grep -x "5000 $IOT_DEV 4300 iot-to-lan-5000" "$lan_hears" >/dev/null \
  || { cat "$lan_hears"; nl_fail "reverse rule (OPT1 -> LAN 5000) did not relay"; }
nl_ok "reverse rule relays OPT1 -> LAN"

echo "=== status + stats + page"
nl_api GET /svc/udp-relay
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the running relay"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"], st
assert st["rules"] == 4, st
PY
STATS=/run/patronus/udp-relay.stats
nl_wait 8 test -s "$STATS" || STATS=$(ls /var/lib/patronus/net/run/udp-relay.stats /run/udp-relay.stats 2>/dev/null | head -1)
nl_web GET /svc/udp-relay
[ "$NL_CODE" = 200 ] && grep -F 'svc-settings-form' "$NL_OUT" >/dev/null || nl_fail "UDP relay page: $NL_CODE"
nl_ok "status + page show the relay"

echo "=== reboot: patronus apply brings it back"
nl_web_stop
nl_kill_daemons
nl_up; iot_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_wait 10 pgrep -f 'udp-relay run' || nl_fail "relay not started by the boot apply"
bcast_iot 255.255.255.255 138 4400 "after-reboot"
grep -x "138 $NL_CLIENT 4400 after-reboot" "$NL_T/iot.txt" >/dev/null \
  || { cat "$NL_T/iot.txt"; nl_fail "no relay after the reboot"; }
nl_ok "after reboot: broadcasts are relayed again"

echo "=== disable: relay stops"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/udp-relay '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -f "[u]dp-relay run"' || nl_fail "relay still running"
bcast_iot 255.255.255.255 137 4500 "after-disable"
[ "$(count "$NL_T/iot.txt" after-disable)" = 0 ] || nl_fail "still relayed after disabling"
nl_ok "disabled: relay stopped, nothing crosses"
nl_web_stop
ip netns del nl-iot 2>/dev/null || true
echo "ALL UDP-RELAY CHECKS PASSED"
