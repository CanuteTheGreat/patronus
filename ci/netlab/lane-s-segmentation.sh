#!/usr/bin/env bash
# Lane S (device segmentation): default-deny isolation proven with real
# packets between real network namespaces, through the shipped binaries.
#
# Topology: the router's LAN is a bridge `br0` (192.168.50.0/24) whose ports are
# isolated by Patronus (bridge link ... isolated on + proxy ARP), so every
# device-to-device packet goes through the router's forward hook where the
# `inet patronus_seg` table (priority -10) decides:
#
#   laptop (nl-client .10)  cam (.12)  tv (.13)  unknown (.99, never enrolled)
#
# Proves: opt-in (an upgraded store changes nothing), adoption into the allow-all
# group `home` on enable, per-group isolation, links, one-way service rules,
# unknown / spoofed-IP / spoofed-MAC drops, quarantine reaching only
# DHCP/DNS/ICMP (NOT SSH or the admin UI on 8443), revocation cutting an
# ESTABLISHED connection, atomic refusal of a bad change, and that all of it
# survives a reboot (`patronus apply` from the store).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-s-seg.db
X() { ip netns exec "$@"; }
SEGNS="nl-cam nl-tv nl-unk"
seg_clean() { for n in $SEGNS; do ip netns del "$n" 2>/dev/null || true; done; }
trap '[ -n "${SEG_KEEP:-}" ] || seg_clean' EXIT

# A keep-alive HTTP server: one connection serves many requests, so a flow can
# be established BEFORE a revocation and tried again after it.
cat > "$NL_T/seg-ka.py" <<'EOF'
import http.server, sys
class H(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        b = b"ok\n"
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
EOF
cat > "$NL_T/seg-flow.py" <<'EOF'
import socket, sys, time
req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)
def rt():
    s.sendall(req); s.settimeout(2); buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d: return False
        buf += d
    head, _, body = buf.partition(b"\r\n\r\n")
    n = int([l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
    while len(body) < n:
        d = s.recv(65536)
        if not d: return False
        body += d
    return True
print("1:", "answered" if rt() else "closed", flush=True)
time.sleep(1)
print("2:", "answered" if rt() else "closed", flush=True)
time.sleep(float(sys.argv[3]))
try:
    print("3:", "answered" if rt() else "closed", flush=True)
except Exception as e:
    print("3: no answer", type(e).__name__, flush=True)
EOF

http_ok()  { X "$1" curl -s -m 3 -o /dev/null "http://$2:$3/"; }
want_ok()   { local d=$1; shift; "$@" || nl_fail "$d: expected reachable"; nl_ok "$d"; }
want_deny() { local d=$1; shift; if "$@"; then nl_fail "$d: expected DENIED but it went through"; fi; nl_ok "$d (denied)"; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

# --- topology: LAN = bridge br0 with isolated-capable ports -------------------
seg_topo() {
  seg_clean
  R ip addr flush dev "$NL_LAN_IF"
  R ip link add br0 type bridge
  R ip link set br0 up
  R ip link set "$NL_LAN_IF" master br0
  R ip addr add 192.168.50.1/24 dev br0
  # the laptop is the netlab client (on rtr-lan); give the others their own ports
  for spec in "nl-cam 12 02:aa:00:00:00:12" "nl-tv 13 02:aa:00:00:00:13" "nl-unk 99 02:aa:00:00:00:99"; do
    set -- $spec
    ip netns add "$1"; ip -n "$1" link set lo up
    ip link add "p$2" netns nl-rtr type veth peer name eth0 netns "$1"
    R ip link set "p$2" master br0; R ip link set "p$2" up
    X "$1" ip link set eth0 address "$3"; X "$1" ip link set eth0 up
    X "$1" ip addr add "192.168.50.$2/24" dev eth0
    X "$1" ip route add default via 192.168.50.1
  done
  # the netlab client = laptop: its real veth MAC is whatever the kernel chose
  C ip link set lan0 address 02:aa:00:00:00:10
  nl_bg C python3 "$NL_T/seg-ka.py" 7000
}
seg_servers() {
  ip netns exec nl-cam python3 "$NL_T/seg-ka.py" 8080 >/dev/null 2>&1 & NL_PIDS+=($!)
  ip netns exec nl-cam python3 "$NL_T/seg-ka.py" 8081 >/dev/null 2>&1 & NL_PIDS+=($!)
  ip netns exec nl-tv python3 "$NL_T/seg-ka.py" 8080 >/dev/null 2>&1 & NL_PIDS+=($!)
  sleep 1
}
# the LAN address lives in the store like on a real install
seg_store_addr() {
  sqlite3 "$DB" "INSERT OR IGNORE INTO interface_addresses (interface_name, address, prefix_len, family) VALUES ('br0','192.168.50.1',24,'ipv4');
                 UPDATE interfaces SET ipv4_mode='static' WHERE name='br0';"
}
seg_boot() {
  nl_up
  seg_topo
  seg_servers
  printf '[network]\nwan_interfaces = ["%s"]\nlan_interfaces = ["br0"]\n' "$NL_WAN_IF" > "$NL_TOML"
  # this scenario is about the forwarding path: keep the resolver out of it
  # (seed the store first, then switch DNS off, then the full boot apply)
  nl_apply "$DB" --phase sysctl || { cat "$NL_OUT"; nl_fail "patronus apply (seed) failed"; }
  sqlite3 "$DB" "INSERT OR REPLACE INTO lan_settings (key, value, updated_at) VALUES ('dns.mode','disabled',0)"
  seg_store_addr
  nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "patronus apply failed"; }
}

rm -f "$DB" "$NL_T/nl-jar"
seg_boot
nl_ok "booted with LAN = bridge br0"
R nft list table inet patronus_seg >/dev/null 2>&1 && nl_fail "a fresh install has a segmentation table"

# --- 0. opt-in: devices may exist, nothing changes until the switch is on -------
nl_web_start "$DB"; nl_login
nl_api GET /segmentation
[ "$NL_CODE" = 200 ] || nl_fail "overview: $NL_CODE $(cat "$NL_OUT")"
[ "$(jget 'd["enforced"]')" = False ] || nl_fail "enforced before opt-in"
want_ok "before opt-in: cam -> laptop tcp 7000 reaches directly" http_ok nl-cam 192.168.50.10 7000
want_ok "before opt-in: unknown -> cam 8080 (nothing is isolated)" http_ok nl-unk 192.168.50.12 8080
R nft list table inet patronus_seg >/dev/null 2>&1 && nl_fail "table exists before opt-in"
nl_ok "opt-in: no segmentation table and no isolation on an upgraded/fresh store"

# --- 1. enable: adoption keeps day one identical --------------------------------
for ns in nl-cam nl-tv; do X $ns ping -c1 -W2 192.168.50.1 >/dev/null; done
C ping -c1 -W2 192.168.50.1 >/dev/null
nl_api POST /segmentation/segments '{"segment":"@lan","enabled":true}'
[ "$NL_CODE" = 200 ] || nl_fail "enable: $NL_CODE $(cat "$NL_OUT")"
nl_ok "enabled; adoption: $(jget 'len(d["adoption"]["adopted"])') device(s) adopted"
[ "$(jget 'len(d["adoption"]["adopted"])')" -ge 3 ] || nl_fail "adoption missed the devices on the segment: $(cat "$NL_OUT")"
nl_assert_nft_has "table inet patronus_seg" "unbound or revoked destination"
seg_prio() { R nft list table inet patronus_seg | grep -qE 'hook (forward|input) priority (filter - 10|-10)'; }
seg_prio || { R nft list table inet patronus_seg; nl_fail "the segmentation hooks are not at priority -10"; }
nl_ok "forward and input hooks at priority -10 (before the main table)"
port_iso() { R bridge -d link show dev "$1" | grep -q "isolated $2"; }
port_iso p12 on && port_iso p13 on && port_iso rtr-lan on || { R bridge -d link show; nl_fail "bridge ports are not isolated"; }
[ "$(R cat /proc/sys/net/ipv4/conf/br0/proxy_arp_pvlan)" = 1 ] || nl_fail "proxy_arp_pvlan is off"
nl_ok "bridge ports isolated, proxy ARP on"
# the laptop (admin) can still manage the box and everything still talks, now THROUGH the router
nl_api GET /segmentation; [ "$NL_CODE" = 200 ] || nl_fail "UI lost after enabling"
nl_ok "admin UI reachable from the adopted laptop"
want_ok "day one: laptop -> cam 8080 (home allows everything)" C curl -s -m 3 -o /dev/null http://192.168.50.12:8080/
want_ok "day one: cam -> tv 8080" http_ok nl-cam 192.168.50.13 8080
want_ok "day one: laptop still online" C curl -s -m 5 -o /dev/null "http://$NL_WWW/"
R nft list chain inet patronus_seg seg_forward | grep -E 'comment "group [0-9]+"' | grep -qE 'packets [1-9]' \
  || { R nft list chain inet patronus_seg seg_forward; nl_fail "no packet was counted by the group rule: traffic did not go through the router"; }
nl_ok "device-to-device traffic is counted by the router's group rule (it really is routed)"

DEVS=$(sqlite3 "$DB" "SELECT group_concat(name || ':' || mac || ':' || ip4, ' ') FROM seg_devices")
nl_ok "devices: $DEVS"
id_of() { sqlite3 "$DB" "SELECT id FROM seg_devices WHERE mac = '$1'"; }
ID_LAPTOP=$(id_of 02:aa:00:00:00:10); ID_CAM=$(id_of 02:aa:00:00:00:12); ID_TV=$(id_of 02:aa:00:00:00:13)
[ -n "$ID_LAPTOP" ] && [ -n "$ID_CAM" ] && [ -n "$ID_TV" ] || nl_fail "an adopted device is missing: $DEVS"

# --- 2. groups: laptop stays in home, cam and tv go to iot -----------------------
nl_api POST /segmentation/groups '{"name":"iot","intra":true,"internet":"allow"}'; [ "$NL_CODE" = 201 ] || nl_fail "group: $NL_CODE $(cat "$NL_OUT")"
nl_api PUT /segmentation/devices/$ID_CAM '{"group":"iot"}'; [ "$NL_CODE" = 200 ] || nl_fail "move cam $NL_CODE $(cat "$NL_OUT")"
nl_api PUT /segmentation/devices/$ID_TV '{"group":"iot"}'; [ "$NL_CODE" = 200 ] || nl_fail "move tv $NL_CODE $(cat "$NL_OUT")"
want_deny "laptop -> cam icmp" C ping -c2 -W2 192.168.50.12
want_deny "cam -> laptop tcp 7000" http_ok nl-cam 192.168.50.10 7000
want_deny "laptop -> tv tcp 8080" C curl -s -m 3 -o /dev/null http://192.168.50.13:8080/
want_ok "cam -> tv tcp 8080 (same group)" http_ok nl-cam 192.168.50.13 8080
want_ok "tv -> cam tcp 8081 (same group)" http_ok nl-tv 192.168.50.12 8081
want_ok "laptop is still online (internet allow)" C curl -s -m 5 -o /dev/null "http://$NL_WWW/"
want_ok "cam is online too" http_ok nl-cam "$NL_WWW" 80

# --- 3. group link (both directions), then one-way service rule -------------------
nl_api POST /segmentation/links '{"a":"home","b":"iot"}'; [ "$NL_CODE" = 201 ] || nl_fail "link: $NL_CODE $(cat "$NL_OUT")"
LINK=$(sqlite3 "$DB" "SELECT id FROM seg_links")
want_ok "linked: laptop -> cam 8081" C curl -s -m 3 -o /dev/null http://192.168.50.12:8081/
want_ok "linked: cam -> laptop 7000 (links are bidirectional)" http_ok nl-cam 192.168.50.10 7000
nl_api DELETE /segmentation/links/$LINK; [ "$NL_CODE" = 200 ] || nl_fail "unlink $NL_CODE"
want_deny "unlinked: laptop -> cam 8081" C curl -s -m 3 -o /dev/null http://192.168.50.12:8081/
nl_api POST /segmentation/services '{"name":"laptop-cam","src":"device:'"$(sqlite3 "$DB" "SELECT name FROM seg_devices WHERE id=$ID_LAPTOP")"'","dst":"device:'"$(sqlite3 "$DB" "SELECT name FROM seg_devices WHERE id=$ID_CAM")"'","proto":"tcp","ports":"8080"}'
[ "$NL_CODE" = 201 ] || nl_fail "service: $NL_CODE $(cat "$NL_OUT")"
want_ok "one-way service: laptop -> cam tcp 8080 (request and reply)" C curl -s -m 3 -o /dev/null http://192.168.50.12:8080/
want_deny "one-way service: laptop -> cam tcp 8081 (other port)" C curl -s -m 3 -o /dev/null http://192.168.50.12:8081/
want_deny "one-way service: cam -> laptop tcp 7000 (reverse stays denied)" http_ok nl-cam 192.168.50.10 7000
want_deny "one-way service: laptop -> tv tcp 8080 (names cam only)" C curl -s -m 3 -o /dev/null http://192.168.50.13:8080/

# --- 4. unknown / spoofed devices and the quarantine input chain -------------------
want_deny "unknown device -> cam 8080" http_ok nl-unk 192.168.50.12 8080
want_deny "unknown device -> laptop 7000" http_ok nl-unk 192.168.50.10 7000
want_deny "unknown device -> internet" http_ok nl-unk "$NL_WWW" 80
want_ok "unknown device -> router: ping still answers (ICMP)" X nl-unk ping -c1 -W2 192.168.50.1
# the management plane: the anti-lockout rule would let ANY lan source reach 22 and 8443
want_ok "adopted laptop -> router SSH (22) stays reachable" C python3 "$NL_T/nl-conn.py" 192.168.50.1 22
want_deny "quarantine/unknown -> router SSH (22)" X nl-unk python3 "$NL_T/nl-conn.py" 192.168.50.1 22
want_deny "quarantine/unknown -> admin UI (8443)" X nl-unk curl -sk -m 3 -o /dev/null https://192.168.50.1:8443/login
want_ok "adopted laptop -> admin UI (8443)" C curl -sk -m 5 -o /dev/null https://192.168.50.1:8443/login
# spoofing: the laptop's IP with a foreign MAC, then the laptop's MAC with its own IP
X nl-unk ip addr flush dev eth0; X nl-unk ip addr add 192.168.50.10/24 dev eth0; X nl-unk ip route add default via 192.168.50.1
want_deny "unknown device with the LAPTOP's IP -> cam 8080" http_ok nl-unk 192.168.50.12 8080
X nl-unk ip addr flush dev eth0; X nl-unk ip link set eth0 address 02:aa:00:00:00:10; X nl-unk ip addr add 192.168.50.99/24 dev eth0; X nl-unk ip route add default via 192.168.50.1
want_deny "unknown device with the LAPTOP's MAC (own IP) -> cam 8080" http_ok nl-unk 192.168.50.12 8080
X nl-unk ip link set eth0 address 02:aa:00:00:00:99
R bridge fdb del 02:aa:00:00:00:10 dev p99 master 2>/dev/null || true
R ip neigh flush all; C ping -c1 -W2 192.168.50.1 >/dev/null || true
# a device moved into the quarantine group loses everything but DHCP/DNS/ICMP
nl_api PUT /segmentation/devices/$ID_TV '{"group":"quarantine"}'; [ "$NL_CODE" = 200 ] || nl_fail "quarantine tv: $NL_CODE $(cat "$NL_OUT")"
want_deny "quarantined tv -> cam 8081" http_ok nl-tv 192.168.50.12 8081
want_deny "quarantined tv -> internet" http_ok nl-tv "$NL_WWW" 80
want_deny "quarantined tv -> admin UI" X nl-tv curl -sk -m 3 -o /dev/null https://192.168.50.1:8443/login
want_deny "cam -> quarantined tv" http_ok nl-cam 192.168.50.13 8080
nl_api PUT /segmentation/devices/$ID_TV '{"group":"iot"}'; [ "$NL_CODE" = 200 ] || nl_fail "release tv"
want_ok "released tv -> cam 8081 again" http_ok nl-tv 192.168.50.12 8081

# --- 5. adopting a discovered host --------------------------------------------------
X nl-unk ping -c1 -W2 192.168.50.1 >/dev/null || true
nl_api GET /segmentation/discovered; [ "$NL_CODE" = 200 ] || nl_fail "discovered $NL_CODE"
grep -q '02:aa:00:00:00:99' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "the unknown host is not listed as discovered"; }
nl_ok "the unknown host shows up under Discovered"
nl_api POST /segmentation/discovered/02:aa:00:00:00:99/adopt '{"name":"guest","group":"home"}'
[ "$NL_CODE" = 201 ] || nl_fail "adopt: $NL_CODE $(cat "$NL_OUT")"
want_ok "adopted guest -> internet" http_ok nl-unk "$NL_WWW" 80
want_ok "guest (home) -> laptop 7000" http_ok nl-unk 192.168.50.10 7000
ID_GUEST=$(id_of 02:aa:00:00:00:99)

# --- 6. revocation cuts an ESTABLISHED connection ------------------------------------
echo "=== revocation"
C python3 "$NL_T/seg-flow.py" 192.168.50.12 8080 6 > "$NL_T/seg-flow.out" 2>&1 &
FLOW=$!
sleep 3
nl_api POST /segmentation/devices/$ID_CAM/revoke; [ "$NL_CODE" = 200 ] || nl_fail "revoke: $NL_CODE $(cat "$NL_OUT")"
wait $FLOW || true
cat "$NL_T/seg-flow.out" | sed 's/^/    /'
grep -q '^2: answered' "$NL_T/seg-flow.out" && grep -q '^3: no answer' "$NL_T/seg-flow.out" \
  || nl_fail "the established flow survived revocation (or never worked)"
nl_ok "an ESTABLISHED laptop -> cam connection answered before the revoke and is cut after it"
want_deny "after revoke: laptop -> cam 8080 (service rule gone)" C curl -s -m 3 -o /dev/null http://192.168.50.12:8080/
want_deny "after revoke: tv -> cam 8081" http_ok nl-tv 192.168.50.12 8081
want_deny "after revoke: revoked cam -> tv 8080" http_ok nl-cam 192.168.50.13 8080
want_deny "after revoke: revoked cam -> internet" http_ok nl-cam "$NL_WWW" 80
nl_assert_nft_lacks "02:aa:00:00:00:12"
nl_ok "the revoked MAC is in no nft set"
[ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM dhcp_static_mappings WHERE mac='02:aa:00:00:00:12'")" = 0 ] || nl_fail "reservation of the revoked device still there"

# --- 7. a bad change is refused and the ruleset stays as it was ---------------------------
FP=$(nl_ruleset_fingerprint)
nl_api POST /segmentation/services '{"name":"bad","src":"device:ghost","dst":"group:home","proto":"tcp","ports":"1"}'
[ "$NL_CODE" = 400 ] || nl_fail "unknown endpoint must be a 400, got $NL_CODE"
nl_api POST /segmentation/groups '{"name":"x\"; flush ruleset; \"","internet":"allow"}'
[ "$NL_CODE" = 400 ] || nl_fail "hostile group name must be a 400, got $NL_CODE"
[ "$(nl_ruleset_fingerprint)" = "$FP" ] || nl_fail "a refused change altered the ruleset"
nl_ok "refused changes (unknown endpoint, hostile name) left the ruleset byte-identical"

# the guest goes into quarantine: it must STILL be there after the reboot
nl_api PUT /segmentation/devices/$ID_GUEST '{"group":"quarantine"}'; [ "$NL_CODE" = 200 ] || nl_fail "quarantine guest: $NL_CODE $(cat "$NL_OUT")"
want_deny "guest in quarantine -> router SSH" X nl-unk python3 "$NL_T/nl-conn.py" 192.168.50.1 22

# --- 8. reboot: isolation comes back from the store -------------------------------------------
echo "=== reboot"
nl_web_stop
seg_boot
R nft list table inet patronus_seg >/dev/null 2>&1 || nl_fail "segmentation table missing after reboot"
nl_assert_nft_has "table inet patronus_seg"
seg_prio || nl_fail "priority after reboot"
port_iso p13 on || nl_fail "ports not isolated after reboot"
want_deny "after reboot: laptop -> tv tcp 8080 still denied" C curl -s -m 3 -o /dev/null http://192.168.50.13:8080/
want_deny "after reboot: revoked cam stays revoked (cam -> tv)" http_ok nl-cam 192.168.50.13 8080
want_deny "after reboot: quarantined guest -> router SSH" X nl-unk python3 "$NL_T/nl-conn.py" 192.168.50.1 22
want_deny "after reboot: quarantined guest -> admin UI" X nl-unk curl -sk -m 3 -o /dev/null https://192.168.50.1:8443/login
want_deny "after reboot: quarantined guest -> laptop" http_ok nl-unk 192.168.50.10 7000
nl_assert_store_ok "$DB"

# --- 9. switching it off restores the open network ---------------------------------------------
nl_web_start "$DB"; nl_login
nl_ok "after reboot: the adopted laptop still logs in to the admin UI (8443)"
nl_api POST /segmentation/segments '{"segment":"@lan","enabled":false}'; [ "$NL_CODE" = 200 ] || nl_fail "disable: $NL_CODE $(cat "$NL_OUT")"
R nft list table inet patronus_seg >/dev/null 2>&1 && nl_fail "segmentation table still loaded after switching off"
port_iso p13 off || nl_fail "ports still isolated after switching off"
nl_ok "off: table deleted, ports no longer isolated"
echo "PASS lane-s-segmentation"
