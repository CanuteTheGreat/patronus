# Shared by lane-w-netmap.sh and lane-w-netmap-ui.sh (source after lib.sh; set DB first):
# a deliberately FLAT LAN, bridge br0 192.168.50.0/24 with laptop (nl-client .10), nas (.11), cam (.12),
# tv (.13) and printer (.14), each with a small HTTP server, booted through `patronus apply`.
X() { ip netns exec "$@"; }
MAPNS="nl-nas nl-cam nl-tv nl-prn"
map_clean() { for n in $MAPNS; do ip netns del "$n" 2>/dev/null || true; done; }
trap '[ -n "${MAP_KEEP:-}" ] || map_clean' EXIT
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
http_ok() { X "$1" curl -s -m 3 -o /dev/null "http://$2:$3/"; }
want_ok() { local d=$1; shift; "$@" || nl_fail "$d: expected reachable"; nl_ok "$d"; }
want_deny() { local d=$1; shift; if "$@"; then nl_fail "$d: expected DENIED but it went through"; fi; nl_ok "$d (denied)"; }

# a tiny HTTP server that does no reverse DNS lookup (none exists here)
cat > "$NL_T/map-http.py" <<'EOF'
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"ok\n"; self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
class S(http.server.ThreadingHTTPServer):
    def server_bind(self): socketserver.TCPServer.server_bind(self)
S(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
EOF

map_topo() {
  map_clean
  R ip addr flush dev "$NL_LAN_IF"
  R ip link add br0 type bridge
  R ip link set br0 up
  R ip link set "$NL_LAN_IF" master br0
  R ip addr add 192.168.50.1/24 dev br0
  for spec in "nl-nas 11 02:aa:00:00:00:11" "nl-cam 12 02:aa:00:00:00:12" "nl-tv 13 02:aa:00:00:00:13" "nl-prn 14 02:aa:00:00:00:14"; do
    set -- $spec
    ip netns add "$1"; ip -n "$1" link set lo up
    ip link add "p$2" netns nl-rtr type veth peer name eth0 netns "$1"
    R ip link set "p$2" master br0; R ip link set "p$2" up
    X "$1" ip link set eth0 address "$3"; X "$1" ip link set eth0 up
    X "$1" ip addr add "192.168.50.$2/24" dev eth0
    X "$1" ip route add default via 192.168.50.1
  done
  C ip link set lan0 address 02:aa:00:00:00:10
  nl_bg C python3 "$NL_T/map-http.py" 7000
  for p in 80 8080; do X nl-cam python3 "$NL_T/map-http.py" $p >/dev/null 2>&1 & NL_PIDS+=($!); done
  X nl-tv python3 "$NL_T/map-http.py" 8080 >/dev/null 2>&1 & NL_PIDS+=($!)
  X nl-prn python3 "$NL_T/map-http.py" 9100 >/dev/null 2>&1 & NL_PIDS+=($!)
  X nl-nas python3 "$NL_T/map-http.py" 8080 >/dev/null 2>&1 & NL_PIDS+=($!)
  sleep 1
}
map_store_addr() {
  sqlite3 "$DB" "INSERT OR IGNORE INTO interface_addresses (interface_name, address, prefix_len, family) VALUES ('br0','192.168.50.1',24,'ipv4');
                 UPDATE interfaces SET ipv4_mode='static' WHERE name='br0';"
}
map_boot() {
  nl_up
  map_topo
  printf '[network]\nwan_interfaces = ["%s"]\nlan_interfaces = ["br0"]\n' "$NL_WAN_IF" > "$NL_TOML"
  nl_apply "$DB" --phase sysctl || { cat "$NL_OUT"; nl_fail "patronus apply (seed) failed"; }
  sqlite3 "$DB" "INSERT OR REPLACE INTO lan_settings (key, value, updated_at) VALUES ('dns.mode','disabled',0)"
  map_store_addr
  nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "patronus apply failed"; }
}
wake() { for ns in nl-nas nl-cam nl-tv nl-prn; do X $ns ping -c1 -W2 192.168.50.1 >/dev/null || true; done; C ping -c1 -W2 192.168.50.1 >/dev/null || true; }

