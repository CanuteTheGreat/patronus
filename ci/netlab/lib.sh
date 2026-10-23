# shellcheck shell=bash
# Netlab harness: a small "internet" in network namespaces, with the real
# Patronus binaries routing between a LAN client and it. Source this from a
# ci/netlab/<scenario>.sh script; ci/netlab/run.sh copies it next to the
# scenarios inside the capped netlab container (root, CAP_NET_ADMIN,
# CAP_SYS_ADMIN, writable /proc/sys).
#
#   client 192.168.50.10 ---- rtr-lan [ rtr ] rtr-wan ---- isp ---- inet
#   (LAN, gw .1, DNS         192.168.50.1   203.0.113.2  203.0.113.1  198.51.100.10 www.example.test
#    198.51.100.53)                                       198.51.100.1 198.51.100.20 blocked.example.test
#                                                                      198.51.100.53 DNS (dnsmasq)
#
# - `isp` forwards between the router's WAN and the internet but has NO
#   route back to 192.168.50.0/24: a LAN client only gets online if the
#   router really masquerades.
# - `inet` runs dnsmasq (authoritative for *.example.test) and HTTP
#   servers on :80 and :8080 that answer "<host> sees <client address>".
# - `nl_boot` = a reboot: fresh namespaces (empty nftables, empty conntrack,
#   ip_forward=0) and then exactly what the init system runs:
#   `patronus apply` against the persistent store.
#
# Helpers fail the scenario with a message (`nl_fail`); every assertion
# prints an `ok - ...` line so CI logs show what was proven.

NL_T=${NL_T:-/t}
P=${PATRONUS_BIN:-$NL_T/patronus}
WEB=${PATRONUS_WEB_BIN:-$NL_T/patronus-web}
NL_PASS='Netlab-Test-Passw0rd!'
NL_TOML=$NL_T/nl-patronus.toml
NL_LAN_IF=rtr-lan
NL_WAN_IF=rtr-wan
NL_RTR_LAN=192.168.50.1
NL_RTR_WAN=203.0.113.2
NL_CLIENT=192.168.50.10
NL_WWW=198.51.100.10
NL_BLOCKED=198.51.100.20
NL_DNS=198.51.100.53
NL_UI=https://$NL_RTR_LAN:8443
NL_OUT=/tmp/nl.out

nl_fail() { echo "FAIL: $*" >&2; exit 1; }
nl_ok() { echo "ok - $*"; }
R() { ip netns exec nl-rtr "$@"; }
C() { ip netns exec nl-client "$@"; }
ISP() { ip netns exec nl-isp "$@"; }
INET() { ip netns exec nl-inet "$@"; }
# (exported so polling loops can run `bash -c "R ip route ..."`)
export -f R C ISP INET

NL_PIDS=()
# nl_bg NS-HELPER CMD...: start CMD in that namespace in the background.
# `ip netns exec` is started directly instead of via R/C/ISP/INET: those are
# functions, and backgrounding a function forks a subshell, so $! would be the
# subshell, nl_down would stop only that, and the real server would be
# orphaned in the deleted namespace (7 leaked processes per nl_up; the
# nightly's 30 power cuts leaked ~200 into the 2g netlab container).
nl_bg() {
  local ns=
  case $1 in R) ns=nl-rtr ;; C) ns=nl-client ;; ISP) ns=nl-isp ;; INET) ns=nl-inet ;; esac
  if [ -n "$ns" ]; then
    shift
    ip netns exec "$ns" "$@" >/dev/null 2>&1 &
  else
    "$@" >/dev/null 2>&1 &
  fi
  NL_PIDS+=($!)
}

# --- servers ---------------------------------------------------------------
cat > "$NL_T/nl-http.py" <<'EOF'
# HTTP server: GET -> "<Host header> sees <client address>"
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"{self.headers.get('Host','?').split(':')[0]} sees {self.client_address[0]}\n".encode()
        self.send_response(200); self.send_header("content-length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True; daemon_threads = True
S((sys.argv[1], int(sys.argv[2])), H).serve_forever()
EOF
cat > "$NL_T/nl-tcp.py" <<'EOF'
# TCP server: reply with the client's source address, one line per connection.
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(64)
while True:
    c, a = s.accept(); c.sendall((a[0] + "\n").encode()); c.close()
EOF
cat > "$NL_T/nl-conn.py" <<'EOF'
# Connect and print what the server says; exit 1 if unreachable in 2s.
import socket, sys
try:
    c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)
    print(c.recv(100).decode().strip())
except OSError as e:
    print("unreachable:", e); sys.exit(1)
EOF

# --- topology --------------------------------------------------------------
nl_down() {
  for p in "${NL_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  for p in "${NL_PIDS[@]:-}"; do [ -n "$p" ] && { wait "$p" 2>/dev/null || true; }; done
  NL_PIDS=()
  sleep 0.2
  # Every server nl_bg started must be gone; a survivor means nl_bg lost track
  # of the real process (see nl_bg).
  local left
  left=$(pgrep -af -- "$NL_T/(nl|lb)-[a-z0-9]+\\.py|nl-dnsmasq\\.pid" || true)
  [ -z "$left" ] || nl_fail "nl_down left netlab servers running: $left"
  for n in nl-rtr nl-client nl-isp nl-inet; do ip netns del "$n" 2>/dev/null || true; done
  rm -rf /etc/netns/nl-client
}

# Fresh namespaces = what the kernel looks like right after a (re)boot.
nl_up() {
  nl_down
  for n in nl-rtr nl-client nl-isp nl-inet; do ip netns add "$n"; ip -n "$n" link set lo up; done
  ip link add "$NL_LAN_IF" netns nl-rtr type veth peer name lan0 netns nl-client
  ip link add "$NL_WAN_IF" netns nl-rtr type veth peer name up0 netns nl-isp
  ip link add down0 netns nl-isp type veth peer name inet0 netns nl-inet
  R ip addr add $NL_RTR_LAN/24 dev $NL_LAN_IF; R ip link set $NL_LAN_IF up
  R ip addr add $NL_RTR_WAN/24 dev $NL_WAN_IF; R ip link set $NL_WAN_IF up
  R ip route add default via 203.0.113.1
  C ip addr add $NL_CLIENT/24 dev lan0; C ip link set lan0 up
  C ip route add default via $NL_RTR_LAN
  ISP ip addr add 203.0.113.1/24 dev up0; ISP ip link set up0 up
  ISP ip addr add 198.51.100.1/24 dev down0; ISP ip link set down0 up
  ISP sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  INET ip addr add $NL_WWW/24 dev inet0
  INET ip addr add $NL_BLOCKED/24 dev inet0
  INET ip addr add $NL_DNS/24 dev inet0
  INET ip link set inet0 up
  INET ip route add default via 198.51.100.1
  # the LAN client's resolver (ip netns exec bind-mounts this over /etc/resolv.conf)
  mkdir -p /etc/netns/nl-client
  echo "nameserver $NL_DNS" > /etc/netns/nl-client/resolv.conf
  nl_bg INET dnsmasq --no-daemon --no-resolv --no-hosts --user=root --bind-interfaces \
      --listen-address=$NL_DNS --pid-file=/tmp/nl-dnsmasq.pid \
      --address=/www.example.test/$NL_WWW --address=/blocked.example.test/$NL_BLOCKED
  nl_bg INET python3 "$NL_T/nl-http.py" 0.0.0.0 80
  nl_bg INET python3 "$NL_T/nl-http.py" 0.0.0.0 8080
  nl_bg INET python3 "$NL_T/nl-tcp.py" 0.0.0.0 9000
  nl_bg C python3 "$NL_T/nl-tcp.py" $NL_CLIENT 9000
  nl_bg R python3 "$NL_T/nl-tcp.py" 0.0.0.0 22     # stands in for sshd
  nl_bg R python3 "$NL_T/nl-tcp.py" 0.0.0.0 2222
  # A new namespace copies IPv4 devconf from the host (CI hosts forward for
  # Docker); a booting router starts with forwarding off.
  R sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward; echo 0 > /proc/sys/net/ipv6/conf/all/forwarding'
  for _ in $(seq 1 50); do
    INET sh -c "exec 3<>/dev/tcp/$NL_WWW/80" 2>/dev/null && break; sleep 0.1
  done
  [ "$(R cat /proc/sys/net/ipv4/ip_forward)" = 0 ] || nl_fail "fresh router namespace already forwards"
  [ -z "$(R nft list ruleset)" ] || nl_fail "fresh router namespace already has a ruleset"
}

# The patronus.toml the installer writes (crates/patronus-installer
# install/network.rs), for this topology.
nl_write_installer_toml() {
  printf '# written by patronus-installer\nwan_interfaces = ["%s"]\nlan_interfaces = ["%s"]\n' \
    "$NL_WAN_IF" "$NL_LAN_IF" > "$NL_T/nl-net.part"
  { echo "[network]"; cat "$NL_T/nl-net.part"; } > "$NL_TOML"
}

# nl_apply DB [extra args]: what the boot unit runs. Output in $NL_OUT;
# returns patronus' exit status.
nl_apply() {
  local db=$1; shift
  R "$P" --db "$db" apply --bootstrap "$NL_TOML" "$@" >"$NL_OUT" 2>&1
}

# nl_boot DB: reboot the box = fresh namespaces + `patronus apply`.
nl_boot() {
  nl_up
  nl_apply "$1" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
  nl_ok "boot: patronus apply ($(grep -c '✓' "$NL_OUT") appliers ok)"
}

# --- web UI / API ------------------------------------------------------------
NL_WEB_PID=
nl_web_start() { # DB
  env PATRONUS_DB="$1" PATRONUS_BOOTSTRAP="$NL_TOML" PATRONUS_ADMIN_PASSWORD="$NL_PASS" \
      PATRONUS_ADMIN_PASSWORD_FILE=$NL_T/nl-pw PATRONUS_TLS_DIR=$NL_T/nl-tls RUST_LOG=info \
      ip netns exec nl-rtr "$WEB" >>"$NL_T/nl-web.log" 2>&1 &
  NL_WEB_PID=$!
  for _ in $(seq 1 60); do
    C curl -sk -o /dev/null "$NL_UI/login" && { rm -f "$NL_T/nl-jar"; return 0; }
    sleep 0.5
  done
  tail -50 "$NL_T/nl-web.log"; nl_fail "patronus-web did not come up on $NL_UI (from the LAN)"
}
nl_web_stop() {
  [ -n "$NL_WEB_PID" ] && kill "$NL_WEB_PID" 2>/dev/null
  wait "$NL_WEB_PID" 2>/dev/null || true
  NL_WEB_PID=
}
# nl_web METHOD PATH [JSON]: request from the LAN client with the session
# cookie; body in $NL_OUT, HTTP status in $NL_CODE.
nl_web() {
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  NL_CODE=$(C curl -sk -m "${NL_CURL_MAX:-60}" -b "$NL_T/nl-jar" -c "$NL_T/nl-jar" -o "$NL_OUT" -w '%{http_code}' \
    -X "$1" -H 'content-type: application/json' "${data[@]}" "$NL_UI$2")
}
nl_api() { local m=$1 p=$2; shift 2; nl_web "$m" "/api$p" "$@"; }
# Log in the way the login page's form does (POST /api/auth/login).
nl_login() {
  nl_web GET /login
  [ "$NL_CODE" = 200 ] && grep -q 'id="login-form"' "$NL_OUT" || nl_fail "login page ($NL_CODE)"
  nl_api POST /auth/login "{\"username\":\"admin\",\"password\":\"$NL_PASS\"}"
  [ "$NL_CODE" = 200 ] || nl_fail "login: $NL_CODE $(cat "$NL_OUT")"
}

# --- traffic assertions --------------------------------------------------------
# nl_expect_http DESC URL [WANT]: the LAN client fetches URL (name resolved
# through the router's path to the internet DNS); body must contain WANT.
nl_expect_http() {
  local d=$1 url=$2 want=${3:-}
  C curl -s --max-time 4 -o "$NL_OUT" "$url" || { nl_fail "$d: $url unreachable"; }
  [ -z "$want" ] || grep -qF "$want" "$NL_OUT" || nl_fail "$d: got '$(cat "$NL_OUT")', want '$want'"
  nl_ok "$d ($(cat "$NL_OUT"))"
}
nl_expect_http_blocked() {
  local d=$1 url=$2
  if C curl -s --max-time 3 -o "$NL_OUT" "$url"; then nl_fail "$d: expected blocked, got '$(cat "$NL_OUT")'"; fi
  nl_ok "$d (blocked)"
}
nl_expect_dns() { # NAME IP
  local got
  got=$(C python3 -c "import socket,sys; print(socket.gethostbyname(sys.argv[1]))" "$1" 2>&1) \
    || nl_fail "DNS: $1 did not resolve from the LAN ($got)"
  [ "$got" = "$2" ] || nl_fail "DNS: $1 -> $got, want $2"
  nl_ok "LAN client resolves $1 -> $2 via $NL_DNS through the router"
}
# nl_expect_tcp DESC NS-WRAPPER HOST PORT / nl_expect_no_tcp ...
nl_expect_tcp() {
  local d=$1; shift
  "$1" python3 "$NL_T/nl-conn.py" "$2" "$3" >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "$d: expected reachable"; }
  nl_ok "$d ($(cat "$NL_OUT"))"
}
nl_expect_no_tcp() {
  local d=$1; shift
  if "$1" python3 "$NL_T/nl-conn.py" "$2" "$3" >"$NL_OUT" 2>&1; then nl_fail "$d: expected blocked, got $(cat "$NL_OUT")"; fi
  nl_ok "$d (blocked)"
}
nl_expect_ping() { C ping -c1 -W2 "$1" >/dev/null 2>&1 || nl_fail "ping $1 from the LAN failed"; nl_ok "LAN client pings $1"; }

# The everyday "is this box a working router" check.
nl_expect_online() {
  nl_expect_ping $NL_WWW
  nl_expect_dns www.example.test $NL_WWW
  nl_expect_http "LAN -> http://www.example.test (masqueraded)" http://www.example.test/ "www.example.test sees $NL_RTR_WAN"
}
# ... and the WAN side stays shut.
nl_expect_wan_closed() {
  ISP ip route replace 192.168.50.0/24 via $NL_RTR_WAN   # an ISP-side host that knows the LAN prefix
  nl_expect_no_tcp "WAN -> router SSH" ISP $NL_RTR_WAN 22
  nl_expect_no_tcp "WAN -> LAN host" ISP $NL_CLIENT 9000
  ISP ip route del 192.168.50.0/24 via $NL_RTR_WAN
}

# --- kernel state assertions ---------------------------------------------------
nl_ruleset() { R nft list ruleset; }
nl_assert_nft_has() {
  local rs; rs=$(nl_ruleset)
  for want in "$@"; do grep -qF -- "$want" <<<"$rs" || { echo "$rs"; nl_fail "ruleset lacks: $want"; }; done
  nl_ok "nft ruleset has: $*"
}
nl_assert_nft_lacks() {
  local rs; rs=$(nl_ruleset)
  for bad in "$@"; do if grep -qF -- "$bad" <<<"$rs"; then echo "$rs"; nl_fail "ruleset still has: $bad"; fi; done
  nl_ok "nft ruleset lacks: $*"
}
# Ruleset without handles/counters, for before/after equality.
nl_ruleset_fingerprint() { R nft -s list ruleset | sha256sum | cut -d' ' -f1; }
nl_assert_sysctl() { # key value
  local f=/proc/sys/${1//.//}
  [ "$(R cat "$f")" = "$2" ] || nl_fail "sysctl $1 = $(R cat "$f"), want $2"
  nl_ok "sysctl $1 = $2"
}
nl_assert_conntrack() { # PATTERN: a tracked flow in the router
  local ct; ct=$(R conntrack -L 2>/dev/null)
  grep -qE -- "$1" <<<"$ct" || { echo "$ct"; nl_fail "conntrack has no flow matching $1"; }
  nl_ok "conntrack: flow matching '$1'"
}
nl_assert_store_ok() { # DB
  local r; r=$(sqlite3 "$1" 'PRAGMA integrity_check;')
  [ "$r" = ok ] || nl_fail "store $1 integrity_check: $r"
}
# The safe router baseline every boot must produce.
nl_assert_router_baseline() {
  nl_assert_sysctl net.ipv4.ip_forward 1
  nl_assert_nft_has 'policy drop' "iifname \"$NL_LAN_IF\" tcp dport { 22, 8443 } accept" \
    "oifname \"$NL_WAN_IF\" masquerade"
  nl_assert_nft_lacks "iifname \"$NL_WAN_IF\" tcp dport { 22, 8443 }"
}
# Fail-closed lockdown: reachable from the LAN for repair, nothing forwarded.
nl_assert_lockdown() {
  nl_assert_nft_has 'policy drop' "iifname \"$NL_LAN_IF\" tcp dport { 22, 8443 } accept"
  nl_assert_nft_lacks masquerade "iifname \"$NL_LAN_IF\" accept"
  nl_expect_tcp "LAN -> router SSH in lockdown (anti-lockout)" C $NL_RTR_LAN 22
  nl_expect_http_blocked "LAN -> internet in lockdown" "http://$NL_WWW/"
  nl_expect_wan_closed
}

# --- helpers for the daemon-backed feature scenarios (lane J) -------------------
# nl_wait SECONDS CMD...: poll until CMD succeeds (quiet).
nl_wait() {
  local t=$1; shift
  local end=$((SECONDS + t))
  while [ "$SECONDS" -lt "$end" ]; do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.3
  done
  return 1
}
# nl_kill_daemons NAME...: a reboot ends the daemons Patronus started
# directly (no init system in the netlab container) and their pid files.
nl_kill_daemons() {
  for n in "$@"; do pkill -x "$n" 2>/dev/null || true; done
  sleep 0.5
  rm -rf /var/lib/patronus/net /run/patronus
}
# nl_api_ok DESC METHOD PATH [JSON]: the call must answer 2xx.
nl_api_ok() {
  local d=$1; shift
  nl_api "$@"
  case "$NL_CODE" in 2??) ;; *) nl_fail "$d: $NL_CODE $(cat "$NL_OUT")";; esac
}
# nl_api_code DESC WANT METHOD PATH [JSON]
nl_api_code() {
  local d=$1 want=$2; shift 2
  nl_api "$@"
  [ "$NL_CODE" = "$want" ] || nl_fail "$d: got $NL_CODE (want $want): $(cat "$NL_OUT")"
}
# nl_json FILE PYTHON-EXPR: print a field of a JSON file (d = the document).
nl_json() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"; }
