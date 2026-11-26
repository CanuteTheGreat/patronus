#!/usr/bin/env bash
# Lane N: reverse proxy / load balancer (HAProxy) in the shipped binary.
#  - off by default: no daemon, no firewall rule;
#  - "publish a LAN service" creates listener + backend + firewall rule: a host on the
#    internet reaches the LAN server by host name through the router's WAN address;
#  - two backend servers behind one name are balanced; one goes down -> every request
#    goes to the other; it comes back -> traffic spreads again;
#  - a TLS frontend serves its certificate (and routes by host name);
#  - an invalid configuration (a certificate file haproxy cannot load) is refused, the
#    change is undone and the old configuration keeps serving the same requests;
#  - a listener on the web UI's port is refused with an explanation;
#  - live statistics come from haproxy; switching off stops the daemon and removes the rule.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-reverse-proxy.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
command -v haproxy >/dev/null || apt-get install -y -qq haproxy >/dev/null
command -v haproxy >/dev/null || nl_fail "haproxy not installed"
command -v openssl >/dev/null || apt-get install -y -qq openssl >/dev/null
pkill -x haproxy 2>/dev/null || true
alive() { ps -eo stat=,comm= | awk -v n="$1" '$2 == n && $1 !~ /^Z/ { f = 1 } END { exit !f }'; }
export -f alive

# backend servers on the LAN: answer "backend <id>", /health 200 (kept apart from lib.sh's nl-*.py so nl_down knows them)
cat > "$NL_T/lb-rpsrv.py" <<'EOF'
import http.server, socketserver, sys
ident = sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (b"ok\n" if self.path == "/health" else f"backend {ident} host {self.headers.get('Host','?').split(':')[0]} for {self.headers.get('X-Forwarded-For','-')}\n".encode())
        self.send_response(200); self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True; daemon_threads = True
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]
S((sys.argv[1], int(sys.argv[2])), H).serve_forever()
EOF

nl_write_installer_toml
nl_boot "$DB"
# two more LAN servers' addresses on the client side
C ip addr add 192.168.50.11/24 dev lan0
C ip addr add 192.168.50.12/24 dev lan0
C ip addr add 192.168.50.13/24 dev lan0
nl_bg C python3 "$NL_T/lb-rpsrv.py" 192.168.50.11 8080 one
nl_bg C python3 "$NL_T/lb-rpsrv.py" 192.168.50.12 8080 two
nl_bg C python3 "$NL_T/lb-rpsrv.py" 192.168.50.13 8080 solo
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
ok2xx() { case "$NL_CODE" in 200|201) ;; *) nl_fail "$1: $NL_CODE $(cat "$NL_OUT")" ;; esac; }

# the router's own address on the LAN (the proxy reaches the servers through it)
nl_api PUT /interfaces/$NL_LAN_IF "{\"role\":\"lan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$NL_RTR_LAN/24\"],\"ipv6_mode\":\"none\",\"force\":true}"
ok2xx "LAN address"
nl_wait 20 C curl -s -m 2 http://192.168.50.11:8080/health || nl_fail "LAN servers do not answer"

# from the internet: INET reaches the router's WAN address; the request carries a host name
inet_get() { INET curl -s -m 4 --resolve "$1:${3:-80}:$NL_RTR_WAN" "http://$1:${3:-80}${2:-/}"; }

nl_api GET /svc/revproxy; ok2xx "reverse proxy page API"
[ "$(jget 'd["settings"]["enabled"]')" = False ] || nl_fail "reverse proxy is on by default"
! alive haproxy || nl_fail "haproxy runs although the reverse proxy is off by default"
nl_assert_nft_lacks "reverse proxy"
nl_expect_no_tcp "WAN -> router :80 while off" INET $NL_RTR_WAN 80
nl_ok "off by default: no daemon, no listener, no firewall rule"

echo "=== publish a LAN service (one step)"
nl_api POST /svc/revproxy/action/publish '{"name":"solo","address":"192.168.50.13","port":8080,"host":"solo.example.test","public_port":80}'
ok2xx "publish"
nl_wait 20 alive haproxy || { tail -20 /var/lib/patronus/net/*haproxy* 2>/dev/null || true; nl_fail "haproxy did not start after publishing"; }
nl_assert_nft_has "reverse proxy solo"
nl_wait 15 bash -c "INET curl -s -m 3 --resolve solo.example.test:80:$NL_RTR_WAN http://solo.example.test/ | grep -q 'backend solo'" || nl_fail "published service not reachable by name"
out=$(inet_get solo.example.test)
grep -q "backend solo host solo.example.test" <<<"$out" || nl_fail "the published service answered: $out"
grep -q "for 198.51.100.10" <<<"$out" || nl_fail "X-Forwarded-For lacks the client address: $out"
nl_ok "internet host -> solo.example.test through the router: $out"

echo "=== two servers behind one name, health checks, failover"
nl_api POST /svc/revproxy/backends '{"name":"pool","balance":"roundrobin","health":"http","check_uri":"/health","check_interval":1,"rise":1,"fall":2}'
ok2xx "backend pool"
nl_api POST /svc/revproxy/servers '{"backend":"pool","name":"one","address":"192.168.50.11","port":8080}'; ok2xx "server one"
nl_api POST /svc/revproxy/servers '{"backend":"pool","name":"two","address":"192.168.50.12","port":8080}'; ok2xx "server two"
nl_api POST /svc/revproxy/rules '{"frontend":"solo","host":"pool.example.test","backend":"pool"}'; ok2xx "rule pool"
seen=""
for _ in $(seq 1 12); do
  b=$(inet_get pool.example.test | sed -n 's/^backend \([a-z]*\) .*/\1/p')
  seen="$seen $b"
done
echo "$seen" | grep -q one && echo "$seen" | grep -q two || nl_fail "balancing: servers seen:$seen"
nl_ok "round robin reaches both servers:$seen"
# the host name still picks the backend: solo.example.test is not the pool
grep -q "backend solo" <<<"$(inet_get solo.example.test)" || nl_fail "host routing: solo.example.test no longer reaches solo"
nl_ok "host name routing keeps the other service apart"

# one backend goes down
pid=$(pgrep -f 'lb-rpsrv.py 192.168.50.11' | head -1); kill "$pid"
nl_wait 20 bash -c "! INET curl -s -m 2 --resolve pool.example.test:80:$NL_RTR_WAN http://pool.example.test/ | grep -q 'backend one'" || true
sleep 4
bad=0; seen=""
for _ in $(seq 1 12); do
  b=$(inet_get pool.example.test | sed -n 's/^backend \([a-z]*\) .*/\1/p'); seen="$seen $b"
  [ "$b" = two ] || bad=1
done
[ "$bad" = 0 ] || nl_fail "after server one died traffic still went elsewhere:$seen"
nl_ok "server one down: all 12 requests went to server two"
# live statistics report it
nl_api POST /svc/revproxy/action/stats '{}'; ok2xx "stats"
python3 - "$NL_OUT" <<'EOF' || nl_fail "statistics do not show one DOWN / two UP"
import json, sys
d = json.load(open(sys.argv[1]))
st = {(r["pxname"], r["svname"]): r["status"] for r in d["stats"]}
assert st[("be_pool", "one")].startswith("DOWN"), st
assert st[("be_pool", "two")] == "UP", st
EOF
nl_ok "live statistics: be_pool/one DOWN, be_pool/two UP"
# it comes back
nl_bg C python3 "$NL_T/lb-rpsrv.py" 192.168.50.11 8080 one
sleep 4
seen=""
for _ in $(seq 1 12); do seen="$seen $(inet_get pool.example.test | sed -n 's/^backend \([a-z]*\) .*/\1/p')"; done
echo "$seen" | grep -q one || nl_fail "server one came back but gets no traffic:$seen"
nl_ok "server one back: traffic spreads again:$seen"

echo "=== TLS frontend serves its certificate"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$NL_T/rp-key.pem" -out "$NL_T/rp-cert.pem" -days 2 \
  -subj "/CN=tls.example.test" -addext "subjectAltName=DNS:tls.example.test" >/dev/null 2>&1
cat "$NL_T/rp-cert.pem" "$NL_T/rp-key.pem" > "$NL_T/rp-site.pem"
nl_api POST /svc/revproxy/frontends '{"name":"secure","port":443,"tls":true,"cert_file":"/t/rp-site.pem","default_backend":"solo"}'
ok2xx "TLS frontend"
nl_wait 15 bash -c "INET curl -s -m 3 --cacert $NL_T/rp-cert.pem --resolve tls.example.test:443:$NL_RTR_WAN https://tls.example.test/ | grep -q 'backend solo'" \
  || { INET curl -sv -m 3 --cacert $NL_T/rp-cert.pem --resolve tls.example.test:443:$NL_RTR_WAN https://tls.example.test/ 2>&1 | tail -15; nl_fail "https://tls.example.test did not answer"; }
subj=$(INET sh -c "echo | openssl s_client -connect $NL_RTR_WAN:443 -servername tls.example.test 2>/dev/null | openssl x509 -noout -subject")
grep -q "tls.example.test" <<<"$subj" || nl_fail "served certificate: $subj"
nl_ok "TLS frontend answers with its certificate ($subj) and the verified request reaches the backend"
nl_assert_nft_has "tcp dport 443 accept comment \"reverse proxy secure\""

echo "=== invalid configuration is refused, the old one keeps serving"
nl_api POST /svc/revproxy/frontends '{"name":"broken","port":8444,"tls":true,"cert_file":"/t/does-not-exist.pem","default_backend":"solo"}'
case "$NL_CODE" in 2*) nl_fail "a certificate file that does not exist was accepted: $(cat "$NL_OUT")" ;; esac
grep -qi "haproxy\|certificate\|cert" "$NL_OUT" || nl_fail "the refusal does not say why: $(cat "$NL_OUT")"
nl_ok "refused ($NL_CODE): $(head -c 220 "$NL_OUT")"
nl_api GET /svc/revproxy; ok2xx "page"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert all(r["name"]!="broken" for r in d["collections"]["frontends"]), "refused row was kept"' "$NL_OUT" || nl_fail "the refused frontend stayed in the store"
nl_ok "the refused change was undone (no stored 'broken' frontend)"
alive haproxy || nl_fail "haproxy stopped after a refused change"
grep -q "backend solo" <<<"$(inet_get solo.example.test)" || nl_fail "old configuration stopped serving"
grep -q "backend" <<<"$(inet_get pool.example.test)" || nl_fail "pool stopped serving"
nl_ok "old configuration still serves both names"

echo "=== a listener on the web UI's port is refused and explained"
nl_api POST /svc/revproxy/frontends '{"name":"clash","port":8443,"default_backend":"solo"}'
case "$NL_CODE" in 2*) nl_fail "a frontend on the web UI port was accepted" ;; esac
grep -qi "web UI" "$NL_OUT" && grep -q "8443" "$NL_OUT" || nl_fail "the conflict is not explained: $(cat "$NL_OUT")"
nl_ok "port conflict refused: $(head -c 240 "$NL_OUT")"
nl_api POST /svc/revproxy/frontends '{"name":"dup","port":80,"default_backend":"solo"}'
case "$NL_CODE" in 2*) nl_fail "two frontends on port 80 were accepted" ;; esac
grep -q "both listen on port 80" "$NL_OUT" || nl_fail "duplicate listener not explained: $(cat "$NL_OUT")"
nl_ok "two listeners on one port refused"

echo "=== reboot: the proxy comes back from the stored configuration"
nl_web_stop
nl_kill_daemons haproxy
nl_boot "$DB"
for a in 11 12 13; do C ip addr add 192.168.50.$a/24 dev lan0; done
nl_bg C python3 "$NL_T/lb-rpsrv.py" 192.168.50.11 8080 one
nl_bg C python3 "$NL_T/lb-rpsrv.py" 192.168.50.12 8080 two
nl_bg C python3 "$NL_T/lb-rpsrv.py" 192.168.50.13 8080 solo
nl_wait 30 bash -c "INET curl -s -m 3 --resolve solo.example.test:80:$NL_RTR_WAN http://solo.example.test/ | grep -q 'backend solo'" || nl_fail "the proxy did not come back after a reboot"
nl_ok "after a reboot the proxy serves from the stored configuration"

echo "=== switch off"
nl_web_start "$DB"; nl_login
nl_api PUT /svc/revproxy '{"enabled":false}'; ok2xx "disable"
nl_wait 20 bash -c '! alive haproxy' || nl_fail "haproxy still running after switching off"
nl_assert_nft_lacks "reverse proxy"
nl_expect_no_tcp "WAN -> router :80 after off" INET $NL_RTR_WAN 80
nl_ok "off again: daemon stopped, listener and firewall rules gone"
echo "PASS lane-n-reverse-proxy"
