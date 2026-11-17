#!/usr/bin/env bash
# Lane S: DNS over TLS to the upstreams (Unbound forward-tls-upstream). A test
# DoT server on the internet side (TLS on 853 only, no plain DNS there) with a
# certificate from a lab CA. Proves, with real queries from the LAN client:
#   - with DoT on and the right certificate name, LAN names resolve through the
#     encrypted upstream (and the server saw TLS with that SNI);
#   - a wrong certificate name gets SERVFAIL: no silent fallback to plain DNS;
#   - bad settings are refused (no name, forwarder mode, hostile name: 400);
#   - the setting survives a reboot.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-s-dot.db
UP=198.51.100.53
NAME=dot.example.test
CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
unbound_alive() { ps -eo stat=,comm= | awk '$2=="unbound" && $1 !~ /^Z/ {f=1} END{exit !f}'; }
rm -f "$DB" "$NL_T/nl-jar" "$NL_T/dot.log"
nl_write_installer_toml
pkill -x unbound 2>/dev/null || true

# lab CA + server certificate for $NAME; the CA joins the system bundle for
# this lab only (restored at the end)
D=$NL_T/dot-pki; rm -rf "$D"; mkdir -p "$D"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=netlab DoT CA" \
  -keyout "$D/ca.key" -out "$D/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$NAME" -keyout "$D/srv.key" -out "$D/srv.csr" 2>/dev/null
printf 'subjectAltName=DNS:%s\n' "$NAME" > "$D/ext"
openssl x509 -req -in "$D/srv.csr" -CA "$D/ca.pem" -CAkey "$D/ca.key" -CAcreateserial -days 2 \
  -extfile "$D/ext" -out "$D/srv.pem" 2>/dev/null
[ -f "$CA_BUNDLE" ] || nl_fail "no system CA bundle at $CA_BUNDLE"
cp "$CA_BUNDLE" "$D/bundle.orig"
cat "$D/ca.pem" >> "$CA_BUNDLE"
restore_bundle() { cp "$D/bundle.orig" "$CA_BUNDLE" 2>/dev/null || true; }
trap restore_bundle EXIT

cat > "$NL_T/nl-dot.py" <<'PY'
# minimal DNS-over-TLS server: *.svc.example -> 198.51.100.88, else NXDOMAIN
import socket, ssl, struct, sys, threading
cert, key, addr, log = sys.argv[1:5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
def sni(sock, name, c):
    with open(log, 'a') as f: f.write('sni=%s\n' % name)
ctx.sni_callback = sni
def answer(q):
    i = 12; labels = []
    while q[i]: labels.append(q[i+1:i+1+q[i]].decode()); i += q[i] + 1
    qend = i + 5; name = '.'.join(labels).lower(); qtype = struct.unpack('!H', q[i+1:i+3])[0]
    with open(log, 'a') as f: f.write('query=%s type=%d\n' % (name, qtype))
    hit = name.endswith('svc.example')
    an = 1 if hit and qtype == 1 else 0
    flags = 0x8180 if hit else 0x8183
    r = q[:2] + struct.pack('!HHHHH', flags, 1, an, 0, 0) + q[12:qend]
    if an: r += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('198.51.100.88')
    return r
def serve(c):
    try:
        t = ctx.wrap_socket(c, server_side=True)
        while True:
            h = t.recv(2)
            if len(h) < 2: return
            n = struct.unpack('!H', h)[0]; q = b''
            while len(q) < n:
                b = t.recv(n - len(q))
                if not b: return
                q += b
            r = answer(q); t.sendall(struct.pack('!H', len(r)) + r)
    except Exception as e:
        with open(log, 'a') as f: f.write('tls-error=%s\n' % e)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, 853)); s.listen(16)
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
cat > "$NL_T/dot-a.py" <<'PY'
import socket, struct, sys
name, server = sys.argv[1], sys.argv[2]
q = struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
for l in name.split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
s.sendto(q, (server, 53)); d, _ = s.recvfrom(4096)
rcode = d[3] & 15; an = struct.unpack("!H", d[6:8])[0]
i = 12
while d[i]: i += d[i] + 1
i += 5
out = []
for _ in range(an):
    if d[i] & 0xC0 == 0xC0: i += 2
    else:
        while d[i]: i += d[i] + 1
        i += 1
    t, _c, _ttl, ln = struct.unpack("!HHIH", d[i:i+10]); i += 10
    if t == 1: out.append(socket.inet_ntoa(d[i:i+4]))
    i += ln
print("rcode=%d answers=%s" % (rcode, ",".join(sorted(out)) or "none"))
PY
ask() { C python3 "$NL_T/dot-a.py" "$1" 192.168.50.1 2>&1 || true; }
start_upstream() {
  INET ip addr add $UP/24 dev inet0 2>/dev/null || true
  nl_bg INET python3 "$NL_T/nl-dot.py" "$D/srv.pem" "$D/srv.key" $UP "$NL_T/dot.log"
  for _ in $(seq 1 40); do INET bash -c "exec 3<>/dev/tcp/$UP/853" 2>/dev/null && return 0; sleep 0.25; done
  nl_fail "DoT test server did not start"
}
resolves() { case "$(ask "$1")" in *answers=198.51.100.88*) return 0 ;; esac; return 1; }

echo "=== DoT on"
nl_boot "$DB"; start_upstream
nl_web_start "$DB"; nl_login
for bad in '{"upstream_tls":true,"upstreams":"","upstream_tls_name":"x.example"}' \
           "{\"upstream_tls\":true,\"upstreams\":\"$UP\",\"upstream_tls_name\":\"\"}" \
           "{\"mode\":\"forwarder\",\"upstream_tls\":true,\"upstreams\":\"$UP\",\"upstream_tls_name\":\"$NAME\"}" \
           "{\"upstream_tls\":true,\"upstreams\":\"$UP\",\"upstream_tls_name\":\"a.example\\nforward-addr: 6.6.6.6\"}"; do
  nl_api PUT /dns/settings "$bad"
  [ "$NL_CODE" = 400 ] || nl_fail "bad DoT setting accepted ($NL_CODE): $bad"
done
nl_ok "DoT without upstreams / name, with the forwarder, or a hostile name: 400"
nl_api_ok "dns settings" PUT /dns/settings "{\"mode\":\"resolver\",\"dnssec\":false,\"upstreams\":\"$UP\",\"upstream_tls\":true,\"upstream_tls_name\":\"$NAME\"}"
nl_wait 15 unbound_alive || nl_fail "unbound is not running"
grep -F "forward-addr: $UP@853#$NAME" /etc/unbound/unbound.conf >/dev/null || { cat /etc/unbound/unbound.conf; nl_fail "no DoT forward-addr"; }
if ! nl_wait 20 resolves www.svc.example; then
  echo "--- diag: $(ask www.svc.example)"; cat "$NL_T/dot.log" 2>/dev/null | tail -5
  nl_fail "a LAN client does not resolve through the DoT upstream"
fi
grep -F "sni=$NAME" "$NL_T/dot.log" >/dev/null || nl_fail "the DoT server never saw TLS with SNI $NAME: $(cat "$NL_T/dot.log")"
grep -F "query=www.svc.example" "$NL_T/dot.log" >/dev/null || nl_fail "query did not arrive over TLS"
nl_ok "www.svc.example -> 198.51.100.88 through DNS over TLS (SNI $NAME, upstream has no plain DNS)"

echo "=== wrong certificate name: no fallback"
nl_api_ok "wrong name" PUT /dns/settings '{"upstream_tls_name":"other.example.test"}'
nl_wait 10 grep -q '@853#other.example.test' /etc/unbound/unbound.conf || nl_fail "new name not rendered"
servfail() { case "$(ask "x$RANDOM.svc.example")" in *rcode=2*) return 0 ;; esac; return 1; }
nl_wait 20 servfail || nl_fail "a certificate name mismatch must fail (SERVFAIL), got: $(ask y.svc.example)"
nl_ok "certificate name mismatch -> SERVFAIL (no plain-DNS fallback)"
nl_api_ok "right name" PUT /dns/settings "{\"upstream_tls_name\":\"$NAME\"}"
nl_wait 20 resolves "z$RANDOM.svc.example" || nl_fail "does not resolve again with the right name"
nl_web_stop

echo "=== reboot keeps it"
pkill -x unbound 2>/dev/null || true; rm -f /run/openrc/started/unbound
: > "$NL_T/dot.log"
nl_boot "$DB"; start_upstream
nl_wait 15 unbound_alive || nl_fail "unbound not started by the boot apply"
nl_wait 20 resolves "r$RANDOM.svc.example" || nl_fail "no DoT resolution after reboot"
grep -F "sni=$NAME" "$NL_T/dot.log" >/dev/null || nl_fail "after reboot: not over TLS"
nl_ok "after reboot: still resolving over TLS"

pkill -x unbound 2>/dev/null || true
nl_down
echo "PASS lane-s-dns-dot"
