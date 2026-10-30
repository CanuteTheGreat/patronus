#!/usr/bin/env bash
# Lane S (c1): DNS rebinding protection. A public name must not resolve to a
# private address on the LAN: Unbound (resolver mode, forwarding to a test
# upstream) strips private addresses from public answers. Proves, with real DNS
# queries to the router from the LAN client:
#   - a fresh install has it ON (seeded), a store that predates the setting
#     keeps it OFF through `patronus apply` (a split-horizon setup must not break),
#   - on: a name that points into the LAN gets no answer, a mixed answer loses
#     only its private record, public names are untouched,
#   - an exception domain (private-domain) may resolve to private addresses,
#   - off: the private record comes back; the state survives a reboot.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-s-rebind.db
UP=198.51.100.54
# a killed daemon stays a zombie where no init reaps it: judge liveness by state, not by name
unbound_alive() { ps -eo stat=,comm= | awk '$2=="unbound" && $1 !~ /^Z/ {f=1} END{exit !f}'; }
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
pkill -x unbound 2>/dev/null || true

# a test upstream that answers with private addresses for public-looking names
cat > "$NL_T/seg-a.py" <<'PY'
import socket, struct, sys
name, server = sys.argv[1], sys.argv[2]
q = struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
for l in name.split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
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
ask() { C python3 "$NL_T/seg-a.py" "$1" 192.168.50.1; }
expect_answer() { # NAME WANT-SUBSTRING
  local got; got=$(ask "$1") || nl_fail "query $1 failed: $got"
  case "$got" in *"$2"*) nl_ok "$1 -> $got" ;; *) nl_fail "$1: got '$got', want '$2'" ;; esac
}
expect_not() { # NAME UNWANTED
  local got; got=$(ask "$1") || nl_fail "query $1 failed"
  case "$got" in *"$2"*) nl_fail "$1: '$got' still contains $2" ;; *) nl_ok "$1 -> $got (no $2)" ;; esac
}

setup_upstream() {
  INET ip addr add $UP/24 dev inet0 2>/dev/null || true
  nl_bg INET dnsmasq --no-daemon --no-resolv --no-hosts --user=root --bind-interfaces \
      --listen-address=$UP --pid-file=/tmp/nl-dnsmasq-up.pid \
      --address=/pub.example.org/198.51.100.77 \
      --address=/rebind.example.org/192.168.77.7 \
      --address=/mixed.example.org/192.168.77.8 --address=/mixed.example.org/198.51.100.99 \
      --address=/lan.corp.example.org/192.168.77.9 \
      --address=/loop.example.org/127.0.0.1
  sleep 1
}
configure() {
  nl_api_ok "dns settings" PUT /dns/settings "{\"mode\":\"resolver\",\"dnssec\":false,\"upstreams\":\"$UP\"}"
  nl_wait 15 unbound_alive || nl_fail "unbound is not running"
  nl_wait 10 ask pub.example.org || nl_fail "the router does not answer DNS"
}

echo "=== fresh install: protection is seeded ON"
nl_boot "$DB"; setup_upstream
[ "$(sqlite3 "$DB" "SELECT value FROM lan_settings WHERE key='dns.rebind_protection'")" = 1 ] || nl_fail "a new install does not have rebind protection on"
nl_web_start "$DB"; nl_login
configure
grep -q 'private-address: 192.168.0.0/16' /etc/unbound/unbound.conf || { cat /etc/unbound/unbound.conf; nl_fail "no private-address in unbound.conf"; }
expect_answer pub.example.org "answers=198.51.100.77"
expect_answer rebind.example.org "answers=none"
expect_answer loop.example.org "answers=none"
expect_answer mixed.example.org "answers=198.51.100.99"
expect_not mixed.example.org 192.168.77.8
nl_ok "on: a public name pointing into the LAN is stripped, a mixed answer keeps only its public record"

echo "=== exception"
nl_api_ok "exception" PUT /dns/settings '{"rebind_exceptions":"corp.example.org"}'
nl_wait 10 grep -q 'private-domain: "corp.example.org."' /etc/unbound/unbound.conf || nl_fail "exception not rendered"
# NB: not `sh -c "C ..."` -- C is a bash function from lib.sh, invisible to a child sh (always rc 127)
excepted_resolves() { ask lan.corp.example.org | grep 192.168.77.9 >/dev/null; }
if ! nl_wait 20 excepted_resolves; then
  echo "--- diagnostics"; ps -eo stat,pid,lstart,args | grep -E "[u]nbound"; grep -nE "private|^server|interface" /etc/unbound/unbound.conf | head -30
  unbound-checkconf /etc/unbound/unbound.conf 2>&1 | tail -3
  echo "answer: $(ask lan.corp.example.org 2>&1 | tail -1) | upstream direct: $(R python3 "$NL_T/seg-a.py" lan.corp.example.org $UP 2>&1 | tail -1)"
  nl_fail "the excepted domain does not resolve to its private address"
fi
nl_ok "private-domain exception: lan.corp.example.org -> 192.168.77.9"
expect_answer rebind.example.org "answers=none"
nl_api_ok "bad exception refused" PUT /dns/settings '{"rebind_exceptions":"corp.example.org"}'
nl_api PUT /dns/settings '{"rebind_exceptions":"evil\"; private-address: 0.0.0.0/0"}'
[ "$NL_CODE" = 400 ] || nl_fail "a hostile exception must be a 400, got $NL_CODE"
nl_ok "hostile exception refused (400)"

echo "=== off"
nl_api_ok "off" PUT /dns/settings '{"rebind_protection":false}'
nl_wait 10 sh -c "! grep -q private-address /etc/unbound/unbound.conf" || nl_fail "private-address still rendered"
nl_wait 15 sh -c "C python3 $NL_T/seg-a.py rebind.example.org 192.168.50.1 | grep 192.168.77.7 >/dev/null" || nl_fail "off: the private record did not come back"
nl_ok "off: rebind.example.org -> 192.168.77.7 again"
nl_api_ok "on again" PUT /dns/settings '{"rebind_protection":true}'
nl_web_stop

echo "=== reboot keeps it on"
pkill -x unbound 2>/dev/null || true; rm -f /run/openrc/started/unbound   # the reboot ended the daemon (and OpenRC's record of it)
nl_boot "$DB"; setup_upstream
nl_wait 15 unbound_alive || nl_fail "unbound not started by the boot apply"
nl_wait 15 ask pub.example.org || nl_fail "no DNS after reboot"
expect_answer rebind.example.org "answers=none"
nl_ok "after reboot: still protected"

echo "=== a store that predates the setting stays OFF through an upgrade"
pkill -x unbound 2>/dev/null || true; rm -f /run/openrc/started/unbound
sqlite3 "$DB" "DELETE FROM lan_settings WHERE key='dns.rebind_protection'"
nl_boot "$DB"; setup_upstream
nl_wait 15 unbound_alive || nl_fail "unbound not started"
nl_wait 15 ask pub.example.org || nl_fail "no DNS"
[ -z "$(sqlite3 "$DB" "SELECT value FROM lan_settings WHERE key='dns.rebind_protection'")" ] || nl_fail "an existing store got the setting re-seeded"
expect_answer rebind.example.org "192.168.77.7"
nl_ok "upgrade: split-horizon answers keep working (setting absent = off)"
pkill -x unbound 2>/dev/null || true
echo "PASS lane-s-dns-rebind"
