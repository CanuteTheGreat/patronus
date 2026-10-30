#!/bin/bash
# Spike for design (c): per-device DNS policy on stock unbound (views keyed by client address),
# rebinding protection (private-address / private-domain) and per-client query logs.
# Hand-written config in the shape the applier would render (generator not part of this spike).
# Run inside a debian:trixie container: apt install unbound bind9-dnsutils
set -u
W=/w; mkdir -p $W; pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }; bad(){ echo "  FAIL  $*"; fail=$((fail+1)); }
ip addr add 127.0.0.2/8 dev lo 2>/dev/null; ip addr add 127.0.0.3/8 dev lo 2>/dev/null
# stand-in "internet": an authoritative-only unbound
cat > $W/stub.conf <<EOF
server:
    interface: 127.0.0.1@5301
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    pidfile: "$W/stub.pid"
    local-zone: "example." static
    local-data: "public.example. 60 IN A 93.184.216.34"
    local-data: "games.example. 60 IN A 198.51.100.7"
    local-data: "evil.rebind.example. 60 IN A 192.168.1.10"
    local-data: "mixed.rebind.example. 60 IN A 192.168.1.10"
    local-data: "mixed.rebind.example. 60 IN A 93.184.216.35"
    local-data: "nas.home.example. 60 IN A 192.168.1.5"
EOF
# what the Patronus DNS applier would render for 'kid' (127.0.0.2) and a default device (127.0.0.3)
cat > $W/main.conf <<EOF
server:
    interface: 127.0.0.1@5300
    access-control: 127.0.0.0/8 allow
    access-control-view: 127.0.0.2/32 view_kid
    username: ""
    chroot: ""
    pidfile: "$W/main.pid"
    do-not-query-localhost: no
    # rebinding protection: public names must not resolve to private space
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    private-domain: "home.example."
    logfile: "$W/unbound.log"
    use-syslog: no
    log-queries: yes
    log-replies: yes
    log-tag-queryreply: yes
    verbosity: 1
view:
    name: "view_kid"
    view-first: yes
    local-zone: "games.example." always_nxdomain
forward-zone:
    name: "."
    forward-addr: 127.0.0.1@5301
EOF
unbound-checkconf $W/stub.conf >/dev/null && unbound-checkconf $W/main.conf && ok "unbound-checkconf accepts the views/private-address config" || bad "checkconf failed"
unbound -c $W/stub.conf; unbound -c $W/main.conf; sleep 2
q() { dig +time=3 +tries=1 -b $1 @127.0.0.1 -p 5300 $2 A 2>&1; }
st() { q "$1" "$2" | sed -n 's/.*status: \([A-Z]*\).*/\1/p'; }
an() { q "$1" "$2" | awk '/^;; ANSWER SECTION/{f=1;next} /^$/{f=0} f{print $5}' | sort | tr '\n' ' '; }
echo "== per-device policy (same name, two source addresses)"
[ "$(st 127.0.0.3 games.example)" = NOERROR ] && [ "$(an 127.0.0.3 games.example)" = "198.51.100.7 " ] && ok "default device resolves games.example -> $(an 127.0.0.3 games.example)" || bad "default device games.example: $(st 127.0.0.3 games.example) $(an 127.0.0.3 games.example)"
[ "$(st 127.0.0.2 games.example)" = NXDOMAIN ] && ok "'kid' device: games.example -> NXDOMAIN (view_kid block)" || bad "kid device games.example: $(st 127.0.0.2 games.example)"
[ "$(an 127.0.0.2 public.example)" = "93.184.216.34 " ] && ok "'kid' device: other names still resolve (view-first falls back to global policy)" || bad "kid public.example: $(an 127.0.0.2 public.example)"
echo "== rebinding protection"
echo "   evil.rebind.example (-> 192.168.1.10):  status=$(st 127.0.0.3 evil.rebind.example) answer=[$(an 127.0.0.3 evil.rebind.example)]"
[ -z "$(an 127.0.0.3 evil.rebind.example)" ] && ok "private address stripped from a public name's answer" || bad "private answer leaked"
echo "   mixed.rebind.example (private + public):   answer=[$(an 127.0.0.3 mixed.rebind.example)]"
[ "$(an 127.0.0.3 mixed.rebind.example)" = "93.184.216.35 " ] && ok "only the private record of a mixed answer is removed" || bad "mixed answer: $(an 127.0.0.3 mixed.rebind.example)"
[ "$(an 127.0.0.3 nas.home.example)" = "192.168.1.5 " ] && ok "private-domain home.example may resolve to private addresses (LAN names keep working)" || bad "nas.home.example: $(an 127.0.0.3 nas.home.example)"
echo "== per-device query log"
sleep 1
grep -E "query: 127.0.0.2 games.example" $W/unbound.log | head -2 | sed 's/^/   /'
grep -qE "query: 127.0.0.2 games.example" $W/unbound.log && grep -qE "query: 127.0.0.3 games.example" $W/unbound.log && ok "log lines carry the client address, so rows map to device names via the lease/enrolment table" || bad "log has no per-client rows"
grep -E "reply: 127.0.0.2 games.example" $W/unbound.log | head -1 | sed 's/^/   /'
unbound-control -c $W/main.conf status >/dev/null 2>&1 || true
echo; echo "RESULT: $pass passed, $fail failed"; [ $fail -eq 0 ]
