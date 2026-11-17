#!/bin/sh
# ap-addr with a real bridge in a network namespace: an unconfirmed trial reverts by itself, a confirmed one stays.
# Needs root with CAP_NET_ADMIN + CAP_SYS_ADMIN (ip netns), ip, setsid. Prints PASS/FAIL lines.
set -u
D=$(cd "$(dirname "$0")/.." && pwd); S=$D/overlay/usr/libexec/patronus/ap-addr
pass=0 fail=0; ok() { echo "PASS: $1"; pass=$((pass + 1)); }; no() { echo "FAIL: $1"; fail=$((fail + 1)); }
ip netns add rtg-addr 2>/dev/null || { echo "SKIP: no network namespaces"; exit 0; }
T=$(mktemp -d); trap 'ip netns del rtg-addr; rm -rf "$T"' EXIT
X() { ip netns exec rtg-addr "$@"; }
X ip link add br-lan type bridge; X ip link set br-lan up; X ip addr add 192.0.2.10/24 dev br-lan; X ip route add default via 192.0.2.1
E="AP_ENV=$T/ap.env AP_ADDR_RUN=$T/run AP_ADDR_TMP=$T"
echo "AP_ADDR=192.0.2.10/24 AP_GW=192.0.2.1 AP_DNS=192.0.2.1" > "$T/ap.env.addr-prev"
echo "AP_ADDR=198.51.100.5/24 AP_GW=198.51.100.1 AP_DNS=198.51.100.1" > "$T/ap.env"
X env $E sh "$S" trial 4 > /dev/null || no "trial start"
sleep 3; a=$(X ip -4 -o addr show dev br-lan); st=$(X env $E sh "$S" status)
case "$a" in *192.0.2.10/24*198.51.100.5/24*) ok "trial: new address next to the old one";; *) no "trial addresses: $a";; esac
case "$st" in *pending=yes*"new=198.51.100.5/24"*) ok "status: pending with the new address";; *) no "status: $st";; esac
sleep 6; a=$(X ip -4 -o addr show dev br-lan); r=$(X ip route show default)
case "$a" in *198.51.100.5*) no "unconfirmed address still there: $a";; *192.0.2.10/24*) ok "unconfirmed: reverted by itself";; *) no "revert: $a";; esac
case "$r" in *"via 192.0.2.1"*) ok "unconfirmed: default route back";; *) no "route: $r";; esac
grep -q '^AP_ADDR=192.0.2.10/24' "$T/ap.env" && [ ! -e "$T/ap.env.addr-prev" ] && [ ! -e "$T/ap.env.addr-pending" ] && ok "unconfirmed: previous file back, no trial left" || no "files: $(ls "$T")"
# confirmed
cp "$T/ap.env" "$T/ap.env.addr-prev"; echo "AP_ADDR=192.0.2.20/24 AP_GW=192.0.2.1 AP_DNS=192.0.2.53" > "$T/ap.env"
X env $E sh "$S" trial 30 > /dev/null; sleep 3
X env $E sh "$S" confirm > /dev/null && ok "confirm accepted" || no "confirm"
a=$(X ip -4 -o addr show dev br-lan)
case "$a" in *192.0.2.10/*) no "old address kept after confirm: $a";; *192.0.2.20/24*) ok "confirmed: new address only";; *) no "confirmed: $a";; esac
grep -q 'nameserver 192.0.2.53' "$T/resolv.conf.auto" && ok "confirmed: DNS servers written" || no "resolv: $(cat "$T/resolv.conf.auto" 2>/dev/null)"
X env $E sh "$S" confirm > /dev/null 2>&1 && no "second confirm accepted" || ok "nothing pending: confirm refused"
echo "address trial: $pass passed, $fail failed"; [ $fail -eq 0 ]
