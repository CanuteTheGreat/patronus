#!/usr/bin/env bash
# Lane J: TFTP server (USE=tftp). Real TFTP clients (curl's tftp:// and tftp-hpa)
# on the LAN fetch and upload files through the shipped `patronus tftp run`
# daemon, started by the boot apply / the web API; a device on a second segment
# (OPT1, namespace nl-iot) must NOT be served.
#   - nothing listens before the feature is switched on; validation refuses a
#     system directory as root, bad ports, too few data ports, IPv6 networks (400)
#   - enabled: the daemon runs as an unprivileged account with only the
#     net-bind and raw-socket capabilities, listens on the LAN address only, and
#     the firewall opens the request port + data range on the LAN only
#   - files uploaded through the web API are served byte for byte (curl and
#     tftp-hpa), with and without RFC 2348 block-size negotiation; a missing file
#     is "not found"
#   - the root directory is a jail: ../, absolute names, hidden names, a planted
#     symlink and a directory symlink all fail, nothing outside is ever read
#   - read only by default: an upload is refused and nothing is created
#   - uploads on: a new file is stored, an existing one is refused until
#     "replace" is on, an upload over the size cap is aborted and leaves no
#     partial file
#   - client networks restrict who is served (and the firewall rule follows)
#   - counters/status, the page, `patronus tftp show`, a reboot apply, and
#     disabling (daemon gone, rule gone)
set -euo pipefail
. "$(dirname "$0")/lib.sh"

export PATH="$NL_T:$PATH"   # the daemon is `patronus tftp run`
DB=/t/lane-j-tftp.db
ROOT=/var/lib/patronus/tftp
rm -f "$DB" "$NL_T/nl-jar"
rm -rf "$ROOT"
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
  ip -n nl-iot route add default via $IOT_RTR
}

# a raw protocol client for the cases a normal client cannot send (odd names,
# a wrong transfer ID): nl-tftp.py get HOST PORT NAME | put HOST PORT NAME | stranger
cat > "$NL_T/nl-tftp.py" <<'PY'
import socket, sys
cmd, host, port, name = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
op = b"\x00\x01" if cmd == "get" else b"\x00\x02"
s.sendto(op + name.encode() + b"\x00octet\x00", (host, port))
try:
    d, a = s.recvfrom(2048)
except socket.timeout:
    print("TIMEOUT"); sys.exit(3)
if d[:2] == b"\x00\x05":
    print("ERROR", int.from_bytes(d[2:4], "big"), d[4:-1].decode(errors="replace")); sys.exit(2)
if d[:2] == b"\x00\x03":
    # a data block arrived: report how much (file served) and acknowledge so the server finishes
    print("DATA", len(d) - 4)
    s.sendto(b"\x00\x04" + d[2:4], a)
    sys.exit(0)
if d[:2] == b"\x00\x04":
    print("ACK"); sys.exit(0)
print("OTHER", d[:4].hex()); sys.exit(4)
PY

# fetch/upload helpers (the real clients); output is the client's own exit status
tget() { # NAME OUT [curl options...]  (from the LAN client)
  local n=$1 o=$2; shift 2
  C curl -s -m 20 "$@" -o "$o" "tftp://$NL_RTR_LAN/$n"
}
tput() { # LOCAL REMOTE
  C curl -s -m 20 -T "$1" "tftp://$NL_RTR_LAN/$2"
}
upload_api() { # NAME FILE [replace]: the body goes through a file (a 1 MB argument is too long for curl's command line)
  { printf '{"name":"%s","overwrite":%s,"data":"' "$1" "${3:-false}"; base64 -w0 "$2"; printf '"}'; } > "$NL_T/up.json"
  NL_CODE=$(C curl -sk -m 60 -b "$NL_T/nl-jar" -c "$NL_T/nl-jar" -o "$NL_OUT" -w '%{http_code}' -X POST \
    -H 'content-type: application/json' --data-binary @"$NL_T/up.json" "$NL_UI/api/svc/tftp/action/upload")
}
listening_lan() { local o; o=$(R ss -ulnH 'sport = :69'); grep -F "$NL_RTR_LAN" >/dev/null <<<"$o"; }
daemon_pid() { pgrep -f '[p]atronus tftp run' | head -1; }
status_field() { nl_api GET /svc/tftp; nl_json "$NL_OUT" "$1"; }

head -c 700000 /dev/urandom > "$NL_T/tftp-big.bin"
head -c 1500 /dev/urandom > "$NL_T/tftp-small.bin"
: > "$NL_T/tftp-empty.bin"
head -c 1024 /dev/urandom > "$NL_T/tftp-exact.bin"
sha() { sha256sum "$1" | cut -d' ' -f1; }

nl_up; iot_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_web_start "$DB"; nl_login
nl_api_ok "OPT1 on the IoT port" PUT /interfaces/rtr-iot "{\"role\":\"opt1\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$IOT_RTR/24\"]}"

diag() {
  set +e
  echo "--- diag: daemon"; ps -eo pid,user,stat,args | grep '[t]ftp run'
  echo "--- diag: sockets in the router namespace"; R ss -ulpn
  echo "--- diag: stats"; cat /run/patronus/tftp.stats /var/lib/patronus/net/run/tftp.stats 2>/dev/null
  echo "--- diag: root"; ls -la "$ROOT"
  echo "--- diag: log"; tail -15 /var/log/patronus-daemon.tftp.log /var/lib/patronus/net/log/*tftp* 2>/dev/null
  echo "--- diag: nft"; R nft list chain inet patronus input 2>/dev/null | grep -i tftp
}
trap 'rc=$?; [ $rc = 0 ] || diag' EXIT

echo "=== before the feature is on: nothing listens"
[ -z "$(R ss -ulnH 'sport = :69')" ] || nl_fail "something already listens on UDP 69"
if tget nothing.bin "$NL_T/x.out" -m 5; then nl_fail "a TFTP fetch worked with the feature off"; fi
nl_ok "feature off: no listener, a fetch fails"

echo "=== validation"
nl_api_code "root = a system directory" 400 PUT /svc/tftp '{"root":"/etc"}'
nl_api_code "root with .." 400 PUT /svc/tftp '{"root":"/srv/../etc"}'
nl_api_code "root = the state directory" 400 PUT /svc/tftp '{"root":"/var/lib/patronus"}'
nl_api_code "port 0" 400 PUT /svc/tftp '{"port":0}'
nl_api_code "block size under the minimum" 400 PUT /svc/tftp '{"blksize_max":100}'
nl_api_code "bad interface" 400 PUT /svc/tftp '{"interfaces":"lan;x"}'
nl_api_code "unknown setting" 400 PUT /svc/tftp '{"nope":1}'
nl_api_code "IPv6 client network" 400 POST /svc/tftp/clients '{"cidr":"fd00::/64"}'
nl_api_code "bad client network" 400 POST /svc/tftp/clients '{"cidr":"10.0.0.0/33"}'
nl_api_code "upload name that climbs" 400 POST /svc/tftp/action/upload '{"name":"../x","data":"AA=="}'
nl_api_code "upload that is not base64" 400 POST /svc/tftp/action/upload '{"name":"x","data":"!!"}'
nl_api_code "too few data ports for the sessions" 400 PUT /svc/tftp '{"enabled":true,"max_sessions":64,"data_ports":"50000-50009"}'
[ -z "$(daemon_pid)" ] || nl_fail "the server started although the change was refused"
nl_api_ok "restore sane values" PUT /svc/tftp '{"max_sessions":16,"data_ports":"49152-49407"}'
nl_api_ok "disable again (refused enable left nothing behind)" PUT /svc/tftp '{"enabled":false}'
nl_ok "system directories, bad values and too few data ports are refused (400), nothing started"

echo "=== enable (read only, serving @lan)"
nl_api_ok "enable" PUT /svc/tftp '{"enabled":true,"interfaces":"@lan"}'
nl_wait 10 daemon_pid || { tail -20 "$NL_T/nl-web.log"; nl_fail "the TFTP daemon did not start"; }
nl_wait 10 listening_lan || nl_fail "nothing listens on $NL_RTR_LAN:69"
PID=$(daemon_pid)
uid=$(awk '/^Uid:/{print $2}' /proc/$PID/status)
nobody=$(id -u nobody)
[ "$uid" = "$nobody" ] || nl_fail "the daemon runs as uid $uid, want nobody ($nobody)"
capeff=$(awk '/^CapEff:/{print $2}' /proc/$PID/status)
[ "$capeff" = 0000000000002400 ] || nl_fail "CapEff is $capeff, want only net-bind + net-raw (0x2400)"
nnp=$(awk '/^NoNewPrivs:/{print $2}' /proc/$PID/status)
[ "$nnp" = 1 ] || nl_fail "NoNewPrivs is $nnp"
nl_ok "daemon runs as nobody with CapEff 0x2400 (net-bind + net-raw) and no new privileges"
sockets=$(R ss -ulnH 'sport = :69')
grep -q "$IOT_RTR" <<<"$sockets" && nl_fail "also listens on the IoT address: $sockets"
grep -q "$NL_RTR_WAN" <<<"$sockets" && nl_fail "also listens on the WAN address: $sockets"
nl_ok "listens on the LAN address only"
nl_assert_nft_has 'iifname "rtr-lan" udp dport { 69, 49152-49407 } accept comment "TFTP"'
nl_assert_nft_lacks 'iifname "rtr-wan" udp dport { 69' 'iifname "rtr-iot" udp dport { 69'
python3 - /var/lib/patronus/net/tftp.json <<'PY' || nl_fail "generated server config is wrong"
import json, sys
c = json.load(open(sys.argv[1]))
assert c["port"] == 69 and c["root"] == "/var/lib/patronus/tftp", c
assert c["listen"] == ["rtr-lan"] and not c["allow_write"] and not c["overwrite"], c
assert c["data_ports"] == [[49152, 49407]] and c["clients"] == [] and c["run_as"] == "nobody", c
PY
nl_ok "firewall opens 69 + the data range on the LAN only; generated config matches the settings"

echo "=== files through the web API are served"
upload_api boot.bin "$NL_T/tftp-small.bin"; [ "$NL_CODE" = 200 ] || nl_fail "upload boot.bin: $NL_CODE $(cat "$NL_OUT")"
upload_api big.bin "$NL_T/tftp-big.bin"; [ "$NL_CODE" = 200 ] || nl_fail "upload big.bin (700 kB): $NL_CODE $(cat "$NL_OUT")"
head -c 1300000 /dev/zero > "$NL_T/tftp-huge.bin"
upload_api huge.bin "$NL_T/tftp-huge.bin"; [ "$NL_CODE" = 400 ] || nl_fail "an upload over the page limit (1 MiB) must be refused, got $NL_CODE"
[ ! -e "$ROOT/huge.bin" ] || nl_fail "oversized upload through the page was stored"
upload_api boot.bin "$NL_T/tftp-small.bin"; [ "$NL_CODE" = 400 ] || nl_fail "a second upload of boot.bin without replace must be refused, got $NL_CODE"
upload_api boot.bin "$NL_T/tftp-small.bin" true; [ "$NL_CODE" = 200 ] || nl_fail "upload with replace: $NL_CODE"
# files an admin copies in (scp) appear too, including an empty one and an exact block multiple
install -m 0644 "$NL_T/tftp-empty.bin" "$ROOT/empty.bin"
install -m 0644 "$NL_T/tftp-exact.bin" "$ROOT/exact.bin"
mkdir -p "$ROOT/sub" && install -m 0644 "$NL_T/tftp-small.bin" "$ROOT/sub/deep.bin"
nl_api POST /svc/tftp/action/files '{}'
python3 - "$NL_OUT" <<'PY' || nl_fail "file list is wrong"
import json, sys
f = {x["name"]: x["size"] for x in json.load(open(sys.argv[1]))["files"]}
assert f.get("boot.bin") == 1500 and f.get("big.bin") == 700000 and f.get("sub/deep.bin") == 1500 and f.get("empty.bin") == 0, f
PY
nl_ok "files uploaded through the API and placed in the root are listed with their sizes"

for pair in "boot.bin:tftp-small.bin" "big.bin:tftp-big.bin" "exact.bin:tftp-exact.bin" "sub/deep.bin:tftp-small.bin"; do
  n=${pair%%:*}; f=${pair##*:}
  rm -f "$NL_T/got.out"
  tget "$n" "$NL_T/got.out" || nl_fail "curl tftp get $n failed"
  [ "$(sha "$NL_T/got.out")" = "$(sha "$NL_T/$f")" ] || nl_fail "curl: $n differs from what was stored"
done
nl_ok "curl fetches 1500 B, 700 kB (1366 blocks), an exact multiple of 512 and a file in a sub directory byte for byte"
out=$(C python3 "$NL_T/nl-tftp.py" get $NL_RTR_LAN 69 empty.bin 2>&1 || true)   # curl writes no file for an empty body
[ "$out" = "DATA 0" ] || nl_fail "an empty file should arrive as one empty block, got: $out"
rm -f "$NL_T/got.out"; tget big.bin "$NL_T/got.out" --tftp-blksize 1400 || nl_fail "get with blksize 1400 failed"
[ "$(sha "$NL_T/got.out")" = "$(sha "$NL_T/tftp-big.bin")" ] || nl_fail "blksize 1400: content differs"
rm -f "$NL_T/got.out"; tget big.bin "$NL_T/got.out" --tftp-blksize 8192 || nl_fail "get with a block size above the ceiling failed"
[ "$(sha "$NL_T/got.out")" = "$(sha "$NL_T/tftp-big.bin")" ] || nl_fail "blksize 8192 (clamped to 1468): content differs"
rm -f "$NL_T/got.out"; tget big.bin "$NL_T/got.out" --tftp-no-options || nl_fail "get without options failed"
[ "$(sha "$NL_T/got.out")" = "$(sha "$NL_T/tftp-big.bin")" ] || nl_fail "plain 512-byte transfer: content differs"
nl_ok "block size negotiation (1400, a request above the ceiling, and none) all deliver the same bytes"
if C tftp "$NL_RTR_LAN" -m binary -c get boot.bin "$NL_T/hpa.out" >/dev/null 2>&1; then
  [ "$(sha "$NL_T/hpa.out")" = "$(sha "$NL_T/tftp-small.bin")" ] || nl_fail "tftp-hpa: boot.bin differs"
  nl_ok "an independent client (tftp-hpa) fetches boot.bin"
else
  nl_fail "tftp-hpa could not fetch boot.bin"
fi
# the router tier's own client (the embedded QEMU gate fetches with it): busybox tftp, with and without a block size
rm -f "$NL_T/bb.out"; C busybox tftp -g -r boot.bin -l "$NL_T/bb.out" "$NL_RTR_LAN" >/dev/null 2>&1 || nl_fail "busybox tftp could not fetch boot.bin"
[ "$(sha "$NL_T/bb.out")" = "$(sha "$NL_T/tftp-small.bin")" ] || nl_fail "busybox tftp: boot.bin differs"
rm -f "$NL_T/bb.out"; C busybox tftp -g -b 1400 -r big.bin -l "$NL_T/bb.out" "$NL_RTR_LAN" >/dev/null 2>&1 || nl_fail "busybox tftp -b 1400 could not fetch big.bin"
[ "$(sha "$NL_T/bb.out")" = "$(sha "$NL_T/tftp-big.bin")" ] || nl_fail "busybox tftp -b 1400: big.bin differs"
nl_ok "busybox tftp (the router tier's client) fetches a small and a 700 kB file, with and without a block size"
rc=0; tget nosuch.bin "$NL_T/x.out" || rc=$?
[ "$rc" = 68 ] || nl_fail "a missing file should be 'not found' (curl 68), got $rc"
nl_ok "a missing file is reported as not found"

echo "=== the root is a jail"
echo "TOP-SECRET-OUTSIDE" > /t/tftp-outside.txt
ln -sf /t/tftp-outside.txt "$ROOT/link.txt"
ln -sfn /t "$ROOT/dirlink"
ln -sf /etc/passwd "$ROOT/abs.txt"
echo hidden > "$ROOT/.hidden"
for name in "../t/tftp-outside.txt" "../../../../etc/passwd" "sub/../../../etc/passwd" "/etc/passwd" "link.txt" "dirlink/tftp-outside.txt" "abs.txt" ".hidden" "sub" "a\\..\\..\\etc\\passwd"; do
  out=$(C python3 "$NL_T/nl-tftp.py" get $NL_RTR_LAN 69 "$name" 2>&1 || true)
  case "$out" in
    ERROR\ 1*|ERROR\ 2*) ;;
    *) nl_fail "name '$name' was not refused: $out";;
  esac
done
rm -f "$NL_T/got.out"; C tftp "$NL_RTR_LAN" -m binary -c get ../../../etc/passwd "$NL_T/got.out" >/dev/null 2>&1 || true
[ ! -s "$NL_T/got.out" ] || nl_fail "tftp-hpa read /etc/passwd through ../"
grep -q TOP-SECRET "$NL_T/got.out" 2>/dev/null && nl_fail "read a file outside the root"
nl_ok "../ names, absolute names, hidden names, a file symlink, a directory symlink, a link to /etc/passwd and a directory all refused"
out=$(C python3 "$NL_T/nl-tftp.py" get $NL_RTR_LAN 69 boot.bin); case "$out" in DATA*) ;; *) nl_fail "regular files still served: $out";; esac

echo "=== read only by default"
rc=0; tput "$NL_T/tftp-small.bin" ro-upload.bin || rc=$?
[ "$rc" = 69 ] || nl_fail "an upload with writes off should be refused with 'access violation' (curl 69), curl said $rc"
[ ! -e "$ROOT/ro-upload.bin" ] || nl_fail "an upload was stored although writes are off"
nl_ok "uploads are refused and nothing is created"

echo "=== a device on another segment is not served"
out=$(ip netns exec nl-iot python3 "$NL_T/nl-tftp.py" get $IOT_RTR 69 boot.bin 2>&1 || true)
[ "$out" = TIMEOUT ] || [ "$out" = "TIMEOUT" ] || nl_fail "OPT1 got an answer: $out"
nl_ok "OPT1: no answer on the request port (no listener, no firewall hole)"

echo "=== uploads on"
nl_api_ok "allow uploads, cap 64 KiB" PUT /svc/tftp '{"allow_write":true,"max_write_kb":64}'
nl_wait 10 sh -c "grep -q '\"allow_write\": true' /var/lib/patronus/net/tftp.json" || nl_fail "config not rewritten"
nl_wait 10 daemon_pid || nl_fail "daemon not running after the change"
sleep 1
tput "$NL_T/tftp-small.bin" up1.bin || nl_fail "upload failed with writes on"
[ "$(sha "$ROOT/up1.bin")" = "$(sha "$NL_T/tftp-small.bin")" ] || nl_fail "stored file differs"
[ "$(stat -c %a "$ROOT/up1.bin")" = 644 ] || nl_fail "stored mode $(stat -c %a "$ROOT/up1.bin")"
nl_ok "an upload is stored byte for byte (mode 0644)"
rc=0; tput "$NL_T/tftp-exact.bin" up1.bin || rc=$?
[ "$rc" = 73 ] || nl_fail "an existing file must be refused with 'file exists' (curl 73), curl said $rc"
[ "$(sha "$ROOT/up1.bin")" = "$(sha "$NL_T/tftp-small.bin")" ] || nl_fail "existing file changed"
nl_ok "an existing file is not replaced"
nl_api_ok "overwrite on" PUT /svc/tftp '{"overwrite":true}'
nl_wait 10 sh -c "grep -q '\"overwrite\": true' /var/lib/patronus/net/tftp.json"; nl_wait 10 daemon_pid; sleep 1
tput "$NL_T/tftp-exact.bin" up1.bin || nl_fail "overwrite upload failed"
[ "$(sha "$ROOT/up1.bin")" = "$(sha "$NL_T/tftp-exact.bin")" ] || nl_fail "overwrite did not replace the file"
nl_ok "with overwrite on the file is replaced"
rc=0; tput "$NL_T/tftp-big.bin" toobig.bin || rc=$?
[ "$rc" != 0 ] || nl_fail "an upload over the cap was accepted"
sleep 1
[ ! -e "$ROOT/toobig.bin" ] || nl_fail "oversized upload left toobig.bin"
left=$(ls -a "$ROOT"); if grep '\.part$' >/dev/null <<<"$left"; then nl_fail "partial file left behind: $left"; fi
nl_ok "an upload over max_write_kb is aborted and leaves no partial file"
for name in "../esc.bin" ".dot.bin" "nodir/x.bin" "link.txt"; do
  out=$(C python3 "$NL_T/nl-tftp.py" put $NL_RTR_LAN 69 "$name" 2>&1 || true)
  case "$out" in ERROR*) ;; *) nl_fail "write to '$name' was not refused: $out";; esac
done
[ ! -e /t/esc.bin ] && [ ! -e "$ROOT/../esc.bin" ] || nl_fail "an upload escaped the root"
[ "$(cat /t/tftp-outside.txt)" = TOP-SECRET-OUTSIDE ] || nl_fail "an upload followed a symlink out of the root"
nl_ok "writes to ../, hidden, missing-directory and symlink names are refused; the file behind the symlink is untouched"
nl_api_ok "uploads off again" PUT /svc/tftp '{"allow_write":false,"overwrite":false}'

echo "=== client networks"
nl_api_ok "allow only a host that is not the client" POST /svc/tftp/clients '{"cidr":"10.99.0.5/32","description":"someone else"}'
tftp_rule() { R nft list ruleset | grep 'comment "TFTP"'; }
r=$(tftp_rule); grep -q 'ip saddr 10.99.0.5' <<<"$r" && grep -q 'iifname "rtr-lan"' <<<"$r" || nl_fail "rule not limited to the client network: $r"
nl_wait 10 sh -c "grep -q 10.99.0.5 /var/lib/patronus/net/tftp.json"; nl_wait 10 daemon_pid; sleep 1
rc=0; tget boot.bin "$NL_T/x.out" || rc=$?
[ "$rc" = 69 ] || nl_fail "a client outside the allowed networks must get 'access violation' (curl 69), curl said $rc"
sleep 3
[ "$(status_field "d['status']['stats']['denied_client']")" -ge 1 ] || nl_fail "denied_client counter did not move"
nl_ok "a client outside the allowed networks is refused (and the firewall rule is limited to them)"
nl_api_ok "allow the LAN network" POST /svc/tftp/clients '{"cidr":"192.168.50.0/24"}'
r=$(tftp_rule); grep -q '10.99.0.5' <<<"$r" && grep -q '192.168.50.0/24' <<<"$r" || nl_fail "rule lacks the second client network: $r"
nl_wait 10 sh -c "grep -q 192.168.50.0/24 /var/lib/patronus/net/tftp.json"; nl_wait 10 daemon_pid; sleep 1
rm -f "$NL_T/got.out"; tget boot.bin "$NL_T/got.out" || nl_fail "an allowed client was refused"
[ "$(sha "$NL_T/got.out")" = "$(sha "$NL_T/tftp-small.bin")" ] || nl_fail "content differs"
nl_ok "a client inside an allowed network is served"
nl_api GET /svc/tftp
for id in $(nl_json "$NL_OUT" "' '.join(str(r['id']) for r in d['collections']['clients'])"); do nl_api_ok "remove client network $id" DELETE /svc/tftp/clients/$id; done
r=$(tftp_rule); grep -q "ip saddr" <<<"$r" && nl_fail "client networks removed but the rule is still limited: $r"

echo "=== status, counters, page, CLI"
nl_wait 10 daemon_pid; sleep 1
tget boot.bin "$NL_T/got.out" || nl_fail "fetch before the counter check"
tget big.bin "$NL_T/got.out" || nl_fail "big fetch before the counter check"
tget nosuch.bin "$NL_T/got.out" || true
tput "$NL_T/tftp-small.bin" ro2.bin || true
sleep 3
nl_api GET /svc/tftp
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the running server"
import json, sys
d = json.load(open(sys.argv[1]))
st = d["status"]
assert st["enabled"] and st["installed"] and st["running"] and st["mode"] == "read only", st
assert d["settings"]["port"] == 69 and d["settings"]["root"] == "/var/lib/patronus/tftp", d["settings"]
PY
nl_wait 8 sh -c 'f=$(ls /run/patronus/tftp.stats /var/lib/patronus/net/run/tftp.stats 2>/dev/null | head -1); [ -n "$f" ] && grep -q reads_ok "$f"'
nl_api GET /svc/tftp
python3 - "$NL_OUT" <<'PY' || { cat "$NL_OUT"; nl_fail "counters are wrong"; }
import json, sys
s = json.load(open(sys.argv[1]))["status"]["stats"]
assert s["reads_ok"] >= 2 and s["bytes_sent"] >= 700_000 + 1_500, s
assert s["denied_write"] >= 1 and s["failed"] >= 2 and s["active"] == 0, s
assert any(r["file"] == "boot.bin" and r["direction"] == "read" and r["result"] == "ok" for r in s["recent"]), s["recent"]
assert any("192.168.50.1" in l for l in s["listening"]), s
PY
nl_ok "status + counters: reads, failures, denied writes and the recent transfers are reported"
nl_web GET /svc/tftp
[ "$NL_CODE" = 200 ] && grep -F 'svc-settings-form' "$NL_OUT" >/dev/null && grep -F 'tftpFiles' "$NL_OUT" >/dev/null || nl_fail "TFTP page: $NL_CODE"
out=$(R "$P" --db "$DB" tftp show); grep -q '"root": "/var/lib/patronus/tftp"' <<<"$out" && grep -q '"port": 69' <<<"$out" || nl_fail "patronus tftp show: $out"
nl_ok "the page and 'patronus tftp show' reflect the stored settings"
nl_api POST /svc/tftp/action/delete '{"name":"up1.bin"}'; [ "$NL_CODE" = 200 ] && [ ! -e "$ROOT/up1.bin" ] || nl_fail "delete through the API: $NL_CODE"
nl_api_code "delete refuses a symlink" 400 POST /svc/tftp/action/delete '{"name":"link.txt"}'
[ "$(cat /t/tftp-outside.txt)" = TOP-SECRET-OUTSIDE ] || nl_fail "delete followed a symlink"
nl_ok "file delete works through the API and never follows a link"

echo "=== reboot: patronus apply brings it back"
nl_web_stop
nl_kill_daemons
pkill -f '[t]ftp run' || true
nl_wait 10 sh -c '! pgrep -f "[t]ftp run"' || nl_fail "daemon survived the simulated reboot"
nl_up; iot_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_wait 10 daemon_pid || nl_fail "the boot apply did not start the TFTP daemon"
nl_wait 10 listening_lan || nl_fail "no listener after reboot"
rm -f "$NL_T/got.out"; tget boot.bin "$NL_T/got.out" || nl_fail "fetch after reboot failed"
[ "$(sha "$NL_T/got.out")" = "$(sha "$NL_T/tftp-small.bin")" ] || nl_fail "content differs after reboot"
nl_assert_nft_has 'iifname "rtr-lan" udp dport { 69, 49152-49407 } accept comment "TFTP"'
nl_ok "after a reboot: daemon, rule and files are back"

echo "=== disable: daemon and rule are gone"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/tftp '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -f "[t]ftp run"' || nl_fail "daemon still running"
nl_assert_nft_lacks 'comment "TFTP"'
[ -z "$(R ss -ulnH 'sport = :69')" ] || nl_fail "port 69 still open"
if tget boot.bin "$NL_T/x.out" -m 5; then nl_fail "served after disabling"; fi
[ "$(sha "$ROOT/boot.bin")" = "$(sha "$NL_T/tftp-small.bin")" ] || nl_fail "files were touched by disabling"
nl_ok "disabled: daemon stopped, firewall rule removed, files kept"
nl_web_stop
rm -f "$NL_T/tftp-"*.bin /t/tftp-outside.txt
ip netns del nl-iot 2>/dev/null || true
echo "ALL TFTP CHECKS PASSED"
