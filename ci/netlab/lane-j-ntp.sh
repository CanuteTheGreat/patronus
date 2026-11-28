#!/usr/bin/env bash
# Lane J: NTP server access list + GPS reference clock (docs/NTP-GPS-ACL.md, claim C1304).
#   1. a LAN client is answered by the real chronyd the product configured;
#   2. an address on the deny list gets NO answer while its neighbours do; explicit-only mode answers just the
#      listed hosts and blocks; the settings survive a reboot;
#   3. bad ACL entries, devices, baud rates, offsets are refused (400) and nothing is stored;
#   4. a fake GPS receiver (NMEA on a pty) feeds a real gpsd, chrony reads it as the GPS source, the page and the
#      API show it; a missing PPS device falls back to NMEA instead of stopping chronyd; switching the GPS off
#      removes the refclock and stops gpsd.
# The container has no init system: an OpenRC look-alike (rc-service / rc-update) starts chronyd and gpsd inside the
# router's namespace, the way OpenRC would on the product.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-ntp.db
rm -f "$DB" "$NL_T/nl-jar"
command -v chronyd >/dev/null && command -v gpsd >/dev/null || nl_fail "chrony and gpsd are not installed (ci/netlab/run.sh installs them)"

mkdir -p /run/openrc /etc/init.d /etc/chrony /var/lib/chrony /run/chrony /etc/conf.d
for s in chronyd gpsd; do printf '#!/bin/sh\n' > /etc/init.d/$s; chmod +x /etc/init.d/$s; done
cat > /usr/local/sbin/rc-service <<'EOF2'
#!/bin/bash
# OpenRC look-alike for the netlab container (no init system); started from inside the router namespace
svc=$1; act=$2
case "$svc" in chronyd) comm=chronyd ;; gpsd) comm=gpsd ;; *) exit 1 ;; esac
up() { pgrep -x "$comm" >/dev/null; }
start() {
  up && return 0
  case "$svc" in
    chronyd) mkdir -p /run/chrony /var/lib/chrony; chronyd -x -u root -f /etc/chrony/chrony.conf ;;
    gpsd) . /etc/conf.d/gpsd; rm -f /run/gpsd-nl.pid; gpsd -P /run/gpsd-nl.pid $GPSD_OPTIONS $DEVICES ;;
  esac >/tmp/svc-$svc.log 2>&1
  sleep 1
  up || { cat /tmp/svc-$svc.log >&2; return 1; }
}
stop() { pkill -x "$comm" 2>/dev/null || true; for _ in $(seq 1 20); do up || break; sleep 0.2; done; }
case "$act" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) if up; then echo " * status: started"; else echo " * status: stopped"; exit 3; fi ;;
esac
EOF2
cat > /usr/local/sbin/rc-update <<'EOF2'
#!/bin/sh
# add/del keep a list; show prints "<service> | default"
F=/tmp/nl-rc-update
case "$1" in
  add) grep -qx "$2" $F 2>/dev/null || echo "$2" >> $F ;;
  del) if [ -f $F ]; then grep -vx "$2" $F > $F.n || true; mv $F.n $F; fi ;;
  show) if [ -f $F ]; then while read -r s; do echo "$s | default"; done < $F; fi ;;
esac
exit 0
EOF2
chmod +x /usr/local/sbin/rc-service /usr/local/sbin/rc-update
rm -f /etc/chrony/chrony.conf /etc/conf.d/gpsd /tmp/nl-rc-update /dev/ttyUSB9 /dev/pps0

cleanup() { pkill -x chronyd 2>/dev/null || true; pkill -x gpsd 2>/dev/null || true; rm -f /dev/ttyUSB9 /etc/chrony/chrony.conf /etc/conf.d/gpsd; }
trap cleanup EXIT
nl_kill_daemons chronyd gpsd

cat > "$NL_T/nl-ntpq.py" <<'PY'
# one NTP client query from a given source address: prints "OK stratum N" or "TIMEOUT"
import socket, sys
src, dst, wait = sys.argv[1], sys.argv[2], float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
s.settimeout(wait)
s.sendto(b"\x1b" + 47 * b"\0", (dst, 123))
try:
    d, _ = s.recvfrom(512)
except socket.timeout:
    print("TIMEOUT")
    sys.exit(3)
print("OK stratum %d" % d[1])
PY
cat > "$NL_T/nl-gps.py" <<'PY'
# a GPS receiver: NMEA at 1 Hz on a pty, the slave side reachable as /dev/ttyUSB9
import os, pty, time, tty
m, s = pty.openpty()
tty.setraw(s)
try:
    os.unlink("/dev/ttyUSB9")
except FileNotFoundError:
    pass
os.symlink(os.ttyname(s), "/dev/ttyUSB9")
def cs(b):
    c = 0
    for ch in b.encode():
        c ^= ch
    return "$%s*%02X\r\n" % (b, c)
while True:
    t = time.gmtime()
    hms = time.strftime("%H%M%S", t) + ".00"
    dmy = time.strftime("%d%m%y", t)
    for body in [
        "GPGGA,%s,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,," % hms,
        "GPGSA,A,3,04,05,09,12,24,25,29,31,,,,,1.8,1.0,1.5",
        "GPRMC,%s,A,4807.038,N,01131.000,E,000.0,000.0,%s,,,A" % (hms, dmy),
    ]:
        os.write(m, cs(body).encode())
    time.sleep(1 - (time.time() % 1))
PY

q() { C python3 "$NL_T/nl-ntpq.py" "$1" "$NL_RTR_LAN" "${2:-2}"; }   # q SRC [WAIT]
answers() { q "$1" >/dev/null 2>&1; }
silent() { ! q "$1" 1 >/dev/null 2>&1; }

nl_write_installer_toml
nl_boot "$DB"
for ip in 11 12 130; do C ip addr add 192.168.50.$ip/24 dev lan0; done
nl_web_start "$DB"; nl_login

echo "=== validation: nothing bad is stored"
nl_api_code "ACL /0" 400 PUT /ntp '{"acl_allow":"0.0.0.0/0"}'
nl_api_code "ACL ::/0" 400 PUT /ntp '{"acl_deny":"::/0"}'
nl_api_code "ACL word" 400 PUT /ntp '{"acl_allow":"everyone"}'
nl_api_code "ACL prefix" 400 PUT /ntp '{"acl_allow":"10.0.0.0/33"}'
nl_api_code "ACL mode" 400 PUT /ntp '{"acl_mode":"all"}'
nl_api_code "GPS device" 400 PUT /ntp '{"gps_device":"/dev/sda"}'
nl_api_code "GPS device path trick" 400 PUT /ntp '{"gps_device":"/dev/ttyUSB0/../sda"}'
nl_api_code "GPS baud" 400 PUT /ntp '{"gps_baud":1234}'
nl_api_code "GPS offset" 400 PUT /ntp '{"gps_offset":3}'
nl_api_code "PPS device" 400 PUT /ntp '{"gps_pps_device":"/dev/ttyS0"}'
nl_api GET /ntp
[ "$(nl_json "$NL_OUT" 'len(d["settings"]["acl_allow"]) + len(d["settings"]["acl_deny"]) + d["settings"]["gps"]["baud"]')" = 9600 ] || nl_fail "a refused change was stored: $(cat "$NL_OUT")"
nl_ok "/0 blocks, bad words and prefixes, bad modes, devices, baud rates, offsets are all refused (400) and nothing was stored"

echo "=== the LAN is served"
nl_api_ok "enable" PUT /ntp '{"enabled":true,"servers":"192.0.2.123"}'
grep -q '^allow 192.168.50.0/24' /etc/chrony/chrony.conf || { cat /etc/chrony/chrony.conf; nl_fail "no allow line for the LAN"; }
nl_wait 20 answers 192.168.50.10 || nl_fail "the LAN client got no NTP answer from the router"
nl_wait 5 answers 192.168.50.130 || nl_fail "130 got no answer"
nl_ok "chronyd answers LAN clients ($(q 192.168.50.10))"

echo "=== deny list: one host silent, its neighbours served"
nl_api_ok "deny .12" PUT /ntp '{"acl_deny":"192.168.50.12"}'
grep -q '^deny 192.168.50.12$' /etc/chrony/chrony.conf || nl_fail "no deny line"
nl_wait 20 answers 192.168.50.10 || nl_fail "after the change the allowed client is not answered"
answers 192.168.50.11 || nl_fail ".11 should still be served"
silent 192.168.50.12 || nl_fail "the denied host 192.168.50.12 still got an answer"
nl_ok "192.168.50.12 gets no answer, .10 and .11 do"
nl_api_ok "clear deny" PUT /ntp '{"acl_deny":""}'
nl_wait 20 answers 192.168.50.12 || nl_fail "clearing the deny list did not serve .12 again"
nl_ok "clearing the deny list serves it again"

echo "=== explicit-only mode"
nl_api_ok "explicit" PUT /ntp '{"acl_mode":"explicit","acl_allow":"192.168.50.11, 192.168.50.128/25"}'
! grep -q '^allow 192.168.50.0/24' /etc/chrony/chrony.conf || nl_fail "the interface subnet is still allowed in explicit mode"
nl_wait 20 answers 192.168.50.11 || nl_fail ".11 is on the explicit list but got no answer"
answers 192.168.50.130 || nl_fail "130 is inside the listed /25 but got no answer"
silent 192.168.50.10 || nl_fail ".10 is not listed but was answered"
silent 192.168.50.12 || nl_fail ".12 is not listed but was answered"
nl_ok "only .11 and 192.168.50.128/25 are answered; .10 and .12 are not"

echo "=== it survives a reboot"
nl_web_stop; nl_kill_daemons chronyd gpsd; rm -f /etc/chrony/chrony.conf
nl_boot "$DB"
for ip in 11 12 130; do C ip addr add 192.168.50.$ip/24 dev lan0; done
nl_wait 30 answers 192.168.50.11 || { cat "$NL_OUT"; nl_fail "after the reboot .11 is not served"; }
silent 192.168.50.10 || nl_fail "after the reboot .10 is answered"
nl_ok "the access list is applied again after a reboot"
nl_web_start "$DB"; nl_login
nl_api_ok "back to the interface subnets" PUT /ntp '{"acl_mode":"interfaces","acl_allow":""}'
nl_wait 20 answers 192.168.50.10 || nl_fail ".10 not served after going back to interface mode"

echo "=== GPS: a receiver, gpsd, chrony's GPS source"
python3 "$NL_T/nl-gps.py" >/dev/null 2>&1 &
NL_PIDS+=($!)
nl_wait 10 test -L /dev/ttyUSB9 || nl_fail "the fake receiver did not start"
nl_api_ok "gps on" PUT /ntp '{"gps_enabled":true,"gps_device":"/dev/ttyUSB9","gps_baud":38400,"gps_offset":0.05,"gps_prefer":true}'
grep -q '^DEVICES="/dev/ttyUSB9"' /etc/conf.d/gpsd || { cat /etc/conf.d/gpsd; nl_fail "gpsd config"; }
grep -q 'GPSD_OPTIONS="-n -s 38400"' /etc/conf.d/gpsd || nl_fail "gpsd options"
grep -q '^refclock SHM 0 refid GPS offset 0.05 delay 0.2 poll 4 prefer' /etc/chrony/chrony.conf || { cat /etc/chrony/chrony.conf; nl_fail "no GPS refclock line"; }
pgrep -x gpsd >/dev/null || nl_fail "gpsd is not running"
nl_api GET /ntp
[ "$(nl_json "$NL_OUT" 'd["status"]["gps"]["running"]')" = True ] && [ "$(nl_json "$NL_OUT" 'd["status"]["gps"]["device_present"]')" = True ] || nl_fail "status: $(cat "$NL_OUT")"
nl_ok "gpsd runs on the receiver at 38400 baud and chrony has the GPS refclock; the API status says so"
gps_reach() { chronyc -c sources 2>/dev/null | awk -F, '$3=="GPS" && $6>0 {f=1} END{exit !f}'; }
nl_wait 120 gps_reach || { chronyc sources; tail -20 /tmp/svc-gpsd.log /tmp/svc-chronyd.log 2>/dev/null; nl_fail "chrony never received a sample from the GPS source"; }
nl_ok "chrony reads the receiver's time through gpsd: $(chronyc -c sources | grep ',GPS,')"
answers 192.168.50.10 || nl_fail "the LAN is not served while the GPS is on"

echo "=== a missing PPS device falls back to NMEA, chronyd stays up"
nl_api_ok "pps" PUT /ntp '{"gps_pps_device":"/dev/pps0"}'
pgrep -x chronyd >/dev/null || nl_fail "chronyd died because of a missing PPS device"
! grep -q 'refclock PPS' /etc/chrony/chrony.conf || nl_fail "a PPS refclock was written for a device that does not exist"
grep -q '^DEVICES="/dev/ttyUSB9 /dev/pps0"' /etc/conf.d/gpsd || nl_fail "gpsd was not told about the PPS device"
nl_ok "no refclock PPS line while /dev/pps0 is absent; chronyd keeps running"
nl_api_ok "pps off" PUT /ntp '{"gps_pps_device":""}'

echo "=== the page"
nl_web GET /ntp
[ "$NL_CODE" = 200 ] && grep -q 'id="ntp-acl-form"' "$NL_OUT" && grep -q 'id="ntp-gps-form"' "$NL_OUT" || nl_fail "NTP page: $NL_CODE"
grep -q 'value="/dev/ttyUSB9"' "$NL_OUT" && grep -q 'running' "$NL_OUT" || nl_fail "the page does not show the saved receiver and gpsd state"
nl_ok "the page shows the access list and the GPS source"

echo "=== GPS off"
nl_api_ok "gps off" PUT /ntp '{"gps_enabled":false}'
! grep -q refclock /etc/chrony/chrony.conf || nl_fail "refclock still configured"
nl_wait 10 sh -c '! pgrep -x gpsd' || nl_fail "gpsd still running"
pgrep -x chronyd >/dev/null || nl_fail "chronyd stopped"
answers 192.168.50.10 || nl_fail "LAN not served after GPS off"
nl_ok "switching the GPS off removes the refclock and stops gpsd; the LAN is still served"
nl_web_stop
echo "PASS lane-j-ntp"
echo "ALL NTP CHECKS PASSED"
