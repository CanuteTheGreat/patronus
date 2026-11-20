#!/usr/bin/env bash
# Lane W: where the web UI listens. OpenWrt / pfSense users expect http(s)://ROUTER-IP, so the built-in default is
# HTTPS on 443, plain HTTP on 80 that only redirects to HTTPS, and 8443 kept as an extra HTTPS port; every one of
# them is a setting (System page / PUT /api/system/web, patronus.toml [web], environment) and the firewall's
# anti-lockout rule follows them.
#
# Runs the real patronus-web the way the shipped OpenRC script and systemd unit do: as an UNPRIVILEGED user whose
# only capabilities are net_admin, net_raw and net_bind_service (ambient), in the router namespace.
#
# Proves, from the LAN client: https://router/ -> login page; http://router/<path>?<query> -> 308 to the same
# path on https and nothing else is served on port 80; 8443 still answers; the process is not root and holds
# net_bind_service; the anti-lockout rule opens 22,443,80,8443 on the LAN only; a change through the API opens the
# new ports in the firewall at once, leaves the old listener up until the restart, then 443/80 are gone and the
# new port answers (8443 kept as extra); an impossible combination is refused (400) and changes nothing; without
# net_bind_service the UI still comes up (8443) and the failure is logged; --help / --version answer and never
# start a server.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

# this lane proves the built-in defaults: drop the single-listener environment lib.sh gives the other lanes
unset PATRONUS_HTTPS_PORT PATRONUS_HTTP_REDIRECT_PORT PATRONUS_WEB_EXTRA_HTTPS_PORTS

W=$NL_T/w-ports
DB=$W/c.db
rm -rf "$W" "$NL_T/nl-jar"; mkdir -p "$W"
command -v setpriv >/dev/null || { echo "SKIP lane-w-web-ports: setpriv not installed"; exit 0; }
nl_write_installer_toml
nl_boot "$DB"
chown -R 65534:65534 "$W"

CAPS=net_admin,net_raw,net_bind_service
# start_web BOUNDING-SET-CAPS: the router namespace, user nobody, only those capabilities (ambient)
start_web() {
  local caps=$1 inh amb
  inh=$(sed 's/\([a-z_]*\)/+\1/g' <<<"$caps"); amb=$inh
  env PATRONUS_DB="$DB" PATRONUS_BOOTSTRAP="$NL_TOML" PATRONUS_ADMIN_PASSWORD="$NL_PASS" \
      PATRONUS_ADMIN_PASSWORD_FILE="$W/pw" PATRONUS_TLS_DIR="$W/tls" RUST_LOG=info \
      ip netns exec nl-rtr setpriv --reuid=65534 --regid=65534 --clear-groups \
        --bounding-set="-all,$inh" --inh-caps="$inh" --ambient-caps="$amb" "$WEB" >>"$W/web.log" 2>&1 &
  NL_WEB_PID=$!
}
wait_ui() { # URL
  nl_wait 40 C curl -sk -m 3 -o /dev/null "$1" || { tail -40 "$W/web.log"; nl_fail "patronus-web did not answer on $1"; }
}
stop_web() {
  [ -n "${NL_WEB_PID:-}" ] && kill "$NL_WEB_PID" 2>/dev/null || true
  wait "${NL_WEB_PID:-}" 2>/dev/null || true
  NL_WEB_PID=
}
code_of() { C curl -sk -m 5 -o "$NL_OUT" -w '%{http_code}' "$1" || true; }
refused() { # URL: no listener (connection refused / reset), not a web answer
  local rc=0; C curl -sk -m 4 -o /dev/null "$1" || rc=$?
  [ "$rc" != 0 ] || nl_fail "$1 still answers"
}

echo "=== --help and --version never start a server"
out=$(timeout 10 "$WEB" --help) || nl_fail "patronus-web --help exited non-zero"
for want in "Usage: patronus-web" PATRONUS_HTTPS_PORT PATRONUS_HTTP_REDIRECT_PORT patronus.toml web.https_port; do
  grep -qF -- "$want" <<<"$out" || nl_fail "--help lacks: $want"
done
out=$(timeout 10 "$WEB" --version) || nl_fail "--version failed"
grep -q '^patronus-web [0-9]' <<<"$out" || nl_fail "--version printed: $out"
rc=0; timeout 10 "$WEB" --nonsense >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || nl_fail "an unknown argument must exit 2 (got $rc), not start the server"
nl_ok "--help lists the settings, --version prints the version, an unknown argument is refused"

echo "=== built-in defaults, as the unprivileged service user"
start_web "$CAPS"
wait_ui "https://$NL_RTR_LAN/login"
[ "$(code_of "https://$NL_RTR_LAN/login")" = 200 ] || nl_fail "https://router/login did not answer 200"
grep -qF 'id="login-form"' "$NL_OUT" || nl_fail "https://router/ answered, but not with the login page"
nl_ok "https://$NL_RTR_LAN (port 443) serves the login page"
[ "$(code_of "https://$NL_RTR_LAN:8443/login")" = 200 ] || nl_fail "8443 no longer answers"
nl_ok "https://$NL_RTR_LAN:8443 still answers (extra listener)"
hdr=$(C curl -s -m 5 -o "$NL_OUT" -D - "http://$NL_RTR_LAN/some/page?x=1&y=2" | tr -d '\r') || true
grep -q '^HTTP/1.1 308' <<<"$hdr" || nl_fail "http://router/ did not answer 308: $hdr"
grep -qi "^location: https://$NL_RTR_LAN/some/page?x=1&y=2\$" <<<"$hdr" || nl_fail "wrong redirect target: $hdr"
[ ! -s "$NL_OUT" ] || nl_fail "the plain-HTTP listener served a body: $(head -c 200 "$NL_OUT")"
grep -qi '^set-cookie' <<<"$hdr" && nl_fail "the plain-HTTP listener set a cookie"
nl_ok "http://$NL_RTR_LAN/some/page?x=1&y=2 -> 308 https://$NL_RTR_LAN/some/page?x=1&y=2, empty body, no cookie"
st=$(cat "/proc/$NL_WEB_PID/status")
uid=$(awk '/^Uid:/ {print $2}' <<<"$st"); capeff=$(awk '/^CapEff:/ {print $2}' <<<"$st")
[ "$uid" = 65534 ] || nl_fail "patronus-web runs as uid $uid, want the unprivileged user"
[ $(( (0x$capeff >> 10) & 1 )) = 1 ] || nl_fail "patronus-web lacks CAP_NET_BIND_SERVICE (CapEff $capeff)"
[ $(( (0x$capeff >> 21) & 1 )) = 0 ] || nl_fail "patronus-web holds CAP_SYS_ADMIN (CapEff $capeff)"
nl_ok "patronus-web runs as uid $uid with CapEff $capeff (net_bind_service, no more than the unit grants)"
nl_assert_nft_has "iifname \"$NL_LAN_IF\" tcp dport { 22, 443, 80, 8443 } accept"
nl_assert_nft_lacks "iifname \"$NL_WAN_IF\" tcp dport { 22, 443, 80, 8443 }"

echo "=== a change through the API: firewall first, listeners at restart"
nl_login
nl_api_ok "read the web settings" GET /system/web
nl_json "$NL_OUT" 'd["effective"]["https_port"]' >"$W/p"
[ "$(cat "$W/p")" = 443 ] || nl_fail "effective https_port is $(cat "$W/p"), want 443"
nl_json "$NL_OUT" 'd["effective"]["extra_https_ports"]' >"$W/p"
[ "$(cat "$W/p")" = "[8443]" ] || nl_fail "effective extra ports $(cat "$W/p")"
nl_ok "GET /api/system/web reports the effective defaults (443, redirect 80, extra 8443)"
before=$(nl_ruleset_fingerprint)
nl_api_code "redirect port equal to the HTTPS port is refused" 400 PUT /system/web '{"http_redirect_port":443}'
nl_api_code "a half certificate is refused" 400 PUT /system/web '{"tls_cert":"/x/cert.pem"}'
nl_api_code "a listen name is refused" 400 PUT /system/web '{"listen":"@lan"}'
[ "$(nl_ruleset_fingerprint)" = "$before" ] || nl_fail "a refused change altered the firewall"
nl_ok "impossible combinations are 400 and change nothing"
nl_api_ok "move the UI to 9443, no redirect, keep 8443" PUT /system/web \
  '{"https_port":9443,"http_redirect_port":0,"extra_https_ports":"8443"}'
nl_assert_nft_has "iifname \"$NL_LAN_IF\" tcp dport { 22, 9443, 8443 } accept"
nl_assert_nft_lacks "tcp dport { 22, 443, 80, 8443 }"
[ "$(code_of "https://$NL_RTR_LAN/login")" = 200 ] || nl_fail "the old listener should stay up until the restart"
nl_ok "the firewall already opens 9443; the running UI still answers on 443 until it is restarted"
stop_web
start_web "$CAPS"
wait_ui "https://$NL_RTR_LAN:9443/login"
[ "$(code_of "https://$NL_RTR_LAN:9443/login")" = 200 ] || nl_fail "9443 does not answer after the restart"
[ "$(code_of "https://$NL_RTR_LAN:8443/login")" = 200 ] || nl_fail "8443 does not answer after the restart"
refused "https://$NL_RTR_LAN/login"
refused "http://$NL_RTR_LAN/"
nl_ok "after the restart 9443 and 8443 answer; 443 and 80 are gone"
nl_json_state=$(sqlite3 "$DB" "select value from system_config where key='web.https_port'")
[ "$nl_json_state" = 9443 ] || nl_fail "web.https_port in the store is '$nl_json_state'"
echo "=== it is part of the configuration: survives a reboot, export carries it"
stop_web
nl_boot "$DB"
chown -R 65534:65534 "$W"
nl_assert_nft_has "iifname \"$NL_LAN_IF\" tcp dport { 22, 9443, 8443 } accept"
nl_ok "after a reboot the anti-lockout rule still follows the stored ports"

echo "=== a back-to-defaults reset"
start_web "$CAPS"
wait_ui "https://$NL_RTR_LAN:9443/login"
rm -f "$NL_T/nl-jar"; nl_login
nl_api_ok "reset" PUT /system/web '{"reset":true}'
nl_assert_nft_has "iifname \"$NL_LAN_IF\" tcp dport { 22, 443, 80, 8443 } accept"
stop_web
nl_ok "reset forgets the stored values: the defaults (and their firewall ports) are back"

echo "=== no CAP_NET_BIND_SERVICE: the UI still comes up on the unprivileged port, the failure is logged"
: >"$W/web.log"
start_web "net_admin,net_raw"
wait_ui "https://$NL_RTR_LAN:8443/login"
refused "https://$NL_RTR_LAN/login"
refused "http://$NL_RTR_LAN/"
grep -q 'cannot listen on https://0.0.0.0:443' "$W/web.log" || { tail -20 "$W/web.log"; nl_fail "the failed 443 bind was not logged"; }
grep -q 'cannot listen on http://0.0.0.0:80' "$W/web.log" || nl_fail "the failed 80 bind was not logged"
nl_ok "without the capability only 8443 serves, and the log names the listeners that could not be bound"
stop_web

echo "PASS lane-w-web-ports"
