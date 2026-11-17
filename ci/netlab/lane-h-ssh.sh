#!/usr/bin/env bash
# Lane H (L3): the managed OpenSSH server (OpenWrt parity) through the web API on the real binaries,
# with the effect checked in real sshd, nftables and real SSH logins from the LAN client.
#
# Proves: sshd listens ONLY on the configured LAN address and port (not 22, not the WAN address);
# a key signed by the trusted user CA with the right principal logs in; an unsigned key, a certificate
# with another principal and a password are refused; the CA-signed host certificate is presented (and
# verifies through @cert-authority); the firewall anti-lockout rule opens the new port instead of 22;
# a bad config is refused and rolled back (port and sshd unchanged).
#
# sshd runs in the router namespace under a tiny /etc/init.d/sshd shim (this container has no init system),
# so Patronus' own ServiceManager reload path is what starts and reloads it.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

command -v sshd >/dev/null && command -v ssh-keygen >/dev/null && command -v ssh >/dev/null \
  || { echo "SKIP lane-h-ssh: openssh server/client not installed"; exit 0; }
DB=/t/lane-h-ssh.db
rm -f "$DB" "$NL_T/nl-jar"
K=/t/ssh-keys; rm -rf "$K"; mkdir -p "$K" /run/sshd
PORT=2222
SSHD=$(command -v sshd)

# --- keys: user CA, host CA, a good/unsigned/wrong-principal user -----------------------------
ssh-keygen -q -t ed25519 -N '' -f "$K/user_ca" -C user-ca
ssh-keygen -q -t ed25519 -N '' -f "$K/host_ca" -C host-ca
for u in good unsigned wrongp; do ssh-keygen -q -t ed25519 -N '' -f "$K/$u" -C "$u"; done
ssh-keygen -q -s "$K/user_ca" -I good-id -n admin -V +1h "$K/good.pub"
ssh-keygen -q -s "$K/user_ca" -I wrongp-id -n somebody-else -V +1h "$K/wrongp.pub"
# host key + certificate signed by the host CA
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
ssh-keygen -q -s "$K/host_ca" -I rtr-host -h -n "$NL_RTR_LAN" -V +1h /etc/ssh/ssh_host_ed25519_key.pub
HOSTCERT=$(cat /etc/ssh/ssh_host_ed25519_key-cert.pub)
echo "@cert-authority * $(cat "$K/host_ca.pub")" > "$K/known_hosts"

# --- init shim so Patronus' ServiceManager can start/reload sshd here ---------------------------
cat > /etc/init.d/sshd <<SH
#!/bin/sh
PIDF=/run/sshd-lane.pid
alive() { [ -f \$PIDF ] && kill -0 "\$(cat \$PIDF)" 2>/dev/null; }
case "\$1" in
  start) alive || $SSHD -E /run/sshd-lane.log -o PidFile=\$PIDF ;;
  stop) alive && kill "\$(cat \$PIDF)"; rm -f \$PIDF ;;
  restart) alive && kill "\$(cat \$PIDF)"; sleep 0.5; $SSHD -E /run/sshd-lane.log -o PidFile=\$PIDF ;;
  reload) if alive; then kill -HUP "\$(cat \$PIDF)"; else $SSHD -E /run/sshd-lane.log -o PidFile=\$PIDF; fi ;;
  status) alive ;;
esac
SH
chmod 755 /etc/init.d/sshd
rm -f /etc/ssh/sshd_config.d/50-patronus.conf; rm -rf /etc/ssh/patronus
printf 'Include /etc/ssh/sshd_config.d/*.conf\n' > /etc/ssh/sshd_config
mkdir -p /etc/ssh/sshd_config.d
nl_kill_daemons sshd
rm -f /run/sshd-lane.pid

# lib.sh starts stand-in TCP servers on the router's 22 and 2222; the real sshd needs those ports
free_ssh_ports() { # kill them and forget their pids (nl_down's kill of a gone pid would end the script)
  local p q keep
  for p in $(pgrep -f '[n]l-tcp.py 0.0.0.0 (22|2222)$' || true); do
    kill "$p" 2>/dev/null || true
    keep=(); for q in "${NL_PIDS[@]}"; do [ "$q" = "$p" ] || keep+=("$q"); done; NL_PIDS=("${keep[@]}")
  done
  sleep 0.3
}
nl_write_installer_toml
nl_boot "$DB"
free_ssh_ports
nl_web_start "$DB"; nl_login
nl_api_ok "overview" GET /system/ssh

ssh_c() { # extra ssh args... : log in as root from the LAN client with the given identity
  local id=$1; shift
  C ssh -p "$PORT" -i "$id" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 \
    -o UserKnownHostsFile="$K/known_hosts" -o StrictHostKeyChecking=yes "$@" "root@$NL_RTR_LAN" 'echo logged-in-as-$(id -un)'
}
PUB_CA=$(cat "$K/user_ca.pub")

echo "=== validation: bad input refused, nothing stored"
for bad in '{"port":0}' '{"listen":"eth0\nPermitEmptyPasswords yes"}' '{"root_login":"sometimes"}' \
  '{"trusted_user_ca_keys":"not a key"}' '{"host_certificate":"ssh-ed25519 AAAA x"}'; do
  nl_api_code "bad ssh input $bad" 400 PUT /system/ssh "$bad"
done
[ -z "$(sqlite3 "$DB" "SELECT value FROM system_config WHERE key='ssh.port'")" ] || nl_fail "a refused change was stored"
nl_ok "bad port, listen, root policy, CA key and host certificate are refused (400), nothing stored"

echo "=== configure: port $PORT on the LAN only, CA + principals + host certificate"
BODY=$(python3 - "$PORT" "$PUB_CA" "$HOSTCERT" <<'PY'
import json, sys
print(json.dumps({"port": int(sys.argv[1]), "listen": "@lan", "password_auth": False, "root_login": "prohibit-password",
  "trusted_user_ca_keys": sys.argv[2], "authorized_principals": {"root": ["admin"]}, "host_certificate": sys.argv[3]}))
PY
)
nl_api PUT /system/ssh "$BODY"
[ "$NL_CODE" = 200 ] || { cat "$NL_OUT"; echo; cat /etc/ssh/sshd_config.d/50-patronus.conf 2>&1; tail -20 /run/sshd-lane.log 2>&1; $SSHD -t 2>&1 | tail -5; nl_fail "save ssh: $NL_CODE"; }
nl_ok "save ssh"
nl_wait 10 bash -c "R ss -ltnH | grep :$PORT >/dev/null" || nl_fail "sshd is not listening on $PORT: $(R ss -ltn)"
[ -f /etc/ssh/sshd_config.d/50-patronus.conf ] || nl_fail "no drop-in"
grep -q "^Port $PORT$" /etc/ssh/sshd_config.d/50-patronus.conf || nl_fail "drop-in lacks Port: $(cat /etc/ssh/sshd_config.d/50-patronus.conf)"
$SSHD -t && nl_ok "sshd -t accepts the Patronus drop-in"

echo "=== listens only on the configured address and port"
LISTEN=$(R ss -ltnH | awk '{print $4}' | grep -E ":($PORT|22)\$" | sort | tr '\n' ' ')
[ "$LISTEN" = "$NL_RTR_LAN:$PORT " ] || nl_fail "sshd listeners: '$LISTEN' (want only $NL_RTR_LAN:$PORT)"
nl_ok "listeners: $LISTEN (not 22, not the WAN address, not 0.0.0.0)"
! C ssh -p 22 -o ConnectTimeout=3 -o BatchMode=yes "root@$NL_RTR_LAN" true 2>/dev/null || nl_fail "port 22 still answers"
! ISP bash -c "exec 3<>/dev/tcp/$NL_RTR_WAN/$PORT" 2>/dev/null || nl_fail "sshd answers on the WAN address"
nl_ok "nothing answers on port 22 or on the WAN address"

echo "=== logins"
OUT=$(ssh_c "$K/good" -o CertificateFile="$K/good-cert.pub") || nl_fail "CA-signed key with principal admin was refused: $OUT"
[ "$OUT" = "logged-in-as-root" ] || nl_fail "unexpected login output: $OUT"
nl_ok "CA-signed key with the right principal logs in as root"
ssh_c "$K/unsigned" >/dev/null 2>&1 && nl_fail "an unsigned key logged in"
nl_ok "an unsigned key is refused"
ssh_c "$K/wrongp" -o CertificateFile="$K/wrongp-cert.pub" >/dev/null 2>&1 && nl_fail "a certificate with another principal logged in"
nl_ok "a CA-signed certificate with the wrong principal is refused"
PW=$(C ssh -p "$PORT" -o PreferredAuthentications=password -o PubkeyAuthentication=no -o BatchMode=yes -o ConnectTimeout=5 \
  -o UserKnownHostsFile="$K/known_hosts" "root@$NL_RTR_LAN" true 2>&1 || true)
grep -q "Permission denied (publickey)" <<<"$PW" || nl_fail "password auth not refused as publickey-only: $PW"
nl_ok "password login is refused (only publickey offered)"
V=$(ssh_c "$K/good" -v -o CertificateFile="$K/good-cert.pub" 2>&1 || true)
grep -q "Server host certificate: ssh-ed25519-cert-v01@openssh.com" <<<"$V" || nl_fail "no host certificate presented: $V"
nl_ok "sshd presents the CA-signed host certificate (verified via @cert-authority, StrictHostKeyChecking=yes)"

echo "=== anti-lockout follows ssh.port"
RS=$(R nft list ruleset)
grep -Eq "tcp dport \{ ?$PORT, ?8443 ?\} accept" <<<"$RS" || { echo "$RS" | grep -n "8443"; nl_fail "no anti-lockout rule on $PORT"; }
! grep -Eq "tcp dport \{ ?22, ?8443 ?\}" <<<"$RS" || nl_fail "anti-lockout still opens 22"
nl_ok "nft anti-lockout rule opens tcp $PORT and 8443 (no longer 22)"
# and it survives a reboot (fresh namespaces + patronus apply)
nl_web_stop; nl_kill_daemons sshd; rm -f /run/sshd-lane.pid
nl_up; free_ssh_ports; nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "reboot: patronus apply failed"; }
nl_wait 10 bash -c "R ss -ltnH | grep :$PORT >/dev/null" || nl_fail "sshd not listening on $PORT after reboot"
OUT=$(ssh_c "$K/good" -o CertificateFile="$K/good-cert.pub") || nl_fail "login after reboot: $OUT"
nl_ok "config survives a reboot (apply): listener, anti-lockout and CA login"

echo "=== a bad change is refused and rolled back"
nl_web_start "$DB"; nl_login
nl_api_code "listen on an unassigned role" 500 PUT /system/ssh '{"listen":"@opt7"}' || true
[ "$(sqlite3 "$DB" "SELECT value FROM system_config WHERE key='ssh.listen'")" = "@lan" ] || nl_fail "failed change was not rolled back"
nl_wait 5 bash -c "R ss -ltnH | grep :$PORT >/dev/null" || nl_fail "sshd gone after the failed change"
nl_ok "listen on a role with no address fails, the store keeps @lan and sshd keeps listening"
nl_web_stop; nl_down
echo "PASS lane-h-ssh"
