#!/usr/bin/env bash
# Lane C: traffic shaping (USE=qos) from the web UI API, proven in the
# kernel and with real traffic: a 8 Mbit/s rate limit on the WAN slows a
# 3 MB upload from the LAN client to ~3 s (unshaped: well under a second),
# fq_codel replaces it, the qdisc is re-applied after a reboot and removed
# when the shaper is deleted; CAKE is exercised when the kernel has sch_cake.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-c-shaping.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml

cat > "$NL_T/nl-sink.py" <<'PY'
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(8)
while True:
    c, _ = s.accept()
    while c.recv(65536):
        pass
    c.sendall(b"done\n"); c.close()
PY
cat > "$NL_T/nl-upload.py" <<'PY'
import socket, sys, time
n = int(sys.argv[3]); s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=30)
chunk = b"x" * 65536; t = time.time(); sent = 0
while sent < n:
    s.sendall(chunk[: min(len(chunk), n - sent)]); sent += min(len(chunk), n - sent)
s.shutdown(socket.SHUT_WR); s.recv(10)
print("%.2f" % (time.time() - t))
PY
upload() { C python3 "$NL_T/nl-upload.py" "$NL_WWW" 9100 3000000; }
wan_qdisc() { R tc qdisc show dev "$NL_WAN_IF" | head -1; }

nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-sink.py" 0.0.0.0 9100
sleep 0.5
nl_web_start "$DB"; nl_login

BASE=$(upload)
python3 -c "import sys; sys.exit(0 if float('$BASE') < 1.5 else 1)" || nl_fail "unshaped upload already slow: $BASE s"
nl_ok "unshaped 3 MB upload: $BASE s"

echo "=== a rate limit on the WAN"
for bad in '{"interface":"@wan","mode":"cake"}' '{"interface":"@wan","mode":"limit","rate_kbit":1}' '{"interface":"@wan","mode":"magic","rate_kbit":1000}'; do
  nl_api POST /qos "$bad"
  [ "$NL_CODE" = 400 ] || nl_fail "bad shaper accepted: $bad -> $NL_CODE"
done
nl_ok "cake without a rate / absurd rate / unknown mode are refused (400)"
nl_api POST /qos '{"interface":"@wan","mode":"limit","rate_kbit":8000,"description":"upload cap"}'
[ "$NL_CODE" = 201 ] || nl_fail "add shaper: $NL_CODE $(cat "$NL_OUT")"
ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT")
case "$(wan_qdisc)" in *"qdisc tbf"*"rate 8Mbit"*) ;; *) nl_fail "WAN root qdisc is not a tbf at 8Mbit: $(wan_qdisc)";; esac
nl_ok "kernel: $(wan_qdisc)"
SHAPED=$(upload)
python3 -c "import sys; sys.exit(0 if 2.2 <= float('$SHAPED') <= 6.0 else 1)" || nl_fail "3 MB through an 8 Mbit/s limit took $SHAPED s (want ~3 s)"
nl_ok "3 MB upload through the 8 Mbit/s limit took $SHAPED s (unshaped $BASE s)"
nl_api GET /qos
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the active shaper"
import json, sys
d = json.load(open(sys.argv[1]))
s = d["status"]["shapers"]
assert s and s[0]["active"] and s[0]["kernel"] == "tbf", s
PY
nl_ok "API status reports the shaper active (kernel qdisc tbf)"
nl_web GET /qos
[ "$NL_CODE" = 200 ] && grep -q 'id="qos-form"' "$NL_OUT" || nl_fail "shaping page: $NL_CODE"

echo "=== edit to fq_codel"
nl_api PUT "/qos/$ID" '{"mode":"fq_codel"}'
[ "$NL_CODE" = 200 ] || nl_fail "edit: $NL_CODE $(cat "$NL_OUT")"
case "$(wan_qdisc)" in *"qdisc fq_codel"*) ;; *) nl_fail "WAN root qdisc is not fq_codel: $(wan_qdisc)";; esac
UNLIM=$(upload)
python3 -c "import sys; sys.exit(0 if float('$UNLIM') < 1.5 else 1)" || nl_fail "fq_codel is not a rate limit but took $UNLIM s"
nl_ok "fq_codel: kernel root qdisc replaced, upload back to $UNLIM s"

echo "=== CAKE, when the kernel has it"
if R tc qdisc add dev "$NL_LAN_IF" root cake bandwidth 1000mbit 2>/dev/null; then
  R tc qdisc del dev "$NL_LAN_IF" root
  nl_api PUT "/qos/$ID" '{"mode":"cake","rate_kbit":1000000}'
  [ "$NL_CODE" = 200 ] || nl_fail "cake: $NL_CODE $(cat "$NL_OUT")"
  case "$(wan_qdisc)" in *"qdisc cake"*) ;; *) nl_fail "WAN root qdisc is not cake: $(wan_qdisc)";; esac
  nl_ok "CAKE at 1 Gbit/s on the WAN: $(wan_qdisc)"
else
  nl_api PUT "/qos/$ID" '{"mode":"cake","rate_kbit":1000000}'
  [ "$NL_CODE" = 500 ] || nl_fail "without sch_cake the API must refuse (500), got $NL_CODE"
  grep -qi cake "$NL_OUT" || nl_fail "the refusal should mention CAKE: $(cat "$NL_OUT")"
  nl_api GET /qos
  grep -q '"mode":"fq_codel"' "$NL_OUT" || nl_fail "the refused change was not undone: $(cat "$NL_OUT")"
  nl_ok "this kernel has no sch_cake: the API refuses CAKE with a clear error and keeps fq_codel"
fi
nl_api PUT "/qos/$ID" '{"mode":"limit","rate_kbit":8000}'
[ "$NL_CODE" = 200 ] || nl_fail "back to limit: $NL_CODE"

echo "=== reboot: the shaper is re-applied from the store"
nl_web_stop
nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-sink.py" 0.0.0.0 9100
sleep 0.5
case "$(wan_qdisc)" in *"qdisc tbf"*"rate 8Mbit"*) ;; *) nl_fail "after reboot the WAN qdisc is: $(wan_qdisc)";; esac
nl_ok "after reboot: $(wan_qdisc)"

echo "=== delete the shaper"
nl_web_start "$DB"; nl_login
nl_api DELETE "/qos/$ID"
[ "$NL_CODE" = 200 ] || nl_fail "delete: $NL_CODE"
case "$(wan_qdisc)" in *"qdisc tbf"*|*cake*) nl_fail "the shaper is still on the WAN: $(wan_qdisc)";; esac
nl_ok "deleted: the WAN root qdisc is back to $(wan_qdisc | awk '{print $2}')"
nl_web_stop
nl_down
