#!/bin/sh
# Host test of overlay/usr/libexec/patronus/board-settings and board.sh's UPLINK5 key (no radio, no root):
# the JSON the web UI reads (System > Hardware settings) is valid, carries the typed key, default, reason and live state.
D=$(cd "$(dirname "$0")/.." && pwd)
BS=$D/overlay/usr/libexec/patronus/board-settings
W=$(mktemp -d "${TMPDIR:-/tmp}/bs-test.XXXX"); trap 'rm -rf "$W"' EXIT
fails=0
ok() { echo "ok: $*"; }
bad() { echo "FAIL: $*"; fails=$((fails+1)); }
chk() { n=$1; shift; if "$@"; then ok "$n"; else bad "$n"; fi; }
mkdir -p "$W/etc" "$W/run" "$W/bin"
printf '#!/bin/sh\n[ -f "%s/connected" ] && echo "Connected to aa:bb:cc:dd:ee:ff (on $3)"; exit 0\n' "$W" > "$W/bin/iw"; chmod +x "$W/bin/iw"
# board.sh with the real UPLINK5 block, no unit.conf, no hardware lookups
sed -e "s#/etc/patronus/unit.conf#$W/etc/unit.conf#g" "$D/overlay/etc/patronus/board.sh" > "$W/etc/board.sh"
run() { BOARD_SH="$W/etc/board.sh" PATH="$W/bin:$PATH" WF_RUN="$W/run" BOARD_SETTINGS_OUT="$W/out.json" sh "$BS" write && cat "$W/out.json"; }
js() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); e=[x for x in d if x['key']=='UPLINK5'][0]; print(eval(sys.argv[2]))" "$W/out.json" "$1"; }
run > /dev/null
chk "board default: valid JSON, UPLINK5 off, default off, allowed on|off" test "$(js "e['value'],e['default'],e['allowed']")" = "('off', 'off', ['on', 'off'])"
chk "default carries its reason and how to change it" sh -c "[ -n \"\$(python3 -c \"import json;print(json.load(open('$W/out.json'))[0]['reason'])\")\" ] && grep -q 'UPLINK5=on' $W/out.json"
chk "off: state says the 2.4 GHz client is the uplink" sh -c "grep -q '2.4 GHz client is the uplink' $W/out.json"
echo 'UPLINK5=on' > "$W/etc/unit.conf"; touch "$W/connected"; run > /dev/null
chk "unit.conf UPLINK5=on: value on, default still off, state connected" test "$(js "e['value'],e['default'],e['state']")" = "('on', 'off', 'on: connected')"
echo "100 3700" > "$W/run/wl5-sta.dropped"; echo 'firmware of radio 0000:00:00.0 restarted 3 times in 900 s' > "$W/run/wl5-sta.why"; run > /dev/null
chk "dropped by the watchdog: state names the reason" sh -c "grep -q 'stopped by the radio watchdog' $W/out.json && grep -q 'restarted 3 times' $W/out.json"
echo 'UPLINK5=maybe' > "$W/etc/unit.conf"; run > /dev/null 2>&1
chk "a value that is not on|off falls back to the board default" test "$(js "e['value']")" = off
printf 'UPLINK5=on\nUPLINK5_REASON="has \\"quotes\\" and a back\\\\slash"\n' > "$W/etc/unit.conf"; rm -f "$W/run"/wl5-sta.*; run > /dev/null
chk "quotes and backslashes in text stay valid JSON" python3 -c "import json; json.load(open('$W/out.json'))"
mj() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); e=[x for x in d if x['key']=='MGMT_FAILOVER'][0]; print(eval(sys.argv[2]))" "$W/out.json" "$1"; }
rm -f "$W/etc/unit.conf" "$W/run"/*; run > /dev/null
chk "MGMT_FAILOVER: typed on|off, default on, with reason and how" test "$(mj "e['value'],e['default'],e['allowed'],bool(e['reason']),'MGMT_FAILOVER=off' in e['how']")" = "('on', 'on', ['on', 'off'], True, True)"
chk "MGMT_FAILOVER: one uplink only -> idle, says it needs UPLINK5=on" sh -c "grep -q 'on, but idle: needs a second uplink' $W/out.json"
echo 'UPLINK5=on' > "$W/etc/unit.conf"; echo "10.9.9.173" > "$W/run/mgmt.addr"; run > /dev/null
chk "MGMT_FAILOVER: ready state names the address" test "$(mj "e['state']")" = "on: ready (10.9.9.173 on wl24-sta); moves to the other uplink if the primary loses its Wi-Fi link"
echo "wl5-sta 10.9.9.173" > "$W/run/mgmt.on"; run > /dev/null
chk "MGMT_FAILOVER: active state names the carrier" sh -c "grep -q 'ACTIVE: 10.9.9.173 is carried by wl5-sta while wl24-sta is down' $W/out.json"
printf 'MGMT_FAILOVER=off\n' > "$W/etc/unit.conf"; rm -f "$W/run"/*; run > /dev/null
chk "MGMT_FAILOVER=off from unit.conf: value off, default still on" test "$(mj "e['value'],e['default']")" = "('off', 'on')"
printf 'MGMT_FAILOVER=sometimes\nMGMT_FAILOVER_AFTER=abc\n' > "$W/etc/unit.conf"; run > /dev/null 2>&1
chk "MGMT_FAILOVER: a bad value falls back to the default" test "$(mj "e['value']")" = on
chk "MGMT_FAILOVER_AFTER: a bad value falls back to 4" sh -c ". '$W/etc/board.sh' 2>/dev/null; [ \"\$MGMT_FAILOVER_AFTER\" = 4 ]"
chk "board-network publishes the settings at boot" grep -q 'board-settings write' "$D/overlay/usr/libexec/patronus/board-network"
chk "board-network starts the 5 GHz client only with UPLINK5=on" grep -q 'if \[ "$UPLINK5" = on \]; then radio5 client; else radio5; fi' "$D/overlay/usr/libexec/patronus/board-network"
[ "$fails" = 0 ] && echo "board-settings: all checks passed" || { echo "board-settings: $fails failed"; exit 1; }
