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
chk "board-network publishes the settings at boot" grep -q 'board-settings write' "$D/overlay/usr/libexec/patronus/board-network"
chk "board-network starts the 5 GHz client only with UPLINK5=on" grep -q 'if \[ "$UPLINK5" = on \]; then radio5 client; else radio5; fi' "$D/overlay/usr/libexec/patronus/board-network"
[ "$fails" = 0 ] && echo "board-settings: all checks passed" || { echo "board-settings: $fails failed"; exit 1; }
