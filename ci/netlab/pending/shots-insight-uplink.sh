#!/usr/bin/env bash
# NOT a CI scenario (lives in pending/, which run.sh does not glob): builds the
# lab the insight / uplink pages are photographed in. Real: the netns lab, the
# DB-IP-format fixture files downloaded by `patronus ipdb update`, live flows
# from three client addresses to ten fixture "countries", the gateway monitor,
# a live DNS probe. Seeded (clearly: rows written straight into ins_* tables):
# 24 hours of earlier uplink samples with two outages and a degraded patch, and
# earlier hourly traffic buckets, so the 24 h charts have something to draw.
# Leaves everything running; /t/shots.ready appears when it is up.
set -eu
. "$(dirname "$0")/../lib.sh"
T=/t/shots; rm -rf "$T"; mkdir -p "$T/feeds" "$T/pub"
DB=$T/config.db
export NO_COLOR=1 CLICOLOR=0 PATRONUS_INIT=direct PATRONUS_NET_DIR=$T/net PATRONUS_RUN_DIR=$T/run
export PATRONUS_APPLYD_SOCKET=$T/applyd.sock PATRONUS_GATEWAY_STATUS=$T/gateway-status.json
export PATRONUS_FEEDS_DIR=$T/feeds PATRONUS_IPDB_REFRESH=0 PATRONUS_INSIGHT_TICK_SECS=2 PATRONUS_INSIGHT_FLUSH_SECS=4
ISP2() { ip netns exec nl-isp2 "$@"; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
must() { local want=$1; shift; nl_api "$@"; [ "$NL_CODE" = "$want" ] || nl_fail "$1 $2 -> $NL_CODE (want $want): $(cat "$NL_OUT")"; }
sql() { python3 - "$DB" "$1" <<'EOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=30); c.execute(sys.argv[2]); c.commit()
EOF
}

# fixture "internet": ten countries / networks, each one address of inet0
python3 - "$T/pub" <<'EOF'
import gzip, sys
d = sys.argv[1]
nets = [("US", 64510, "Example Cloud Inc."), ("DE", 64511, "Beispiel Hosting GmbH"), ("JP", 64512, "Sakura Example KK"),
        ("NL", 64513, "Voorbeeld Networks BV"), ("GB", 64514, "Example Streaming Ltd"), ("FR", 64515, "Exemple Telecom SA"),
        ("SG", 64516, "Example Asia Pte"), ("BR", 64517, "Exemplo CDN Ltda"), ("AU", 64518, "Example Southern Transit"), ("CA", 64519, "Example Maple Cloud")]
cc, asn = [], []
for i, (c, a, o) in enumerate(nets):
    lo, hi = f"198.51.100.{16 + i * 16}", f"198.51.100.{31 + i * 16}"
    cc.append(f'"{lo}","{hi}","{c}"'); asn.append(f'"{lo}","{hi}","{a}","{o}"')
for n, rows in (("country", cc), ("asn", asn)):
    with gzip.open(f"{d}/{n}.csv.gz", "wt") as f:
        f.write("\n".join(rows) + "\n")
open(f"{d}/big.bin", "wb").write(b"\0" * 1048576)
EOF

nl_write_installer_toml
nl_up; second_wan() {
  ip netns add nl-isp2; ip -n nl-isp2 link set lo up
  ip link add rtr-wan2 netns nl-rtr type veth peer name up0 netns nl-isp2
  ip link add down1 netns nl-isp2 type veth peer name inet1 netns nl-inet
  ISP2 ip addr add 100.64.0.1/24 dev up0; ISP2 ip link set up0 up
  ISP2 ip addr add 192.0.2.1/24 dev down1; ISP2 ip link set down1 up
  ISP2 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  ISP2 ip route add 198.51.100.0/24 via 192.0.2.10
  INET ip addr add 192.0.2.10/24 dev inet1; INET ip link set inet1 up
  INET ip route add 100.64.0.0/24 via 192.0.2.1
  R ip link set rtr-wan2 up
}
second_wan
for i in $(seq 0 9); do INET ip addr add 198.51.100.$((17 + i * 16))/24 dev inet0; done
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_bg INET python3 -m http.server 8081 --bind 0.0.0.0 --directory "$T/pub"
for _ in $(seq 1 50); do INET sh -c "exec 3<>/dev/tcp/$NL_WWW/8081" 2>/dev/null && break; sleep 0.1; done
now=$(date +%s)
sql "INSERT OR REPLACE INTO system_config VALUES ('firewall.geoip.db_url','http://$NL_WWW:8081/country.csv.gz',$now)"
sql "INSERT OR REPLACE INTO system_config VALUES ('insight.asn.db_url','http://$NL_WWW:8081/asn.csv.gz',$now)"
R "$P" --db "$DB" ipdb update
env PATRONUS_DB="$DB" RUST_LOG=info ip netns exec nl-rtr "$P" --db "$DB" applyd --socket "$PATRONUS_APPLYD_SOCKET" --group nogroup >>"$T/applyd.log" 2>&1 &
for _ in $(seq 1 40); do [ -S "$PATRONUS_APPLYD_SOCKET" ] && break; sleep 0.25; done
nl_web_start "$DB"; nl_login
must 200 PUT /interfaces/rtr-wan2 '{"role":"opt1","ipv4_mode":"static","ipv4":["100.64.0.2/24"],"gateway4":"100.64.0.1"}'
must 201 POST /routing/gateways '{"name":"WAN1","interface":"@wan","description":"Fibre"}'
must 201 POST /routing/gateways '{"name":"WAN2","interface":"@opt1","monitor_ip":"192.0.2.10","description":"LTE backup"}'
must 201 POST /routing/groups '{"name":"FAILOVER","members":"WAN1:1, WAN2:2","trigger":"loss_latency"}'
must 200 PUT /routing/default '{"ipv4":"FAILOVER"}'
must 201 POST /uplinks/probes '{"gateway":"WAN1","kind":"dns","target":"198.51.100.53","name":"www.example.test"}'
must 201 POST /uplinks/probes "{\"gateway\":\"WAN1\",\"kind\":\"tcp\",\"target\":\"$NL_WWW\",\"port\":80}"
must 201 POST /uplinks/probes '{"gateway":"WAN2","kind":"tcp","target":"198.51.100.17","port":8081,"critical":true}'
must 200 PUT /uplinks/settings '{"sla_target":99.5}'

# three devices on the LAN
for a in 11 12; do C ip addr add 192.168.50.$a/24 dev lan0; done
for d in "laptop 192.168.50.10 home" "tv 192.168.50.11 home" "cam 192.168.50.12 home"; do
  set -- $d
  sql "INSERT INTO seg_devices (name, group_id, segment, ip4, state, created_at, kind) VALUES ('$1',(SELECT id FROM seg_groups WHERE name='$3'),'@lan','$2','active',$now,'wired')"
done
sql "UPDATE seg_devices SET group_id = (SELECT id FROM seg_groups WHERE name='quarantine') WHERE name='cam'"
dl() { C curl -s -m 30 --interface "$1" -o /dev/null "http://198.51.100.$2:8081/big.bin" || true; }
# laptop: heavy, many countries; tv: streaming from GB/US; cam: uploads to one cloud
for r in 1 2 3; do for h in 17 33 49 65 81 97 113 129; do dl 192.168.50.10 $h; done; done
for r in 1 2 3 4 5 6; do dl 192.168.50.11 81; dl 192.168.50.11 17; done
for r in 1 2; do dl 192.168.50.12 17; done
sleep 8

# seeded earlier history (24 h): uplink samples + hourly rollup, traffic buckets
python3 - "$DB" <<'EOF'
import math, random, sqlite3, sys, time, json
random.seed(7)
c = sqlite3.connect(sys.argv[1], timeout=30)
now = int(time.time()); now -= now % 60
hours = {}
def put(ts, gw, state, rtt, loss, probes_failed=False):
    deg = 1 if (state == "online" and probes_failed) else 0
    c.execute("INSERT OR IGNORE INTO ins_uplink_samples (ts,gateway,state,rtt_ms,loss_pct,icmp_ok,tcp_ok,dns_ok,http_ok,degraded,probes) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
              (ts, gw, state, rtt, loss, 0 if state == "down" else 1, None, 0 if probes_failed else (1 if gw == "WAN1" else None), None, deg, "[]"))
    h = ts - ts % 3600
    hr = hours.setdefault((h, gw), dict(n=0, up=0, good=0, deg=0, down=0, rs=0.0, rn=0, rm=None, ls=0.0))
    hr["n"] += 1
    if state == "down": hr["down"] += 1
    else:
        hr["up"] += 1
        if state == "online" and not deg: hr["good"] += 1
        else: hr["deg"] += 1
    if rtt is not None:
        hr["rs"] += rtt; hr["rn"] += 1; hr["rm"] = rtt if hr["rm"] is None else max(hr["rm"], rtt)
    hr["ls"] += loss
for ts in range(now - 24 * 3600, now - 300, 60):
    age_h = (now - ts) / 3600
    for gw in ("WAN1", "WAN2"):
        base = 9 if gw == "WAN1" else 48
        rtt = base + 4 * math.sin(ts / 1700) + random.random() * 3
        state, loss, pf = "online", 0.0, False
        if gw == "WAN1":
            if 15.2 < age_h < 15.45 or 6.1 < age_h < 6.17: state, rtt, loss = "down", None, 100.0
            elif 9.0 < age_h < 9.5: rtt += 130; state = "latency"
            elif 3.0 < age_h < 3.4: pf = True            # ping fine, DNS dead
        elif 6.1 < age_h < 6.17: rtt += 6
        put(ts, gw, state, rtt, loss, pf)
for (h, gw), r in hours.items():
    c.execute("INSERT OR REPLACE INTO ins_uplink_hourly (hour,gateway,samples,up,good,degraded,down,rtt_sum,rtt_n,rtt_max,loss_sum) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
              (h, gw, r["n"], r["up"], r["good"], r["deg"], r["down"], r["rs"], r["rn"], r["rm"], r["ls"]))
# earlier traffic buckets (hourly) for the three devices
cur = now - now % 3600
rows = [("192.168.50.10", "AU", 64518, "Example Southern Transit", .2), ("192.168.50.10", "US", 64510, "Example Cloud Inc.", 1.0),
        ("192.168.50.10", "DE", 64511, "Beispiel Hosting GmbH", .5), ("192.168.50.11", "GB", 64514, "Example Streaming Ltd", 1.6),
        ("192.168.50.11", "US", 64510, "Example Cloud Inc.", .6), ("192.168.50.12", "US", 64510, "Example Cloud Inc.", .15)]
for k in range(1, 24):
    b = cur - k * 3600
    hr = (b // 3600) % 24
    act = 0.3 + 0.7 * max(0, math.sin((hr - 7) / 24 * 2 * math.pi)) if True else 1
    for ip, cc, asn, org, w in rows:
        dn = int(w * act * (20e6 + random.random() * 80e6)); up = int(dn * (0.9 if ip.endswith(".12") else 0.06))
        for d, by in (("down", dn), ("up", up)):
            c.execute("INSERT OR IGNORE INTO ins_usage (bucket,ip,dir,country,asn,asn_org,bytes,packets,flows) VALUES (?,?,?,?,?,?,?,?,?)",
                      (b, ip, d, cc, asn, org, by, by // 1200, random.randint(3, 40)))
c.commit()
EOF
touch /t/shots.ready
echo "shots lab is up (web $NL_UI inside nl-rtr)"
sleep 7200
