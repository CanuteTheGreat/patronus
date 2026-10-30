# Device segmentation: per-device identity, default isolation, DNS policy, insight, time limits

Status: **design for owner review** (2026-10-29). No product code is changed by this
document. A throw-away spike backs the two riskiest claims; it lives on the branch
`spike/device-segmentation` (commit `c1503ba4`, `spikes/device-segmentation/`, not in the
workspace, not on `main`).

Origin: the owner asked to compare SPR (Secure Programmable Router,
github.com/spr-networks/super, BSD-3-Clause) with Patronus and design the best ideas into
Patronus. SPR is a reference for *ideas*. Nothing is copied: every part below is a Rust
re-implementation on Patronus' own store / applier / netlab pattern. If a later change does
copy an SPR file, keep its BSD-3 notice beside it.

## 0. Summary

| | Item | Verdict | Estimate (agent-days) |
|---|---|---|---|
| F | Shared foundation (lane `s`, groups + devices model, DHCP binding, RBAC area, USE flags) | needed first | 3 |
| b | Default-deny inter-device isolation in nftables | **proven in the lab** (23/23) | 6 |
| a | Per-device Wi-Fi credentials (hostapd WPA2 per-MAC PSK, WPA3 SAE ids) | **proven on mac80211_hwsim** (26/26), with one stock-hostapd limitation | 9 |
| c | Per-device/group DNS policy, rebinding protection, DNS logs | config **proven** (8/8) on stock unbound | 5 |
| d | Country/ASN insight + uplink health history | design only; data sources verified | 6.5 |
| e | Parental time limits (windows + daily quota) | design only | 4 |
| | **Total** | | **33.5** |

Recommended order: **F + b -> c1 (rebinding, 0.5 d, ships alone) -> a -> c2 (views/logs) -> e -> d**
(section 9).

Two facts from the spike change the design compared with a naive port of SPR:

1. **Stock hostapd cannot hot-reload SAE passwords.** `wpa_psk_file` (WPA2) reloads live with
   `hostapd_cli reload_wpa_psk`; per-device `sae_password=...|mac=...|id=...` lines are read
   only at start (reload + deauth: the revoked phone re-joined; restart: refused). SPR gets
   live reload from its own hostap fork (`sae_psk_file`, `sae_track_password`; the 2.10
   binaries contain neither string). See 5.2.
2. **The default `LAN -> any accept` rule and the base `ct state established accept` would
   defeat isolation and revocation**, so the segmentation chain must run *before* them
   (own table, hook priority -10) and must drop flows to a revoked device even when
   conntrack says "established". See 6.3.

## 1. Gap analysis: SPR vs Patronus today

Status: **present** / **partial** / **missing**. Evidence = code in `CanuteTheGreat/patronus`
`main` at `01be8b10`, found by reading and grepping, not by guessing.

| # | SPR feature | Patronus today | Evidence |
|---|---|---|---|
| 1 | Per-device Wi-Fi passwords (WPA2 per-MAC PSK, WPA3 SAE ids) | **missing**. A hostapd generator exists but is dead code: `wireless.rs` is **not declared** in `patronus-network/src/lib.rs` (never compiled), nothing in `patronus-config/migrations/`, no applier, route or template mentions Wi-Fi. Even the dead code writes ONE shared `wpa_passphrase` / `sae_password` for the whole AP. | `crates/patronus-network/src/wireless.rs:270-395` (`generate_hostapd_config`, single `passphrase`); `grep -rn "mod wireless" crates` = no hit; `ls migrations/` has no wireless file |
| 2 | Isolation by default, bidirectional groups, one-way service rules | **missing**. No MAC (`ether saddr`) matching anywhere in the firewall renderer; the seeded default is "Allow LAN to any" (forward); bridge members are layer 2 and explicitly NOT filtered (`bridges_stay_layer2`). "Groups" in Patronus are RBAC groups (accounts), not device groups. Building blocks that exist: host aliases rendered as nft sets, schedules, per-interface rules, DHCP reservations. | `crates/patronus-config/src/defaults.rs:12-13`; `AGENTS.md` "Bridges are layer 2"; `crates/patronus-web/src/routes/api/groups.rs` (RBAC); `crates/patronus-firewall/src/aliases.rs` (sets); `migrations/0300_d_lan_services.sql:51` (`dhcp_static_mappings`) |
| 3a | Per-device DNS rules / overrides / block lists | **partial**. unbound resolver/forwarder with global block lists (manual + URL lists, `always_nxdomain` or null), global host and domain overrides, DNSSEC, per-interface access-control. Nothing is per device or per group. | `crates/patronus-network/src/dns.rs:579-700` (`render_unbound`), `migrations/0300_d_lan_services.sql:110-139` |
| 3b | DNS rebinding protection | **missing**. No `private-address` in the generated unbound.conf (`private-domain` is emitted only for domain overrides). | `dns.rs:669` (only `private-domain`); `grep private-address dns.rs` = none |
| 3c | DNS logs | **missing**. unbound runs `use-syslog: yes`, `verbosity: 1`; no `log-queries`, no per-client store or UI. | `dns.rs:589` |
| 4a | Traffic insight by country / ASN | **missing**. `/insights` ranks conntrack flows by host, service and protocol, no history ("the router keeps no history"). A DB-IP *country* database (CSV, download, refresh, `GeoDb::lookup`) exists but is used only for GeoIP alias sets (blocking), not for insight. **No ASN data anywhere.** | `crates/patronus-web/src/routes/api/insights.rs:6,30,85`; `crates/patronus-firewall/src/feeds.rs:587-735` (`GeoDb`); no ASN database or lookup in firewall/network/web/config (the only `asn` hits are BGP settings in `frr.rs`) |
| 4b | Uplink / internet health | **partial**. Gateway monitor in `patronus applyd`: ping per gateway, loss and latency thresholds, failover groups (tiers, ECMP weights), status file. No history or graphs, no alert events, ICMP only (an ISP that answers ping but has broken DNS looks healthy). | `crates/patronus-network/src/routes.rs` (`Monitor`, `Trigger::Loss/Latency`, `probe` ~2333), `AGENTS.md` "Routing (lane E)" |
| 5a | Parental: time windows | **partial**. Firewall schedules (weekdays + daily window, wraps midnight, re-applied when a window starts/ends, fake-clock hook for CI). Per rule, not per device. | `crates/patronus-firewall/src/schedule.rs` (`scheduled_rule_states` :210), `firewall_rules.schedule` |
| 5b | Parental: daily time quota, family DNS | **missing**. `patronus-captiveportal` (vouchers, bandwidth) is only reachable from `patronus-cli` and never reads the store or the web UI. | `crates/patronus-cli/src/main.rs:683`; `crates/patronus-captiveportal/src/*` (1446 lines, no store access) |
| 6a | WireGuard | **present** (stronger, see below) | `crates/patronus-network/src/wireguard.rs`, `migrations/0500_f_vpn.sql`, `ci/netlab/lane-f-wireguard.sh` |
| 6b | Multi-WAN with load balancing | **present** | `migrations/0400_e_routing.sql` (`route_gateways`, `route_gateway_groups`), `ci/netlab/lane-e-routing.sh` |
| 6c | Plugin API | **partial / different**. Signed plugin bundles (ed25519, supervised service) and API keys exist. No runtime plugin API or event bus like SPR's docker plugins + `sprbus`. | `crates/patronus-network/src/plugins.rs`, `migrations/1270_n_plugins.sql`, `routes/api/apikeys.rs` |

### Where Patronus is ahead of SPR

- **Atomic, fail-closed firewall.** One `nft -f` transaction for the whole ruleset, lockdown
  ruleset if the kernel had no table at boot, an unassignable rule is skipped, never widened
  (`crates/patronus-firewall/src/applier.rs` header).
- **One store, one Applier per subsystem, GitOps, revisions and rollback**
  (`patronus-config`, `patronus-gitops`); export/import of every lane.
- **Netlab proof** of kernel state in CI (`ci/netlab/lane-*.sh`), mutation-score floors,
  claims ledger.
- **Wider network feature set than SPR**: HA (VRRP/conntrackd, `ha.rs`), BGP/OSPF via FRR
  (`frr.rs`), IPsec (site-to-site and road warrior), OpenVPN, L2TP, VRF, NAT64, UPnP, IDS/IPS
  with Suricata (`ids.rs`), threat-intel feeds and GeoIP *blocking* sets, CAKE shaping,
  SD-WAN crates.
- **Accounts**: RBAC with areas, LDAP, TOTP, API keys, audit log.
- **Gentoo/USE-flag packaging** and bootable installer ISO.
- SPR's identity model (per-device /30, unspoofable MAC + passphrase) is stronger *at the
  Wi-Fi layer*; Patronus has no equivalent today. That is what this document adds.

## 2. Shared model (foundation F)

A new migration lane **`s`** (`1300-1399`, add `("s", 1300, 1399)` to
`patronus-config/src/migrate.rs::LANE_RANGES`; `lane_ranges_are_respected` enforces it).
All tables prefixed `seg_` (and `ins_` for insight, see 7). Feature gate: Cargo/USE flag
`segmentation` (nft + DNS parts) and `wifi-ap` (hostapd; RDEPEND `net-wireless/hostapd`),
added to network/web/cli crates and both ebuilds like lane N did (AGENTS.md "Lane N").

```sql
-- 1300_s_segmentation.sql  (sketch; final column types in review)
CREATE TABLE seg_groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,           -- [a-z0-9_-]{1,32}
  description TEXT,
  intra INTEGER NOT NULL DEFAULT 1,    -- members may talk to each other
  internet TEXT NOT NULL DEFAULT 'allow',  -- allow | deny
  quarantine INTEGER NOT NULL DEFAULT 0,
  builtin INTEGER NOT NULL DEFAULT 0,
  dns_policy_id INTEGER, time_policy_id INTEGER
);
CREATE TABLE seg_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  mac TEXT UNIQUE,                     -- NULL while a Wi-Fi device is 'pending' (name only)
  group_id INTEGER NOT NULL REFERENCES seg_groups(id),
  kind TEXT NOT NULL,                  -- wifi | wired | vpn
  segment TEXT NOT NULL,               -- '@lan' / '@opt1' role or interface name; vpn: wg ifname
  ip4 TEXT,                            -- reservation (see 2.1); NULL only for 'pending'
  wg_peer_id INTEGER,                  -- kind=vpn: identity is the key, not a MAC
  state TEXT NOT NULL DEFAULT 'active',-- pending | active | revoked
  dns_policy_id INTEGER, time_policy_id INTEGER,  -- per-device override of the group's
  created_at INTEGER NOT NULL, activated_at INTEGER, revoked_at INTEGER,
  last_seen INTEGER, last_ip TEXT, note TEXT
);
CREATE TABLE seg_links    (id INTEGER PRIMARY KEY AUTOINCREMENT, group_a INTEGER NOT NULL, group_b INTEGER NOT NULL,
                           UNIQUE(group_a, group_b));            -- bidirectional
CREATE TABLE seg_services (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
                           src_kind TEXT NOT NULL, src_id INTEGER NOT NULL,   -- device | group
                           dst_kind TEXT NOT NULL, dst_id INTEGER NOT NULL,
                           proto TEXT NOT NULL, ports TEXT NOT NULL,          -- tcp|udp, "80,443,8000-8010"
                           schedule TEXT, enabled INTEGER NOT NULL DEFAULT 1);
```

Wi-Fi, DNS, time and insight tables are given in their sections. Rules of the road:

- Secrets (`seg_wifi_creds.secret`) sit in the store like WireGuard private keys and IPsec
  PSKs do today: DB is `patronus`-owned 0600, the API never lists them; a *reveal* is an
  explicit admin-only call that writes an `audit_log` row. `export_json()` must redact
  them unless the operator asks for a full backup (same as WG keys).
- **Seeding / migration**: nothing changes on upgrade. `seg.enabled` is `0`. Turning
  segmentation on for an interface runs an *adoption* step: every current DHCP lease /
  reservation / ARP entry on that interface becomes a device in the built-in group `home`
  (`intra=1`, `internet=allow`) so behaviour is identical on day one. The owner then
  tightens (move the TV to `iot`, add a link, ...). Built-in groups: `home`, `quarantine`
  (`internet=deny`, `quarantine=1`).
- **GitOps**: `resource_kinds()` for `SegGroup`, `SegLink`, `SegService`, `SegDevice`
  (credentials excluded from the declarative form; they are generated, or referenced by
  secret name through `patronus-secrets`).
- **RBAC**: new area `("segmentation", "Device groups, Wi-Fi credentials, DNS and time policies")`
  in `patronus-web/src/rbac.rs::AREAS`; reading credentials needs `admin`.

### 2.1 Device identity binding

The nft layer keys a device by `(ingress interface, MAC, IPv4)` (spike: set
`bound_v4`, type `ifname . ether_addr . ipv4_addr`). The IPv4 must therefore be stable:
creating a device **allocates a DHCP reservation** in the segment's pool
(`dhcp_static_mappings`, outside the dynamic range) and the applier for kea/dnsmasq already
renders it. No lease-file watcher is needed in v1; a device that ignores its reservation and
uses another address is dropped as spoofed (spike section 5). VPN devices (`kind=vpn`) bind
`ifname . ipv4_addr` of their WireGuard peer; the kernel's cryptokey routing already prevents
source spoofing, so no MAC is involved.

## 3. How the pieces fit in the running system

```
hostapd (per-SSID)      kea/dnsmasq          unbound
  wpa_psk_file  ----->  reservations ---->   views keyed by device IPv4
  sae_password          (mac->ip)            (+ rebinding, logs)
       |                    |
  seg_wifi_creds       seg_devices  <---- seg_groups / seg_links / seg_services
                            |
                  patronus_firewall::seg_rules   (new, like svc_rules.rs / vpn_rules.rs)
                            |  rendered into the SAME atomic nft -f transaction
                 table inet patronus_seg  (forward & input hooks, priority -10)
                 table inet patronus      (unchanged: anti-lockout, user rules, NAT)
```

Applier registration follows AGENTS.md: a `SegApplier` (phase `Firewall`, renders the nft
table into the firewall transaction and sets the bridge/ARP sysctls), a `WifiApplier`
(phase `Services`, hostapd), the existing `DnsApplier` extended. All behind
`RemoteApplier::wrap` for the root broker; one line each in
`patronus-cli/src/commands/apply.rs::registry()`.

## 4. (b) Default-deny inter-device isolation (build first)

### 4.1 Semantics

- Two devices may exchange NEW flows only if: they are in the same group with `intra=1`;
  or their groups are linked (bidirectional); or a service rule allows
  `src -> dst proto/ports` (one way; replies ride conntrack, the reverse direction stays
  denied).
- Anything else between two managed devices is dropped (default deny), logged to NFLOG
  group 7 (rate limited), which `fwlog` already collects.
- A frame from an `(iface, MAC, IP)` that is not an enrolled, un-revoked device forwards
  **nothing** (unknown / spoofed / revoked / quarantine), and an address inside the segment
  that is not a live device receives nothing, even on established flows.
- Device -> internet and device -> router stay with the ordinary rules; a group with
  `internet=deny` adds one drop for `oifname` outside the segment interfaces.
- Layer 2 must force traffic through the router: Wi-Fi `ap_isolate=1`; wired ports of the
  Patronus bridge `bridge link set dev X isolated on`; the segment bridge gets
  `proxy_arp=1`, `proxy_arp_pvlan=1`, `send_redirects=0` (all set by the sysctl/bridge
  appliers; `proxy_arp_pvlan` is what lets the router answer ARP for a device on the *same*
  interface). Spike proof below uses exactly this.

### 4.2 Generated nftables (verbatim output of the spike generator for 3 devices)

Full file: `spikes/device-segmentation/evidence/generated-pseg.nft`.

```nft
add table inet pseg
delete table inet pseg
table inet pseg {
  set seg_ifaces { type ifname; elements = { "br0" } }
  set bound_v4 { type ifname . ether_addr . ipv4_addr; elements = {
    "br0" . 02:aa:00:00:00:11 . 172.31.77.11 comment "laptop",
    "br0" . 02:aa:00:00:00:12 . 172.31.77.12 comment "cam",
    "br0" . 02:aa:00:00:00:13 . 172.31.77.13 comment "tv" } }
  set seg_v4 { type ipv4_addr; elements = { 172.31.77.11, 172.31.77.12, 172.31.77.13 } }
  set grp_iot_v4 { type ipv4_addr; elements = { 172.31.77.12, 172.31.77.13 } }
  set grp_trusted_v4 { type ipv4_addr; elements = { 172.31.77.11 } }
  set svc_v4 { type ipv4_addr . ipv4_addr . inet_proto . inet_service;
               elements = { 172.31.77.11 . 172.31.77.12 . tcp . 8080 }; }
  set seg_net_v4 { type ipv4_addr; flags interval; elements = { 172.31.77.0/24 } }
  set seg_v6 { type ipv6_addr; flags interval; elements = { fd77:31::/64 } }
  chain seg_forward {
    ip daddr @seg_net_v4 ip daddr != @seg_v4 counter drop comment "unbound or revoked destination"
    iifname != @seg_ifaces return
    ip6 saddr @seg_v6 ip6 daddr @seg_v6 counter drop comment "IPv6 between devices: denied"
    iifname . ether saddr . ip saddr != @bound_v4 limit rate 10/second log prefix "seg-unbound " group 7 counter drop
    iifname . ether saddr . ip saddr != @bound_v4 drop
    ct state established,related accept
    ct state invalid drop
    ip daddr != @seg_v4 return                       # not device-to-device: ordinary firewall decides
    ip saddr . ip daddr . meta l4proto . th dport @svc_v4 counter accept comment "service rule"
    ip saddr @grp_trusted_v4 ip daddr @grp_trusted_v4 counter accept comment "group trusted"
    ip saddr @grp_iot_v4 ip daddr @grp_iot_v4 counter accept comment "group iot"
    limit rate 10/second log prefix "seg-deny " group 7
    counter drop comment "default deny between devices"
  }
  chain forward { type filter hook forward priority -10; policy accept; jump seg_forward }
}
```

Scaling: sets are O(1) lookups; the rule count is O(groups + links), not O(devices);
service rules expand to elements of one concatenated set at render time.

### 4.3 Why a separate table at priority -10 (decision)

`inet patronus` begins with `ct state established,related accept` and seeds
`LAN -> any accept` (`defaults.rs`). If the segmentation rules lived after them, neither
default deny nor revocation would work. A second table `inet patronus_seg` is loaded in
the **same `nft -f` script** as the main table (still one atomic transaction), runs first
(priority -10) and only ever decides device-to-device traffic: it accepts allowed pairs and
drops the rest, and `return`s everything else to the unchanged main table. No edit to
`base_table_script()` or to the mutation-floor files is needed. Lockdown mode (no table at
boot) omits it; fail closed is already the main table's drop policy.

An `input` chain in the same table is also required (not covered by the spike, to be
tested in lane s): from `@seg_ifaces`, unbound/quarantine sources may reach only DHCP
(udp 67/68), DNS (53), ICMP and the enrolment endpoint. The anti-lockout rule opens SSH and
the web UI (tcp 22, 8443) on the LAN role, so without this a quarantined device could reach
the admin UI.

### 4.4 Wired, VLAN, VPN

| Device type | Isolation at L2 | Identity | Status |
|---|---|---|---|
| Wi-Fi (Patronus runs the AP) | hostapd `ap_isolate=1` | MAC + per-device passphrase | proven in 5 (assoc) and 4.5 (forwarding, emulated with isolated bridge ports) |
| Wired device on a Patronus bridge port (one device per port) | `bridge link set isolated on` | MAC + reservation | **proven** (spike uses isolated veth ports of a bridge) |
| Wired devices behind an unmanaged switch (many MACs on one port) | none possible at L2 | MAC + reservation | **limitation**: the switch forwards between them without the router. v1: group them in one group and document it; options for later: DHCP `/32` + classless-route (RFC 3442) so hosts send everything via the router (not tested), or managed-switch port isolation configured by the user. |
| VLAN sub-interface (`vlans` table, lane C) | each VLAN is a separate segment interface (`segment_ifaces`), routed between VLANs through the seg chain; inside a VLAN the same isolation as above | `iifname` = the VLAN device | design; the generator already takes several segment interfaces |
| Dynamic VLAN per group (hostapd `vlanid=` in `wpa_psk_file`) | real L2 separation per group on one SSID | | **idea only**, not tested; no proxy ARP needed |
| WireGuard peer | n/a (routed) | `ifname . ipv4` of the peer | design (set `bound_vpn_v4`) |

A device that moves between interfaces/VLANs would mismatch its binding and be dropped;
v1 has one `segment` per device, v1.1 may allow a list.

IPv6: v1 denies device-to-device IPv6 inside the segment prefixes (proven: the lab
ping6 passes in the baseline and is denied with the table loaded) and leaves
device-to-internet IPv6 to the ordinary firewall. IPv6 identity binding (SLAAC/privacy
addresses) is out of scope for v1.

### 4.5 Spike evidence (b)

Run in the Patronus lab VM 107 (`ssh -i ~/.ssh/id_ed25519_patronus-lab root@10.66.69.30`,
kernel 6.18.57, nftables 1.1.7) inside five throw-away network namespaces (router +
laptop, cam, tv, unknown). The VM's own `inet patronus` table was not touched
(`nft list tables` before/after identical; namespaces and processes removed afterwards).
Generator: `seg-spike nft lab.json` (Rust, built on rw-man-03). Script:
`spikes/device-segmentation/lab/netns-isolation.sh`; full output:
`spikes/device-segmentation/evidence/netns-isolation-run.txt`.

```
== 0. baseline: no segmentation rules       (laptop->cam icmp, cam->laptop tcp, ipv6, unknown->cam)  4/4 reachable
== 2. default deny between devices (laptop=trusted, cam/tv=iot)
  PASS  laptop -> cam icmp (deny) / cam -> laptop icmp (deny) / cam -> laptop tcp 7000 (deny)
  PASS  laptop -> cam ipv6 icmp (deny)
  PASS  laptop -> tv tcp 8080 (service rule names cam only) (deny)
== 3. group = bidirectional (cam and tv both in iot)
  PASS  cam -> tv tcp 8080 (ok)      PASS  tv -> cam tcp 8081 (ok)
== 4. one-way service rule laptop -> cam tcp/8080
  PASS  laptop -> cam tcp 8080 (request and reply) (ok)
  PASS  laptop -> cam tcp 8081 (other port) (deny)
  PASS  cam -> laptop tcp 7000 (reverse direction is not allowed) (deny)
== 5. identity: unknown MAC, spoofed IP, spoofed MAC
  PASS  unknown device -> cam / -> laptop (deny)
  PASS  unknown device with the LAPTOP's IP -> cam tcp 8080 (deny)
  PASS  unknown device with the LAPTOP's MAC (own IP) -> cam tcp 8080 (deny)
== 6. revocation: re-render with cam revoked, reload atomically
    request 1/2 (before revoke, same keep-alive connection): answered
    request 3 (after revoke, same connection): no answer, TimeoutError
  PASS  keep-alive flow worked before the revoke and is cut after it
  PASS  laptop -> cam 8080 / tv -> cam 8081 (group peer) / revoked cam -> tv: all denied
RESULT: 23 passed, 0 failed       (5 consecutive runs 23/23)
```

Two harness mistakes were found and fixed on the way (documented because they look like
product bugs): a python `http.server` closes after one response, so an early "established
flow survived" result was a false positive (partial read of the previous response), and a
same-MAC spoof test leaves a stale bridge FDB entry (flush it before the next test).
The first *real* finding was ordering: the revoked-destination drop has to precede the
conntrack accept, otherwise established flows survive revocation (fixed in the generator,
unit test `unbound_destination_in_segment_is_dropped_before_established`).

### 4.6 UI, API, tests (b)

- **UI**: `/segmentation` (template `segmentation.html`, JS-rendered cards like
  `system.html`; honesty guard: live state or empty state, 501 when unmanaged). Tabs:
  *Devices* (name, MAC, IP, group, kind, state, last seen, drop counters; revoke, move
  group), *Discovered* (leases/ARP entries with no device: adopt), *Groups & policy*
  (group list with intra/internet toggles; a matrix of links; one-way service rules
  list "A -> B tcp 8080"), *Status* (what is loaded, drop log from `firewall_log`).
- **API** (`routes/api/segmentation.rs::router()`, one `.merge` line):
  `GET/POST /api/segmentation/groups`, `PUT/DELETE .../groups/{id}`,
  `GET/POST /api/segmentation/devices`, `PUT/DELETE .../devices/{id}`,
  `POST .../devices/{id}/revoke`, `GET .../discovered`, `POST .../discovered/{mac}/adopt`,
  `GET/POST .../links`, `GET/POST .../services`, `GET .../status`,
  `POST /api/segmentation/preview` (render without applying, = `patronus apply --dry-run`
  for the seg table).
  A mutation = validate -> write store -> apply -> undo on failure (existing pattern).
- **Config generation**: `patronus_firewall::seg_rules::render(store, roles)` (pure, the
  spike's `render_nft` grown up: `ifname` roles resolved like `@lan`, hostile-input
  validation as in the spike's `hostile_input_is_rejected`), plus sysctls
  (`net.ipv4.conf.<br>.proxy_arp|proxy_arp_pvlan|send_redirects`) and
  `bridge link set isolated on` in the interfaces phase.
- **Migration**: 1300 + adoption step (2). Existing installs: no behaviour change.
- **Tests**: unit tests of the renderer (spike has 6); `ci/netlab/lane-s-segmentation.sh`
  (port of `netns-isolation.sh` onto `lib.sh`: `nl_up`, `nl_assert_nft_has`, real traffic);
  `lane-s-segmentation-reboot.sh` (power cut: devices still isolated after `nl_boot`);
  `failure-atomic-apply` variant (a bad service rule leaves the old table in force);
  honesty-guard drive of the new page/API; claims-ledger rows; mutation floor for
  `seg_rules.rs`.

## 5. (a) Per-device Wi-Fi credentials when Patronus runs the AP

### 5.1 Data model

```sql
-- 1310_s_wifi.sql
CREATE TABLE seg_wifi_networks (          -- one row = one SSID on one radio interface
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
  ifname TEXT NOT NULL,                   -- wlan interface that supports AP mode
  ssid TEXT NOT NULL, band TEXT NOT NULL, channel INTEGER NOT NULL, country TEXT NOT NULL,
  security TEXT NOT NULL DEFAULT 'wpa2',  -- wpa2 | wpa2_wpa3 | wpa3
  bridge TEXT NOT NULL,                   -- segment bridge/role the AP is enslaved to
  unknown_policy TEXT NOT NULL DEFAULT 'reject',  -- reject | enrol   (5.4)
  enrol_secret TEXT, enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE seg_wifi_creds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL REFERENCES seg_devices(id) ON DELETE CASCADE,
  network_id INTEGER NOT NULL REFERENCES seg_wifi_networks(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                     -- psk | sae
  secret TEXT NOT NULL, sae_id TEXT,
  state TEXT NOT NULL DEFAULT 'active',   -- pending (MAC unknown) | active | revoked
  created_at INTEGER NOT NULL, revoked_at INTEGER, expires_at INTEGER,
  UNIQUE(network_id, secret));
```

### 5.2 hostapd integration (facts measured with hostapd/wpa_supplicant 2.10)

Generated files (the spike generator, `seg-spike hostapd`): `hostapd.conf` and
`wpa_psk_file`, both 0600, owned by root, marked "generated by Patronus" like other
appliers (`lan::MARKER`), written temp + rename.

```
# wpa_psk_file                               # hostapd.conf (WPA2+WPA3 transition shown)
keyid=laptop 02:aa:..:11 laptop-psk-4f9c2e71   wpa=2  rsn_pairwise=CCMP
keyid=phone  02:aa:..:12 phone-psk-71be09d3    wpa_key_mgmt=WPA-PSK SAE   ieee80211w=1  sae_pwe=2
                                               ap_isolate=1  multicast_to_unicast=1  tdls_prohibit=1
                                               wpa_disable_eapol_key_retries=1
                                               wpa_psk_file=/etc/hostapd/patronus-<net>.psk
                                               sae_password=laptop-sae-8d31b0aa|mac=02:aa:..:11|id=laptop
```

What the lab showed on `mac80211_hwsim` (output: `evidence/hwsim-run.txt`):

| Test | Result |
|---|---|
| hostapd 2.10 accepts the generated WPA2 and SAE configs | yes (starts, ENABLED) |
| device with its own PSK / SAE password (+id) | associates |
| another MAC using that device's PSK, or its SAE password+id | **refused** (the credential is bound to the MAC) |
| SAE password right but identifier missing | refused |
| revoke (PSK): drop entry, `reload_wpa_psk`, `deauthenticate <mac>` | AP no longer AUTHORIZED for the MAC, retries with the old PSK fail, other station unaffected, **no hostapd restart** |
| revoke (SAE): `reload_wpa_psk` + deauth, then `hostapd_cli reload` + deauth | **phone re-joined with the revoked password**: stock hostapd does not re-read `sae_password` |
| revoke (SAE): full hostapd restart | refused |
| enrolment wildcard (`00:00:00:00:00:00` entry) enabled, revoked device with its old personal PSK | refused (exact MAC entry gone, wildcard has another passphrase) |
| pending device joins with a per-device wildcard passphrase | **`AP-STA-CONNECTED <mac> keyid=dev-cam`**: the event carries the device key id and the MAC |
| entry rewritten to the learned MAC + `reload_wpa_psk` | station keeps its link; the passphrase now only works from that MAC; the other pending passphrase still works for a new MAC |

Consequences for the design:

1. **WPA2 per-MAC PSK is the default** (hot add/revoke without a hostapd restart).
2. **WPA3-SAE per device is supported but changing it restarts hostapd** (all stations
   reconnect, a few seconds). The applier debounces (>= 5 s), shows "this change restarts the
   Wi-Fi" in the UI, and `security=wpa2_wpa3` (transition) lets a device pick either; SAE
   entries are rendered only for devices that have an `sae` credential.
3. Options to avoid the restart, owner decision needed (section 10): (i) accept it;
   (ii) carry a Gentoo overlay patch for hostapd that adds SAE password reload (SPR's
   fork does this, `github.com/spr-networks/hostap`, commit pinned in its `wifid/Dockerfile`;
   hostap is BSD-licensed so reuse is possible with notices, effort ~3 days incl. rebasing
   on each hostapd bump; not estimated in the totals); (iii) WPA2 only per device.
4. **`hostapd -t` is not a config check** (it adds timestamps to debug output). There is
   no dry-run; validation is (1) the generator rejects what breaks the file formats
   (spike unit test `hostile_input_is_rejected`: `|` in an SAE password would inject
   `|mac=` options, whitespace/short PSKs, duplicate MACs, unknown groups), and (2) the
   applier starts the new config on a temp control socket only on first enable; thereafter
   a failed start restores the previous files and the old process keeps running. CI runs the
   real binary against `mac80211_hwsim` (lane s, see tests).
5. Passphrases are generated by Patronus (default 20 chars, 100 bits, base32-ish groups
   `xxxxx-xxxxx-xxxxx-xxxxx`), never user-typed, shown once with a `WIFI:T:WPA;S:..;P:..;;`
   QR code.

### 5.3 Device enrolment

1. **Admin creates the device** (name, group, kind=wifi) -> row `state=pending`, `mac=NULL`,
   a credential with `state=pending` and a fresh passphrase; the UI shows the passphrase/QR
   once. hostapd gets a wildcard line `keyid=dev-<id> 00:00:00:00:00:00 <passphrase>` (many
   wildcard entries with distinct passphrases are fine, proven).
2. **First join**: hostapd emits `AP-STA-CONNECTED <mac> keyid=dev-<id>`. A small
   watcher (a `hostapd_cli -a` action script or the control-socket attach inside applyd)
   hands `(mac, keyid)` to the store: the device gets its MAC, `state=active`, the credential
   `active`; DHCP reservation created; nft sets and `wpa_psk_file` re-rendered, wildcard line
   replaced by the MAC-bound line, `reload_wpa_psk` (the connected station keeps its link,
   proven). The window where the passphrase is usable from any MAC ends at first join;
   un-used pending credentials expire (`expires_at`, default 24 h).
3. **Admin knows the MAC** (e.g. printed on the box): create with the MAC, credential is
   MAC-bound from the start.
4. MAC randomisation: phones use a stable random MAC per SSID, which is fine; a phone set to
   "rotate every connection" cannot be bound to a MAC (UI help text; the join fails closed).

### 5.4 Unknown devices (quarantine group)

`unknown_policy` per SSID:

- `reject` (default): not in the passphrase list = cannot associate.
- `enrol`: a shared `enrol_secret` is rendered as a wildcard entry. A device that joins with
  it gets an IP from the dynamic pool but **no binding**, so the seg table drops everything it
  forwards and the `input` chain lets it reach only DHCP/DNS/the enrolment page; it shows up in
  *Discovered* with its MAC, vendor (OUI) and hostname. The admin *approves* it into a group,
  which creates the device + personal credential; the device is told its new passphrase and
  reconnects. The enrolment secret never grants access to anything.
- Wired unknown devices appear in *Discovered* from DHCP leases/ARP; unbound = dropped
  until adopted.

### 5.5 Revocation and rotation

Order matters (fail closed): (1) set `seg_devices.state=revoked` and reload the nft table
(the device is cut at once, also established flows - proven), (2) remove its credential,
`reload_wpa_psk` + `hostapd_cli deauthenticate <mac>` (SAE: debounced restart), (3) remove
the DHCP reservation. Rotation = new credential created `active` for the same MAC, old one
`revoked`; both PSKs may coexist for a configurable grace period (`expires_at`), which also
gives a no-downtime rotation.

### 5.6 UI, API, config generation, migration, tests (a)

- **UI**: *Wi-Fi* tab (networks: radio, SSID, security, unknown_policy, "restart impact"
  notice; per-device credential state with *Show passphrase / QR* (audit-logged), *Rotate*,
  *Revoke*); *Discovered* shows pending joins. The *Interfaces* page needs wireless
  interface discovery (`/sys/class/ieee80211`, `iw list` for AP-mode / bands) - a small
  addition to lane C, 1 d (counted in the estimate).
- **API**: `GET/POST /api/segmentation/wifi/networks`, `PUT/DELETE .../{id}`;
  `POST /api/segmentation/devices` with `wifi: {network_id, kind}` returns the secret
  **once**; `POST .../devices/{id}/credentials/{cid}/reveal` (admin, audit row),
  `.../rotate`, `.../revoke`; `GET .../wifi/stations` (live from `hostapd_cli all_sta`).
- **Config generation**: `patronus_network::wifi` (new, reimplementing the dead
  `wireless.rs` against the store; the dead file is deleted or reduced to the radio-capability
  helpers): `render_hostapd`, `render_psk_file`, the same functions as the spike generator
  plus multi-SSID (`bss=` blocks, each with its own `bridge=`). Services via
  `ServiceManager` with the config path passed explicitly (OpenRC `hostapd`, systemd
  `hostapd@`-style unit shipped in `files/`).
- **Migration**: 1310; none for existing installs (no Wi-Fi existed).
- **Tests**: renderer unit tests incl. hostile input; netlab `lane-s-wifi-hwsim.sh` =
  the spike's `hwsim-run.sh` ported (needs the `mac80211_hwsim` module: runs on
  rw-man-02/03 (x86_64, kernel 7.0 ships the module; tested). rw-man-04/05 (arm64) also ship
  the module but were not tried; rw-man-01 (kernel 6.8) has no `mac80211_hwsim`. Load/unload under a
  lock because the module is host-global);
  watcher test (event -> store); applier tests for "failed start keeps old files";
  secret redaction test for `export_json`.

### 5.7 Spike evidence (a)

Environment: rw-man-03 (x86_64, kernel 7.0.0-1014-aws, `mac80211_hwsim radios=4`, loaded
for the run and removed afterwards; hostapd/wpa_supplicant 2.10 from debian:trixie in a
throw-away privileged container with the phys moved into its netns; four stations in their
own netns). Script: `lab/hwsim-run.sh` + `lab/hwsim-inner.sh`; output
`evidence/hwsim-run.txt` (excerpt):

```
hostapd v2.10   wpa_supplicant v2.10
--- generated wpa_psk_file:  keyid=laptop 02:00:00:00:01:00 laptop-psk-4f9c2e71 / keyid=phone 02:00:00:00:02:00 phone-psk-71be09d3
  PASS  hostapd accepted the generated config and is ENABLED
  PASS  laptop with its own PSK -> associated        PASS  phone with its own PSK -> associated
  PASS  stranger MAC using the laptop's PSK -> refused (state=SCANNING)
  PASS  phone using the LAPTOP's PSK -> refused (state=SCANNING)
--- revoke the phone: reload_wpa_psk + deauthenticate (no hostapd restart)
  PASS  AP no longer has the revoked phone AUTHORIZED
  PASS  revoked phone is disconnected and its old PSK is refused on retry     PASS  laptop unaffected
  PASS  revoked phone with its old personal PSK (enrolment wildcard enabled) -> refused
  AP-STA-CONNECTED 02:00:00:00:03:00 keyid=dev-cam                (pending-device join)
  PASS  the already-associated camera keeps its link across the reload
  PASS  another MAC with the camera's now-bound passphrase -> refused
--- SAE: sae_password=laptop-sae-8d31b0aa|mac=02:00:00:00:01:00|id=laptop
  PASS  laptop/phone with SAE password + identifier -> associated
  PASS  stranger MAC / phone with the laptop's SAE password+id -> refused
  PASS  phone with the right SAE password but WITHOUT the identifier -> refused
  (a) reload_wpa_psk + deauth: phone state COMPLETED   <- not reloaded
  (b) hostapd_cli reload + deauth: phone state COMPLETED   <- not reloaded
  (c) full hostapd restart: phone SCANNING, laptop COMPLETED  PASS
RESULT: 26 passed, 0 failed
```

What is **not** proven: real radios (roaming, 802.11r, 6 GHz/WPA3-only clients, client
quirks with SAE identifiers), DHCP/forwarding over the hwsim link (the forwarding proof in
4.5 is separate, over veth), and the quarantine `input` chain.

## 6. (c) Per-device / per-group DNS policy and rebinding protection

### 6.1 Approach on the existing stack

The existing applier renders unbound (`dns.rs::render_unbound`, `DnsApplier`, validated and
installed via `lan::install`). unbound already offers what is needed; nothing new to run:

- **Views** keyed by client address: `access-control-view: <ip>/32 view_<policy>`, a
  `view:` block per policy with `view-first: yes` (fall back to the global policy) holding
  `local-zone: "<d>." always_nxdomain|always_null` and `local-data` overrides. The device's
  IP is the one reserved in 2.1, so DNS and nft use the same identity.
- **Rebinding protection**: `private-address:` for 10/8, 172.16/12, 192.168/16, 169.254/16,
  fd00::/8, fe80::/10 plus `private-domain:` for every local zone and domain override
  (the existing code already emits `private-domain` for overrides at `dns.rs:669`).
- **Logs**: `log-queries: yes`, `log-replies: yes`, `log-tag-queryreply: yes`,
  `logfile:` (lines carry the client address).
- Enforcement of "use my resolver": a prerouting `redirect` of udp/tcp 53 from segment
  interfaces to the local resolver and an optional drop of tcp 853 (DoT) in the seg table.
  DoH cannot be blocked reliably; stated as a limitation in the UI.

Spike (`lab/dns-views.sh`, unbound 1.26.2, `evidence/dns-views-run.txt`, 8/8 pass):

```
PASS  unbound-checkconf accepts the views/private-address config
PASS  default device resolves games.example -> 198.51.100.7
PASS  'kid' device: games.example -> NXDOMAIN (view_kid block)
PASS  'kid' device: other names still resolve (view-first falls back to global policy)
      evil.rebind.example (-> 192.168.1.10): status=NOERROR answer=[]          # record stripped
PASS  private address stripped from a public name's answer
PASS  only the private record of a mixed answer is removed  ([93.184.216.35])
PASS  private-domain home.example may resolve to private addresses
      [..] unbound[691:0] query: 127.0.0.2 games.example. A IN
      [..] unbound[691:0] reply: 127.0.0.2 games.example. A IN NXDOMAIN 0.000000 1 42
```

(The config in the spike is hand-written in the shape the applier would render; the Rust
renderer is part of the implementation estimate.)

### 6.2 Data model

```sql
-- 1320_s_dns.sql
CREATE TABLE seg_dns_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
  block_mode TEXT NOT NULL DEFAULT 'nxdomain',     -- nxdomain | null
  blocklist_urls TEXT NOT NULL DEFAULT '',          -- extra lists on top of the global ones
  family INTEGER NOT NULL DEFAULT 0,                -- family preset: adult/malware lists + safe-search CNAMEs
  log_queries INTEGER NOT NULL DEFAULT 0,           -- DNS logs are sensitive: off by default, per policy
  inherit_global INTEGER NOT NULL DEFAULT 1);       -- view-first
CREATE TABLE seg_dns_rules (                        -- per policy: block / allow / override
  id INTEGER PRIMARY KEY AUTOINCREMENT, policy_id INTEGER NOT NULL REFERENCES seg_dns_policies(id) ON DELETE CASCADE,
  action TEXT NOT NULL,                             -- block | allow | override
  domain TEXT NOT NULL, address TEXT);
CREATE TABLE seg_dns_log (                          -- ring buffer, default 7 days / 200k rows
  ts INTEGER NOT NULL, client TEXT NOT NULL, device_id INTEGER, qname TEXT NOT NULL,
  qtype TEXT, rcode TEXT, blocked INTEGER NOT NULL DEFAULT 0);
```

Global settings in `system_config`: `dns.rebind_protection` (**off on upgraded installs, on
for new ones**: split-horizon setups that resolve a public name to a private address would
break silently), `dns.rebind_exceptions` (domains -> extra `private-domain`).
Groups/devices point at a policy (`dns_policy_id`; device overrides group).

Memory: one `view:` per policy duplicates its block list; with several 100k-domain lists and
many policies prefer unbound **tags** (`define-tag`, `local-zone-tag`,
`access-control-tag`, `access-control-tag-action`) so each list is loaded once. Tags were
not tested in the spike (views were); the implementation starts with tags and a test of
memory/lookup, falls back to views if a needed action is not tag-capable.

### 6.3 Log ingestion

patronus-web (or applyd) tails the unbound logfile (`inotify`/poll), maps client IP to
`device_id` via `seg_devices.ip4`, inserts into `seg_dns_log` in batches and prunes by age and
row count. Stored only for policies with `log_queries=1`. Logrotate-safe (reopen on inode
change). An export/CSV button and a *clear* button; excluded from `export_json()` by
default.

### 6.4 UI, API, tests (c)

- **UI**: *DNS* tab: policies (block lists, family preset, log toggle), rules table, per
  device/group assignment, live log view with filters (device, domain, blocked only).
- **API**: `/api/segmentation/dns/policies` CRUD, `.../policies/{id}/rules`,
  `PUT /api/segmentation/devices/{id}` (`dns_policy_id`), `GET .../dns/log?device=&since=`,
  `PUT /api/dns/settings` gains `rebind_protection`, `rebind_exceptions`.
- **Family preset**: adult/malware lists plus safe-search CNAMEs (Google
  `forcesafesearch.google.com`, Bing `strict.bing.com`, YouTube `restrict.youtube.com`);
  the exact hostnames are verified against the providers' docs at implementation time.
- **Tests**: renderer unit tests (golden unbound.conf, `unbound-checkconf` in CI where
  unbound is installed, as `dns.rs` tests already do); netlab `lane-s-dns.sh` = spike
  script using the netlab LAN client from two bound devices; log-tail unit test with
  rotation; upgrade test (`upgrade-store.sh` pattern): old install keeps rebinding off and
  resolves a split-horizon name.

## 7. (d) Country / ASN traffic insight and uplink health

### 7.1 Data sources (verified)

- **Flows**: `/proc/net/nf_conntrack` with byte counters (`nf_conntrack_acct` is already
  enabled by the sysctl applier; parsing exists in `insights.rs::parse_flows`).
- **Country**: the existing DB-IP "IP to Country Lite" CSV (`feeds.rs::GeoDb`, download +
  refresh + status already in `fwfeeds`).
- **ASN**: DB-IP "IP to ASN Lite" (`https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.csv.gz`;
  both the current and the previous month answer HTTP 200 today, CC-BY 4.0). New `AsnDb`
  next to `GeoDb` (sorted ranges + binary search, same refresh code, `start,end,asn,org`).
- **Reuse of w2fire**: `devsecops-dashboard-fix/w2fire/src/geoip.rs` (272 lines, `maxminddb`
  with GeoLite2 country + ASN mmdb) gives the **API shape** worth keeping
  (`lookup(ip) -> GeoInfo`, `lookup_asn(ip) -> AsnInfo{asn, organization}`,
  `networks_for_asn(asn)`, `is_known_datacenter_asn`). We do **not** take the `maxminddb`
  dependency or GeoLite2: it needs a MaxMind account/licence key and EULA acceptance, while
  Patronus already ships DB-IP CSV with no account. An optional `geoip-mmdb` feature that
  reads a user-supplied `.mmdb` can be added later behind the same trait.
  CC-BY attribution for DB-IP is shown on the Insights page footer.

### 7.2 Collection and storage

A collector task (patronus-web, same pattern as `scheduled_rule_states`) polls conntrack
every 15 s, keeps the last counters per flow, and adds the *delta* per
`(hour bucket, device_id, direction, country, asn)`; flows that vanish between polls lose at
most one interval (acceptable; `conntrack -E` DESTROY events are the precise alternative, v2).

```sql
-- 1330_s_insight.sql (prefix ins_ for the insight/uplink tables, lane s owns them)
CREATE TABLE ins_usage (bucket INTEGER NOT NULL, device_id INTEGER, ip TEXT, dir TEXT NOT NULL,
  country TEXT, asn INTEGER, asn_org TEXT, bytes INTEGER NOT NULL, packets INTEGER NOT NULL, flows INTEGER NOT NULL,
  PRIMARY KEY (bucket, device_id, ip, dir, country, asn));
CREATE TABLE ins_uplink_samples (ts INTEGER NOT NULL, gateway TEXT NOT NULL, state TEXT NOT NULL,
  rtt_ms REAL, loss_pct REAL, dns_ok INTEGER, http_ok INTEGER, PRIMARY KEY (ts, gateway));
```

Retention default 30 days of hourly buckets, top-N per bucket (default 200) with the rest
folded into `country='--'`; a per-group switch turns collection off for privacy.
Unknown devices are recorded by IP only.

### 7.3 Uplink health

Reuse `routes::Monitor` (loss/latency state per gateway already computed and published)
and add: (1) a sample writer (1 per minute per gateway into `ins_uplink_samples`),
(2) optional extra probes per gateway (DNS lookup of a configurable name through that
gateway, HTTPS HEAD) so "ping works but DNS is dead" shows as degraded, (3) events:
write uplink up/down/degraded to the existing events table (`0720_h_events.sql`) so
alerting that exists for other events applies, (4) retention 7 days of samples.

### 7.4 UI, API, tests (d)

- **UI**: extend `/insights` with tabs *Countries*, *ASNs*, *Devices* (device drill-down:
  top countries/ASNs, bytes over time) and an *Uplinks* panel (state, RTT/loss sparkline,
  last 24 h availability %, per gateway).
- **API**: `GET /api/insights/countries?window=24h&device=`, `.../asns`, `.../devices/{id}`,
  `GET /api/uplinks/health?gateway=&since=`.
- **Tests**: `AsnDb::parse`/`lookup` unit tests like the `GeoDb` ones (range edges, v6);
  collector delta logic with scripted conntrack text (restart, counter reset, flow
  expiry); netlab `lane-s-insight.sh` extends `lane-n-insights.sh`: real flows to two
  addresses in the ISP/inet namespaces mapped by a tiny CSV fixture (no real internet
  lookups); uplink test with a gateway namespace taken down (the Monitor part exists in
  `lane-e-routing.sh`).

**Status: implemented** (lane s part d, 2026-10-29): see `docs/INSIGHT-UPLINK.md`.
Deviations from the sketch above: `ins_usage` is keyed by the internal IP (the
device join happens at query time, so the history also works without
`seg_devices`); `ins_exclude` holds the privacy exclusions (ip/CIDR, device
name, group name); the uplink tables add an hourly rollup (`ins_uplink_hourly`,
90 days) next to the 7 days of raw samples; probes are `ins_uplink_probes`
(tcp/http/dns, optional `critical` = counts as loss for failover).

## 8. (e) Parental time limits

### 8.1 Model

```sql
-- 1340_s_time.sql
CREATE TABLE seg_time_policies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
  daily_limit_minutes INTEGER,          -- NULL = no quota
  reset_hour INTEGER NOT NULL DEFAULT 6,-- the "day" rolls over at 06:00 local, not midnight
  active_bytes_per_min INTEGER NOT NULL DEFAULT 20000,  -- a minute counts as used above this
  allow_dns INTEGER NOT NULL DEFAULT 1);               -- keep DNS/DHCP while blocked
CREATE TABLE seg_time_windows (policy_id INTEGER NOT NULL, days TEXT NOT NULL,   -- e.g. "mon,tue,wed"
  start TEXT NOT NULL, end TEXT NOT NULL);           -- end < start wraps midnight (same as firewall schedules)
CREATE TABLE seg_time_usage (day TEXT NOT NULL, device_id INTEGER NOT NULL,
  used_minutes INTEGER NOT NULL DEFAULT 0, bonus_minutes INTEGER NOT NULL DEFAULT 0,
  paused INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, device_id));
```

Policies attach to a group or a device (device wins). Windows reuse the `Schedule` type and
clock of `patronus_firewall::schedule` (so `PATRONUS_FAKE_TIME_FILE` works in netlab, midnight
wrap and DST are already handled).

### 8.2 Enforcement

A minute ticker (same spawn pattern as `scheduled_rule_states`) per device: outside every
window, or `used_minutes >= limit + bonus`, or `paused` -> the device's IPv4 is added to the
named set `seg_time_blocked_v4` with `nft add element` (no full reload, so the other
devices see no blip), and a seg-table rule drops its forwarded traffic (DNS/DHCP kept when
`allow_dns`). A minute is *used* when the device moved more than `active_bytes_per_min`
(per-element nft counters on `seg_v4` or the conntrack delta already collected for (d)),
so an idle phone does not burn the quota. State survives reboot (usage rows; `patronus
apply` recomputes the blocked set before the first packet is forwarded: fail closed).
Parent actions: *+30 min today*, *Pause internet now*, *Resume*.

### 8.3 UI, API, tests (e)

- **UI**: *Time limits* tab: policies (windows grid, daily minutes), who it applies to, a
  live per-device bar "used 74 / 120 min", override buttons.
- **API**: `/api/segmentation/time/policies` CRUD (+ `/windows`), `POST
  /api/segmentation/devices/{id}/time/bonus {minutes}`, `.../pause`, `.../resume`,
  `GET .../time/usage?day=`.
- **Tests**: ticker logic as a pure function over a fake clock (window edges, midnight
  wrap, reset hour, DST day); netlab `lane-s-time.sh`: fake-time file moves a device out of
  its window and back, quota exhaustion cuts HTTP while DNS stays, reboot keeps the block.

## 9. Order of work and estimates

Agent-day = one agent working a day including CI iteration on the rw-man hosts.
The spike's generator and the three netlab-style scripts are reused, which is why (a) and
(b) are cheaper than they look cold.

| Step | Work | Days |
|---|---|---|
| F | lane `s`, `seg_groups/devices/links/services`, RBAC area, USE flags + both ebuilds, DHCP reservation binding, adoption wizard, GitOps kinds, claims rows | 3 |
| b | `seg_rules.rs`, sysctls + bridge isolation, input chain (quarantine), API + page, `lane-s-segmentation(.reboot).sh`, mutation floor | 6 |
| c1 | rebinding protection setting + exceptions (global, default off on upgrade) | 0.5 |
| a | wireless discovery (1), `wifi.rs` renderer + `WifiApplier` (2.5), enrolment watcher + pending/approve flow (2), revoke/rotate/QR/audit + UI (2), hwsim CI lane (1.5) | 9 |
| c2 | views/tags renderer, policies + rules, family preset, log tail + store + UI, tests | 4.5 |
| e | ticker, nft element updates, usage, UI/API, tests | 4 |
| d | `AsnDb` + refresh (1.5), collector + `ins_usage` (2), API/UI (1.5), uplink samples/probes/events (1.5) | 6.5 |
| | **Total** | **33.5** |

Not included: a hostapd SAE-reload patch (~3 d, only if the owner wants live SAE revoke),
IPv6 identity binding (~4 d), DHCP `/32` + classless-route hardening for wired devices behind
dumb switches (~2 d plus real-device validation).

Recommended order and why:

1. **F + b**. It needs no Wi-Fi hardware, works for wired and VLAN today, and every later
   item hangs on `seg_devices` and the identity set. It is also the safest to roll out
   (opt-in, adoption keeps behaviour).
2. **c1** (rebinding) in parallel: half a day, independent, immediately useful.
3. **a**. Headline feature, but only valuable where Patronus runs the AP; hardware proof on
   the Jetson or a spare AP-capable card should be scheduled before starting the UI work.
4. **c2**, then **e** (e uses c's family DNS preset and b's sets), then **d** (largest
   data-handling surface, least coupling).

## 10. Risks and decisions needed from the owner

1. **SAE live revoke**: accept hostapd restart on SAE changes (default), carry a hostapd
   patch (+~3 d plus upkeep), or ship WPA2-only per device. Recommendation: accept the
   restart, WPA2 default, SAE opt-in per SSID.
2. **Wired devices behind unmanaged switches cannot be isolated** by Patronus (4.4).
   Recommendation: document; ship the DHCP `/32` variant later if wanted.
3. **Default-deny changes behaviour**, so it is opt-in per interface with adoption into
   `home` (2). OK?
4. **Credentials at rest** are plaintext in the 0600 store like WG/IPsec keys; encryption at
   rest would be a separate project (`patronus-secrets` exists but the store does not use it
   for lane F either).
5. **DNS logs are personal data**: off by default, per policy, retention-capped.
6. **hwsim CI** needs the `mac80211_hwsim` module on the runner (rw-man-02..05 yes, 01 no); it
   is host-global, so the job takes a lock and unloads it afterwards.
7. **Licence**: DB-IP Lite is CC-BY 4.0 (attribution in the UI); SPR code is BSD-3 and is not
   copied here.

## Appendix A. Spike inventory (branch `spike/device-segmentation`, commit `c1503ba4`)

```
spikes/device-segmentation/
  src/lib.rs, src/main.rs      seg-spike: nft + hostapd generator, 6 unit tests (cargo test: 6 passed)
  examples/lab.json, hwsim.json
  lab/netns-isolation.sh       proof (b)            -> evidence/netns-isolation-run.txt  23/23
  lab/hwsim-run.sh, hwsim-inner.sh   proof (a)      -> evidence/hwsim-run.txt            26/26
  lab/dns-run.sh, dns-views.sh       proof (c)      -> evidence/dns-views-run.txt         8/8
  evidence/generated-pseg.nft
```

Hosts touched and restored: rw-man-03 (docker `--rm` containers, `mac80211_hwsim` loaded and
removed, `iw` installed and removed, `/tmp/segspike-*` deleted); the lab VM (`/root/seg-spike`
removed, namespaces gone, `nft list tables` unchanged). Nothing on the owner's home network
was touched beyond ssh to the lab VM.
