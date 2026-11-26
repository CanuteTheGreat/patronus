# Feature parity

Patronus aims to replace pfSense, OPNsense, OpenWrt and commercial routers and
firewalls (UniFi gateways, Firewalla, GL.iNet, mesh systems, SMB firewalls).
This page lists every user-facing feature of those products and where Patronus
stands on each hardware tier. It is generated from a code-and-CI audit, not
from plans: a feature counts only when it is compiled into the shipped
binaries and reachable from the web UI or CLI.

A hands-on comparison against the current pfSense CE and OPNsense releases
(installed in QEMU, every installer screen and web page inventoried) and the
resulting gap plan is in [design/pfsense-opnsense-parity.md](design/pfsense-opnsense-parity.md).

Status words:

- **tested**: shipped and exercised by an automated test that CI runs
  (netlab network-namespace scenarios in `ci/netlab/`, QEMU/vmtest runs,
  or unit tests where noted in the audit);
- **untested**: shipped and wired end to end, without such a test yet;
- **partial**: part of it exists (the notes say what is missing);
- **missing**: not in the shipped product yet;
- **n/a (hardware)**: does not fit the tier's flash/RAM/CPU (numbers in the notes);
- **in progress**: being built now.

"Found in": pfS = pfSense, OPN = OPNsense, OWrt = OpenWrt, UniFi = UniFi
gateways, FW = Firewalla, GL = GL.iNet, eero = eero/Orbi-style mesh,
Fort/Forti/SMB = Fortinet/Sophos/Meraki-class SMB firewalls.

Tiers: **Standard** = x86_64/arm64 install from the ISO (all default USE
flags); **Router** = 128 MiB NAND / 512 MB RAM class routers and access points
(e.g. GL-AX1800); **Small** = 16 MiB NOR / 128 MB RAM class routers (e.g.
GL-AR750S). Features a tier leaves out are listed on the device's own
System page with the reason.

Last generated: 2026-11-17 (279 features).

| Tier | tested | untested | partial | missing | n/a (hardware) | in progress |
|---|---|---|---|---|---|---|
| Standard | 127 | 3 | 53 | 88 | 1 | 7 |
| Router | 4 | 89 | 20 | 153 | 6 | 7 |
| Small | 0 | 83 | 13 | 168 | 8 | 7 |

## Firewall, NAT and security

| Feature | Found in | Standard | Router | Small | What is missing / notes | Impact |
|---|---|---|---|---|---|---|
| Stateful filter rules (allow/block/reject, proto, src/dst, ports, in/out interface, log flag) | pfS/OPN/OWrt/UniFi/FW/GL/eero/Fort | tested | untested | untested | No TCP-flag/ICMP-type/DSCP/OS match, no per-rule state options (keep/sloppy), no source-port-only UI limits, no rule hit counters. Router tiers compile it but only the QEMU boot gate checks that nftables tables exist. | P0 |
| Per-interface rules via interface roles (@wan/@lan/@optN, one nft rule per interface) | pfS/OPN/UniFi/Fort | tested | untested | untested | One interface or one role per rule: no interface groups / multi-select list as in pfSense. | P0 |
| Rule ordering (drag/move, order survives reboot, system rules pinned first) | pfS/OPN/UniFi/Fort | tested | untested | untested | No rule groups/separators, no bulk enable/disable/clone in the API. | P0 |
| Floating rules (multi-interface, any direction, quick/last-match control) | pfS/OPN | partial | untested | untested | A rule with no interface already behaves floating, but multi-interface selection, explicit in/out direction and ordering across interfaces is not modelled as pfSense floating tab. | P1 |
| Anti-lockout rule on management interface | pfS/OPN/Fort | tested | untested | untested | Cannot be disabled from the UI (pfSense can) - arguably a feature; no per-interface override UI. | P0 |
| Fail-closed boot: lockdown ruleset when store unreadable / atomic apply (bad rule never half-applies) | pfS/OPN | tested | untested | untested | None noted; no 'commit-confirm' auto-revert timer after risky changes (see rollback row). | P1 |
| Config history / rollback of firewall changes | pfS/OPN/OWrt/UniFi | tested | untested | untested | No timed auto-rollback ('revert in 60 s unless confirmed') like OpenWrt/UniFi. | P1 |
| Host/network aliases (IPv4+IPv6 ranges, CIDR; nft sets updated live without reload) | pfS/OPN/OWrt/UniFi | tested | untested | untested | No FQDN alias (resolved periodically) kind, no interface-address alias, no MAC alias. | P0 |
| Port aliases (ports and ranges) | pfS/OPN/OWrt | tested | untested | untested | Not in a netlab scenario. | P0 |
| Nested aliases (alias containing other aliases) | pfS/OPN | missing | missing | missing | Needs an `alias` entry type expanded at render time (cycle check) in aliases.rs + UI entry validation; nft sets can be unioned in the renderer. | P1 |
| FQDN / dynamic-DNS hostname alias | pfS/OPN/OWrt/UniFi | missing | missing | missing | Add `fqdn` source kind refreshed by the existing feeds periodic task. | P1 |
| URL table aliases (pfSense 'URL Table', auto-refreshing remote lists) | pfS/OPN/OWrt(banIP) | tested | untested | untested | SMALL: 100k-entry default cap is heavy at ~68 MB free RAM; needs a lower default cap on that tier. | P1 |
| GeoIP country blocking/allowing (DB-IP country DB -> alias -> rule) | pfS(pfBlockerNG)/OPN/UniFi/FW/Fort | tested | untested | untested | Country sets only (no per-country 'allow only' wizard, no GeoIP on outbound by default UI); dead geoip.rs/GeoIpManager should be deleted; SMALL RAM caps untested. | P1 |
| ASN-based blocking alias | pfS(pfBlockerNG)/OPN | missing | missing | missing | Add `asn` alias source reusing asn.rs prefix DB. | P2 |
| Firewall schedules (time-of-day / weekday windows attached to a rule) | pfS/OPN/UniFi/FW/Fort | tested | untested | untested | No date-range/specific-date or repeat-month schedules; no timezone-per-schedule. | P1 |
| Port forwards (DNAT with paired accept, matched on inbound interface) | pfS/OPN/OWrt/UniFi/FW/GL/eero/Fort | tested | untested | untested | No port-range-to-range mapping check shown in UI, no 'source restrict' UI beyond rule source, no auto-associated filter rule toggle. | P0 |
| 1:1 NAT (binat) inbound+outbound | pfS/OPN/OWrt/Fort | tested | untested | untested | IPv4 only; no per-interface scoping UI beyond external_address. | P1 |
| Outbound NAT modes (automatic / hybrid / manual / disabled) and manual SNAT/masquerade rules | pfS/OPN/OWrt/Fort | tested | untested | untested | Static-port / no-NAT exemption flags per rule absent. | P0 |
| NAT reflection / hairpin NAT | pfS/OPN/OWrt/UniFi | tested | untested | untested | Needs explicit external_address; no automatic 'pure NAT' mode, split-DNS is the alternative (host overrides). | P1 |
| NPTv6 (IPv6 prefix translation) | pfS/OPN/OWrt | tested | untested | untested | None noted. | P2 |
| Bogon + RFC1918 'block private networks' on WAN | pfS/OPN | missing | missing | missing | Seed two system rules (drop on @wan from RFC1918/bogon set, toggle per WAN) via a builtin alias source; nft `fib saddr . iif oif missing` rp-filter is the cheaper alternative. Test: netlab inject spoofed source from the… | P1 |
| Inbound policy on WAN drop vs reject, drop IPv4 options | pfS/OPN/OWrt | in progress | in progress | in progress | Wait for another work item. | P1 |
| SYN-flood protection (syncookies/synproxy) | pfS/OPN/OWrt/UniFi/Fort | in progress | in progress | in progress | Wait for another work item. | P1 |
| MSS clamping (PPPoE/VPN MTU) | pfS/OPN/OWrt/UniFi | in progress | in progress | in progress | Wait for another work item; matters for PPPoE WANs (lane-c PPPoE is tested). | P0 |
| Firewall logging per rule + default-deny logging (NFLOG, rate limited) | pfS/OPN/UniFi/FW/Fort | tested | untested | untested | No syslog-per-rule destination, no log-level; ROUTER: collector lives in patronus-web (compiled) but RAM-bounded history untested. | P0 |
| Live firewall log viewer with filters | pfS/OPN/UniFi/FW | tested | untested | untested | Poll-based not push; no GeoIP/app column; no 'pass' logging dashboard graphs. | P0 |
| States table: list connections | pfS/OPN/OWrt(conntrack) | tested | untested | untested | No state-summary/ 'per rule' states, no filter by interface. | P1 |
| Kill states (by source/dest/port; reset all) | pfS/OPN | tested | untested | untested | Kill-by-host works; no automatic kill on gateway failover (pfSense option) - check lane-e failover. | P1 |
| Limiters / per-rule rate and connection limits (dummynet limiters, max-src-nodes) | pfS/OPN/OWrt(sqm)/UniFi | missing | missing | missing | Add `limit` (rate/burst, per-source via nft meter or `ct count over`) columns to firewall_rules (new migration in lane B range), render in nftables.rs, UI fields; netlab: exceed rate and observe drop. | P1 |
| Traffic shaping: per-interface rate limit / fq_codel / CAKE (SQM) | pfS/OPN/OWrt(sqm-scripts)/UniFi/eero/GL | tested | missing | missing | Egress only (no IFB/ingress shaping so download SQM needs shaper on LAN); no autorate, no per-host/dual-isolate cake flags or overhead presets; ebuild: `qos` USE is not default (+vlan +pppoe only). Ship `qos` in ROUTER/… | P0 |
| Traffic shaper rules: classify by rule/host/app, priority queues, DSCP marking | pfS/OPN/OWrt/UniFi/FW | missing | missing | missing | Add classification rows (match -> nft mark/dscp -> cake diffserv / htb class) in shaping.rs + qos.html. | P1 |
| IDS: Suricata alert mode on an interface (custom rules, eve.json alerts) | pfS/OPN/UniFi/Fort | tested | n/a (hardware) | n/a (hardware) | ebuild: USE intrusion-detection is not default; Suricata binary is not a hard dep. | P1 |
| IPS: inline blocking via NFQUEUE (drop rules really drop) | pfS/OPN/UniFi/Fort | tested | n/a (hardware) | n/a (hardware) | Only one watch interface and one queue (QUEUE=3); no per-rule enable/disable. | P1 |
| IDS rule management: ET Open / suricata-update, enable/disable by SID, categories, suppress/threshold | pfS/OPN/UniFi | partial | n/a (hardware) | n/a (hardware) | Add rule-source table (ET Open, abuse.ch...), run suricata-update from applyd on a timer, SID disable list + threshold.config rendering, rule count/status card (M-L). Netlab: serve a tiny rules tarball, assert alert. | P1 |
| IDS alerts view (recent eve.json alerts on the page) | pfS/OPN/UniFi/FW | tested | n/a (hardware) | n/a (hardware) | No history beyond eve.json rotation; no alert->block quick action; no GeoIP/ASN enrichment. | P1 |
| Threat-intelligence IP blocklists (Spamhaus DROP/EDROP, FireHOL, abuse.ch, ET compromised) as pre-user rules | pfS(pfBlockerNG)/OPN/OWrt(banIP)/FW/UniFi/Fort | tested | untested | untested | No feed-hit dashboard counters, no per-feed 'alert vs deny' logging UI; SMALL cap needed. | P0 |
| DNS blocklist / ad blocking (DNSBL via Unbound or dnsmasq, URL lists + manual domains, NXDOMAIN or null) | pfS(pfBlockerNG-DNSBL)/OPN(Unbound DNSBL)/OWrt(adblock)/FW/… | tested | untested | untested | No curated list catalog UI (user pastes URLs), no regex/wildcard allowlist, no per-list hit stats or query-log based 'block this domain' button, no per-client lists on the global DNS (group lists exist under segmentatio… | P0 |
| Per-device/group DNS filtering policy (Firewalla-style profiles: family preset, custom lists, allow overrides) | FW/UniFi/eero/Fort | tested | untested | untested | ROUTER gets it (wifi-ap implies segmentation) but dnsmasq-only boxes: seg DNS views need Unbound (not in router list). | P1 |
| Application identification / L7 DPI (nDPI-class: block or report by app) | UniFi/FW/pfS(Zenarmor,ntopng)/OPN(Zenarmor)/Fort | partial | n/a (hardware) | n/a (hardware) | Integrate nfqws/nDPI via NFQUEUE or `ndpiReader` library as an optional USE=dpi plugin (via the existing signed-plugin path), expose app category in insights and as a rule match (L). | P1 |
| Category web filtering (URL/category database) | FW/UniFi/eero/Fort/pfS(squidGuard)/OPN(Zenarmor) | partial | partial | partial | No category taxonomy (e.g. UT1/Shalla) selectable per group, no HTTPS URL-path filtering (needs TLS inspection). | P1 |
| Safe-search enforcement (Google/Bing/YouTube/DDG/Brave CNAME) | FW/UniFi/eero/Fort/OPN | tested | untested | untested | Per-group toggle only; no YouTube restricted-mode header for HTTPS. | P2 |
| Force clients through router DNS / block DoT+DoH bypass | FW/UniFi/pfS/OPN/OWrt | tested | untested | untested | DoH to arbitrary resolvers cannot be blocked without L7/SNI filtering or a DoH IP list; no global (non-group) redirect toggle. | P1 |
| SSL/TLS inspection (MITM) for web filter / IPS | pfS(squid)/OPN(Zenarmor)/Fort/UniFi(partial) | missing | missing | missing | Depends on internal CA manager (missing, see C area). | P2 |
| Captive portal (guest auth page, redirect, time limits) | pfS/OPN/OWrt(nodogsplash)/UniFi/GL/Fort | partial | missing | missing | Needs Applier + captive_portal tables + nft redirect/set of authorized MACs + web page (L). Netlab: unauthenticated client gets redirected, voucher grants access. | P1 |
| Captive portal vouchers / RADIUS / social login | pfS/OPN/UniFi/GL/Fort | missing | missing | missing | Depends on the portal row above. | P2 |
| UPnP IGD / NAT-PMP / PCP | pfS/OPN/OWrt/UniFi/GL/eero | tested | missing | missing | ebuild: USE upnp not default; add `upnp` to ROUTER/SMALL features (S) - gamers expect it on a router. | P0 |
| Policy-based routing via firewall rules (send rule traffic via a gateway/group) | pfS/OPN/OWrt(mwan3)/UniFi/Fort | tested | untested | untested | Gateway groups need USE multiwan (absent on router tiers) so only single gateways work there. | P0 |
| Per-device / per-group segmentation (default-deny between enrolled devices, groups, services) | UniFi/FW/eero/Fort | tested | untested | missing | Model is MAC-bound device identity + bridge port isolation; no VLAN-per-group auto-assignment (UniFi) UI. | P1 |
| Quarantine group (unknown/new/revoked devices reach only DHCP/DNS/ICMP) | UniFi/FW/Fort | tested | untested | missing | No auto-quarantine on new-device detection notification. | P1 |
| Parental controls: time limits / quota per group | FW/UniFi/eero | tested | untested | missing | Pause-device button only through group; no per-app time limits. | P1 |
| IPv6 firewall parity (ip6 rules, no NAT, ICMPv6 handling, v6 aliases/sets) | pfS/OPN/OWrt/UniFi | tested | untested | untested | ICMPv6 and ICMP echo to the router are accepted unconditionally on all interfaces (base_table_script lines 80-81): no per-interface/ per-type control, no WAN ping toggle. | P1 |
| Web UI login brute-force throttle | pfS(sshguard)/OPN/UniFi/Fort | tested | untested | untested | No netlab proof; no permanent ban/allowlist UI; LDAP/RADIUS paths share the throttle by design. | P1 |
| SSH brute-force protection (sshguard/fail2ban-style auto-ban) | pfS/OPN/OWrt(dropbear+banIP)/Fort | missing | missing | missing | Implement as nft meter rule on tcp dport ssh (`ct state new meter ... over 5/min add @ssh_ban`) with a timeout set, rendered by the firewall applier from an `ssh_guard` setting; netlab: 6 rapid connects then blocked (S-… | P1 |
| Auto-ban from IDS/threat events (CrowdSec/fail2ban style dynamic blocklist) | pfS(pfBlockerNG)/OPN(CrowdSec)/Fort/FW | missing | missing | missing | Feed IDS alert source IPs to a timed nft set (M). | P2 |
| Transparent bridging firewall (filter bridged L2 traffic) | pfS/OPN/OWrt | missing | missing | missing | Bridge-family filtering is a deliberate non-feature; add nft `bridge` family table if wanted. | P2 |
| Static port / outbound NAT exemptions, NAT64 and VPN exemptions | pfS/OPN | partial | untested | untested | Add `no_nat` + `static_port` NatType options. | P2 |
| Rule hit counters / per-rule traffic statistics in UI | pfS/OPN/UniFi | missing | missing | missing | Add `counter` to rendered rules + read back via `nft -j list` for the Rules tab (S). | P1 |
| Import firewall config from OpenWrt (UCI) / other products | OWrt/pfS(config.xml)/OPN | in progress | in progress | in progress | pfSense/OPNsense config.xml importer missing (P1 for switchers). | P1 |

## Interfaces, routing, multi-WAN and HA

| Feature | Found in | Standard | Router | Small | What is missing / notes | Impact |
|---|---|---|---|---|---|---|
| Interface assignment / roles (WAN/LAN/OPTn), first-boot wizard | pfS/OPN/OWrt/UniFi/GL/eero | tested | untested | untested | No interface-group objects (pfSense groups), no port-to-switch-VLAN mapping for DSA/swconfig switch chips (OpenWrt/GL switch UI). | P0 |
| Static IPv4/IPv6 addressing on interfaces | all | tested | untested | untested | Secondary/alias addresses only as HA alias VIPs; no IPv4 /32 point-to-point UI. | P0 |
| WAN via DHCPv4 client | all | tested | untested | untested | No DHCP client options UI (vendor class, hostname send, request options, reject leases from) beyond the dhcp_client switch; DUID is IN-PROGRESS. | P0 |
| WAN via PPPoE (pppd kernel plugin, supervised) | all | tested | missing | missing | No PPPoE on VLAN-tagged WAN check in UI docs, no MTU/MSS auto (MSS clamp IN-PROGRESS another work item), no IPv6 over PPPoE test, no multilink. PPPoE is P0 for EU/AU ISPs: add `pppoe` to router FEATURES (S; pppd + kmod-… | P0 |
| 802.1Q VLANs | all | tested | missing | missing | Add `vlan` to ROUTER/SMALL features + kmod-8021q; also no switch-chip VLAN (DSA bridge vlan_filtering) config for LAN ports - the common router case (M). | P0 |
| QinQ (802.1ad) stacked VLANs | pfS/OPN/OWrt/Fort | tested | missing | missing | Niche; follows VLAN gap on router tiers. | P2 |
| LAGG / bonding (LACP 802.3ad, active-backup, balance modes) | pfS/OPN/OWrt/UniFi/Fort | tested | untested | untested | Also at install time (answer file / guided installer, [ISO-INSTALL.md](ISO-INSTALL.md)): vmtest `installed_lagg_vlan.py` (ISO gate, both inits) proves LACP against a Linux 802.3ad partner (one aggregator, partner MAC, member cut + rejoin) with WAN/LAN/management on VLANs of the bond at the first boot. Not yet: hash-policy/failover-mode UI check on the Interfaces page, a real switch. | P1 |
| Bridges (STP flag, member ports) | pfS/OPN/OWrt/UniFi/GL | tested | untested | untested | No bridge VLAN filtering / per-port PVID, no RSTP/priority/path-cost settings, no bridge-family firewalling. | P0 |
| GRE / GRE-TAP / VXLAN tunnels | pfS/OPN/OWrt/Fort | tested | untested | untested | No tunnel keepalive/monitoring, no IPv6-underlay test, no multicast VXLAN. | P1 |
| GIF / 6in4 / SIT / IPIP tunnels | pfS/OPN/OWrt | missing | missing | missing | Add `sit` (6in4, Hurricane Electric) and `ipip` kinds to overlay.rs + UI (S). | P1 |
| Cellular 4G/5G modem WAN (QMI/MBIM/ModemManager, ppp/NCM) | OWrt/GL/UniFi(U-LTE)/Fort/eero(some) | missing | missing | missing | Needs ModemManager/uqmi dependency, `modem` store table, supervisor unit, signal/ APN/PIN UI, gateway integration with failover groups. Netlab: no modem emulation (use a fake wwan netdev + mock mmcli) - L. GL.iNet's fla… | P1 |
| Wi-Fi client (STA) uplink as WAN / repeater | OWrt/GL/eero(mesh)/UniFi | in progress | in progress | in progress | Wait for another work item. | P0 |
| MAC address clone/override on WAN | pfS/OPN/OWrt/UniFi/GL | tested | untested | untested | Randomise-MAC option absent. | P1 |
| MTU per interface | all | tested | untested | untested | No automatic path-MTU/MSS (see MSS clamp). | P0 |
| IPv6 WAN: SLAAC client (accept_ra=2 with forwarding on) | pfS/OPN/OWrt/UniFi | tested | untested | untested | No dedicated netlab where the ISP only sends an RA with a prefix and the router self-configures. | P0 |
| IPv6 WAN: DHCPv6 client (IA_NA) incl. DUID control | pfS/OPN/OWrt/UniFi | tested | untested | untested | DUID and IAID pinnable per interface (`dhcp6_duid`, `dhcp6_iaid`: the ISP binds address + delegated prefix to DUID + IAID, so a replacement router with both keeps the prefix at once; another IAID gets NoPrefixAvail until the old binding expires); `patronus import-uci` carries the old OpenWrt router's IAID (24.10: 1; 25.12: md5 of the device name; read live with `--ssh`; see docs/embedded-routers.md). A server that refuses only the prefix (NoPrefixAvail) leaves the WAN its IA_NA address and dhcpcd asks for the prefix again at every renew; the Interfaces page and `GET /api/interfaces` (`problems`) say "The ISP refused the delegated prefix (NoPrefixAvail...)" from dhcpcd's log (netlab `lane-n-dhcp6pd-refused.sh`, dhcpcd 9.4 and 10.5). The base input rule accepts DHCPv6 replies by destination (a relayed ISP server answers from a global address; `lane-n-dhcp6pd.sh` answers from one); dhcpcd not in router image. | P0 |
| DHCPv6 prefix delegation to LANs (/64 per LAN from delegated prefix, RA on LAN) | pfS/OPN/OWrt/UniFi | tested | untested | untested | LAN ULA + PD coexistence IN-PROGRESS; prefix-id selection per LAN; no hint of requested prefix length UI check. | P0 |
| Router advertisements modes (SLAAC/stateless/managed/assisted), RDNSS, per-interface | pfS/OPN/OWrt/UniFi | tested | untested | untested | No router-preference/ MTU/ route-info options; no ULA prefix advert controls (IN-PROGRESS another work item). | P0 |
| NDP proxy / NDP relay (IPv6 for bridged-WAN or single-/64 ISPs) | OWrt(odhcpd relay)/pfS(ndp proxy)/OPN | missing | missing | missing | Add `ndp_proxy` interface option writing proxy_ndp + `ip -6 neigh add proxy`, or odhcpd relay mode (M). | P1 |
| IPv6 transition: 6rd / 6in4 / DS-Lite / MAP-E | pfS(6rd,6in4)/OPN/OWrt(all)/UniFi(6rd) | missing | missing | missing | 6in4 = sit tunnel (S, see GIF row); 6rd = sit with 6rd prefix from DHCP option 212 (M); DS-Lite = ip6tnl + AFTR (M); MAP-E = needs kernel map/ebpf (L). Netlab per mode with an ISP-ns endpoint. | P1 |
| NAT64 / DNS64 (tayga + Unbound dns64) | pfS/OPN/OWrt(jool) | tested | untested | missing | ebuild: USE nat64 not default. | P2 |
| Static routes (via IP or gateway name; dynamic gateways keep routes) | all | tested | untested | untested | IPv6 static routes not exercised in lane-e (no 2001:db8 strings); no blackhole/unreachable/ route-table selection in the UI. | P0 |
| Gateway monitoring (ping per gateway, loss/latency thresholds, events) | pfS/OPN/OWrt(mwan3)/UniFi/GL/Fort | tested | untested | untested | ICMP only in the base monitor; TCP/HTTP/DNS probes exist (uplink_probe.rs) - see next row. | P0 |
| Multi-target / TCP-HTTP-DNS health probes with degraded state and uplink SLA history | OWrt(mwan3)/pfS(partial)/UniFi/Fort | in progress | in progress | in progress | another work item adds mwan3-style tracking for the Wi-Fi uplink; wired side already tested. | P1 |
| Gateway groups: failover by tier | pfS/OPN/OWrt/UniFi/GL/Fort | tested | missing | missing | `multiwan` is a pure cfg flag; add it to router FEATURES (S) - multi-WAN is P0 for SMB. | P0 |
| Gateway groups: weighted load balancing (ECMP by weight) | pfS/OPN/OWrt(mwan3)/UniFi/Fort | tested | missing | missing | Per-flow ECMP hashing only: no per-connection balancing ratios audit, no packet-level bonding. | P0 |
| Sticky connections / per-source sticky balancing (mwan3 sticky) | OWrt/pfS(sticky)/OPN | missing | missing | missing | Implement with nft `ct mark` + `meta mark` per source address (timeout set) in routes.rs; netlab: same client keeps uplink for N seconds (M). | P1 |
| Policy routing by source/destination/port to a specific WAN | pfS/OPN/OWrt(mwan3)/UniFi/Fort | tested | untested | untested | Per-domain/per-app (FQDN, geoip) steering absent (patronus-app-steering is aspirational). | P0 |
| Dynamic routing: BGP / OSPF via FRR | pfS(FRR)/OPN(FRR)/OWrt(bird/frr)/Fort | tested | missing | missing | ebuild USE dynamic-routing not default; no route-maps/prefix-list UI, no BFD, no BGP md5/ttl-security. | P1 |
| RIP / RIPng / BFD / IS-IS | pfS(FRR)/OPN(FRR)/OWrt | missing | missing | missing | Add ripd/ripngd/bfdd stanzas (S each). | P2 |
| VRF (routing table per tenant) | OPN(partial)/pfS(multi-table via gateways)/Fort | tested | missing | missing | No inter-VRF route leaking UI. | P2 |
| SD-WAN (overlay between appliances, path steering) | UniFi(SD-WAN)/Fort/GL(none)/pfS(none) | partial | missing | missing | Edge enrolls and maintains a WG mesh; the Fortinet-style SLA-based path selection per app is absent. | P2 |
| VRRP/CARP virtual IPs (keepalived, failover, preempt, maintenance mode) | pfS/OPN/OWrt(keepalived)/UniFi(some)/Fort | tested | missing | missing | ebuild: USE ha not default. IPv6 VIP supported by design (VRID per family) - not asserted in test. | P1 |
| HA configuration sync (primary pushes config to secondary, XMLRPC-style) | pfS/OPN/Fort/UniFi | missing | missing | missing | Implement as `patronus ha-sync`: store dump of selected tables over HTTPS API with API key (apikeys.rs exists) applied on the backup by applyd; netlab: rule added on master appears on backup. Size M. | P1 |
| Connection-state sync (conntrackd FTFW) so established flows survive failover | pfS(pfsync)/OPN/Fort | tested | missing | missing | Needs both nodes on conntrackd; no pfsync-style DHCP lease sync. | P1 |
| IGMP proxy (IPTV multicast routing) | pfS/OPN/OWrt/UniFi/GL | tested | missing | missing | No PIM, no IGMP snooping UI on bridges; add `igmp` to router FEATURES (S). | P1 |
| mDNS repeater / Avahi reflector across VLANs | pfS(avahi)/OPN/OWrt(umdns)/UniFi/FW/eero | missing | missing | missing | Add `mdns` Svc page (slug mdns) rendering avahi-daemon.conf `enable-reflector=yes` + allow-interfaces + nft udp/5353 rule; netlab: avahi-publish on VLAN A seen on B (S-M). Needed for AirPlay/Chromecast across IoT VLANs… | P0 |
| UDP broadcast relay (e.g. game/printer discovery) / SSDP relay | pfS(udpbroadcastrelay)/OPN/OWrt(bcrelay) | missing | missing | missing | Add `udp-broadcast-relay` Svc (S). | P2 |
| Wake-on-LAN (named hosts, wake button, from the interface) | pfS/OPN/OWrt/UniFi/FW/GL | tested | untested | untested | No 'wake from DHCP lease list' button check; no WoL-over-WAN proxy. | P2 |
| Packet steering (RPS/XPS/IRQ affinity on multi-queue NICs) | OWrt/OPN(tunable) | in progress | in progress | in progress | Wait for another work item. | P2 |
| Flow offloading (nftables flowtable / hw offload) | OWrt(flow offload)/UniFi/GL(NSS) | missing | missing | missing | Render `flowtable ft { hook ingress ... devices }` + `flow add @ft` in forward chain behind a setting (software offload; M). IPQ6018 would need qca-nss for hardware; software flowtable is the realistic win. Netlab: iper… | P1 |
| XDP/eBPF fast path (blocklist drop at driver) | pfS(none)/OPN(none)/Fort | missing | n/a (hardware) | n/a (hardware) | Wire patronus-ebpf as optional dep of patronus-network + an `xdp` Svc page (attach/detach, blocklist from the feeds sets) (M). | P2 |
| Per-interface traffic graphs (rates now + history) | pfS(RRD)/OPN/OWrt(luci-statistics)/UniFi/eero | partial | untested | untested | No per-interface rate-over-time graphs (RRD/sparklines), no per-queue/ per-VLAN counters; add a ring buffer in insight_history keyed by interface (S-M). | P1 |
| Link-state tracking / carrier failover of WAN (link down -> failover) | pfS/OPN/OWrt/UniFi | untested | untested | untested | Add a lane-e step that sets the WAN link down and expects failover within N s. | P1 |

## LAN services

| Feature | Found in | Standard | Router | Small | What is missing / notes | Impact |
|---|---|---|---|---|---|---|
| DHCPv4 server: pools per interface, lease time, gateway/DNS/domain/NTP options, enable per pool | all | tested | untested | untested | Backend Kea is Gentoo-only (USE kea); router tiers dnsmasq only. | P0 |
| DHCPv4 static mappings (MAC->IP + hostname) | all | tested | untested | untested | No client-id/DUID match, no per-mapping options. | P0 |
| DHCP custom options (arbitrary option codes, vendor class, option 43/60/66/67/150) | pfS/OPN/OWrt/UniFi/Fort | missing | missing | missing | Add `dhcp_options` table (code, type, value, pool_id) rendered to Kea `option-data` and dnsmasq `dhcp-option`; netlab: client requests option 150 and sees it (S-M). | P1 |
| PXE/network boot (next-server, bootfile, per-arch) and built-in TFTP server | pfS/OPN/OWrt/UniFi | missing | missing | missing | Extend DhcpPool with next_server/boot_file/boot_file_efi + tftp-root for dnsmasq (`enable-tftp`) (S-M). Netlab: dnsmasq TFTP fetch of a test file via tftp client. | P1 |
| DHCP relay (relay agent to remote server) | pfS/OPN/OWrt/Fort | tested | untested | untested | No option 82 insertion control. | P2 |
| DHCP lease list (active leases page/API, hostname, MAC, expiry) | all | tested | untested | untested | No per-lease actions (make static, wake, delete lease) verified; no vendor/ OS fingerprint column. | P1 |
| DHCPv6 server (stateful IA_NA) | pfS/OPN/OWrt/UniFi | tested | untested | untested | No DHCPv6 static mappings by DUID, no PD server for downstream routers. | P1 |
| Router advertisements (RA modes, RDNSS/DNSSL) for the LAN | pfS/OPN/OWrt/UniFi | tested | untested | untested | See B-network for modes caveat. | P0 |
| Unbound recursive resolver with local data, access control per interface | pfS/OPN | tested | missing | missing | Resolver vs forwarder choice on router: dnsmasq only; no custom unbound options box, no query log/statistics UI. | P0 |
| DNSSEC validation (trust anchor, bogus answers refused) | pfS/OPN/OWrt/UniFi | partial | untested | untested | Add a signed+broken zone to the lan-services test (S). | P0 |
| dnsmasq forwarder mode (DNS+DHCP in one daemon) | pfS/OPN/OWrt/GL/eero | tested | untested | untested | None noted. | P0 |
| Host overrides / aliases | pfS/OPN/OWrt/UniFi | tested | untested | untested | No host alias (CNAME) or wildcard record UI; no MX/SRV/TXT custom records. | P1 |
| Domain overrides / conditional forwarding | pfS/OPN/OWrt/UniFi | tested | untested | untested | None noted. | P1 |
| DoT upstream (forward-tls / stubby) | pfS/OPN/OWrt/GL/UniFi/eero | missing | missing | missing | Add `upstream_tls` + SNI per upstream, render `forward-tls-upstream: yes` + `tls-cert-bundle` for Unbound (S-M); netlab: run a stunnel DoT endpoint and observe resolution through it. IN-PROGRESS may cover - unverified. | P0 |
| DoH (upstream or local listener) | OPN/OWrt/GL/UniFi/eero | missing | missing | missing | Needs dnscrypt-proxy or https-dns-proxy dependency (M). Netlab: local DoH test endpoint. | P1 |
| DNS rebind protection | pfS/OPN/OWrt | tested | untested | untested | No netlab proof that a public name answering 10.x is stripped (S). | P1 |
| Local domain + DNS for DHCP lease hostnames | pfS/OPN/OWrt/UniFi | tested | untested | untested | No separate per-interface local domain. | P1 |
| DNS query log / statistics | pfS/OPN/OWrt/UniFi/FW | missing | missing | missing | Enable unbound log-queries to a ring buffer + page (M). Needed for DNSBL 'who asked' workflow. | P1 |
| Dynamic DNS (providers, IPv4+IPv6, update on change + 25-day refresh) | pfS/OPN/OWrt/UniFi/GL | tested | missing | missing | Providers: dyndns2, duckdns, cloudflare, custom only (ddns.rs:37); IPv6 update handled via address selection, test only IPv4 (203.0.113.2). | P1 |
| NTP server (chrony serving LAN) + client sync | pfS/OPN/OWrt/UniFi | tested | untested | untested | No GPS/PPS refclock, no NTP statistics page. | P1 |
| ACME / Let's Encrypt certificates (HTTP-01, DNS-01, wildcard, auto-renew) | pfS(acme pkg)/OPN(os-acme)/OWrt(acme)/UniFi/Fort | missing | missing | missing | Implement via lego/acme.sh dependency: `acme_certs` table, HTTP-01 through a temporary nft/redirect on :80, DNS-01 via provider hooks, renew timer in applyd, install into web TLS + HAProxy; netlab with pebble ACME test… | P0 |
| Internal CA / certificate manager (issue server/client certs, CRL) | pfS/OPN/UniFi/Fort | partial | missing | missing | Add a `ca` Svc with CA create/import, cert issue/revoke, CRL, download (M-L). | P1 |
| Web UI HTTPS certificate management (upload/replace, self-signed bootstrap) | all | partial | untested | untested | Tie to ACME/CA rows. | P1 |
| HAProxy / reverse proxy with TLS offload, backends, health checks | pfS(HAProxy)/OPN(os-haproxy)/OWrt | missing | missing | missing | New Svc `haproxy`: frontends, TLS certs from ACME/CA, backends with checks (L). | P1 |
| Squid / transparent web proxy (+ blocked domains, cache) | pfS(Squid)/OPN(os-squid) | tested | missing | n/a (hardware) | HTTP only (no ssl-bump), no cache stats UI, no ICAP/ClamAV. | P2 |
| SNMP agent (v2c/v3, community, location) | pfS/OPN/OWrt/UniFi | tested | missing | missing | v3 users not covered by the page. | P2 |
| NetFlow / IPFIX export (softflowd) | pfS/OPN/OWrt/UniFi | tested | missing | missing | Export only; no built-in collector/ntopng view (Insights does its own conntrack aggregation). | P2 |
| Remote syslog forwarding (UDP/TCP/TLS, facility filters) | pfS/OPN/OWrt/UniFi/Fort | tested | missing | missing | TLS syslog and per-source filters not covered. | P1 |
| PPPoE server (for LAN clients/ISP-in-a-box) | pfS/OPN | missing | missing | missing | Add pppoe-server Svc (S-M). | P2 |
| L2TP server (LNS, with IPsec) | pfS/OPN/OWrt/Fort | tested | missing | missing | ebuild: USE l2tp not default. | P2 |
| LLDP/CDP neighbour discovery | OPN/OWrt/UniFi | missing | missing | missing | Svc `lldp` rendering lldpd.conf + neighbour table from `lldpcli -f json` (S). | P2 |
| UPS monitoring (NUT) | pfS/OPN/OWrt | missing | missing | missing | Svc `nut` (ups.conf driver, upsd, upsmon shutdown) (M). Needs USB HW to really test - netlab with dummy-ups driver. | P2 |
| FreeRADIUS server (for Wi-Fi 802.1X / captive portal) | pfS/OPN/OWrt/UniFi/Fort | missing | missing | missing | Svc `radius` with users/NAS clients; consumed by hostapd (M-L). | P2 |
| Prometheus node exporter / metrics endpoint | pfS/OPN/OWrt/UniFi | partial | untested | untested | Add node_exporter Svc or extend /metrics with host/interface gauges (S). | P2 |
| iperf3 server / built-in throughput test | OPN/OWrt/pfS(pkg) | missing | missing | missing | Svc `iperf` systemd/openrc unit (S). | P2 |
| Samba / USB storage sharing | OWrt/GL/pfS(no)/OPN(no) | missing | missing | n/a (hardware) | Out of firewall scope; only worth it for OpenWrt/GL parity (M). | P2 |
| mDNS / Avahi (publish/ reflect) | OWrt/UniFi/pfS(avahi)/OPN | missing | missing | missing | Same item. | P1 |
| Speedtest (WAN throughput test from the UI/CLI) | OPN/OWrt/UniFi/eero/GL | missing | missing | missing | Add `patronus speedtest` using librespeed/ookla CLI + history chart (S). | P2 |
| Services status/start/stop/restart page + DNS/DHCP apply safety (bad input never reaches daemon config) | pfS/OPN | tested | untested | untested | OpenWrt procd init not tested (router tier uses its own init). | P1 |

## VPN and wireless

| Feature | Found in | Standard | Router | Small | What is missing / notes | Impact |
|---|---|---|---|---|---|---|
| WireGuard road-warrior server, peers added in the UI | pfS/OPN/OWrt/UniFi/GL/FW | tested | missing | missing | No peer expiry, no per-peer rate limit, no peer-endpoint DNS re-resolve found. ROUTER/SMALL builds omit it though the WG kernel module and tool fit easily | P0 |
| WireGuard client config download + QR code | pfS(no QR)/OPN/OWrt/UniFi/GL/FW | tested | missing | missing | Only for peers whose private key Patronus generated (`exportable`). No share link or email | P0 |
| WireGuard preshared keys + server-side keygen | OPN/OWrt/UniFi/GL | tested | missing | missing | none for STD | P1 |
| WireGuard site-to-site (peer networks routed, firewall opened automatically) | pfS/OPN/OWrt/UniFi/GL/SMB | tested | missing | missing | Static routes only; no failover between two tunnels, no dynamic routing over WG helper | P0 |
| WireGuard client to a commercial VPN provider (import provider .conf, default route via tunnel) | pfS/OPN/OWrt/UniFi/FW/GL (GL core feature) | partial | missing | missing | No provider .conf import, no wizard, no provider presets, no "use as default gateway" toggle; client-only mode is awkward (listen_port mandatory); no netlab | P0 |
| Per-device / per-group policy routing through a VPN client | UniFi/FW/GL/OWrt(pbr)/pfS/OPN | partial | missing | missing | No per-device "route via VPN" in the segmentation/device UI (rule must be hand-written per IP/alias); no netlab with a real tunnel | P0 |
| VPN kill switch (fail closed when tunnel is down) | UniFi/FW/GL/OWrt/pfS(manual)/OPN(manual) | missing | missing | missing | Add a `fail_closed` flag on a gateway rule: routes applier installs `unreachable default` in the mark table when the gateway is down; netlab: stop the peer, assert no packet leaves the WAN | P0 |
| OpenVPN server with automatic PKI (CA, server cert, tls-crypt) | pfS/OPN/OWrt/GL | tested | missing | missing | Fixed EC P-256 + AES-256-GCM; one server instance; revoke = disable via ccd (no CRL UI) | P0 |
| OpenVPN client profile (.ovpn) export | pfS(pkg)/OPN/OWrt/GL | tested | missing | missing | No Windows installer bundle | P0 |
| OpenVPN user/password (local, LDAP, RADIUS) authentication, optional TOTP | pfS/OPN/OWrt/GL | missing | missing | missing | Add `auth-user-pass-verify` script calling a `patronus auth check` subcommand against existing local users + auth_servers (0730_h_auth_servers.sql, 1260_n_ldap.sql) + TOTP; netlab with a real client using auth-user-pass… | P1 |
| OpenVPN server options (redirect-gateway, push DNS, several routes, static client IP, TCP) | pfS/OPN/OWrt | partial | missing | missing | No full-tunnel option, no DNS push, no client-to-client, no per-client fixed address | P1 |
| OpenVPN client (connect to a provider or remote server, import .ovpn) | pfS/OPN/OWrt/GL | missing | missing | missing | New `openvpn_instances` table + applier supervising `openvpn --config` with auth-user-pass, interface usable as a gateway for #6; netlab client-to-server (M) | P1 |
| IPsec site-to-site IKEv2 with pre-shared key (strongSwan swanctl) | pfS/OPN/OWrt/UniFi/SMB | tested | missing | missing | IKEv2 only (no IKEv1 for older Forti/Cisco peers); policy mode takes one local_ts/remote_ts string pair | P0 |
| IPsec route-based tunnels (XFRM interfaces, routes and OSPF over IPsec) | pfS/OPN(VTI)/OWrt | tested | missing | missing | docs/IPSEC-ROUTE-BASED.md, claim C1301, netlab lane-f-ipsec-vti.sh; PSK + IKEv2 only; no embedded-tier strongSwan | P0 |
| Mesh VPN client: Tailscale / Headscale (advertise routes, exit node, firewalled interface) | pfS(pkg)/OPN(plugin)/OWrt/UniFi/GL | tested | missing | missing | docs/MESH-VPN.md, claim C1302, netlab lane-j-tailscale.sh; ZeroTier (non-free parts, no ebuild) and NetBird (no ebuild) not shipped | P1 |
| IPsec site-to-site with certificates | pfS/OPN/UniFi/SMB | missing | missing | missing | Add auth column + peer cert pin reusing ipsec_pki (S-M) | P1 |
| IPsec road warrior IKEv2 EAP-MSCHAPv2 (built-in OS clients) | pfS/OPN/UniFi(L2TP)/SMB | tested | missing | missing | Local users only (no RADIUS/LDAP backend for EAP) | P1 |
| IPsec road warrior with client certificates + setup files (.mobileconfig, .sswan, PowerShell, PKCS#12) | pfS/OPN/SMB | tested | missing | missing | none notable | P1 |
| L2TP server | pfS/OPN/OWrt/UniFi/SMB | tested | missing | missing | n/a | P1 |
| L2TP over IPsec (transport mode, PSK) for native iOS/Android/Windows clients | pfS/OPN/OWrt/UniFi/SMB | missing | missing | missing | Native clients cannot connect without the IPsec layer. Generate a transport-mode swanctl connection (PSK field on the L2TP page) from the ipsec applier; netlab with a strongSwan transport client (S-M) | P1 |
| Tailscale / Headscale | OWrt/pfS(pkg)/OPN(plugin)/GL | missing | missing | missing | `overlay_vpn` table (auth key, login-server, advertise-routes, exit node) + applier supervising tailscaled, status from `tailscale status --json`; netlab against a headscale container (M) | P1 |
| ZeroTier / NetBird | OWrt/pfS(pkg)/OPN(plugin)/GL | missing | missing | missing | Same overlay_vpn pattern (M each) | P2 |
| VPN status page (tunnels, handshake, bytes, connected clients) | pfS/OPN/OWrt/UniFi/GL | partial | missing | missing | IPsec: SAs with bytes, kernel SPs, XFRM interfaces and Connect/Disconnect are on /vpn (C1301); OpenVPN and L2TP sessions are not on /vpn; no per-session bytes or "disconnect" button for them | P1 |
| Split tunnel / domain-based or app-based VPN routing | UniFi/FW/GL/OWrt(pbr) | missing | missing | missing | dnsmasq `nftset=` feeding an nft set used by the gateway-mark rule; table vpn_domain_rules; netlab resolves a name and asserts the mark (M) | P1 |
| Multi-site VPN mesh wizard (hub-and-spoke, Auto-VPN style) | UniFi(Site Magic)/Meraki/Forti | missing | missing | missing | WG-based generator on top of wg tables (L) | P2 |
| Several SSIDs, store-driven (one hostapd per network) | pfS/OPN/OWrt/UniFi/GL/eero | partial | partial | missing | Admin must create the wlan interface; no `bss=` multi-BSS on one radio; not run in PR CI | P0 |
| Router-tier AP: 2 SSIDs x 2 bands from ap.env + `ap` script | OWrt/GL/UniFi/eero | n/a (hardware) | tested | missing | Not in the store: no UI, not in `patronus apply`, backup, GitOps or uci import coverage (the router-tier UI work job working on the page) | P0 |
| WPA2-PSK / WPA3-SAE / WPA2+WPA3 transition | pfS/OPN/OWrt/UniFi/GL/eero | tested | tested | missing | Store path not in PR CI | P0 |
| OWE (enhanced open) / open guest network | OWrt/UniFi/GL | missing | missing | missing | Add `owe` and `open` security values (ieee80211w=2 for OWE) + hwsim case (S) | P1 |
| Hidden SSID | pfS/OPN/OWrt/UniFi/GL/eero | missing | tested | missing | Store path has no knob | P1 |
| Isolated guest network (VLAN and/or SSID) with bandwidth limit, schedule, shared password and vouchers | UniFi/FW/GL/eero/OWrt/pfS/OPN | tested | n/a (AP role: main router provides it) | missing | USE=guest, page Guest network, `patronus guest`, [docs/GUEST-NETWORK.md](GUEST-NETWORK.md): own VLAN/bridge, DHCP+DNS only, no LAN/management/other-guest access, per-network and per-guest caps, schedule and timed access, WPA2/WPA3 SSID with vouchers. Netlab `lane-t-guest.sh` (66 checks), hwsim `lane-t-guest-wifi.sh`, browser `lane-t-guest-ui.sh`. Not yet: IPv6 for guests, a login page (captive portal), per-voucher data caps, the embedded Router/Small images (flash/RAM budget) | P0 |
| Wi-Fi client list with signal/rate and kick/ban | OWrt/UniFi/GL/eero/FW | partial | missing | missing | No RSSI, TX/RX rate, uptime, bytes; no kick/deauth or timed-ban button; no MAC ban | P0 |
| MAC filter (allow/deny list) | OWrt/UniFi/GL/eero | partial | missing | missing | accept/deny mac file + table (S) | P2 |
| Channel / width / tx power / country | pfS/OPN/OWrt/UniFi/GL/eero | partial | partial | missing | Store path: add width, ACS, DFS, txpower. Router: txpower | P0 |
| Wi-Fi 6 (802.11ax) HE settings, VHT, BSS colour | OWrt/UniFi/GL/eero | missing | tested | missing | STD installs are capped at 802.11n; port he_lines and chan5_lines into render_hostapd with a per-radio table (M) | P0 |
| 802.11r fast transition | OWrt/UniFi/GL/eero | missing | partial | missing | Needs multiple APs to be useful (see #36) | P1 |
| 802.11k/v and band steering | OWrt/UniFi/GL/eero | missing | partial | missing | Add ieee80211v/rrm lines and a usteer-like steering applier (M) | P1 |
| Mesh (802.11s / EasyMesh) and multi-AP management from one controller | OWrt/UniFi/GL/eero | missing | missing | missing | `ap_nodes` table + satellite agent pulling rendered hostapd config; wired multi-AP with shared SSID/PSK/FT first, 802.11s later (L) | P1 |
| WPS | pfS(no)/OWrt/GL/eero | missing | missing | missing | Skip; state it in the "not available" listing | P2 |
| Wi-Fi schedules (radio or SSID off by time) | UniFi/GL/eero/OWrt(cron) | partial | missing | missing | schedule on seg_wifi_networks, applier does `hostapd_cli disable/enable` on the seg_time clock (S) | P1 |
| Per-SSID VLAN / segment | pfS/OPN/OWrt/UniFi/GL/SMB | partial | missing | missing | Router path cannot map an SSID to a VLAN or OPT segment; no dynamic VLAN per device | P0 |
| WPA-Enterprise (802.1X) with RADIUS | pfS/OPN/OWrt/UniFi/SMB | missing | missing | missing | security `wpa_eap` + auth_servers rows, optional built-in EAP with local users (M) | P1 |
| Private PSK per device (rotate, revoke, enrol, quarantine unknown) | UniFi(PPSK)/Meraki(iPSK) | tested | missing | missing | Unique differentiator, not in PR CI | P1 |
| Wi-Fi QR share (WIFI: URI) | UniFi/GL/eero/FW | tested | missing | missing | Only for per-device credentials; no QR for a shared or guest SSID | P1 |
| AP mode vs router mode | OWrt/GL/UniFi/eero | missing | partial | missing | IN-PROGRESS for the AP-mode menu | P1 |
| Repeater / WDS / STA uplink | OWrt/GL/UniFi | missing | missing | missing | being built by another work item | P1 |
| Neighbour AP scan / channel survey | UniFi/OWrt/eero | missing | missing | missing | `iw dev scan` via applyd shown in the Wi-Fi page (S) | P2 |
| Wi-Fi config covered by store, backup/restore, GitOps | pfS/OPN/OWrt/UniFi | partial | missing | missing | Router Wi-Fi is lost by config backup and cannot be edited in the UI | P0 |

## System, management and monitoring

| Feature | Found in | Standard | Router | Small | What is missing / notes | Impact |
|---|---|---|---|---|---|---|
| First-boot setup wizard (roles, LAN/WAN addressing, DHCP pool) | pfS/OPN/OWrt(no)/UniFi/GL/eero | tested | partial | partial | The ISO installer now sets bonds, VLAN-tagged WAN/LAN, PPPoE and a management network (SSH + web UI only there) before the first boot; the web wizard still has no step for WAN type (PPPoE/VLAN), WAN speed for shaping, Wi-Fi, admin password strength; no phone/QR flow | P0 |
| Responsive web UI (mobile layout) | pfS(partial)/OPN/UniFi/GL/eero | untested | partial | partial | No documented mobile viewport test; no PWA manifest or service worker (only a service-worker cleanup in login.html:133) | P1 |
| Dashboard widgets | pfS/OPN/UniFi/FW/GL/eero | partial | partial | partial | Not customisable, no live graph widgets, no gateway quality / top talkers / Wi-Fi clients widget | P1 |
| Console menu (text menu on tty/serial: set IPs, reset password, reboot) | pfS/OPN/OWrt(failsafe)/GL | missing | missing | missing | Add `patronus console` (interface assignment, LAN IP, admin password reset, factory reset, ping) launched from agetty/serial inittab; OpenRC+systemd units; vmtest scenario drives it over serial (M) | P0 |
| Users, local accounts, roles | pfS/OPN/UniFi/GL | tested | untested | untested | none notable | P0 |
| Groups and privileges (RBAC per page) | pfS/OPN | tested | untested | untested | none notable | P1 |
| LDAP login | pfS/OPN/Forti-Sophos | tested | missing | missing | fits router (small); not enabled | P1 |
| RADIUS login | pfS/OPN/Forti-Sophos | tested | untested | untested | no FreeRADIUS integration test | P2 |
| TOTP two-factor login | pfS/OPN/UniFi/GL | tested | missing | missing | small; add `totp` to router FEATURES | P1 |
| WebAuthn / passkeys | OPN(no)/UniFi(yes)/Meraki | missing | missing | missing | Add webauthn-rs, `webauthn_credentials` table, login step + enrol UI (M) | P2 |
| REST API with API keys | pfS(pkg)/OPN/OWrt(ubus)/UniFi | tested | untested | untested | OK | P1 |
| API documentation (OpenAPI / swagger) | pfS/OPN/UniFi | missing | missing | missing | Generate an OpenAPI document from the route table (S-M) | P2 |
| SSH admin access settings + authorized keys | pfS/OPN/OWrt/GL | missing | missing | missing | Port, listen, password auth, key list, user CA are being built by another work item | P0 |
| Backup (download) + restore of whole config | pfS/OPN/OWrt/UniFi/GL | tested | untested | untested | Router Wi-Fi (ap.env) not covered | P0 |
| Scheduled remote backups (SFTP, HTTPS PUT, FTPS) with encryption | pfS(pkg)/OPN/UniFi(cloud)/Meraki | tested | untested | untested | SFTP/FTPS code path not covered by the netlab (only HTTP PUT); no S3 or cloud-drive API; no retention/prune | P1 |
| Config history + diff + rollback | pfS/OPN/OWrt(no)/UniFi | partial | untested | untested | No side-by-side diff in UI; no commit message / "revert in N minutes if I lose access" confirm | P0 |
| Factory reset | pfS/OPN/OWrt/GL/UniFi | tested | untested | untested | no hardware reset-button hook (see LED/button row) | P0 |
| Firmware / OS update from the UI | pfS/OPN/OWrt(LuCI)/UniFi/GL/eero | partial | partial | partial | No release channels, no signature-verified binary update for non-Portage images, no rollback after failed upgrade in UI | P0 |
| Automatic updates on a schedule + release channels | OPN/UniFi/eero/GL/OWrt(no) | missing | missing | missing | `update_policy` table (channel stable/testing, window, auto-reboot); cron-like task in patronus-web or `patronus-update.timer` + OpenRC runner; vmtest with a fake binhost (M) | P1 |
| Attended sysupgrade (build image on server with chosen packages) | OWrt | missing | missing | missing | Out of scope until a binhost/image builder service exists (L) | P2 |
| Package / plugin manager | pfS/OPN/OWrt | tested | missing | missing | Components install only via Portage (no apk/opkg path on router images) | P1 |
| RRD-style historical graphs (CPU, memory, interface throughput, gateway latency) | pfS/OPN/OWrt(statistics)/UniFi | partial | partial | partial | No ring-buffer sampler or graph rendering for CPU/mem/interface rates; Prometheus `/metrics` exists (lane-h-apikeys) for external Grafana | P0 |
| Gateway quality graphs (latency, loss) and SLA | pfS/OPN/OWrt(mwan3)/UniFi/FW | tested | untested | untested | No graph, tables only (in-progress consumer UI not found) | P1 |
| Traffic statistics / per-interface counters | pfS/OPN/OWrt/UniFi | partial | partial | partial | no history | P1 |
| Monthly data accounting (vnStat-class) | OPN(pkg)/OWrt(vnstat)/UniFi/GL/eero | missing | missing | missing | Daily/monthly rollup table fed by the insights collector, quota alert; netlab asserts counts (S-M) | P1 |
| Top talkers (ntopng-class): per host/service/protocol/country/ASN | pfS(ntopng)/OPN/UniFi/FW | tested | untested | missing | No DPI (no L7 names), no real-time chart, no export to ntopng/nProbe; NetFlow export exists (lane-j-netflow) | P1 |
| Per-device bandwidth view | UniFi/FW/GL/eero/OPN | tested | untested | missing | no live rate per device | P1 |
| Log viewer (system journal / firewall log) | pfS/OPN/OWrt/UniFi | partial | partial | missing | no search/filter/download; no log files for non-systemd (OpenRC) hosts beyond what journal feature reads | P1 |
| Remote syslog forwarding | pfS/OPN/OWrt/UniFi | tested | missing | missing | IN-PROGRESS touches syslog items | P1 |
| Notifications: email (SMTP) | pfS/OPN/UniFi/Forti | missing | missing | missing | `notify_channels` table + sender (lettre or curl smtp://) wired to system_events (M) | P0 |
| Notifications: Telegram / ntfy / push | OPN(pkg)/OWrt(pkg)/UniFi/FW/eero | missing | missing | missing | Add channel types to the event dispatcher (S: ntfy/Telegram are plain HTTPS POSTs) | P0 |
| Event log + signed webhooks (gateway up/down, tunnel, HA, config change) | OPN/UniFi | tested | untested | untested | event kinds limited to gateway, group, tunnel, ha, config | P1 |
| Diagnostics: ping / traceroute / DNS lookup | pfS/OPN/OWrt/UniFi/GL | missing | missing | missing | `/api/system/diag/{ping,traceroute,dns}` through applyd with structured args (reuse the capture pattern, lane-j-capture), Diagnostics page; netlab asserts output (S) | P0 |
| Diagnostics: ARP / NDP tables, routing table, open sockets | pfS/OPN/OWrt/UniFi | partial | partial | partial | add `ip neigh`, `ss -tulpn` views (S) | P1 |
| Packet capture with download | pfS/OPN/OWrt(tcpdump)/UniFi | partial | untested | untested | no `.pcap` download, no stop/duration UI | P1 |
| SNMP agent | pfS/OPN/OWrt/Forti-Sophos-Meraki | missing | missing | missing | Wire the module behind a `snmp` feature with net-snmp snmpd config applier (interfaces, CPU, uptime), netlab with snmpwalk (M) | P1 |
| Prometheus metrics | pfS(pkg)/OPN(plugin)/UniFi(unpoller) | tested | untested | untested | none | P2 |
| HA config sync (primary pushes config to secondary) | pfS/OPN/Forti-Sophos | partial | missing | missing | Add sync of the store to the peer (export_json over HTTPS with token) + "maintenance mode" already present (`/ha/maintenance`) (M) | P1 |
| GitOps (config from git) | OPN(no)/pfS(no)/UniFi(no) | tested | missing | missing | watch` (main.rs:128); patronus-gitops crate; docs/GITOPS-RESOURCES.md | res… |
| Terraform / Ansible | OPN(provider)/pfS(ansible)/OWrt(ansible)/Meraki(terraform) | partial | missing | missing | Add a CI job running the playbooks against the netlab router; a minimal terraform provider from the REST API (M-L) | P2 |
| Cloud / remote multi-site management | UniFi/Meraki/Forti/eero/FW/GL | partial | missing | missing | needs a NAT-friendly relay (WireGuard/websocket) so a phone can manage without port-forward | P1 |
| Mobile app | UniFi/Firewalla/GL/eero | missing | missing | missing | PWA manifest + web-push on events (S-M) | P1 |
| LED / button control | OWrt/GL | missing | missing | missing | board.sh hook + page for LED trigger (netdev link) and reset-button -> factory reset (S) | P2 |
| Scheduled tasks / scheduled reboot | pfS(cron)/OPN/OWrt(cron)/UniFi | missing | missing | missing | `scheduled_tasks` (reboot, backup now, update check) + runner in applyd (S) | P1 |
| Timezone, hostname, domain | all | tested | untested | untested | none | P0 |
| NTP server/client settings | pfS/OPN/OWrt/UniFi | tested | missing | missing | IN-PROGRESS for NTP on the router tier | P0 |
| Serial console | OWrt/GL/pfS | partial | partial | partial | no menu (see #4) | P2 |
| Web TLS: self-signed + operator certificate | pfS/OPN/OWrt/UniFi | tested | untested | untested | no ACME / Let's Encrypt (grep acme: none); no cert upload UI (drop file into dir) | P0 |
| ACME (Let's Encrypt) for the web UI | pfS(pkg)/OPN(plugin)/OWrt(acme)/UniFi | missing | missing | missing | `acme` applier using lego/acme.sh DNS-01 or HTTP-01 via DDNS name, store table, cert dir already honoured by tls.rs (M) | P1 |
| Login lockout / brute-force protection | pfS/OPN/UniFi | partial | untested | untested | no admin-visible "unblock" list, no notification | P1 |
| Audit log (who changed what) | pfS/OPN/UniFi/Forti | partial | partial | partial | Add `/system/audit` page with filter + CSV; ship to syslog (S) | P1 |
| Support bundle (logs + config + versions in one download) | OPN/UniFi/Meraki/Forti | missing | missing | missing | `patronus support-bundle` (redacted config export, journal tail, `patronus status`, dmesg, versions) + button; unit test that secrets are redacted (S) | P1 |
| Service control (start/stop/restart daemons from UI) | pfS/OPN/OWrt | tested | untested | untested | none | P1 |
| Reboot / shutdown from UI | all | untested | untested | untested | none | P0 |
| Accessible "Not available on this build" explanations | UniFi/GL | partial | partial | partial | no reasons (RAM/flash) shown | P1 |

## Consumer and commercial features

| Feature | Found in | Standard | Router | Small | What is missing / notes | Impact |
|---|---|---|---|---|---|---|
| Device inventory (every LAN device with MAC, IP, name, last seen) | UniFi/FW/GL/eero | partial | partial | partial | Inventory shows only enrolled + discovered; no online/offline history, no first-seen/last-seen over time, no wired/Wi-Fi/AP column | P0 |
| Device fingerprinting (vendor, OS, device type icon) | UniFi/FW/eero | missing | missing | missing | Add an IEEE OUI table (build-time list) + DHCP fingerprint (options 55/60) + mDNS names; show icon and guess in the device table; unit tests with sample leases (M) | P0 |
| Device naming and grouping by person | UniFi/FW/eero | partial | missing | missing | No person entity that owns several devices (phone, laptop) and carries one schedule/profile; time and DNS policy attach to group or device only | P0 |
| New-device alerts + approval/quarantine | UniFi/FW/eero/GL | partial | missing | missing | No push/email/webhook "new device joined" event (events are gateway/tunnel/ha/config, state/telemetry.rs), no approve-from-notification flow | P0 |
| Parental controls: per-device/group time limits and schedules | UniFi/FW/eero/GL | tested | missing | missing | none notable; best in class vs open-source routers | P0 |
| Bedtime / pause-internet button | FW/eero/UniFi | tested | missing | missing | pause applies to device only; no "pause everyone in the group" or phone widget | P1 |
| Category content filtering (adult, malware, gambling, social, ...) | UniFi/FW/eero/SMB | partial | missing | missing | Only two categories; no gambling/social/streaming/gaming/ads categories, no category picker per profile, no allow-list schedule | P0 |
| SafeSearch + YouTube restricted mode | UniFi/FW/eero | partial | missing | missing | No separate toggles (strict vs moderate YouTube), no TikTok/Instagram controls | P1 |
| Per-device ad blocking | FW/GL(AdGuard)/UniFi | partial | missing | missing | No curated ad list preset with one switch, no per-device toggle in the device UI, no stats of blocked queries per device on a dashboard (query log exists: `/segmentation/dns/log`, CSV export) | P1 |
| Application identification (Netflix, TikTok, games) + per-app blocking | UniFi/FW/SMB | missing | missing | missing | Needs an L7 engine (nDPI as a nfqueue/ntopng sidecar, or Suricata app-layer logging) mapped to app labels, then per-app policy rows; also an N/A-HW check for ROUTER RAM (L) | P1 |
| Per-device usage history | UniFi/FW/eero | tested | missing | missing | No graph of usage over days in the UI, no per-app/per-site breakdown, retention settings exist | P1 |
| Network topology map | UniFi/eero/Orbi | missing | missing | missing | Page drawing WAN -> router -> bridges/VLANs -> devices from interface + discovered tables (reuse `/segmentation/discovered` + interface list); with APs once multi-AP exists (M) | P1 |
| Speed test with history | UniFi/FW/GL/eero | missing | missing | missing | Scheduled `speedtest`-style test against a chosen server (iperf3 or HTTPS download) into a samples table; page + chart; netlab with a local server (S-M) | P0 |
| ISP outage and uplink quality monitoring | FW/UniFi/eero/SMB | tested | untested | untested | outages | sla |
| IPS with simple user-facing alerts | FW/UniFi/SMB | partial | missing | missing | Shows raw rule alerts; no plain-language "Blocked: malware callback on camera" cards, no ET ruleset auto-update status in the netlab, no per-device attribution of alerts | P1 |
| Abnormal upload / data exfil alert | FW/UniFi | missing | missing | missing | Compare per-device bytes to rolling median in the insights collector, emit an event; (S-M once new-device-style notifications (E#30,#31) exist) | P1 |
| DoH / DoT bypass blocking | FW/UniFi/GL | partial | missing | missing | Add a maintained DoH-resolver IP/name list as an nft set + block rule for policed devices (S) | P1 |
| One-click VPN server (WireGuard) with phone QR | UniFi/FW/GL/eero(no) | partial | missing | missing | A "Turn on remote access" button that picks port/subnet/endpoint (from DDNS name) and shows the first QR; DDNS applier exists (network/src/ddns.rs) but is not tied in (S-M) | P0 |
| Guest Wi-Fi with captive portal / vouchers | UniFi/GL/eero/SMB | partial (shared password + time-limited WPA2 vouchers, no login page) | missing | missing | Voucher passwords exist (USE=guest); still missing: Captive portal service (nodogsplash-style: redirect + auth via nft set) + voucher table (code, duration, data cap) + printable list; netlab with a curl client through the portal (L) | P0 |
| Mesh/AP setup UX (adopt a second AP) | UniFi/eero/Orbi/GL | missing | missing | missing | Controller + satellite agent; "add AP" wizard with QR (L) | P1 |
| Automatic firmware + signature (IPS rules, blocklists) updates | UniFi/FW/eero/SMB | partial | missing | missing | No scheduler for feeds or firmware; no channel | P1 |
| Setup via phone / QR | eero/UniFi/GL/FW | missing | missing | missing | Print the setup URL as a QR on the console/first-run page; mDNS name `patronus.local` already in the TLS SANs (lane-n-tls) (S) | P1 |
| Cloud remote access without port forward | UniFi/FW/GL/eero | missing | missing | missing | Outbound-initiated tunnel to a rendezvous (WireGuard or websocket) and a Tailscale/Headscale integration (D row 19) is the cheapest route (M) | P0 |
| Mobile app / PWA with push | UniFi/FW/GL/eero | missing | missing | missing | PWA manifest + web push on events (S-M) | P1 |
| Multi-site management | UniFi/Meraki/SMB | partial | missing | missing | Dashboard shows edges; configuration push to a managed router and per-site config templates are not covered by the netlab | P1 |
| Zero-touch provisioning | Meraki/UniFi/SMB | tested | missing | missing | No DHCP option / claim-by-serial discovery (only a fixed URL in toml); no signed bundles (passphrase only) | P1 |
| SSL inspection (TLS MITM for filtering) | SMB (Forti/Sophos) | missing | missing | missing | Squid ssl-bump + CA distribution wizard; heavy, probably skip for consumer tiers (L) | P2 |
| ZTNA (identity-aware app access) | SMB/Meraki | missing | missing | missing | Out of scope for now; LDAP + WireGuard could be combined into per-user VPN policies (L) | P2 |
| Sandboxing (file detonation) | SMB | missing | missing | missing | Out of scope; needs a cloud service (L) | P2 |
| App-aware SD-WAN | Meraki/Forti/Sophos | partial | missing | missing | Needs L7 labels + policy-route by label | P2 |
| Weekly summary report (email) | FW/eero/UniFi | missing | missing | missing | Weekly job renders a summary (top devices, blocked queries, outages, new devices) and sends through the E-system notification channels (M, depends on E#30) | P1 |
| Honest-state UI (shows only what is real, no fixtures) | none of the competitors guarantee it | tested | untested | untested | A genuine differentiator: extend the journey to Wi-Fi and segmentation pages | P1 |
| "Not available on this device" explanations | UniFi/GL | partial | partial | partial | Add a "What this device can't do and why" page fed by the feature list + a reason table per tier | P1 |
| Segmentation / IoT isolation as a consumer concept ("IoT network", one switch) | UniFi/FW/eero | tested | missing | missing | Differentiator vs. UniFi (VLAN-based); no "IoT" template in the UI, opt-in only (upgraded stores unchanged by design) | P1 |
| Per-device Wi-Fi password (private PSK) and QR share | UniFi(PPSK)/Meraki | tested | missing | missing | Not in PR CI | P1 |
| DNS query log per device | FW/UniFi(no)/GL | tested | missing | missing | none notable | P1 |
| Family profile one-click (kids: filter + SafeSearch + bedtime) | FW/eero/UniFi | partial | missing | missing | Add a profile template that creates group + DNS policy + time policy in one call (S) | P0 |
