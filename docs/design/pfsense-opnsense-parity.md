# Patronus vs pfSense CE and OPNsense: installer and feature parity

Status: audit of 2026-11-25, Patronus `main` 1a47d44c.
Companion plan: [proxmox-9.3-ideas.md](proxmox-9.3-ideas.md) (UI design system, log viewer, access log,
notification matchers, installer bonds/VLANs, HA maintenance hand-off + HA configuration sync). Items
already planned there are referenced here, not repeated.

## What was run

| Product | Version actually run | How it was obtained |
|---|---|---|
| OPNsense | 26.7 installer (serial `.img`, SHA-256 + signature checked against the official mirror), updated in place to **26.7.10** | official mirror |
| pfSense CE | 2.7.2 memstick-serial image from Netgate's public mirror (the newer CE releases ship only through the "Netgate Installer", which needs a store registration), installed, then switched to the newest branch on *System > Update* and upgraded to **2.9.2-RELEASE** (FreeBSD 16.0-CURRENT base) | Netgate mirror + Netgate's own update servers |
| pfSense Plus | not run (paid); docs only | |
| Patronus | daily standard-tier ISO (live + installer) and the web UI of `main` | Patronus CI |

Lab: QEMU/KVM, 6 virtio NICs per firewall (WAN, LAN, OPT/DMZ, VLAN trunk with VLAN 10 and 20, a two-port
LAGG), a WAN-side dnsmasq (DHCPv4 + DHCPv6/RA) and a LAN-side browser in its own network namespace (no separate client VM was booted).
Every installer screen and first-boot prompt was captured over the serial console (text) and VNC
(screenshots); every menu page and tab of the running web UIs was crawled (pfSense 173 pages, OPNsense
177 pages, Patronus 30 pages) with title, tabs, text and a screenshot. The package/plugin catalogs were
read from each box (`pkg search`). Evidence is kept outside the repo.

Status words: **present** = in the shipped binary, reachable from API/UI, covered by a netlab/QEMU test;
**partial** = exists but a switcher would miss something named in the gap column; **missing** = not there.

## 1. Installer and first boot

| What pfSense / OPNsense do | Patronus standard tier | Patronus router tier (embedded) | Status |
|---|---|---|---|
| Serial or VGA console choice at boot; installer runs on serial | GRUB menu, serial console works; installer is a TUI (`liveinst`) and an unattended answer-file mode | image flash (OpenWrt `sysupgrade`, GL stock `factory.ubi`) | present |
| Disk: ZFS (stripe, mirror, raidz1/2/3), UFS; pool name, swap size, 4K, GPT/MBR/BIOS+UEFI | ZFS single or mirror, automatic XFS fallback (RAM < 8 GB / no ZFS module), ext4 as a manual choice, zram only, UEFI + BIOS | fixed UBI/squashfs layout | partial: no raidz, no 3+-disk vdevs, no pool-name/ashift options |
| Encryption (OPNsense: GELI on UFS/ZFS) | LUKS only when TPM2 can unseal unattended, decided automatically | none | present (by design) |
| Boot environments / ZFS snapshots (OPNsense *System: Snapshots*) | `patronus-be` CLI, BE per upgrade | U-Boot A/B rollback | partial: no UI page |
| Interface assignment at first boot (detect link, pick WAN/LAN/OPTn) | installer + console menu "Assign interfaces" (WAN + LAN only) | role from board profile | partial: no OPT interfaces |
| VLANs at first boot (both); LAGG at first boot (OPNsense) | missing | n/a | missing -> job `44-patronus-installer-lagg-vlan` (companion plan) |
| Root/admin password set in installer (OPNsense) | first-run web page with setup code | first-run web page | present |
| Live mode with "importer" (OPNsense: restore `config.xml` from a USB stick before install) | console "Restore a configuration backup" (Patronus format) | settings import from OpenWrt UCI | partial: no pfSense/OPNsense `config.xml` import |
| Web setup wizard: hostname, domain, DNS, NTP server, timezone, WAN type (DHCP/static/PPPoE), LAN IP, admin password, DNS resolver options (steps from the vendor docs; only the first wizard page was captured live) | `/setup`: WAN DHCP/static, LAN IP, DHCP pool, DNS servers | AP role skips it | partial: no PPPoE, no IPv6 WAN, no hostname/domain/timezone/NTP step |
| Console menu: pfSense 0-16 (pfTop, filter logs, restart web UI, PHP shell, update from console, enable SSH, restore recent config, restart PHP-FPM); OPNsense 0-13 (+ update, refresh, plugins) | 0-11: assign, set IP (DHCP/static), reset admin password, factory reset, power off, reboot, ping, shell, show web UI URL, restore backup, create backup | serial shell | partial: no live states/top view, no firewall log tail, no "restart web UI", no update from console, no SSH on/off, no "restore previous revision", no IPv6 in "set IP" |
| Update channel/branch choice (pfSense branch select; OPNsense Community/Business/Development + mirror list) | firmware feed + updates page | signed sysupgrade feed | partial: no channel or mirror selector |

## 2. System

| Feature | pfSense | OPNsense | Patronus | Status |
|---|---|---|---|---|
| General setup (hostname, DNS, timezone, language) | yes | yes | `/system` | partial: no language (UI is English only) |
| Admin access (HTTPS port, cert, SSH, anti-lockout) | yes | yes | `[web]` settings, 443/80, anti-lockout follows ports | present |
| Users, groups, privileges | yes | yes | users, groups, RBAC (lane-n-rbac) | present |
| LDAP / RADIUS login, tester | yes | yes | LDAP + RADIUS (lane-n-ldap) | partial: no "auth tester" page, no RADIUS accounting |
| TOTP 2FA | yes | yes | TOTP | present |
| Certificate manager (CAs, certs, CSRs, CRLs) | yes | *Trust* | self-signed web cert, IPsec road-warrior CA only | **missing** |
| ACME / Let's Encrypt (HTTP-01, DNS-01, renew, deploy to web UI/HAProxy) | acme package | os-acme-client | code stub in `patronus-core/src/certs.rs`, not wired | **missing** |
| Config history, diff, restore | yes | yes | `/system/history` diff + restore | present |
| Automatic off-box backup (pfSense ACB; OPNsense git/SFTP/Nextcloud/Google Drive) | yes | plugins | backup targets | present |
| Notifications (SMTP, Telegram, Pushover...) | yes | Monit | ntfy/Telegram/Discord/Slack/SMTP (lane-h-notify) | present (matchers: companion plan) |
| Tunables / sysctl | yes | yes | sysctl | present |
| Cron jobs page | package | *Settings: Cron* | none | missing (low) |
| Package/plugin manager | about 70 packages | about 120 plugins | signed plugins (lane-n-plugins), small catalog | partial (see section 9) |
| Firmware update with changelog, audit | yes | yes | updates + firmware pages, rollback | partial: no changelog view, no security audit (`pkg audit`-like) |
| HA settings + config sync (XMLRPC) | yes | yes | VRRP + conntrackd, no config sync | partial -> job `45-patronus-ha-maintenance-handoff-and-sync` (companion plan) |
| REST API | pfSense Plus only (CE via package) | full, documented | API + API keys | partial: no OpenAPI spec/docs page, coverage uneven |
| Multi-language UI | yes | yes | English only | missing |

## 3. Interfaces

| Feature | Patronus | Status |
|---|---|---|
| Assignments, static/DHCP v4, DHCPv6 + prefix delegation, SLAAC, track interface | interfaces + `pd_downstream` (lane-c, lane-n-dhcp6pd) | present |
| VLAN, QinQ | yes | present |
| LAGG (LACP, failover, load balance) | bond (lane-c) | present |
| Bridge | yes | present |
| GRE, VXLAN | GRE, GRE-TAP, VXLAN (lane-n-overlays) | present |
| GIF (IP-in-IP), 6in4 / 6rd tunnel broker | none | missing |
| PPPoE / PPP client, L2TP | PPPoE client, L2TP | present |
| Wireless (AP, client) | AP + client, auto channel | present (ahead) |
| Interface groups usable as rule targets | none | **missing** |
| Virtual IPs: CARP / IP alias / proxy ARP | VRRP VIPs; proxy ARP only in segmentation | partial: no IP alias / proxy-ARP VIP type |
| Loopback, TAP devices (OPNsense) | none | missing (low) |
| Hostwatch / neighbor discovery log (OPNsense), ARP watch | none | missing (low) |

## 4. Firewall

| Feature | Patronus | Status |
|---|---|---|
| Per-interface rules, aliases (host/net/port), URL tables, GeoIP, ASN | yes (lane-b-firewall, lane-b-feeds) | present |
| Floating rules (any interface, direction, quick) | none | **missing** |
| Rules on interface groups | none | **missing** |
| NAT: port forward, outbound/source NAT, 1:1, NPTv6 | yes (lane-b-npt) | present |
| Schedules on rules | `patronus-firewall/src/schedule.rs` | present |
| Traffic shaper (CAKE, fq_codel, limit) + limiters | CAKE / fq_codel / limit per interface | partial: no per-rule limiter/queue assignment, no shaper wizard |
| Rule logging, live log view, summary view | NFLOG log viewer | partial: no "dynamic/summary" views, no "block from log" action |
| States table, reset states, pfTop-like live view | states page | partial: no live top-talkers per state with sort/kill |
| Policy routing (gateway per rule) | yes (lane-e) | present |
| Normalization / scrub, max states, syn-proxy, state options per rule | hardening + MSS clamp | partial: no per-rule state limits (max-src-conn etc.) |
| Firewall categories (OPNsense) for rule grouping | none | missing (low) |

## 5. Routing, multi-WAN, HA

| Feature | Patronus | Status |
|---|---|---|
| Static routes, gateways, gateway monitoring (loss/latency) | yes (lane-e, uplink_probe) | present |
| Gateway groups: tiers, weights, failover, load balance, recovery | yes (lane-e) | present |
| Sticky connections, kill states on gateway down/up, per-gateway loss/latency thresholds in UI | none of these confirmed | partial |
| Dynamic routing (FRR: BGP, OSPF) | FRR svc page (lane-j-frr) | present |
| HA: CARP VIPs | VRRP (keepalived) VIPs, IPv4 + IPv6 | present (different protocol, same role) |
| HA: state sync (pfsync) | conntrackd | present |
| HA: configuration sync (XMLRPC, per-section) | none | missing -> job 45 (companion plan) |
| HA: DHCP failover between nodes (pfSense ISC failover / Kea HA) | none | **missing** |
| HA: maintenance mode | exists, no confirmed hand-off | partial -> job 45 |

## 6. Services

| Feature | Patronus | Status |
|---|---|---|
| DHCPv4 (ISC/Kea/dnsmasq), static maps, options | dnsmasq / Kea | present |
| DHCPv6 server, Router Advertisements | Kea / radvd | present |
| DHCP relay v4 | dnsmasq relay | present |
| DHCP relay v6 | none | missing |
| Kea DDNS agent (register DHCP clients in DNS) | none | missing |
| DNS resolver (Unbound): overrides, DNSSEC, DoT, ACLs, blocklists, query forwarding, statistics | yes (lane-s-dns-dot, seg_dns blocklists) | present |
| DNS forwarder (dnsmasq) | yes | present |
| Dynamic DNS clients | yes | partial: no RFC 2136 (nsupdate) clients |
| NTP server | chrony | partial: no GPS/PPS reference clocks, no ACL page |
| Captive portal (splash, local/RADIUS login, vouchers, MAC/IP passthrough, idle/hard timeouts, session list) | none (Wi-Fi vouchers on the guest network only) | **missing** |
| UPnP / NAT-PMP / PCP | miniupnpd | present |
| IGMP proxy, mDNS repeater, UDP broadcast relay | IGMP, mDNS | partial: no UDP broadcast relay |
| Wake-on-LAN | yes | present |
| SNMP | yes | present |
| PPPoE server | none | missing |
| LLDP | none | missing |
| TFTP server | none | missing (low) |
| Monit-style service watchdog with alerts | supervise + notifications | partial |
| IDS/IPS (Suricata inline, rule sets, policies) | Suricata IDS/IPS via NFQUEUE, own rules + optional `suricata-update` rules (lane-j-ids) | partial: no rule-set manager (ET Open/Abuse.ch/PT feeds selectable + scheduled download), no per-category policy (alert/drop), no alert browser with suppress/threshold |
| Web proxy (Squid), transparent | yes (lane-n-proxy) | present |
| Reverse proxy / load balancer (HAProxy, relayd, Caddy, nginx) | `patronus-proxy` crate exists, not wired into any binary | **missing** |
| Netflow export, traffic insight | netflow + insight (lane-s-insight) | present |

## 7. VPN

| Feature | Patronus | Status |
|---|---|---|
| WireGuard | yes (router tier too) | present |
| IPsec site-to-site (policy based) | strongSwan | present |
| IPsec route based (VTI) | none | **missing** |
| IPsec mobile clients, leases, SAD/SPD status | road warriors (lane-f-ipsec-rw) | partial: no SAD/SPD status pages |
| OpenVPN server/client, client export, client-specific overrides | server + client, `.ovpn` export, ccd | present |
| L2TP | yes | present |
| OpenConnect, Tailscale, ZeroTier, NetBird, tinc (OPNsense plugins / pfSense packages) | none | missing (mesh VPNs) |

## 8. Status, diagnostics, reporting

| Feature | Patronus | Status |
|---|---|---|
| Dashboard with widgets | fixed cards | partial: no add/remove/reorder widgets |
| System logs per service | monitoring log viewer | partial -> companion plan (syslog viewer job) |
| Packet capture with download | yes (lane-j-capture) | present |
| Ping, traceroute, DNS lookup, test port, ARP/NDP, routes, sockets | yes (lane-h-diag) | partial: no "test port" |
| System activity (top), pfInfo, tables | none | missing |
| S.M.A.R.T. status/tests | none | **missing** |
| UPS (NUT, apcupsd) with clean shutdown | none | **missing** |
| Traffic graphs, RRD-style history, health reporting | insight history + Prometheus `/metrics` | present |
| Edit file, command prompt, halt/reboot | shell via console; reboot/power off | present (by design no web shell) |

## 9. Packages and plugins a switcher looks for

From the live catalogs (pfSense CE 2.9.2: about 70 packages; OPNsense 26.7: about 120 plugins). Patronus equivalents:

| Package/plugin | Patronus |
|---|---|
| Suricata / Snort, Zeek | Suricata built in (partial, section 6); Zeek missing |
| pfBlockerNG / Unbound blocklists / Q-Feeds | DNS blocklists + URL-table and GeoIP aliases: present |
| CrowdSec | missing |
| Zenarmor / ntopng (application visibility) | traffic insight (partial); app classification missing |
| HAProxy, relayd, Caddy, nginx | missing (section 6) |
| ACME client | missing (section 2) |
| FRR | present |
| WireGuard, OpenVPN client export | present |
| Tailscale, ZeroTier, NetBird, OpenConnect, tinc | missing |
| Squid, SquidGuard, c-icap/ClamAV | Squid present; URL categories + AV missing |
| FreeRADIUS | missing (Patronus is a RADIUS client only) |
| NUT / apcupsd | missing |
| Zabbix agent/proxy, Telegraf, node_exporter, collectd, munin, netdata, Wazuh agent | Prometheus `/metrics` + SNMP + remote syslog; agents missing |
| LLDP (lldpd, LADVD) | missing |
| mDNS bridge, UDP broadcast relay, IGMP proxy, pimd | mDNS + IGMP present; UDP relay + PIM missing |
| arpwatch / ANDwatch | missing |
| iperf, nmap, mtr | missing (diagnostics) |
| git/SFTP/Nextcloud/Google Drive backup | backup targets present |
| Cellular modem | missing |
| BIND, dnscrypt-proxy | missing (Unbound covers most uses) |
| Theme plugins | dark/light follows the device: present |

## 10. Where Patronus is ahead

Declarative config with GitOps and generations, Linux VRF, device segmentation with per-device Wi-Fi
credentials, built-in Wi-Fi AP with channel coordination and steering, NAT64, signed plugins, OpenRC and
systemd builds, an embedded router tier on real AP/router hardware, OpenWrt UCI import, Prometheus metrics,
eBPF/XDP fast path.

## 11. Priority: what a pfSense/OPNsense switcher misses first

Gaps counted: 55 rows marked missing or partial-with-a-named-gap above, grouped into the jobs below
(each with netlab/QEMU acceptance tests; router-tier work included where the feature fits the image).

| Order | Group | Job file |
|---|---|---|
| 1 | Installer + first boot: OPT interfaces at assignment, setup wizard (PPPoE, IPv6 WAN, hostname/domain/timezone/NTP), console menu parity, update channel + mirror selector, boot-environment page, raidz/multi-disk ZFS, pfSense/OPNsense `config.xml` import | `30-patronus-installer-wizard-parity` (+ `44-patronus-installer-lagg-vlan`) |
| 2 | HA: config sync + confirmed maintenance hand-off | `45-patronus-ha-maintenance-handoff-and-sync` (companion plan) |
| 2b | HA: DHCP failover (Kea HA hook) and services bound to VIPs | note added to job 45; `31-patronus-ha-dhcp-failover` |
| 3 | Multi-WAN polish: sticky connections, kill states on gateway change, per-gateway thresholds in UI, gateway-group targets in rules | `32-patronus-multiwan-polish` |
| 4 | IDS/IPS: rule-set manager, scheduled updates, category policies, alert browser + suppress | `33-patronus-ids-rulesets-policy` |
| 5 | Captive portal | `34-patronus-captive-portal` |
| 6 | Certificates: CA/cert/CSR/CRL manager + ACME | `35-patronus-cert-manager-acme` |
| 7 | Reverse proxy / load balancer (HAProxy) | `36-patronus-reverse-proxy` |
| 8 | Firewall: floating rules, interface groups, per-rule limiters/queues, per-rule state limits, log summary + block-from-log | `37-patronus-firewall-floating-groups` |
| 9 | VPN: IPsec VTI, SA/SP status, mesh VPN (Tailscale/ZeroTier/NetBird) | `38-patronus-vpn-vti-mesh` |
| 10 | Small services: PPPoE server, LLDP, DHCPv6 relay, UDP broadcast relay, Kea DDNS, RFC 2136, NTP GPS/PPS + ACLs, TFTP, GIF/6in4 | `39-patronus-small-services` |
| 11 | Hardware + monitoring: SMART, UPS (NUT), system activity, test port, dashboard widgets, monitoring agents (Zabbix/Telegraf) | `46-patronus-hw-monitoring` |
| 12 | API + UI language: OpenAPI spec + docs page, full API coverage check, i18n framework | `47-patronus-openapi-i18n` |
