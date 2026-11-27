# Patronus feature test matrix

Every user-facing feature, the end-to-end test that drives the REAL shipped binaries
(`patronus` + `patronus-web`, real kernel state in network namespaces, real daemons), where it
runs, and its last result. A feature without a passing row here is untested; a failing one is a bug.

Last result source: Forgejo rust-ci run 901 on main 3e4f8316 (2026-11-09), jobs
"Netlab (network namespaces)" (task 43111, job 79462) and "Netlab features" (task 43112, job 79463), both green, every scenario below passed, 0 failed (rows with their own date were re-run in that same job).
Seconds = scenario wall time in that run. Re-run one scenario on a build host with
`NETLAB_BIN_DIR=<dir with patronus + patronus-web> ci/netlab/run.sh ci/netlab/<script>`.

Environment: **netlab** = capped container on the CI hosts (x86_64), one netns per party. **Gentoo** = real stage3 image with OpenRC and with systemd as PID 1.
No physical hardware is involved; the installed-ISO path is covered by the live-ISO QEMU gates, not here.

## Features (netlab)

| Feature | Test | Env | Last result (run 901) |
|---|---|---|---|
| Boot, apply, core store | `ci/netlab/lane-a-foundation.sh` | netlab | PASS 33 s|
| First boot -> NAT online -> UI block rule enforced | `ci/netlab/journey-first-boot.sh` | netlab | PASS 33 s|
| UI shows real state, never fixtures | `ci/netlab/journey-honest-state.sh` | netlab | PASS 13 s|
| Configuration history: list revisions and restore one from the System page / API (applied to the system, undoable) | `ci/netlab/lane-h-system.sh` + `lane_fh_tests::configuration_history_lists_revisions_and_restores_one` | netlab + unit | PASS 2026-11-14, rust-ci run 15997 on fbae5c7c (unit test in the Test job; lane-h-system.sh history step: revision restored, later rule gone from nftables) |
| Backup then restore on a replacement box / same box | `ci/netlab/journey-backup-restore.sh` | netlab | PASS 47 s|
| Failed apply never opens the box or locks the admin out | `ci/netlab/failure-atomic-apply.sh` | netlab | PASS 69 s|
| Power cut (SIGKILL) mid-write keeps the store consistent | `ci/netlab/failure-power-cut.sh` | netlab | PASS 54 s|
| Upgrade from v0.1.0 layout and previous release | `ci/netlab/upgrade-store.sh` | netlab | PASS 16 s|
| Firewall rules + NAT from the UI API | `ci/netlab/lane-b-firewall.sh` | netlab | PASS 55 s|
| Self-filling aliases (URL table, threat feeds) | `ci/netlab/lane-b-feeds.sh` | netlab | PASS 55 s|
| Firewall log viewer (NFLOG) | `ci/netlab/lane-b-fwlog.sh` | netlab | PASS 22 s|
| NPTv6 prefix translation | `ci/netlab/lane-b-npt.sh` | netlab | PASS 25 s|
| Interfaces, VLAN, bridge, bond | `ci/netlab/lane-c-interfaces.sh` | netlab | PASS 35 s|
| Traffic shaping (QoS) | `ci/netlab/lane-c-shaping.sh` | netlab | PASS 19 s|
| WAN + routing, multi-uplink failover, policy routing | `ci/netlab/lane-e-routing.sh` | netlab | PASS 33 s|
| IPsec road warriors (IKEv2, real strongSwan client) | `ci/netlab/lane-f-ipsec-rw.sh` | netlab | PASS 32 s, live EAP-MSCHAPv2 + certificate connections, mobileconfig/sswan/PS1 export, reboot, revoke (run 933 job 86298)|
| WireGuard tunnels + road warrior | `ci/netlab/lane-f-wireguard.sh` | netlab | PASS 15 s|
| API keys + monitoring hooks | `ci/netlab/lane-h-apikeys.sh` | netlab | PASS 48 s|
| Web accounts, 2FA login, backup/restore API | `ci/netlab/lane-h-system.sh` | netlab | PASS 36 s|
| Dynamic routing BGP/OSPF (FRR) | `ci/netlab/lane-j-frr.sh` | netlab | PASS 82 s|
| Intrusion detection / prevention | `ci/netlab/lane-j-ids.sh` | netlab | PASS 59 s|
| IGMP proxy (multicast) | `ci/netlab/lane-j-igmp.sh` | netlab | PASS 34 s|
| L2TP server (real client) | `ci/netlab/lane-j-l2tp.sh` | netlab | PASS 38 s, 2026-11-09 run 898 job 79308 (after post-reboot dial retry); re-run PASS 40 s in run 901 (2026-11-09) |
| NAT64 / DNS64 | `ci/netlab/lane-j-nat64.sh` | netlab | PASS 19 s|
| NetFlow / IPFIX export | `ci/netlab/lane-j-netflow.sh` | netlab | PASS 18 s|
| Remote syslog forwarding | `ci/netlab/lane-j-syslog.sh` | netlab | PASS 29 s|
| Wake-on-LAN | `ci/netlab/lane-j-wol.sh` | netlab | PASS 14 s|
| Packet capture (tcpdump through the root broker, filtered, limited) | `ci/netlab/lane-j-capture.sh` | netlab | PASS, Rust CI run 916 (00099c44), job 45200 (Netlab features) |
| SD-WAN edge agent + dashboard (3 parties) | `ci/netlab/lane-k-sdwan-edge.sh` | netlab | PASS 118 s|
| GitOps: firewall rules from git (sync/watch) | `ci/netlab/lane-m-gitops.sh` | netlab | PASS 28 s|
| GitOps: non-firewall resources | `ci/netlab/lane-m-gitops-resources.sh` | netlab | PASS 37 s|
| Remote encrypted automatic backup | `ci/netlab/lane-n-backup.sh` | netlab | PASS 69 s|
| DHCPv6 prefix delegation on the WAN | `ci/netlab/lane-n-dhcp6pd.sh` | netlab | PASS 12 s|
| DHCPv6: ISP refuses the delegated prefix (address kept, readable problem, prefix taken at the next renew) | `ci/netlab/lane-n-dhcp6pd-refused.sh` | netlab | PASS (CI host lab, dhcpcd 9.4.1 and 10.5.2) |
| Installed image: world records the plain `net-firewall/patronus` atom (upgrade from another repo resolves) | `ci/test-image-world-atom.sh` | Gentoo CI base image | PASS (CI host) |
| Factory reset | `ci/netlab/lane-n-factory-reset.sh` | netlab | PASS 12 s|
| Traffic insights (hosts/services/protocols) | `ci/netlab/lane-n-insights.sh` | netlab | PASS 7 s|
| LDAP login (real OpenLDAP) | `ci/netlab/lane-n-ldap.sh` | netlab | PASS 8 s|
| OpenVPN server + .ovpn export | `ci/netlab/lane-n-openvpn.sh` | netlab | PASS 27 s|
| Signed plugins / package jobs | `ci/netlab/lane-n-plugins.sh` | netlab | PASS 19 s|
| Web proxy (Squid) | `ci/netlab/lane-n-proxy.sh` | netlab | PASS 12 s|
| Groups and privileges (RBAC) | `ci/netlab/lane-n-rbac.sh` | netlab | PASS 8 s|
| Reverse proxy / load balancer (HAProxy) | `ci/netlab/lane-n-reverse-proxy.sh` + `lane-n-reverse-proxy-ui.sh` | netlab | PASS (the CI host, branch run; CI row to be filled from the merge run) |
| UPnP / NAT-PMP | `ci/netlab/lane-n-upnp.sh` | netlab | PASS 7 s|
| VRF segmentation | `ci/netlab/lane-n-vrf.sh` | netlab | PASS 24 s|
| GRE / VXLAN overlay links (Interfaces > Overlays) | `ci/netlab/lane-n-overlays.sh` | netlab | PASS 29 s, 2026-11-16, run 1354 on 36a6cab0 (job 106369): GRE key 7 + VXLAN VNI 100 ping across, key change recreates, reboot rebuild, delete |
| General setup: host name, DNS domain, time zone (System > General) | `ci/netlab/lane-n-general.sh` | netlab | PASS, Rust CI run 1526 (43797117), Netlab features job green |
| First-boot setup wizard | `ci/netlab/lane-n-wizard.sh` | netlab | PASS 12 s|
| Zero-touch provisioning (export/import, sealed) | `ci/netlab/lane-n-ztp.sh` | netlab | PASS 56 s|
| DNS rebinding protection | `ci/netlab/lane-s-dns-rebind.sh` | netlab | PASS 23 s|
| Traffic insight history by country/ASN/device | `ci/netlab/lane-s-insight.sh` | netlab | PASS 47 s|
| SD-WAN dashboard HA cluster: election, token-gated RPC, replicated writes, leader SIGKILL failover, rejoin catch-up, no-quorum refusal (3 real dashboards) | `ci/netlab/lane-k-dashboard-ha.sh` | netlab | PASS 2026-11-08, Rust CI run 864 job 77320 (19 s, first CI run); re-run PASS 18 s in run 901 (2026-11-09) |
| Device segmentation, default-deny isolation | `ci/netlab/lane-s-segmentation.sh` | netlab | PASS 110 s|
| Parental time limits | `ci/netlab/lane-s-time.sh` | netlab | PASS 41 s|
| Uplink health history, multi-probe, SLA | `ci/netlab/lane-s-uplink.sh` | netlab | PASS 131 s|
| Gateway failback delay (hold-down before a recovered uplink carries traffic again; recovered WAN1 reports "failback hold-down", traffic stays on WAN2, then returns) | `ci/netlab/lane-s-uplink.sh` step 4b; unit: `failback_gate_holds_a_recovered_gateway_for_its_delay`, `failback_delay_is_validated_and_stored` | netlab | PASS 172 s, Rust CI run 975 job 91935 (d0835133) |
| Gateway failback ramp (a recovered uplink takes the default back gradually: WAN1 + WAN2 in one weighted multipath route for the ramp, then WAN1 alone) | `ci/netlab/lane-s-uplink.sh` step 4b2; unit: `ramp_pct_grows_in_steps_over_the_ramp`, `a_recovering_tier_shares_traffic_with_the_fallback_tier`, `failback_ramp_is_validated_and_stored` | netlab | PASS, Rust CI run 1526 (43797117): Format+Clippy+Test and Netlab features jobs green |
| Gateway loss hysteresis (a gateway in the loss state leaves it only below half its loss threshold; deterministic 25 % periodic loss at a 25 % threshold must not flap) | `ci/netlab/lane-s-uplink.sh` step 4c; unit: `loss_state_has_hysteresis` | netlab | pending first CI run |
| Dashboard HTTPS: self-signed cert generated on first start (key 0600, SANs), served to the LAN, name verified, untrusted/wrong-name refused, plain HTTP refused, Secure cookie, TLS 1.2/1.3, same cert after restart, operator-supplied cert wins | `ci/netlab/lane-n-tls.sh` | netlab | PASS 2026-11-09, Rust CI run 898 Netlab features job 79308 (9 s); re-run PASS 8 s in run 901 (2026-11-09) |

## Features (real Gentoo image, OpenRC and systemd)

| Feature | Test | Env | Last result (11704) |
|---|---|---|---|
| LAN services: DHCPv4/v6, RA, relay, Unbound DNS, DNSBL, dynamic DNS, NTP (OpenRC + systemd) | `ci/netlab/lan-services-test.sh` | Gentoo stage3 container | PASS (both init paths; step success in job 76603) |
| IPsec site-to-site + service control + WireGuard from the unprivileged UI (OpenRC + systemd) | `ci/netlab/vpn-services-test.sh` | Gentoo stage3 container | PASS (both init paths; step success in job 76603) |
| High availability: VIP failover, preempt, conntrack state sync (OpenRC + systemd) | `ci/netlab/ha-services-test.sh` | Gentoo stage3 container | PASS (both init paths; step success in job 76603) |
| Per-device/group DNS policy + query logs (OpenRC + systemd) | `ci/netlab/segmentation-dns-services-test.sh` | Gentoo stage3 container | PASS (both init paths; step success in job 76603) |
| Dashboard HA stack behind haproxy: generated TLS cert loads, stats page protected, writes through haproxy and directly on a follower replicate, 3-node election/failover (real emerge-built image + haproxy:2.8) | `ci/ha-e2e.sh` | Gentoo-built image + docker | PASS 2026-11-08, Rust CI run 875 (11982) job 77761 on ec272a5b: `[ha-e2e] haproxy up with generated cert (TLS OK, stats protected)`, `two sites created (haproxy + follower dashboard2)`, `[ha-e2e] PASS` (it runs in the Gentoo Docker Build job, so it was already gated on every push; it was missing from this matrix) |

## Not in the per-push run

| Feature | Test | Status |
|---|---|---|
| Dashboard UI phone layout: login + 8 pages at 390 and 360 px, no sideways scroll, nothing sticking out, navigation reachable (real Chromium, mocked APIs) | `frontend/scripts/phone-layout-gate.py` (rust-ci "Dashboard UI" job) | PASS 2026-11-09, run on 5f578ac9, task 42538 (first run 889 failed on the topology legend at 360 px; fixed in 5f578ac9) |
| Guest network: DHCP/DNS/internet, isolation from LAN/router/other guests, measured caps, schedule and timed access, rollback, reboot | `ci/netlab/lane-t-guest.sh` (rust-ci "Netlab features") | passed 66 `ok` lines on CI host, 2026-11-17 (debian:bookworm lab container, shipped binaries); the CI result is recorded in the merge note |
| Guest Wi-Fi (shared password, wrong password, client isolation, voucher expiry, new password) | `ci/netlab/lane-t-guest-wifi.sh` (nightly `wifi-hwsim` job; `ci/netlab/wifi-hwsim.sh`) | SKIPS without mac80211_hwsim; 16 `ok` lines on CI host with 6 hwsim radios, 2026-11-17 |
| Guest network page in Firefox (menu, every setting, refused change, switch on/off, password/QR/voucher/open/close buttons, live status) | `ci/netlab/lane-t-guest-ui.sh` + `ci/guest-page-e2e.py` | SKIPS where Playwright/Firefox cannot be installed; 25 checks passed on CI host, 2026-11-17 |
| Per-device Wi-Fi credentials (WPA2/WPA3, revoke, rotate, enrol, quarantine) | `ci/netlab/lane-s-wifi-hwsim.sh` | SKIPS in the per-push netlab job (no hostapd/iw in that image, needs mac80211_hwsim); runs for real in the `wifi-hwsim` job of nightly-test-depth.yml (verified: run 827, job 74523 on the nightly runner, 6 hwsim radios, 22 `ok` lines incl. WPA3/SAE, `PASS lane-s-wifi-hwsim`, 2026-11-07 21:16 UTC). The "passed in 0 s" line in rust-ci is the skip, not a pass. |
| eBPF/XDP data plane (load, pass, count, blocklist drop, unblock) | `ci/netlab/lane-j-xdp.sh` (rust-ci "Netlab features") | PASS 2026-11-13, run 1019 on ff9fd923, job 94580: the shipped xdp_firewall.bpf.c compiles, the kernel verifier loads it and it attaches (xdpgeneric) to rtr-lan; ping+TCP pass and are counted (packets=7, dropped=0); a blocklisted source is dead and the dropped counter goes 0 -> 5; unblock restores traffic; ARP and other sources are untouched. First green after e0a138ad. |
| Firewall state table: list tracked connections, kill one or all of a source | `ci/netlab/lane-j-states.sh` (rust-ci "Netlab features") | PASS 2026-11-16, run 1335 on f916cef9 (job 60213): two held TCP connections listed as ESTABLISHED, refused empty/malformed kills, kill by source port removes exactly one conntrack entry, kill by address removes the rest |
| Mutation score, 30 power cuts (`netlab-deep`) | nightly-test-depth.yml | nightly, see its run |
| k3s CNI operator | rust-ci "Operator tests against a real k3s cluster" | green in 11704 |

## Gaps (no end-to-end scenario found; each is a feature to test next)

Checked against `ci/netlab/*.sh` (grep, 2026-11-07): `lane-k-sdwan-edge.sh` runs one patronus-dashboard
as the SD-WAN controller, but nothing exercised the HA dashboard stack until `lane-k-dashboard-ha.sh` (three dashboards; the haproxy front end is covered by `ci/ha-e2e.sh`, see its row), and the eBPF/XDP data plane is covered by `lane-j-xdp.sh` (row above). The web UI's phone layout is gated (row above).
No known gaps left; add a row when a scenario lands.
