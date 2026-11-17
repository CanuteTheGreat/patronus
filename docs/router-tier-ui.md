# Router tier: web UI coverage (access points and small routers)

What the web UI of the router-tier images offers, compared with what an owner of the same hardware expects from
OpenWrt's LuCI and from the vendor firmware (GL.iNet 4.x on the GL-AX1800 / GL-AR750S). The router tier builds
`patronus-cli` with a reduced feature list (`ci/embedded-aarch64/ax1800/stage-patronus.sh`,
`ci/embedded-mips/slate/rebuild.sh`); the web UI hides the menu entries of features the build leaves out
(`GET /api/features`), and since this change lists them, with the reason, under System > "Not available on this
device".

Status words: **yes** = works end to end on the router-tier image; **new** = added by this change; **hidden** = not in
this build (reason shown in the UI); **AP: router** = on an access point the main router does this, so the page
explains that instead of offering controls; **gap** = missing, planned.

## 1. Menu by role

| Menu entry | GL-AX1800 (role `ap`) before | GL-AX1800 (role `ap`) now | Router role (e.g. GL-AR750S) |
|---|---|---|---|
| Dashboard | router tiles only (VPN count 0) | uplink card (address, gateway, DNS, ports with link/speed) + Wi-Fi summary; VPN tile hidden when no VPN is built | yes |
| Wi-Fi | absent (radios configured only by a shell file) | **new**: radios, networks, clients | gap (the router image's own hostapd/STA config is not editable yet) |
| Firewall | yes | yes (protects the unit's own management plane) | yes |
| VPN | hidden | WireGuard (server and client tunnels, peers, road-warrior config); OpenVPN/IPsec hidden, listed with reason | GL-AR750S: hidden (flash size), listed with reason |
| Interfaces | yes | yes | yes |
| Routing | shown, does nothing useful on an AP | AP: router | yes |
| DHCP / DNS | shown, would start a second DHCP/DNS server on the LAN | AP: router (page explains, API changes refused with 409) | yes |
| NTP server | hidden | yes (chrony, off by default) | GL-AR750S: hidden, listed with reason |
| HA, Traffic shaping, NetFlow, IGMP proxy, NAT64, L2TP, IDS, BGP/OSPF, Packages | hidden | hidden, listed with reason | hidden, listed with reason |
| Device segmentation, Time limits, DNS policy | shown (needs the router to see DHCP/DNS) | AP: router | yes |
| Traffic insights | shown (an AP bridges, it sees no flows) | AP: router | yes |
| Wake-on-LAN | yes | yes | yes |
| Monitoring (system log) | yes | yes | yes |
| System | yes | yes + "Not available on this device" | yes + "Not available on this device" |

## 2. Feature comparison

| Area | LuCI (OpenWrt) | GL.iNet 4.x | Patronus router tier |
|---|---|---|---|
| Wi-Fi per radio: country, channel, width | yes | yes | **new** (Wi-Fi page) |
| Wi-Fi 6 (802.11ax) | yes | yes | **new** toggle, on by default |
| Transmit power | yes | yes (low/medium/high) | gap |
| SSIDs per band, add/remove/disable | yes | main + guest per band | **new** (up to 4 per band) |
| Security WPA2 / WPA2+WPA3 / WPA3, change password | yes | yes | **new** (password write-only; admins can reveal it, audited) |
| Hidden SSID | yes | yes | **new** |
| Client isolation | yes | guest only | **new** per SSID |
| Guest network isolated from the LAN | firewall zone | yes (router mode) | gap: an AP needs a VLAN to the main router or bridge filtering |
| 802.11r/k/v | yes | no | off on purpose (802.11r crashes this board's Wi-Fi firmware) |
| MAC filter / block a client | yes | yes | gap (disconnect only) |
| Client list: MAC, band, signal, rates, connected time | yes | yes (+ name, traffic) | **new** (+ IPv4 when the unit has seen it); names: gap (the main router has the leases) |
| Disconnect a client | yes | yes (block) | **new** |
| Channel survey / analysis | yes | no | gap |
| Uplink status on an AP (address, gateway, ports) | Overview | network status | **new** dashboard card |
| AP address: DHCP or static | Interfaces | Network mode | gap in the UI (set in the access-point file) |
| Firmware upgrade from the web UI | yes (sysupgrade upload) | yes (online + upload) | done: System > Firmware uploads a sysupgrade image, `patronus-flash check` validates it (board, metadata, checksums, sizes), Install stages it (settings kept) and restarts; no online check yet |
| Backup / restore | yes | yes | yes: the settings store plus, on an access point, its Wi-Fi file (networks, passwords, radios), put back with the same verify + rollback as the Wi-Fi page; gap: system (login) accounts are not in the backup |
| Factory reset | yes | yes | yes |
| Reboot / scheduled reboot | yes / cron | yes / yes | yes / gap |
| Time zone | yes | yes | yes (System > General) |
| NTP client / server | yes / yes | yes / no | client always on (chrony) / yes on the GL-AX1800 |
| System and kernel log | yes | yes | yes (Monitoring) |
| Remote syslog | yes | no | yes on the GL-AX1800 (UDP collectors; busybox syslogd cannot forward over TCP) |
| Admin password, accounts | yes | yes | yes (web accounts, system users) |
| SSH keys | yes | yes | gap (no UI for authorized keys) |
| Diagnostics (ping, traceroute, DNS lookup) | yes | yes | packet capture only; gap |
| LED control | yes | yes | gap |
| WireGuard client and server | package | yes | yes on the GL-AX1800 (kernel module + `wg` + page); GL-AR750S: not yet (flash) |
| OpenVPN, IPsec | package | OpenVPN yes | hidden (size) |
| Package manager | yes | plug-ins | hidden (read-only image) |
| Remote management | no | GoodCloud | ETPhoneHome baked in |

## 3. Size budget

The GL-AX1800 has 128 MiB NAND (root squashfs about 16 MiB, settings volume about 49 MiB) and 512 MB RAM (about 400 MB usable next to the Wi-Fi firmware), so the
router-tier image there carries WireGuard, an NTP server and remote syslog (measured sizes: docs/embedded-routers.md
12.10). The GL-AR750S (16 MiB NOR / 128 MiB NAND, 128 MB
RAM) keeps its smaller feature list; the System page states what it leaves out.

## 4. How the Wi-Fi page works

The access-point file `/etc/patronus/ap.env` stays the one source of truth: the boot (`board-network` ->
`/usr/libexec/patronus/ap start`) and the Wi-Fi page read and write the same file. `patronus_network::apwifi` parses it
(shell assignments; every line it does not manage is kept), validates a change, writes it atomically (0600, the
previous copy kept as `ap.env.prev`), restarts the access points through the same `ap stop` / `ap start` and checks
that every expected network comes up (`hostapd_cli status`: `ENABLED`, or `DFS` while the radar check runs). If one
does not, the previous file is restored and the radios restarted. `/etc` lives on the settings volume, so the result
survives a restart and a sysupgrade. On systemd the new hostapd processes run in their own transient scope
(`systemd-run --scope`), so restarting the web UI never takes the Wi-Fi down.

API: `GET/PUT /api/wifi`, `GET /api/wifi/clients`, `POST /api/wifi/clients/kick`, `POST /api/wifi/networks/:id/reveal`
(admins, audited), `GET /api/ap/uplink`, and `GET /api/features` (adds `role`, `tier`, `board`, `wifi_backend`,
`absent`).
