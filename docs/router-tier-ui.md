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
| Wi-Fi | absent (radios configured only by a shell file) | **new**: radios, networks (guest networks), transmit power, clients with names, block list, channel survey, crash-protection state | gap (the router image's own hostapd/STA config is not editable yet) |
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
| Device | absent | **new**: SSH keys, lights, scheduled restart, this access point's address (with an automatic undo) | **new**: SSH keys, lights, scheduled restart |
| System | yes | yes + "Not available on this device", online update check, login accounts in backups | yes + "Not available on this device" |

## 2. Feature comparison

| Area | LuCI (OpenWrt) | GL.iNet 4.x | Patronus router tier |
|---|---|---|---|
| Wi-Fi per radio: country, channel, width | yes | yes | **new** (Wi-Fi page) |
| Automatic channel selection (default), allowed channel lists, DFS opt-in | yes (ACS) | yes | **new**: auto on every unit by default, the channel/width really in use shown per radio (docs/embedded-routers.md 12.14) |
| Wi-Fi 6 (802.11ax) | yes | yes | **new** toggle, on by default |
| Transmit power | yes | yes (low/medium/high) | **new** per radio (auto or 1-30 dBm), applied without a restart |
| SSIDs per band, add/remove/disable | yes | main + guest per band | **new** (up to 4 per band) |
| Security WPA2 / WPA2+WPA3 / WPA3, change password | yes | yes | **new** (password write-only; admins can reveal it, audited) |
| Hidden SSID | yes | yes | **new** |
| Client isolation | yes | guest only | **new** per SSID |
| Guest network isolated from the LAN | firewall zone | yes (router mode) | **new** per SSID: client isolation plus an nftables bridge filter on the access point (internet through the router only; no LAN host, no other guest, not the access point itself). Same subnet as the LAN: the router cannot tell guests apart (section 5.1) |
| 802.11r/k/v | yes | no | off on purpose (802.11r crashes this board's Wi-Fi firmware) |
| MAC filter / block a client | yes | yes | **new** per SSID or unit-wide (hostapd deny list, applied live: only that client drops) |
| Client list: MAC, band, signal, rates, connected time | yes | yes (+ name, traffic) | **new** (+ IPv4 and name: the client's own DHCP request seen on the bridge, else the router's reverse DNS; blank when neither knows it) |
| Disconnect a client | yes | yes (block) | **new** |
| Channel survey / analysis | yes | no | **new** (busy %, networks heard per channel, least crowded channel; read-only, no client is dropped) |
| Uplink status on an AP (address, gateway, ports) | Overview | network status | **new** dashboard card |
| AP address: DHCP or static | Interfaces | Network mode | **new** (Device page; the new address runs next to the old one and is undone unless confirmed from the new address in time, also across a restart) |
| Firmware upgrade from the web UI | yes (sysupgrade upload) | yes (online + upload) | done: System > Firmware uploads a sysupgrade image, `patronus-flash check` validates it (board, metadata, checksums, sizes), Install stages it (settings kept) and restarts; **new** online check: a feed whose release list is signed by the release key (section 5.5), never installs by itself |
| Backup / restore | yes | yes | yes: the settings store plus, on an access point, its Wi-Fi file (networks, passwords, radios), put back with the same verify + rollback as the Wi-Fi page; **new**: the login accounts (passwd/shadow/group lines, SSH keys) are in the backup and a restore brings them back (section 5.6) |
| Factory reset | yes | yes | yes |
| Reboot / scheduled reboot | yes / cron | yes / yes | yes / **new** (off by default; daily or weekly; the page shows the OpenRC crond / systemd timer state) |
| Time zone | yes | yes | yes (System > General) |
| NTP client / server | yes / yes | yes / no | client always on (chrony) / yes on the GL-AX1800 |
| System and kernel log | yes | yes | yes (Monitoring) |
| Remote syslog | yes | no | yes on the GL-AX1800 (UDP collectors; busybox syslogd cannot forward over TCP) |
| Admin password, accounts | yes | yes | yes (web accounts, system users) |
| SSH keys | yes | yes | **new** (Device page: per login account, validated, audited; root's last key is kept while root has no password) |
| Diagnostics (ping, traceroute, DNS lookup) | yes | yes | packet capture only; gap |
| LED control | yes | yes | **new** (on/off for every LED in /sys/class/leds; a device without LEDs says so) |
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

Transmit power (`AP_TXPOWER24`, `AP_TXPOWER5`), client names (`AP_NAMES`) and block lists (`AP_DENY`, `DENY_<id>`) are
"live" settings: a save that changes only those does not restart the radios; `ap txpower` (`iw ... set txpower`) and
`ap acl` (hostapd `DENY_ACL`) apply them to the running radios.

More API: `GET /api/wifi` also returns `guard`, `guest_filter`, per network `guest` and `blocked`, and `txpower24`,
`txpower5`, `names`, `blocked`; `GET /api/wifi/clients` adds `hostname` and `hostname_source`;
`POST /api/wifi/block` (`{mac, network?, block?}`, admins, audited); `GET /api/wifi/survey[?fresh=true]`.

## 5. Device settings (Wi-Fi additions, Device page, online update check)

### 5.0 Crash protection on the Wi-Fi page

The Wi-Fi page shows `wifi-guard status` (docs/embedded-routers.md 12.6d): "normal" (every network on), or "safe mode"
with the reason and when the other networks come back. In safe mode only the first network of each radio is on.

### 5.1 Guest networks

A network marked Guest is always client-isolated (`ap_isolate=1`) and, on top of that, `/usr/libexec/patronus/ap-guest`
loads an nftables `bridge` table (`patronus_guest`) on `br-lan` before any radio starts. From a guest port it lets
through ARP, DHCP, IPv6 neighbour discovery, DNS and ping to the gateway and the DNS servers, and anything addressed
outside the LAN (the internet, through the router's MAC). It drops every packet to a private or link-local address
(RFC 1918, 100.64/10, 169.254/16, ULA, the bridge's own subnets), every packet from a LAN host that is not the gateway
or a DNS server, traffic between guest ports, and every TCP/UDP packet to the access point itself (web UI, SSH).
Proof with real packets: `ci/embedded-aarch64/ax1800/tests/guest-netns.sh` (17 checks); the QEMU gate loads the
table in the image's own kernel.

Limits, shown on the page: the guests are in the LAN's subnet. The router hands them LAN addresses and sees them as LAN
hosts, so router-side rules cannot single them out; a separate guest subnet needs a VLAN from the router to the access
point (not offered yet). If the kernel cannot filter bridged traffic, or the table fails to load, `ap start` does not
start the guest networks at all (a guest network without the filter would be a plain LAN network) and the page says
why (`ap-guest status`).

### 5.2 Client names

`patronus applyd` on an access point watches the DHCP requests crossing `br-lan` (read-only packet socket, nothing is
answered or changed) and keeps MAC, requested address and host name (option 12) in `/run/patronus/dhcp-names`.
`AP_NAMES=dhcp` (default) uses that plus a reverse lookup at the router's DNS; `AP_NAMES=<IPv4>` asks that DNS
server instead; `off` shows no names. A client that sends no name and is unknown to the DNS stays blank.

### 5.3 Block list, transmit power, channel survey

Blocking writes the MAC to `AP_DENY` (every network) or `DENY_<id>` (one network); each BSS gets a hostapd
`deny_mac_file`, and `ap acl` reloads the lists into the running hostapds, which disconnects only the listed client.
Transmit power is per radio, `auto` or 1-30 dBm (the regulatory limit of the country still applies). The survey reads
`iw survey dump` and the radios' scan results (`scan dump`; "Scan now" = `scan ap-force`, which scans while the access
point keeps serving), and suggests the channel with the least load and the fewest overlapping networks (2.4 GHz: 1, 6
and 11 only; 5 GHz: channels without radar detection).

### 5.3a Channel plan

Each band's channel is `auto` by default (hostapd ACS at every radio start: 2.4 GHz among 1/6/11, 5 GHz among the
non-DFS 80 MHz blocks 36-48/149-161) or a fixed channel; the page also sets the width per band, the channels ACS may use, whether
it may use DFS channels or the 5.9 GHz channels 169-177 (both off by default) and its survey rounds. The radio cards show the channel and width each radio really runs and
whether ACS picked it. The same settings as a document: `patronus ap-wifi export > wifi.yaml`, edit,
`patronus ap-wifi plan wifi.yaml` (what would change, passphrases hidden), `patronus ap-wifi apply wifi.yaml`.

### 5.4 Device page

- SSH keys: one table per login account (root and accounts with a shell); keys are checked (type, base64, matching
  key type, ed25519 length, RSA of 2048 bits or more, no options), written 0600 with the account as owner, audited
  (`add`/`delete`/`delete-refused` on `ssh_key`, with type and fingerprint only). Root's last key cannot be removed
  while root has no password.
- Lights: `LEDS=on|off` in `/etc/patronus/device.env`, applied by `/usr/libexec/patronus/leds` at once and at every
  start; "on" restores the triggers the board set at boot. No `/sys/class/leds` entries: shown as unavailable, with
  that reason.
- Scheduled restart: `RESTART=off|daily|weekly`, `RESTART_TIME`, `RESTART_DAY` in `device.env`; off by default.
  OpenRC: a root crontab line and the `patronus-crond` service (busybox crond), added to the default runlevel only while
  a schedule is on. systemd: `patronus-restart.timer` with an `OnCalendar` drop-in, enabled only while on. The page
  shows the unit's real state (enabled/active, schedule, next run on systemd).
- Address (access point): DHCP or a fixed address/gateway/DNS. `ap-addr trial` brings the new address up next to the
  current one; unless the change is confirmed within the chosen time (1-5 min) from a browser that reached the unit
  over the NEW address, the previous settings come back by themselves. The pending marker lives on `/etc`, so a
  restart during the trial also undoes it. Proof: `ci/embedded-aarch64/ax1800/tests/addr-netns.sh` (real bridge) and
  the QEMU gate (revert, confirm, back to DHCP).

API: `GET/PUT /api/device/leds`, `GET/PUT /api/device/restart-schedule`, `GET/POST /api/device/ssh-keys`,
`DELETE /api/device/ssh-keys/:user/:fingerprint`, `GET/PUT /api/device/address`, `POST /api/device/address/confirm`,
`GET/PUT /api/system/firmware/feed`, `POST /api/system/firmware/feed/check`, `POST /api/system/firmware/feed/download`.
Changes are admin-only and audited. Browser proof: `ci/device-page-e2e.py` (read-only by default; `E2E_WRITE=1` on a
test unit also blocks/unblocks a MAC, adds/removes an SSH key and sets/clears a weekly restart through the pages).

### 5.5 Online update check

System > Firmware > "Check for updates" reads `<feed>/<board>/<init>/latest.json` (board with `,` -> `_`, e.g.
`glinet_gl-ax1800/openrc/latest.json`) and its detached signature `latest.json.sig`, and verifies the signature with
`gpgv` against the release keyring built into the firmware (`/usr/share/openpgp-keys/errantsolutions.gpg`); the good
signature must come from the release key `5439354939B9C0552A68E9BBE323A6A3AC0A6506`, anything else is refused. A signature
by a revoked key is refused too. The list must carry a valid `date` (YYYY-MM-DD) and is refused when that date is older than the
running firmware's own `BUILD_DATE` (in `/etc/patronus-release`), so a replayed old list cannot offer an old build as the update.
`latest.json`:

```json
{"build": "<BUILD= of the image>", "version": "0.3.0", "date": "2026-11-17", "notes": "...",
 "image": "patronus-<tag>-glinet_gl-ax1800-sysupgrade.tar", "sha256": "<64 hex>", "size": 23461888}
```

"Download and check" fetches the image named there (same directory) into the upload slot in RAM, requires the size
and sha256 from the signed list, and then runs the same `patronus-flash check` as an upload. Nothing is installed until
"Install and restart" is pressed. Feed URL: `FW_FEED_URL` in `device.env` (the page's "Update feed" field). A firmware
without the release keyring refuses every feed and says so.

### 5.6 Login accounts in backups

On the router tier a configuration backup also carries `system_accounts`: for each account of a person (uid 1000-65535
except `nobody`, so the web UI's own accounts too) its passwd and shadow lines, the group lines it is in, and its
`authorized_keys`, plus root's `authorized_keys` (root's password is not exported). A restore puts each account back
(replacing lines of the same name, adding missing groups and memberships, skipping an account whose uid belongs to a
different name), merges root's keys, and lists what it did. Backups were already admin-only; they now also carry
password hashes, so keep them as private as the unit.
