# Guest network

An isolated network for visitors, in the way pfSense/OPNsense guest VLANs, OpenWrt guest
networks and UniFi/Firewalla guest networks work. Package flag `USE=guest` (cargo feature
`guest`, default on in the ebuild); the network itself is **off until you switch it on**
(page: Guest network, API: `/api/svc/guest`, CLI: `patronus guest`).

## What guests get, and what they never get

| | |
|---|---|
| Get | DHCP (address, router, DNS, the lease time you set), DNS from the router (or resolvers you hand out), ping to the router (setting), the internet (masqueraded out of the internet interface) |
| Never | the LAN, any other internal VLAN, the router's web UI/SSH/anything else on **any** of its addresses (guest, LAN, WAN), private ranges behind the WAN such as the ISP modem's admin page (setting `block_private`), other guests, IPv6 (dropped; not supported yet) |
| Nothing starts a connection *into* the guest network | from the LAN either (an admin who needs to reach a guest device uses the router) |

## How it is built

- One bridge (`guest.bridge`, default `br-guest`) is the guest L3 interface. Members: the guest
  VLAN sub-interface `<trunk>.<vlan>` (`guest.vlan_id` > 0: the trunk to your access point or switch),
  any devices in `guest.ports` (a spare LAN port) and the guest SSID (own hostapd, `guest.wifi`).
  The applier is full-state: members that are no longer wanted leave the bridge, a stale VLAN
  device is deleted, and switching the network off removes the bridge, table and daemons.
- Layer 2: bridge ports are `isolated` (guests on different ports cannot talk) and the SSID runs
  `ap_isolate=1`, both selectable with `guest.isolate_clients`. A guest VLAN that continues on an
  **unmanaged switch** cannot be isolated by this router (the trunk is one bridge port): use a managed switch with port isolation, or the SSID.
- Firewall: own table `inet patronus_guest` at priority -15 (before the main firewall and the
  segmentation table; it only drops or falls through) plus a few accepts in the main table
  (`patronus-firewall/src/svc_rules.rs`: DHCP, DNS, ping, router services, guest -> internet).
- DHCP/DNS: a dedicated dnsmasq bound to the guest address only. `guest.dns_servers` hands out other
  resolvers instead (then the router answers no DNS on the guest network).
- Daemons run through the generic `patronus-daemon` units, so **OpenRC and systemd** are both covered.

## Settings (every one has a default; all are in the configuration, API, CLI and page)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | off | the switch |
| `bridge`, `parent`, `vlan_id`, `ports` | `br-guest`, `@lan`, `30`, empty | where the network lives (`vlan_id` 0 = no VLAN) |
| `address` | `192.168.30.1/24` | router address and subnet (refused if it overlaps another network) |
| `dhcp_start`, `dhcp_end`, `lease_minutes` | derived, derived, `120` | DHCP range and lease |
| `dns_servers`, `dns_upstreams` | empty, empty | resolvers handed out / the router's guest DNS forwards to |
| `internet_interface` | `@wan` | the only interface guests are forwarded out of |
| `block_private`, `isolate_clients`, `allow_ping` | on, on, on | see above |
| `router_ports`, `egress_ports` | empty, empty | router services guests may use / limit internet ports (`tcp/443,udp/5000-5010`) |
| `down_kbit`, `up_kbit` | 0 (no cap) | cap of the whole guest network (kbit/s) |
| `client_down_kbit`, `client_up_kbit` | 0 (no cap) | cap per guest address |
| `access`, `schedule_from`, `schedule_to`, `schedule_days`, `open_until` | `always`, `07:00`, `23:00`, all days, 0 | always / daily window / timed (closed until opened) |
| `wifi`, `ssid`, `wifi_psk`, `wifi_security`, `wifi_iface`, `wifi_band`, `wifi_channel`, `wifi_country` | off, `Guest`, none, `wpa2_wpa3`, first AP-capable radio, `2g`, `6`, `US` | the guest SSID |
| `lan_overlap_check` | on | refuse a subnet that overlaps another network |

Vouchers (`vouchers` collection): name, a WPA2 password and minutes of validity (0 = never), counted from when the voucher was saved.

## Caps, schedule, vouchers: how exact they are

- Network caps: `tc` token-bucket on the bridge (download) and an ingress policer (upload). Measured on the lab: a cap of 8000 kbit/s gave 958 kB/s (1000 kB/s expected), shared by two guests; 2000 kbit/s upload gave 251 kB/s of 250 kB/s arriving at the server.
- Per-guest caps are policed with nft meters (packets over the rate are dropped, TCP settles near it): measured 580-595 kB/s for a 500 kB/s cap, i.e. within about +20 %. Treat them as approximate.
- Schedule and timed window are nft rules (`meta hour`, `meta day`, `meta time`), so they close **by themselves**, with no daemon, and survive a reboot. The hours are converted from local time when the rules are loaded and the kernel's weekday is UTC, so the closed stretches are cut per UTC weekday (a Thursday-only window that runs past midnight stays open on Thursday's local clock on a router east or west of UTC); the web process re-applies the guest network when the UTC offset changes (daylight saving). While closed, DHCP still answers, nothing is forwarded and DNS/ping are refused.
- Vouchers are extra WPA2 passwords in hostapd's PSK file (accepted live, no restart). The web process checks every 60 s (`PATRONUS_GUEST_TICK_SECS`) and, when one has expired or was deleted, rewrites the PSK file, reloads it and drops the connected stations (the ones with a valid password reconnect by themselves within seconds).
- A WPA3 password change (shared password) restarts the SSID, because stock hostapd reads SAE passwords only at start. Vouchers are WPA2 only for the same reason.

## Where it is not available

An **access-point unit** (role `ap`, e.g. GL-AX1800 as an AP) does not run it: the main router provides the guest network and the AP only carries the Wi-Fi name. The menu entry stays and says "(unavailable)", `/svc/guest` explains why, the System page lists it with the reason, and the API refuses changes. The embedded **Router/Small** images (flash and RAM budget) are built without `guest`; the System page says "not included in this router-tier image".

## Proof

- `ci/netlab/lane-t-guest.sh` (rust-ci "Netlab features"): two guest clients behind two ports, real DHCP, DNS, HTTP; isolation, caps with measured speeds, schedule/timed access, failed apply, `config rollback`, reboot, audit log. 66 `ok` lines.
- `ci/netlab/lane-t-guest-wifi.sh` (nightly `wifi-hwsim`; `ci/netlab/wifi-hwsim.sh`): the SSID on `mac80211_hwsim` with stock hostapd.
- `ci/netlab/lane-t-guest-ui.sh` + `ci/guest-page-e2e.py`: the page in Firefox (Playwright).
- Unit and router tests: `patronus-network` `guest::tests`, `patronus-firewall` `svc_rules`, `patronus-web` `guest_tests`.
- Claims C80, C81 in `docs/claims-ledger.txt`.

## Not yet

IPv6 for guests (dropped for now), a login/terms page (captive portal), per-voucher data caps, device-name based guest client list with kick, embedded Router/Small builds.
