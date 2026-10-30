# Device segmentation

Groups of devices, default-deny isolation between them, one-way service
rules, and (with USE=wifi-ap) per-device Wi-Fi passphrases. Design and
spike evidence: [design/device-segmentation.md](design/device-segmentation.md).
UI: **Network -> Device segmentation** (`/segmentation`). API: `/api/segmentation/*`.

USE flags: `segmentation` (default on; the page, the API, the layer-2 settings)
and `wifi-ap` (per-device Wi-Fi credentials; pulls in `net-wireless/hostapd`).
The nft rules themselves are always compiled in and render nothing until a
segment is switched on.

## Opt-in, and what "day one" means

Nothing is isolated on an existing install. Turning isolation on for a
segment (an interface role such as `@lan`, or an interface name) does two
things in one step:

1. **Adopts** every device that is on the segment right now (DHCP
   reservations, DHCP leases, the ARP/neighbour table) into the built-in
   group `home` (`intra=1`, `internet=allow`), each with its MAC and a DHCP
   reservation at its current address;
2. loads the isolation rules.

`home` may talk to itself and to the internet, so behaviour is the same as
before. You then tighten: create `iot`, move the TV into it, add a link or
a one-way rule. Turning the switch off deletes the table and un-isolates the
ports again.

A device that joins **after** the switch is on is *unknown*: it can get an
address (DHCP) and ping and resolve DNS on the router, and nothing else. It
shows up under **Discovered**; **Adopt** puts it in a group.

## Semantics

- Two devices exchange **new** connections only if they are in the same
  group with *intra* on, or their groups are **linked** (both directions), or a
  **one-way service rule** `A -> B tcp/ports` allows it (replies return,
  the reverse direction stays denied).
- Anything else between devices of a segment is dropped (logged to NFLOG
  group 7, rate limited).
- A frame whose (interface, MAC, IPv4) is not an enrolled, active device
  forwards nothing: unknown, spoofed IP, spoofed MAC, revoked, quarantine.
- An address inside the segment that is not a live device receives nothing,
  **even on an established connection**: revoking a device cuts its running
  connections at once.
- Group `internet=deny`: its devices' traffic to anything outside the
  segments is dropped in both directions.
- Unknown and quarantine devices may reach the router for DHCP (67/68),
  DNS (53), ICMP/ICMPv6 only: **never SSH (22) or the web UI (8443)**, even
  though the LAN anti-lockout rule opens those to the LAN role.
- Device-to-internet and device-to-router stay with the ordinary firewall
  rules; the segmentation table never accepts anything the main table would
  drop.

The rules live in their own table `inet patronus_seg` (hook priority -10),
loaded in the same atomic `nft -f` as the main table. It must run first
because the main table begins with `ct state established,related accept` and
seeds `LAN -> any accept`.

## Layer 2: what isolation needs, and its limits

For device-to-device traffic to pass through the router at all, the devices
must not reach each other directly at layer 2:

- ports of a **Patronus bridge** get `bridge link ... isolated on`, and the
  bridge gets proxy ARP (`proxy_arp`, `proxy_arp_pvlan`, `send_redirects=0`),
  set by the segmentation applier and undone when the switch is turned off;
- Wi-Fi: `ap_isolate=1` in the generated hostapd config.

> **Wired devices behind an unmanaged (dumb) switch cannot be isolated from
> each other.** They share one port of the router; the switch forwards between
> them without involving the router, so no rule here can see that traffic.
> Group such devices together, plug them into separate ports of the router
> or a managed switch with port isolation, or accept the limitation.
> Devices on a plain NIC (not a bridge) have the same limit.

Other limits:

- **IPv6**: device-to-device IPv6 inside a segment's prefixes is denied while
  isolation is on, and an unknown MAC forwards no IPv6. Per-address IPv6
  identity binding (SLAAC/privacy addresses) is the next item.
- A device that moves between segments/interfaces mismatches its binding and
  is dropped (one `segment` per device).
- A phone that rotates its MAC on every connection cannot be bound.
- Service-rule schedules are not enforced yet (the field is refused).

## Per-device Wi-Fi credentials (USE=wifi-ap)

When Patronus runs the access point (hostapd), every Wi-Fi device gets its own
passphrase, bound to its MAC. The **Wi-Fi** tab (`/segmentation#wifi`) manages
networks (radio, SSID, band/channel, security, the bridge it joins) and the
devices on them. One hostapd runs per enabled network (supervised like the
other daemons: OpenRC `patronus-hostapd.<network>`, systemd
`patronus-hostapd@<network>.service`, or directly in a container).

| | WPA2 (default) | WPA3-SAE (`wpa3`, or `wpa2_wpa3`) |
|---|---|---|
| device credential | `keyid=dev-<id> <mac> <passphrase>` in hostapd's `wpa_psk_file` | `sae_password=<pw>\|mac=<mac>` in `hostapd.conf` |
| add / revoke / rotate | **live**: `reload_wpa_psk`, a revoked station is deauthenticated, hostapd is not restarted | **restarts hostapd** (stock hostapd reads SAE passwords only at start): every station reconnects for a few seconds; restarts are debounced to one per 5 s |
| device without a MAC (pending) | supported | not supported on `wpa3` (SAE is bound to a MAC); a `wpa2_wpa3` pending device joins with WPA2 first |

Measured on `mac80211_hwsim` with stock hostapd 2.10 (`ci/netlab/lane-s-wifi-hwsim.sh`,
evidence in `docs/evidence/segmentation/`): a device associates with its own
passphrase; another MAC with that passphrase, and the device with another
device's passphrase, are refused; revoking one device leaves the others
connected without a hostapd restart; rotation cuts the old passphrase at once;
a SAE per-device password works without an identifier (the MAC selects it).

- **Passphrases** are generated (20 symbols, 100 bits, `xxxxx-xxxxx-xxxxx-xxxxx`),
  shown once with a `WIFI:T:WPA;S:..;P:..;;` QR code, never listed by the API,
  and stored like WireGuard keys and IPsec PSKs (the 0600 store; `export` is a
  full backup and contains them). Showing one again needs an administrator
  and writes an audit-log row.
- **Enrolment of a device without a MAC**: create it without a MAC; its
  passphrase works from any MAC (wildcard entry) until the first join. hostapd
  reports `AP-STA-CONNECTED <mac> keyid=dev-<id>`; `hostapd_cli -a` hands that
  to `patronus wifi-event`, which stores the MAC, reserves its address (its
  current DHCP lease when there is one), and the entry becomes MAC-bound,
  live. Unused pending passphrases expire after 24 hours.
- **Unknown devices** (`unknown_policy`): `reject` (default) = not in the list
  cannot associate. `enrol` = a shared secret that grants nothing: such a
  station gets an address but no binding, so it is quarantined (DHCP, DNS and
  ping only; never the admin UI). It shows up under *Discovered*; **Approve
  on Wi-Fi** creates its device and personal passphrase.
- **Revocation**: revoking a device cuts it in the firewall first (established
  connections included), then removes its passphrase (WPA2: reload +
  deauthenticate). Re-enrolling a revoked device's MAC creates a new device.
- **Rotation** gives a new passphrase; with a grace period the old one keeps
  working for that long (no-downtime rotation).
- A phone set to use a *new random MAC on every connection* cannot be bound
  to a MAC: use "fixed" or "private per network" in its Wi-Fi settings.
- `ap_isolate=1` keeps stations from talking to each other directly, so every
  device-to-device packet passes through the isolation rules above.
- Not covered: real radios (roaming, 802.11r, 6 GHz, client quirks with SAE),
  one SSID per radio interface (no multi-SSID `bss=` blocks yet), 6 GHz.

## API


| Method and path | |
|---|---|
| `GET /api/segmentation` | segments, groups, devices, links, services, live state |
| `POST /api/segmentation/segments` `{segment, enabled, adopt?}` | switch isolation on/off (on adopts) |
| `GET/POST /api/segmentation/groups`, `PUT/DELETE .../groups/<id>` | groups (`intra`, `internet`, `quarantine`) |
| `GET/POST /api/segmentation/devices`, `PUT/DELETE .../devices/<id>` | devices (MAC, group, segment; address allocated outside the DHCP range) |
| `POST /api/segmentation/devices/<id>/revoke` | revoke (cuts established connections) |
| `GET /api/segmentation/discovered`, `POST .../discovered/<mac>/adopt` | unknown hosts |
| `GET/POST /api/segmentation/links`, `DELETE .../links/<id>` | group links |
| `GET/POST /api/segmentation/services`, `DELETE .../services/<id>` | one-way rules |
| `POST /api/segmentation/preview` | the nft table, not applied |
| `GET /api/segmentation/wifi` | Wi-Fi networks, credential state (no secrets), radios, live status |
| `POST /api/segmentation/wifi/networks`, `PUT/DELETE .../networks/<id>` | networks |
| `POST /api/segmentation/wifi/devices` `{name, network, group?, mac?}` | a device with its own passphrase; the secret is in the answer once |
| `POST .../wifi/devices/<id>/rotate` `{grace_minutes}`, `POST .../wifi/credentials/<id>/revoke` | rotate / revoke |
| `POST .../wifi/credentials/<id>/reveal`, `.../networks/<id>/enrol-secret/reveal` | admin only, audited |
| `GET /api/segmentation/wifi/stations` | live stations (from `hostapd_cli all_sta`) |

Every change is validate -> snapshot -> write -> apply (segmentation, dhcp,
firewall) -> restore on failure. RBAC area: `segmentation`.
