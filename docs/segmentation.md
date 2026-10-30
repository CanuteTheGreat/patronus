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

Every change is validate -> snapshot -> write -> apply (segmentation, dhcp,
firewall) -> restore on failure. RBAC area: `segmentation`.
