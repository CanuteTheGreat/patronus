# IP tunnels: IPIP, 6in4 (SIT) and GIF-style (USE=tunnels)

Point-to-point IP-in-IP tunnels over IPv4, the equivalent of pfSense's and OPNsense's
GIF / 6in4 tunnel interfaces and of OpenWrt's `ipip` / `6in4` protocols. Typical uses:
an IPv6 tunnel from a tunnel broker (Hurricane Electric style) on an IPv4-only line, an
IPv4-over-IPv4 link to a second site, or a generic tunnel to a BSD box that carries both
families on one interface.

* Page: **Services -> IP tunnels** (`/svc/tunnels`, API `/api/svc/tunnels`).
* Types
  * `ipip`: IPv4 in IPv4 (IP protocol 4).
  * `sit`: IPv6 in IPv4, "6in4" (IP protocol 41).
  * `gif`: BSD-style generic tunnel, IPv4 and IPv6 in IPv4 on one link (Linux `sit` in
    `mode any`, protocols 4 and 41). It may carry one address of each family.
* Settings: `clamp_mss` (default on): TCP connections forwarded into or out of a tunnel get
  an MSS that fits its MTU.
* Tunnels (table `ip_tunnels`): `name` (1-11 lowercase letters, digits, `-`, `_`), `kind`,
  `remote` (IPv4 endpoint, required), `local` (IPv4, empty = any local address, which is what
  a dynamic WAN address needs), `address` / `address2` (this end's inner address with prefix
  length: IPv4 for ipip, IPv6 for sit, either for gif; a gif may carry one of each),
  `mtu` (default 1480), `ttl` (default 64, 0 = copy the inner packet's), `default_route`
  (install a default route over the tunnel, family of `address`, with `metric`), `enabled`,
  `description`.
* Routes (table `ip_tunnel_routes`): networks reached through a tunnel (`tunnel`,
  `destination`). A routed /48 or /64 from a broker is not listed here: it sits on your LAN
  interface, not behind the tunnel.
* Every tunnel is a kernel link named `tn-<name>` with interface alias `patronus-tunnel`.
  Use that name in firewall rules (a rule's interface accepts a device name). The applier owns
  links with the `tn-` prefix only; every other link, including a hand-made ipip link, is
  never touched, and a stray `tn-*` link that is not in the configuration is removed.
* Applier (`patronus-network/src/tunnels.rs`, interfaces phase, so it runs at boot on OpenRC
  and systemd alike through `patronus apply`, no daemon and no extra package): creates a link,
  re-creates it when its type, endpoints or TTL changed (MTU, address and route changes are
  done in place), sets inner addresses (exactly the configured ones), installs routes with
  route protocol 248 (and removes stale ones), and keeps the nft table
  `inet patronus_tunnel` for the MSS clamp.
* Firewall (`patronus-firewall/src/svc_rules.rs`): for each enabled tunnel, protocol 4 / 41 /
  both is accepted from the remote endpoint only (and to the local endpoint when it is pinned),
  and ICMP / ICMPv6 on the tunnel link. Forwarding between a tunnel and the LAN is decided by
  the ordinary firewall rules (the default LAN-to-any rule covers a LAN client reaching the far
  side). No NAT is applied to tunnel traffic: the far end needs a route back to the LAN.
* A default route over the tunnel sits in the main table; a default gateway set on the Routing
  page takes precedence (the Routing page's default lives in its own table and rule).
* Refused with the reason (HTTP 400, nothing stored): bad names, an IPv6 address on an IPIP
  tunnel or an IPv4 address on a 6in4 tunnel, loopback/multicast/unspecified endpoints, local
  = remote, a second address on a non-gif tunnel or of the same family, a default route without
  an address, MTU under 1280 with an IPv6 address, two tunnels with the same endpoints whose
  types the kernel cannot tell apart (gif overlaps both others; ipip and sit on one endpoint
  pair are fine), a route to an unknown tunnel.
* Not included: GRE / GRE-TAP / VXLAN (the Interfaces page's overlays), 6rd, DS-Lite, MAP-E,
  IPv6-outer tunnels (`ip6tnl`), automatic update of a broker's endpoint address when the
  WAN address changes (the broker's own dynamic-update URL is not called).

## Router tier

The router images (AX1800 and Slate) do not carry the page yet: their kernel modules come
from a hash-pinned OpenWrt package set (`ci/embedded-aarch64/ax1800/kmods.pin`), and `ipip` /
`sit` are not in it. Adding `kmod-ipip` + `kmod-sit` (and their `tunnel4` / `ip_tunnel`
dependencies), re-pinning them and re-measuring the NAND budget is the way in; until then the
unit's page lists IP tunnels among its absent features with the reason. Access-point role
units omit it by design (an AP does not route).

## Proof

* Unit tests: `patronus-network/src/tunnels.rs` (row checks, collision rules, kernel link
  parsing and comparison, route and nft rendering, store round trip),
  `patronus-firewall/src/svc_rules.rs` (rules per tunnel, nothing for disabled or malformed
  rows).
* Netlab `ci/netlab/lane-j-tunnels.sh`: the far end is the lab "internet" namespace set up with
  plain iproute2, so Patronus talks to an independent implementation: validation, IPIP and 6in4
  on the same endpoints, GIF with both families, pings in both directions (the far end first, so
  the inbound rule is what lets it in), TCP from a LAN client through the router and the tunnel,
  the MSS seen on the wire (1440 / 1460), the IPv6 default route over the tunnel, a stranger's
  protocol 4 getting nothing, in-place MTU edit vs re-creation on a TTL edit, foreign and stray
  links, disable and re-enable, status, reboot apply, delete.
* Netlab `ci/netlab/lane-j-tunnels-ui.sh` + `ci/tunnels-page-e2e.py`: the page in Firefox
  (desktop and phone width, light and dark), refused entries explained, a tunnel made, edited,
  disabled and deleted through the page while the far end pings through it.
* The page is also in the accessibility gate (`ci/a11y/a11y-config.json`).
