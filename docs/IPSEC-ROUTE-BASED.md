# Route-based IPsec (XFRM interfaces) and OSPF over the tunnel

Patronus has two kinds of IPsec site-to-site tunnel (VPN page, `mode`):

- **policy** (the default): the traffic selectors (`local_ts` / `remote_ts`) decide what is
  encrypted. Nothing else can use the tunnel, so no routing protocol runs over it.
- **route**: the child SA is bound to a kernel XFRM interface (`xfrm<if_id>`) with
  strongSwan's `if_id_in` / `if_id_out`. The routing table decides what goes through the tunnel:
  static routes, or routes learned over the tunnel itself (OSPF through FRR). This is the
  equivalent of pfSense / OPNsense "VTI" (routed IPsec) and of OpenWrt's xfrm interfaces.

Proof: `ci/netlab/lane-f-ipsec-vti.sh` (README claim C87), two routers (Patronus and an independent
strongSwan + FRR), LAN-to-LAN traffic over `xfrm1`, OSPF adjacency, tunnel down / up on the status page.

## Settings (all typed, in the declarative `IpsecTunnel` resource, the API and the VPN page)

| key | meaning | default |
|---|---|---|
| `mode` | `policy` or `route` | `policy` |
| `if_id` | XFRM interface id shared by the SA and the interface | next free id (1, 2, ...) |
| `tunnel_address` | this router's address on the interface, CIDR (`10.255.0.1/30`) | none |
| `mtu` | MTU of the interface (576-9000) | kernel default |
| `xfrm_dev` | device the interface is attached to | `lo` (the SA is bound by `if_id`, not by the device) |
| `local_ts` / `remote_ts` | selectors; in route mode empty means `0.0.0.0/0, ::/0` | wildcard |

## What Patronus does for a route-mode tunnel

1. swanctl: the child gets `if_id_in = if_id_out = <if_id>` and wildcard selectors.
2. `/etc/strongswan.d/patronus-routes.conf` sets `install_routes = no` (for `charon` and
   `charon-systemd`) while a route-mode tunnel exists, because a wildcard selector would otherwise
   make charon install a route to the whole internet towards the peer. The file is removed again
   when the last route-mode tunnel goes. charon reads the setting at start, so the first route-mode
   tunnel restarts charon once.
3. The `xfrm<if_id>` interface is created before charon loads the SA (address, MTU, `multicast on`
   because OSPF hellos need it, up); an edited tunnel updates it in place, a changed `if_id` or
   device recreates it, a deleted tunnel removes it. Only interfaces named `xfrm*` that no
   route-mode tunnel owns are removed.
4. Firewall (`vpn_rules.rs`): traffic arriving from `xfrmN` is forwarded (restricted to the remote
   selectors when they are not wildcard), ICMP to the router is accepted on it, nothing routed into
   it is NATed. Everything else the user decides with normal firewall rules on the interface.
5. FRR: an OSPF interface named `xfrmN` is `ip ospf network point-to-point` unless the page says
   otherwise (`network` = auto / broadcast / point-to-point); an XFRM interface has no broadcast
   domain and FRR would otherwise treat it as NBMA and never send hellos. Protocol 89 is accepted on
   the OSPF interfaces by `svc_rules.rs`.

## Status page (`/vpn`, `/api/vpn/ipsec/...`)

- IPsec security associations: state, subnets, gateway and the **received / sent bytes** of the CHILD SAs.
- IPsec security policies: the kernel's SPs (`ip xfrm policy`): source, destination, direction,
  tunnel endpoints, protocol, and the `if_id`. API: `GET /api/vpn/ipsec/policies`.
- XFRM interfaces: state, `if_id`, addresses, MTU, bytes. API: `GET /api/vpn/ipsec/interfaces`.
- Per tunnel **Connect** / **Disconnect** (`POST /api/vpn/ipsec/connections/:id/connect|disconnect`).
  The web UI is unprivileged, so the click is queued in `ipsec_requests` (not configuration: listed in
  `NON_CONFIG_TABLES`, rows are deleted once carried out and dropped after an hour) and the applier,
  which can talk to charon, runs `swanctl --initiate` / `--terminate` during the apply that the
  change triggers. A tunnel that only responds (`remote_address = %any`) cannot be connected from here.
  A disconnected tunnel stays down until Connect or the next apply that loads it as new.

## Limits

- IKEv2 with a pre-shared key only (as policy mode); IPv4 and IPv6 prefixes on the interface address.
- The embedded router images (APs, Slate) do not ship strongSwan, so nothing changes there.
