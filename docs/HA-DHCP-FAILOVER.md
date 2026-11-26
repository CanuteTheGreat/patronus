# HA: DHCP failover and services that follow the virtual IP

Part of the high-availability lane (`docs/design/pfsense-opnsense-parity.md` section 5).
Two firewalls share virtual IPs (VRRP, keepalived). This page covers what else has to move
with them so a failover does not break clients: DHCP, and the VPN listeners.

## DHCP failover (Kea HA)

With HA on and the **Kea** DHCP backend, both nodes serve the same pools. The DHCP applier
loads Kea's `libdhcp_ha.so` and `libdhcp_lease_cmds.so` (both ship in `net-misc/kea`) and
renders the pair from the HA settings:

| Key (`ha.*`, API `PUT /api/ha/settings`, HA page "DHCP failover") | Default | Meaning |
|---|---|---|
| `dhcp_failover` | on | Use Kea HA when HA is on. Needs a peer address; without one DHCP runs alone and the apply says why |
| `dhcp_mode` | `hot-standby` | `hot-standby` (one node answers, the other takes over) or `load-balancing` (both answer) |
| `dhcp_role` | `primary` | this node's role in the pair: `primary` or `secondary` (set it differently on the two nodes) |
| `dhcp_peer` | the sync peer, else the VRRP peer | peer address for the lease/heartbeat channel |
| `dhcp_local` | this node's address on the sync interface (else on the VIP interface) | our own address towards the peer |
| `dhcp_port4`, `dhcp_port6` | 8000, 8001 | TCP ports of the HA listeners (>= 1024) |
| `dhcp_heartbeat_ms` | 10000 | heartbeat interval |
| `dhcp_max_response_delay_ms` | 60000 | silence after which the other node takes over the peer's leases |
| `dhcp_max_unacked` | 10 | unanswered clients before takeover (0 = as soon as the partner is unreachable) |
| `dhcp_send_lease_updates` | on | copy every lease to the peer as it is granted |

How it behaves:

- Kea runs its own state machine, independent of VRRP. Every lease is sent to the peer when it
  is granted; a node that starts (or comes back) first synchronises the peer's leases. When one
  node stops answering, the other declares it `partner-down` and serves its leases: a client
  that rebinds (broadcast at T2) gets the **same address** from the survivor, new clients get
  new ones, and when the failed node returns both lease databases converge.
- The HA listener of Kea is bound to this node's address on the sync network and the firewall
  opens it to the peer's address only (`HA DHCP failover` rules, on the sync interface; the VIP
  interfaces when there is no sync network).
- With a virtual IP on the LAN, the DHCP options that name the router (default gateway, DNS
  server, NTP server) are the **LAN VIP**, so a client served by either node has a working
  gateway. The VIP is read from the configuration, never from the live addresses, so the
  rendered config is identical on MASTER and BACKUP and a failover never rewrites it. Kea binds
  the router's own address (`dev/addr`), not the VIP (a socket on a VIP that moves would die);
  the server identifier is therefore each node's own address.
- **dnsmasq has no failover protocol and does not share leases**, so it is refused: the apply
  warns (`DHCP failover refused: ...`), `PUT /api/ha/settings {"dhcp_failover":true}` answers 400
  with the reason while pools exist, and the HA page shows why DHCP failover is not in effect.
  Pools keep serving on that node alone.
- The HA page shows Kea's own state per family (`hot-standby`, `partner-down`,
  `communication-interrupted`, ...) read from the local HA listener.
- Roles are node-local: the HA configuration sync must not copy `ha.dhcp_role`, `ha.dhcp_local`
  or `ha.priority` from one node to the other.
- The channel is plain HTTP on the sync network, protected by the firewall rule. Kea can also
  secure it with TLS; that is not configured yet.

## Services that follow the virtual IP

`ha.follow_services` (default `wireguard,openvpn,ipsec`; HA page "Services that follow the
virtual IP") lists the services that run only on the node that holds the VIP.

- keepalived's notify script records the state in `/run/patronus/ha-state` and runs
  `patronus ha-event STATE` (serialised, in the background). That re-applies exactly those
  appliers; each asks `ha_follow::follow_hold` and holds its service down unless this node is
  MASTER. A missing state file (right after boot, before the first election) counts as BACKUP.
- WireGuard: the tunnel interface stays configured (key, peers, addresses) but is set down on
  the node without the VIP; coming up on MASTER re-adds the peer routes. OpenVPN: the server
  is stopped and not started. IPsec: charon is stopped; the swanctl configuration stays written.
- **Bound to the WAN VIP.** OpenVPN gets `local <WAN VIP>` (it starts only on MASTER, when the
  VIP exists). WireGuard's socket cannot be bound to an address and falls back to the
  interface's own address whenever the VIP changes under it, so a peer that dialled the VIP
  would roam to the node's own address and lose the tunnel at the next failover (a keepalive in
  the moment between losing the VIP and the tunnel going down is enough; seen in the netlab): with
  HA on, a WAN carp VIP and WireGuard in the follow list, the firewall adds a stateless postrouting
  rule `udp sport <listen port> ip saddr != <WAN VIP> ip saddr set <WAN VIP>` (`HA: WireGuard
  answers from the virtual IP`) so every answer leaves with the VIP as source. (A source NAT
  does not work here: it opens a second conntrack entry for the peer's 4-tuple and moves the
  source port.) strongSwan answers from the address a packet
  arrived on and needs neither.
- A peer dials the WAN VIP. After the VIP moves, the peer's next packets reach the other node,
  which has the same server key (the HA configuration sync carries it); the peer re-handshakes
  within its keepalive window, with no change on the peer's side.
- Turning HA off, deleting the last VIP or changing the list re-applies the services at once.
- The DNS resolver listens on the VIP too (unbound `ip-freebind`), from the configuration, so
  its config does not change on a failover.
- Unicast VRRP is used only on a VIP whose subnet contains the peer address; a VIP on another
  network (typically the WAN next to a LAN peer) uses multicast.

## Proof

`ci/netlab/ha-services-test.sh` (OpenRC and systemd, real Gentoo stage3 with Kea, keepalived,
wireguard-tools): section 10b is a Kea HA pair (this router and an independent Kea in a
second namespace) with a lease client in its own namespace: a lease from A, A stops, the
same client rebinds the same address from B, a new client is served by B and reaches the
gateway (the VIP, held by B), A returns and both lease files list the same leases. Section 10c
is a WireGuard peer dialling the WAN VIP: A holds `wg0` down when it loses the VIP, B brings
its own up, the tunnel re-establishes through the VIP, and returns to A with a fresh handshake.
Unit tests: `kea_with_ha_loads_the_hook_and_hands_out_the_vip_as_gateway`,
`a_live_vip_on_the_interface_is_never_taken_for_the_router_address`,
`the_dnsmasq_backend_refuses_dhcp_failover_with_a_reason`,
`services_are_held_unless_this_node_is_master`.

## Router tier (GL-AX1800 image)

The router image is built without `ha` and serves DHCP with dnsmasq, so none of this runs there
today. Size of adding it, measured with Alpine edge aarch64 (musl) packages packed with
`mksquashfs -comp xz -b 256K` (Kea 3.2.1: dhcp4, dhcp6, `libdhcp_ha.so`, `libdhcp_lease_cmds.so`
and the Kea libraries, log4cplus, libstdc++, libgcc; keepalived 2.4.3, libnl3):

| Set | squashfs-xz |
|---|---|
| Kea (v4 + v6, HA + lease_cmds hooks, libs, libstdc++, log4cplus) | 3,452,928 B (3.29 MiB) |
| + keepalived + libnl3 | 3,923,968 B (3.74 MiB) |
| + shared OpenSSL 3 (libssl, libcrypto), libmnl, libnftnl, if the image has no copy of them | 6,197,248 B (5.91 MiB) |

Installed (unpacked) sizes: kea-common 7.66 MB, kea-dhcp4 0.88 MB, kea-dhcp6 0.88 MB, HA hook
0.53 MB, lease_cmds 0.33 MB, keepalived 0.66 MB. RAM use on the router was not measured.
