# DHCPv6 relay agent (USE=dhcp6-relay)

Relays the DHCPv6 messages of clients on a LAN segment to a DHCPv6 server on
another network and the answers back (an RFC 8415 section 19 relay agent), so
one central server can serve several segments. This is the Patronus equivalent
of ISC `dhcrelay -6`, pfSense/OPNsense "DHCPv6 Relay" and OpenWrt's odhcpd relay
mode. (The existing IPv4 relay is `dhcp_relays` in the DHCP page.)

* Page: **Services -> DHCPv6 relay** (`/svc/dhcp6-relay`, API `/api/svc/dhcp6-relay`).
* Settings (also in the declarative config / GitOps like every svc page):
  `enabled`, `hop_limit` (1-32, default 32), `interface_id` (send the interface
  name as Interface-Id option, default on), `rate_limit` (client messages/s per
  interface, 0 = off, default 500).
* Rules (table `dhcp6_relay_rules`): the interface the clients are on
  (`@lan`, `@optN` or a device), the server (a unicast address, a link-local
  address, or `ff02::1:2` = all servers on the upstream link) and the upstream
  interface (required for `ff02::1:2` and link-local servers, optional otherwise:
  it only narrows the firewall rule). Several rules may name one client interface
  (every server gets every message) and one server may serve several interfaces.
* Engine: `patronus dhcp6-relay run --conf FILE` under the daemon supervisor
  (`patronus-daemon@dhcp6-relay`, OpenRC and systemd), no extra package. One UDP
  socket per client interface (bound to the device, in `ff02::1:2`, port 547) and
  one unbound socket on port 547 for the servers, which answer to port 547 of the relay.
* On the wire (RFC 8415 19.1/19.2): Relay-forward with hop-count 0, the first global
  address of the client interface as link-address (`::` if it has none), the
  client's address as peer-address, Interface-Id (device name) and the client's
  message as Relay Message. A Relay-forward received from another relay is relayed
  with hop-count + 1 and link-address `::` (dropped at the hop limit). A
  Relay-reply is unwrapped and sent to the client (port 546), or, when the
  unwrapped message is itself a Relay-reply, to the downstream relay (port 547).
  The answer's interface comes from the Interface-Id, else the link-address, else
  (a relayed Relay-forward without Interface-Id) from the interface the downstream
  relay was heard on.
* Only the configured servers may answer (any host on the upstream link when a rule
  uses `ff02::1:2`). Messages of server types from a client are dropped.
* Firewall: udp/547 is accepted on each client interface and the Relay-reply of
  each server (and of any host on the upstream interface for the all-servers group).
  Nothing else opens.
* Do not run a DHCPv6 server (dnsmasq/Kea) on a relayed interface: the relay owns
  udp/547 there.
* Standard and router tiers (USE flag in both the 0.2.0 and 9999 ebuilds, and the
  image ebuild template through the default feature set). The embedded images use
  explicit feature lists and do not carry it.
* Proof: unit tests in `patronus-network/src/dhcp6relay.rs` (wire format, hop
  rules, reply routing, validation) and `patronus-firewall` (`svc_rules.rs`);
  netlab lane `ci/netlab/lane-j-dhcp6-relay.sh` (a probe server that checks every
  field of the Relay-forward; the real ISC dhcpd serving two segments from their
  own pools through a unicast and an all-servers rule; Interface-Id on/off; a
  downstream relay and the hop limit; forged and wrong-type messages; validation;
  firewall; restart after a simulated power cycle; disable) and the page e2e
  `ci/dhcp6-relay-page-e2e.py`.
