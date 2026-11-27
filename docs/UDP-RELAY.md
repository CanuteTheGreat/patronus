# UDP broadcast relay (USE=udp-relay)

Repeats IPv4 UDP broadcasts (NetBIOS 137/138, SSDP 1900, game, printer and
licence-server discovery, Wake-on-LAN, ...) from one segment to others. A
broadcast never leaves its own segment; this is the Patronus equivalent of
pfSense's udpbroadcastrelay package.

* Page: **Services -> UDP broadcast relay** (`/svc/udp-relay`, API `/api/svc/udp-relay`).
* Settings: `enabled`, `rate_limit` (packets/s per source interface, 0 = off, default 200).
* Rules (table `udp_relay_rules`): listen interface, UDP ports and ranges
  (`137,138,5000-5010`, up to 32 entries), target interfaces (comma list of
  devices or `@lan`/`@optN`), "keep original source address" (default on), enabled.
  Several rules may name the same listen interface (multi-port, different targets).
* Port 67/68 (DHCP) is refused: use the DHCP relay.
* Engine: `patronus udp-relay run --conf FILE` under the daemon supervisor
  (`patronus-daemon@udp-relay`, OpenRC and systemd), no extra package. It reads
  with an `AF_PACKET` socket per listen interface and sends with a raw IPv4
  socket bound to the target device, so the firewall needs no rule.
* Loop guard: every relayed copy carries a fixed IP identification and TTL 1 and
  is never relayed again; datagrams from a local address are ignored.
* With "keep original source address" on, the receiving device needs a route to
  the sender's network (a default route is enough) or the kernel's reverse-path
  filter drops the copy. With it off the source is the target interface's address.
* Reaching the discovered service still needs a firewall rule between the segments.
* Proof: unit tests in `patronus-network/src/udprelay.rs`; netlab lane
  `ci/netlab/lane-j-udp-relay.sh` (real broadcasts across two segments, multi-port
  rules on one interface, source handling, no loop across a rule cycle, per-direction
  rules, validation, reboot, disable).
