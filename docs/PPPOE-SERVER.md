# PPPoE server / access concentrator (USE=pppoe-server)

Subscribers (another router's PPPoE WAN, a lab, CPEs) dial in on a LAN or
optional port, authenticate and get an address from a pool; the router then
routes them to the internet. Equivalent of pfSense's PPPoE server and OPNsense's
PPPoE server plugin.

* Page: **Services -> PPPoE server** (`/svc/pppoe-server`, API `/api/svc/pppoe-server`).
* Engine: rp-pppoe `pppoe-server` (discovery, kernel-mode sessions when the
  `pppoe` kernel module and pppd's `rp-pppoe.so` exist, else one `pppoe` helper per
  session) starting one `pppd` per session, supervised as
  `patronus-daemon@pppoe-server` (OpenRC and systemd).
* Every value is a typed setting (`pppoe-server.*` in the declarative config): interfaces
  (`@lan`, `@optN`, device names; never the WAN), access concentrator and service name,
  server address, pool first/last, max sessions, sessions per client MAC, auth
  (chap, mschap-v2, pap, any), DNS 1/2, MTU/MRU, LCP keep-alive, idle timeout, session mode,
  first session device number (`unit_base`), internet access, internet interface, NAT,
  LAN access, router services the clients may use (`proto/port` list; ping is always
  allowed), and RADIUS (server, ports, secret, accounting, timeout, retries, source).
* Users (table `pppoe_server_users`): name, password, optional fixed address, enabled.
  Passwords are shared secrets (CHAP): never returned by API/UI, written only to
  root-owned mode-0600 files. `/etc/ppp/chap-secrets` and `pap-secrets` get a managed block;
  other lines are kept (and shared with L2TP). With RADIUS on, pppd's `radius.so` plugin
  authenticates (and sends accounting) and the local list is not consulted.
* Session devices are `ppp<unit_base>`.. (default 1000+), a range of their own, so firewall
  rules (ping, selected router services, forwarding to the internet/LAN, masquerade) never
  touch a PPPoE WAN client link (`ppp0`).
* Gentoo: `USE=pppoe-server` pulls `net-dialup/rp-pppoe` and `net-dialup/ppp`. RADIUS needs
  a pppd that ships `radius.so` (check the installed ppp package).
* Proof: unit tests in `patronus-network/src/pppoe_server.rs` and `patronus-firewall/src/svc_rules.rs`;
  netlab lane `ci/netlab/lane-j-pppoe-server.sh` (a real PPPoE client, NAT, refused users,
  fixed address, reboot, disable).
