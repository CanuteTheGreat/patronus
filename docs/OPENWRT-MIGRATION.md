# Migrating an x86 OpenWrt router to Patronus

`patronus import-uci` reads an OpenWrt router's configuration and writes the
equivalent Patronus configuration. It targets full routers (WAN, LAN, DHCP/DNS,
firewall, WireGuard, multi-WAN, DDNS, SSH), not only access points.

## Steps

1. Install Patronus on the new box (or VM) and finish the first-run setup.
2. Dry run, straight from the live router (nothing is written, keys are masked):

       patronus import-uci --ssh root@OLD-ROUTER[:PORT] --dry-run \
           --map lan=eth0 --map wan=eth1

   The report lists every WireGuard tunnel and peer by description, and a final
   "not imported" section for anything that has no equivalent.
3. Run it for real without `--dry-run`, then review with `patronus apply --dry-run`
   and `patronus apply`.
4. Give the new box the old WAN address/MAC (or move the cable) and the same LAN
   address. Clients keep their leases, DNS names and tunnel settings.

Offline alternative: `patronus import-uci backup.tar.gz` (from `sysupgrade -b`)
or a directory with `etc/config/*`. Keys travel only over the ssh session (or
the backup you made) into the config store; they are never printed, logged,
or written outside a 0700 scratch directory.

## WireGuard

Every `proto wireguard` interface becomes a Patronus tunnel with the SAME
private key, listen port, IPv4 and IPv6 addresses (including `ip6assign`
prefixes) and MTU, so no client needs reconfiguring. Every
`wireguard_<iface>` peer is carried with: public key, preshared key, allowed
IPs (IPv4 and IPv6), endpoint (IPv4, IPv6 and host names, default port 51820),
persistent keepalive, description (the peer name, made unique) and the
disabled state. Static routes behind a peer are imported with the other
static routes. Firewall zone membership and forwards of the tunnel come
across with the firewall import. A second run changes nothing.

Not carried:

- `route_allowed_ips 0`: Patronus always installs a route for a peer's
  allowed IPs.
- Unknown per-peer or per-interface options are listed in the report
  ("option(s) not imported") instead of being dropped silently.
- Legacy "wgserver" (babeld/olsrd mesh hotplug) setups: reported, not mapped.

Test: `wireguard_seven_peers_all_attributes` (a sanitized seven-peer router,
test keys only) and the `lane-d-uci-import` / `lane-f-wireguard` netlab
lanes with real `wg` clients using their original client configs.

## Other things that need a manual step at cutover

- A second sshd (dropbear fallback on another port) is not recreated:
  Patronus runs one sshd.
- DDNS jobs implemented as custom cron scripts must be recreated as DDNS clients.
- SSH host certificates must be re-signed for the new host key.
- Wi-Fi STA uplinks are imported, but need the radio present on the new box.
- A VM with a tiny disk must be replaced by a properly sized one.
