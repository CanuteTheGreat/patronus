# Patronus

**An open-source firewall/router for Gentoo Linux, with an SD-WAN dashboard.**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Platform: Gentoo](https://img.shields.io/badge/Platform-Gentoo-purple.svg)](https://www.gentoo.org/)

Patronus is built for Gentoo first: it ships as an ebuild in this
repository's own overlay (`gentoo/net-firewall/patronus/`), with USE flags
selecting what is compiled in (see [AGENTS.md](AGENTS.md)). It is written in
Rust and enforces its firewall with the kernel's nftables.

Patronus is under active development. This README only states what the
product does today, and **every claim below is proven by a test that runs in
CI** -- the `[Cn]` marker after a claim is its row in
[docs/claims-ledger.txt](docs/claims-ledger.txt), which names the tests.
`ci/claims-check.sh` fails the build if a claim loses its proof. Features
that are not finished are listed separately under
[Being built](#being-built), without claims.

---

## What works today

### Router and firewall

- A fresh install routes: the first boot turns on forwarding, NATs the LAN
  out of the WAN, and a LAN client is online (ping, DNS, HTTP). [C1]
- The default ruleset is safe: drop policies, SSH and the web UI reachable
  from the LAN only (an anti-lockout rule that cannot be deleted), nothing
  accepted from the WAN. [C2]
- Filter and NAT rules added in the web UI / API are enforced by the kernel
  at once, and deleting a rule lifts it. [C3]
- Rule fields are validated before they reach nftables; ruleset-injection
  attempts are rejected. [C11]
- The Firewall page adds, edits, deletes, enables and reorders rules
  (accept, drop, or reject with a TCP reset; optional logging; per
  interface or role). Rules are evaluated in the order shown and the
  anti-lockout rule always stays first. [C15]
- IPv6: rules with IPv6 addresses match IPv6 traffic only, and IPv6 is
  routed, not NATed. [C16]
- Host and port aliases are nftables sets: rules use them as `$name`, and
  editing an alias changes what is blocked or allowed at once, without
  reloading the ruleset. [C17]
- URL-table aliases (like pfSense's "URL Table"): an alias whose addresses (or
  ports) come from a list on a web server, refreshed on a schedule you set,
  capped in size; a failed download keeps the previous list and the alias shows
  why. [C56]
- GeoIP blocking: a country-set alias holds every address range of the
  countries you pick (free DB-IP "country lite" database, downloaded monthly);
  use it as a source or destination in any rule. [C57]
- Threat-intelligence feeds (Spamhaus DROP/EDROP, FireHOL level 1, abuse.ch or a
  feed of your own): enabled feeds are refreshed, capped, and their addresses
  are dropped ahead of your rules; private ranges a feed lists are never
  blocked and an `ti_allow` alias exempts hosts. [C58]
- Firewall log viewer: packets that a logging rule (or a threat feed, or the
  default policy) drops or accepts are recorded with the rule that caught them;
  search by rule, action, address, port, interface or text, follow it live. [C59]
- Schedules: a rule can be limited to days and hours; it switches on and
  off on time, and after a reboot. [C18]
- Port forwards (protocol + external port to an internal host and port)
  let in exactly the forwarded traffic; NAT reflection lets LAN clients use
  the WAN address. [C19]
- Outbound NAT is automatic (every WAN interface), hybrid, manual or off,
  and 1:1 NAT maps an external address to an internal host both ways.
  [C20]

### Interfaces

- The Interfaces page assigns roles and addresses: static IPv4/IPv6, a DHCP
  WAN (dhcpcd, or busybox udhcpc), a PPPoE WAN, MTU and MAC. Changes reach
  the kernel at once, and a change that would cut off your own admin
  session is refused. [C21]
- VLANs (802.1Q and QinQ), bonds and bridges created on the Interfaces page
  exist in the kernel and carry traffic; an active-backup bond fails over
  when a member's link goes down; deleting one removes it. [C22]
- Interface configuration survives a reboot (`patronus apply` rebuilds it),
  and applying again changes nothing. [C23]

### Routing and multi-WAN

- The Routing page manages gateways (a fixed address, or dynamic: whatever
  the DHCP/PPPoE/static WAN currently uses) and monitors each one with a
  ping a second, showing online, packet loss, high latency or down. [C28]
- A gateway group (USE=multiwan) set as the default gateway fails over: when
  the tier-1 gateway stops answering, traffic moves to the next tier within
  seconds and comes back when it recovers; gateways in the same tier share
  the traffic (load balancing), and every uplink with a gateway gets
  outbound NAT. [C29]
- Static routes go via an IP address or a named gateway, and all routing
  configuration survives a reboot (`patronus apply` rebuilds it; applying
  again changes nothing). [C30]
- Policy routing: a firewall pass rule can name a gateway or group, and the
  traffic it matches leaves through that uplink while everything else
  follows the default gateway. [C31]

### VPN

- WireGuard (USE=wireguard): the VPN page creates tunnels (key pair
  generated by Patronus, UDP port opened on the firewall) and peers; a
  road-warrior peer gets its own generated keys and its client config /
  QR code is downloaded from the page; a remote client with that config
  reaches the LAN through the tunnel, and tunnels come back after a reboot.
  [C32]
- IPsec (USE=ipsec): IKEv2 site-to-site tunnels with a pre-shared key, run
  by strongSwan (swanctl, started through OpenRC or systemd); traffic flows
  both ways between the two LANs without being NATed, live SA state shows
  on the page, and tunnels come back after a reboot. [C33]
- IPsec road warriors (USE=ipsec): an IKEv2 remote-access profile hands out
  addresses from a pool; users log in with a password (EAP-MSCHAPv2) or with
  a client certificate Patronus issues from its own CA (deleting the user
  revokes it). The page exports a ready-made setup file per user: iOS / macOS
  `.mobileconfig`, Android strongSwan `.sswan`, a Windows PowerShell script
  or the `.p12`. [C60]

### LAN services (DHCP, DNS, NTP)

- The DHCP page serves IPv4 pools with static mappings, DHCPv6 pools,
  IPv6 router advertisements and DHCP relay -- with Kea + radvd (USE=kea) or
  dnsmasq -- writing the config files those Gentoo packages read and
  starting them through OpenRC or systemd; clients get leases from the pool
  or their static mapping, and the lease table shows the server's real
  leases. [C24]
- The DNS page runs Unbound as the LAN resolver (or dnsmasq as a forwarder)
  with host overrides, domain overrides and a DNS block list (manual
  entries plus downloaded hosts/domain lists); LAN clients resolve the
  overrides and blocked names come back NXDOMAIN. [C25]
- The NTP page serves time to the LAN with chrony; dynamic DNS publishes
  the WAN address to a provider and re-checks it every 5 minutes. [C26]
- LAN service configuration survives a reboot (`patronus apply` rewrites
  the configs and starts the daemons), and service files are never
  written from unvalidated input. [C27]

### Configuration you can trust

- The configuration survives restarts and reboots: it lives in one SQLite
  store, and `patronus apply` loads it at boot. [C4]
- Applying is atomic and fails closed: a rule the kernel rejects is refused
  and the running ruleset stays as it was; a configuration that cannot load
  at boot falls back to a lockdown ruleset (LAN management only, nothing
  forwarded); if no firewall can be loaded at all, the box stops routing.
  [C5]
- A crash or power cut while editing or applying never corrupts the store or
  loses a saved rule, and the next boot enforces exactly what was saved.
  [C6]
- Every change is kept in the configuration history and can be rolled back.
  [C7]
- Backup and restore: export the whole configuration and import it onto the
  same box or a replacement; an import that does not apply is reverted.
  [C8]
- Upgrades keep the configuration: stores written by earlier releases are
  migrated in place and their rules stay enforced. [C9]
- GitOps (USE=gitops): firewall rules kept as YAML in a git repository
  (`[gitops]` in patronus.toml) are applied by `patronus gitops sync` or the
  `patronus-gitops` service; later commits that change or delete a rule are
  followed, a broken commit is refused with the file named, and applied
  rules survive a reboot. [C38]
- API keys for automation: bearer tokens (read-only or operator, never
  admin) for collectors and scripts; only a digest is stored and a revoked key
  stops working at once. [C39]
- Monitoring: `GET /api/status/summary` and `GET /metrics` (Prometheus text)
  report gateways, tunnels, conntrack, DHCP leases and services; gateway
  up/down, failover and tunnel changes are logged at `GET /api/events` and
  POSTed to signed webhooks. [C40]
- High availability (USE=ha): virtual IPs that fail over between two firewalls
  with VRRP (keepalived), preemption and a maintenance mode, connection-state
  sync (conntrackd) so a failover keeps established connections, and alias
  addresses; configured from the HA page or `/api/ha`. [C42]
- Traffic shaping (USE=qos): CAKE, fq_codel or a rate limit per interface from
  the Traffic shaping page, applied with `tc` and re-applied at boot. [C45]
- External login: people on a RADIUS server (PAP, answers verified with the
  shared secret) can log in to the web UI; local accounts never fall back to
  RADIUS and RADIUS accounts never start as admin. [C44]
- IPv6 network prefix translation (NPTv6): map an internal (ULA) prefix to
  an external prefix in both directions from the firewall's NPTv6 tab. [C43]
- Updates and power: the System page checks and applies updates through
  Portage as background jobs, and reboots or powers off the box. [C41]
- Syslog (USE=syslog): forward the system log to remote collectors (UDP or
  TCP, from a chosen severity up) through an rsyslog drop-in written and
  validated by Patronus, and read the local log on the Syslog page. [C46]
- NetFlow / IPFIX export (USE=netflow): softflowd on a chosen interface
  exports flow records (v5, v9 or IPFIX) to a collector. [C47]
- IGMP proxy (USE=igmp): igmpproxy forwards multicast streams from the WAN to
  LAN interfaces, with the firewall rules it needs generated for it. [C48]
- NAT64 / DNS64 (USE=nat64): IPv6-only clients reach IPv4-only servers through
  tayga, and Unbound answers AAAA queries for IPv4-only names with addresses
  in the NAT64 prefix. [C49]
- L2TP server (USE=l2tp): xl2tpd with PPP MS-CHAPv2 users managed on the L2TP
  page (L2TP itself is not encrypted: pair it with IPsec on untrusted
  networks). [C50]
- Intrusion detection and prevention (USE=intrusion-detection): Suricata
  watches an interface and alerts on your rules, or runs inline where `drop`
  rules really drop packets; the rules are checked by Suricata before they
  replace the running ones. [C51]
- Dynamic routing (USE=dynamic-routing): BGP and OSPF through FRRouting, set up
  on the BGP / OSPF page; learned routes are installed in the kernel and the
  session state is shown live. [C52]
- Wake-on-LAN: saved hosts (MAC + interface) are woken with a magic packet
  broadcast on their network. [C53]
- SD-WAN edge (USE=sdwan): the edge agent enrolls this firewall with a
  Patronus SD-WAN dashboard using a one-time token, builds an encrypted
  WireGuard mesh to the other sites with their subnets routed through it,
  switches a site to its next endpoint when the preferred one stops working,
  and reports measured paths back to the dashboard. [C54]
- SD-WAN dashboard pages: Overview, Topology, SLA, Traffic and Security show
  what the dashboard's store holds right now (sites, paths and their recorded
  measurements, live flows classified by application, the audit log); with
  nothing enrolled they are empty, not filled with sample data. [C55]

### Administration

- The web UI and API require a login; each install gets its own admin
  password (there are no shipped default credentials), and repeated failed
  logins are locked out. [C10]
- Web accounts: admins add, disable and delete accounts with a role (admin,
  operator, read-only) on the System page; accounts are stored with the
  configuration and the last admin cannot be removed. [C34]
- Two-factor login (USE=totp): an account enrols an authenticator app
  (TOTP, QR code) and gets one-time recovery codes; from then on a password
  alone is refused. `patronus users reset-2fa` is the way back in. [C35]
- Backups from the web UI: create, download, upload and restore the whole
  configuration (admins only); a restore is applied to the whole system at
  once and undone if any part of it cannot be applied. [C36]
- Services (DHCP, DNS, IPsec, NTP, ...) can be started, stopped and
  restarted from the System page; the unprivileged web UI does it through
  the root apply broker. [C37]
- Gentoo: installed by the in-tree ebuild (an `emerge` runs in CI), and every
  USE flag that maps to a cargo feature compiles on its own. [C12]
- The installer partitions a real disk, installs, and the installed system
  cold-boots (x86_64 VM, nightly). [C13]

### SD-WAN dashboard

- The dashboard (`USE=dashboard`) runs as a 3-node HA cluster: writes
  replicate to every node and survive a leader failover. [C14]

---

## Being built

These exist partly in the source tree but are **not** usable end to end yet.
They are being wired up one subsystem at a time; each moves to
[What works today](#what-works-today) only together with its CI proof.

- Firewall: GeoIP/threat-feed blocking, URL-table aliases, IPv6 NPt.
- LAN services: DNS over TLS upstreams, DHCP-registered hostnames in DNS,
  captive portal.
- Routing: DHCPv6 prefix delegation on the WAN, dynamic routing via FRR.
- VPN: OpenVPN, IPsec road warriors (EAP / certificates), L2TP.
- Firewall HA (VRRP + state sync), LDAP/RADIUS login, API keys,
  metrics/alerts, diagnostics, captive portal, IDS/IPS, traffic shaping.
- SD-WAN path selection and policies in the dashboard.

Many Gentoo USE flags currently only pull in dependencies for these.

---

## Installation (Gentoo)

The overlay lives in this repository under `gentoo/`:

```bash
mkdir -p /var/db/repos/patronus
cp -r gentoo/* /var/db/repos/patronus/
chown -R portage:portage /var/db/repos/patronus
cat > /etc/portage/repos.conf/patronus.conf <<'EOF'
[patronus]
location = /var/db/repos/patronus
EOF
emerge net-firewall/patronus          # USE="web" (default) for the web UI
```

Tell Patronus which interface is which in `/etc/patronus/patronus.toml`
(the installer writes this for you):

```toml
[network]
wan_interfaces = ["eth0"]
lan_interfaces = ["eth1"]
```

Then enable the services (systemd shown; OpenRC scripts are installed too):

```bash
systemctl enable --now patronus-firewall   # runs `patronus apply` at boot
systemctl enable --now patronus-web        # https://<LAN address>:8443
cat /var/lib/patronus/initial-admin-password
```

### Everyday commands

```bash
patronus apply --dry-run          # show what would be loaded (nft script, sysctls)
patronus apply                    # load the stored configuration now
patronus config revisions         # configuration history
patronus config rollback <id>     # restore a revision and apply it
patronus config export -o backup.json
patronus config import backup.json
```

Rules are managed in the web UI (Firewall page) or through the API, e.g.

```bash
curl -k -b jar -c jar -H 'content-type: application/json' \
  -d '{"username":"admin","password":"..."}' https://192.168.1.1:8443/api/auth/login
curl -k -b jar -H 'content-type: application/json' https://192.168.1.1:8443/api/firewall/rules \
  -d '{"name":"block-host","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"80","description":"block-host","enabled":true}'
```

---

## How it is tested

- **Netlab** (`ci/netlab/`, every push): a small internet in network
  namespaces -- a LAN client, the router running the real `patronus` and
  `patronus-web` binaries, an ISP and an internet host with DNS and HTTP --
  inside one capped container. Scenarios assert real traffic and kernel
  state: first boot, rules through the web API, reboots, failed applies,
  crashes mid-edit, backup/restore and upgrades.
- **Unit and integration tests** per crate, including real-nftables tests in
  a NET_ADMIN container.
- **Nightly** (`nightly-test-depth.yml`): mutation testing of the config
  store and firewall applier with minimum scores (`ci/mutants.sh`,
  `ci/mutants-floors.txt`), longer crash runs and an upgrade from the
  previous release; plus the installer in a VM.

## Development

```bash
cargo build -p patronus-cli -p patronus-web
cargo test -p patronus-config -p patronus-firewall -p patronus-web
ci/netlab/run.sh                       # needs Docker; builds and runs the netlab
ci/claims-check.sh                     # README claims vs. tests
```

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
