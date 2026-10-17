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
- Schedules: a rule can be limited to days and hours; it switches on and
  off on time, and after a reboot. [C18]
- Port forwards (protocol + external port to an internal host and port)
  let in exactly the forwarded traffic; NAT reflection lets LAN clients use
  the WAN address. [C19]
- Outbound NAT is automatic (every WAN interface), hybrid, manual or off,
  and 1:1 NAT maps an external address to an internal host both ways.
  [C20]

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

### Administration

- The web UI and API require a login; each install gets its own admin
  password (there are no shipped default credentials), and repeated failed
  logins are locked out. [C10]
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
- Interfaces: assigning roles/addresses from the UI, VLANs, bonds, bridges,
  PPPoE.
- LAN services: DHCP server, DNS resolver (Unbound), IPv6 router
  advertisements / DHCPv6.
- Routing: static routes, gateways, multi-WAN failover/load balancing,
  dynamic routing via FRR.
- VPN: WireGuard, IPsec, OpenVPN.
- Firewall HA (VRRP + state sync), users and 2FA, web-UI backups, services
  control, metrics/alerts, diagnostics, captive portal, IDS/IPS, traffic
  shaping.
- SD-WAN path selection and policies in the dashboard, GitOps apply.

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
