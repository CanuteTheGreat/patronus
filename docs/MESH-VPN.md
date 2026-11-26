# Mesh VPN clients (Tailscale, with Headscale as the self-hosted control server)

Optional, packaged feature (`USE=tailscale`, RDEPEND `net-vpn/tailscale`). Page: Services > Tailscale
(`/svc/tailscale`), API `GET|PUT /api/svc/tailscale`. Declarative resource: the page's settings.
Proof: unit tests of the rendered command lines and the apply flow (`patronus-network` tailscale
tests), the firewall rules (`svc_rules.rs`) and `ci/netlab/lane-j-tailscale.sh` against a real Headscale
(README claim C88).

## Settings (typed keys, defaults in `tailscale.rs`)

`enabled`, `login_server` (empty = Tailscale's own service; a Headscale URL), `auth_key_file` (a file
holding a pre-auth key: tailscale reads it itself with `--auth-key file:PATH`, so the key never enters
the configuration, the API or a log; only needed to join), `hostname`, `advertise_routes`,
`advertise_exit_node`, `accept_routes`, `accept_dns` (off: Patronus keeps its own resolver),
`interface` (kernel device, default `tailscale0`), `port` (41641), `open_port`, `allow_input`,
`allow_lan`, `tailnet_range` (100.64.0.0/10), `state_dir` (/var/lib/tailscale), `socket`.

## How it runs

- `tailscaled` is a Patronus supervised daemon (`patronus-daemon@tailscaled`: OpenRC and systemd) with
  `--state --socket --port --tun` from the settings. Patronus does not touch the distro's own `tailscale`
  service; do not enable both.
- The node joins with `tailscale up --reset --netfilter-mode=off ...` once: again only when the wanted
  flags change or the node is not Running. A node that needs a login but has no key file is refused with a
  plain message (tailscale would otherwise wait for a browser login).
- Switching the page off stops tailscaled (the node identity in `state_dir` is kept, so switching it on again needs no key).

## Firewall

Patronus owns the firewall (tailscale's own netfilter handling is off). By default the tailnet
interface is closed: no rule accepts anything from it. Settings open exactly what they say
(`svc_rules.rs`): `open_port` accepts the UDP port (direct connections), `allow_input` accepts traffic
from the tailnet to the router itself, `allow_lan` forwards tailnet to LAN (plus replies),
`advertise_exit_node` forwards tailnet to WAN and masquerades the tailnet range out of the WAN.

## Which mesh clients package cleanly on Gentoo (checked 2026-11-25)

| client | Gentoo | licence | maintenance | decision |
|---|---|---|---|---|
| Tailscale (`tailscaled`) | `net-vpn/tailscale` in ::gentoo, 1.104.5, `~amd64 ~arm ~arm64 ~ppc64 ~riscv ~x86`, OpenRC + systemd units, maintainers williamh / arthurzam | BSD-3-Clause upstream (ebuild: MIT, Apache-2.0, BSD, ISC, MPL-2.0 Go deps) | upstream pushed daily, release 1.104.7 on 2026-11-12 | **shipped** |
| Headscale (control server, lab and self-hosting) | `net-vpn/headscale` in ::gentoo | BSD-3-Clause | release 0.29.7 on 2026-10-30 | used by the netlab lane; the router is a client, a Headscale server on the router is not offered |
| ZeroTier (`zerotier-one`) | not in ::gentoo, not in ::guru | upstream: MPL-2.0 for most of the tree, but `nonfree/` holds "source available" code under a restrictive licence (GitHub reports "Other") | release 1.16.2 on 2026-05-28, last push 2026-09-03 | **not shipped**: a licence that is not free software, and no ebuild to maintain against it |
| NetBird | not in ::gentoo, not in ::guru | client BSD-3-Clause, but `management/`, `signal/`, `relay/` are AGPLv3 | release 0.83.2 on 2026-11-20, active | **not shipped yet**: it would need an ebuild (Go build of the client only) in the project overlay; add when a user asks, the svc framework page is a copy of `tailscale.rs` with `netbird up --setup-key-file` |

Nothing mesh related ships on the embedded tier (AP / Slate images): the flash and RAM budget there
excludes a Go daemon, and the page is simply not in those builds.
