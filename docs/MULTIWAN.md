# Multi-WAN: gateway groups beyond tiers and weights

Lane E (`crates/patronus-network/src/{routes,multiwan}.rs`, USE=`multiwan`). Tiers, weights, failover, load
balancing, policy routing and the gateway monitor are described in `AGENTS.md` (Routing) and the README; this page
covers what a gateway group can do on top, the way pfSense and OPNsense gateway groups behave. Everything below is a
typed setting: the Routing page, `/api/routing/*`, the declarative config (export / plan / apply, GitOps
`GatewayGroup` documents) and the store tables carry the same values.

## Per-gateway levels

| Setting | Default | Meaning |
| --- | --- | --- |
| `loss_threshold` (%) | 20 | packet loss over the last 10 probes from which the gateway is in the `loss` state ("down" level) |
| `latency_threshold` (ms) | 500 | average round trip above which it is in the `latency` state ("down" level) |
| `loss_warn` (%) | 0 = off | warning level below `loss_threshold` |
| `latency_warn` (ms) | 0 = off | warning level below `latency_threshold` |
| `dns_servers` | none | the uplink's DNS servers (at most four, same address family) |

A gateway above a *warning* level stays `online` and keeps carrying traffic; the status has `warning: loss|latency`,
the Routing page and the dashboard Uplinks tile show it and a `gateway_warning` event (and `gateway_warning_cleared`)
goes to the event log and the webhooks. Warning levels are validated to sit below the down levels.

## Trigger per group

`trigger` decides what makes a member unusable for the group: `down` (no replies), `loss`, `latency` or
`loss_latency` (either). A group with trigger `loss` keeps a member whose latency is high (it still shows
`latency` on the gateway), a group with `latency` leaves it.

## Sticky connections (load-balancing groups)

`sticky_secs` > 0 gives every client address one member and keeps it for that many seconds after the client's last
packet (0 = off, flows are hashed over the members by weight). The assignment sits in an nftables map with element
timeouts in the own table `inet patronus_wan` (chain `sticky`, prerouting, hook priority -140, after the
policy-routing marks of the firewall's `pbr` chain):

1. a client that has an entry gets its member's routing mark and the timeout is refreshed;
2. a client without one gets a member by weight (`numgen random`) and an entry;
3. the member's mark selects that gateway's routing table (the same tables policy routing uses), so the group's
   default route is not consulted for that client.

It applies to traffic that carries the group's own mark (a firewall rule whose gateway is the group) and, when the group
is the default gateway, to unmarked forwarded traffic; traffic arriving on a gateway interface is never assigned.
Entries pointing at a member that no longer carries traffic are dropped at the next apply (that map is flushed, those
clients are assigned again); a member that returns does not pull anybody back, so a client keeps its uplink until its
entry expires or its uplink leaves. IPv4 and IPv6 groups use separate maps (`st<gid>_4`, `st<gid>_6`). Switching it off
removes the table. A changed timeout applies to new entries.

## Kill states

`kill_states`: `none` | `down` (default) | `down_recovery`.

What Linux does by itself: a masqueraded flow whose output interface changes is re-NATed (the kernel replaces the
tracking entry and drops that one packet), so an *active* flow follows a moved route without help. What stays behind is
the tracked state of *idle* connections (an idle TCP connection is tracked for five days) and of *inbound* connections
that arrived through the lost uplink (port forwards, services on the router). After the routes phase moved, the monitor
deletes the connections of the uplink that left (`conntrack -D` by the address of the gateway's interface, as
`--reply-dst` for masqueraded flows and `--orig-dst` for inbound ones; the addresses are remembered while the link is
down). With `down_recovery` the same happens to the fallback members' connections when a better member returns. A
failback ramp (`failback_ramp` > 0) suppresses the recovery kill: the ramp moves new flows gradually. The last action
(time, number of connections, reason) is in the gateway status, on the Routing page and as a `gateway_states_killed`
event. Needs `conntrack` (conntrack-tools; the ebuild depends on it with USE=multiwan); without it the monitor logs a
warning and the entries time out by themselves. IPv4 (NAT) flows only: routed IPv6 flows keep their client address.

## DNS per gateway

A gateway's DNS servers get a host route through that gateway (like a monitor IP, route protocol 252) so they are
reachable even while another uplink carries the default route, and `dns.gateway_servers` (default on) makes the
resolver (Unbound / dnsmasq) forward to the DNS servers of the gateways that carry traffic, in addition to
`dns.upstreams`. The gateway monitor re-applies DNS when that set changes (applyd). Not used together with DNS over TLS
(these servers are not assumed to speak it). A slow or lossy uplink still answers DNS; a down one is skipped.

## Events and notifications

`gateway_down`, `gateway_up`, `gateway_degraded`, `group_failover` (existing) plus `gateway_warning`,
`gateway_warning_cleared` and `gateway_states_killed` are recorded in `system_events`, offered to webhooks and
notification channels (`EVENT_KINDS`), and the dashboard's Uplinks tile lists the last five.

## Router tier (GL-AX1800, GL-AR750S)

See the measurements in `docs/FEATURE-PARITY.md` (Gateway groups rows) and `docs/embedded-routers.md`.

## Proof

`ci/netlab/lane-e-routing.sh` (OpenRC and systemd images): warning level and trigger choice with `tc netem` latency on
one ISP, sticky connections (one client one uplink, per-client entries, lost uplink, returning uplink, timeout, off),
kill states (an idle TCP connection's state stays without them and goes with them, recovery, the active UDP flow follows the route); unit tests in
`multiwan/tests.rs`, `dns.rs` and `state/telemetry.rs`. Claim C93.
