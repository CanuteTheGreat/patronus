# Floating rules, interface groups, state limits and limiters

Lane B (firewall), docs for the pfSense/OPNsense parity items in
`docs/design/pfsense-opnsense-parity.md` section 4. Everything here is stored
in the config store (migration `0120_b_floating.sql`), set through the
Firewall page or `/api/firewall/...`, and rendered by `patronus-firewall`.

## Floating rules

A rule with `floating: true` names `interfaces` (device names, `@role`
tokens or `group:NAME`) and a `direction` (`in`, `out`, `any`) instead of one
interface and one chain.

- `in` renders on the input and forward chains with `iifname`, `out` on the
  output and forward chains with `oifname`, `any` renders both.
- No interface listed = every interface.
- **Quick** (default): the rule is evaluated before every interface rule, the
  first match wins. **Not quick**: the rule is evaluated after the interface
  rules, so an interface rule that matches takes precedence. nftables has no
  "last match wins" evaluation, so this ordering is how Patronus models pf's
  non-quick rules; the position of a floating rule in the list does not matter,
  the quick setting decides.
- The anti-lockout system rules always come first.
- A floating rule whose interfaces are all unassigned roles, or that names a
  group that does not exist, is skipped with a warning and never widened.

## Interface groups

`POST /api/firewall/interface-groups {"name", "members": ["eth1", "@lan"]}`.
A group renders as the nft set `ifgrp_<name>` (`type ifname`). A rule uses it
as its interface (`group:NAME`) or inside a floating rule's interface list.
Changing a group's members swaps the set elements live (one nft transaction, no
ruleset reload); a rule is never edited. A group that a rule uses cannot be
deleted. Members given as `@role` follow the role assignment at apply time.

## Per-rule state limits (pass rules only)

| Field | Meaning | nft |
|---|---|---|
| `max_states` | most open connections of the rule, all sources | `ct state new ct count over N drop` |
| `max_src_conn` | most simultaneous connections per source | dynamic set + `ct count over N` |
| `max_src_rate` per `max_src_rate_secs` | new connections per source | dynamic set + `limit rate over` |
| `overload` (+ `overload_secs`) | a source over the rate is added to this table | `ov_<name>_v4/_v6` set with a timeout |

Connections over a limit are dropped (pf falls through to later rules; dropping
is the fail-closed choice). A source in an overload table is dropped on the
interfaces and chain of the rule that fed it until the entry times out
(default one hour) or is released: `GET /api/firewall/overload` lists the
tables with their sources and seconds left, `DELETE /api/firewall/overload/NAME`
releases all, `DELETE /api/firewall/overload/NAME/ADDRESS` one source. Limits
on a drop/reject rule are refused (400).

## Limiters

`PUT /api/firewall/limiters/NAME {"rate_kbit", "burst_kb", "per_source"}`; a
rule names one in `limiter`. A limiter caps the data rate of the traffic the
rule matches, for each source address (`per_source`) or for all of it together.
It renders into a `lim_<hook>` chain at priority -10 so established flows are
counted too (the normal chains accept established traffic early). The burst
is at least 70 kB so a 64 kB GSO packet fits; a smaller bucket makes TCP crawl.
A limiter that a rule uses cannot be deleted.

## Categories

`category` is a label (letters, digits, space, `_-.`; at most 40) shown in the
rules table; `GET /api/firewall/categories` lists the names with their rule
counts.

## Log views

The Logs tab summarises the displayed lines (busiest sources, destination
ports and rules, blocked vs passed) with a "Block this source" button per
source; "Pass this" prefills a rule for review. Nothing is saved until you
press Save, and a pass draft says that it does not restrict the source port.

## Tiers

Standard tier: all of it. Embedded router tier (ax1800): the same renderer is
compiled into the router image, the QEMU gate checks that a floating rule, a
group and a limiter render and load.
