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

The size of the per-source tables and the default overload timeout are
settings (`GET/PUT /api/firewall/limit-settings`, keys `firewall.limit_set_size`
default 65535 and `firewall.overload_secs` default 3600; Groups & limiters tab,
"Limit tables"). A rule's own `overload_secs` wins.

## Kernel capabilities

Connection counting (`nft_connlimit`) and rate limiting (`nft_limit`) are
probed once with `nft -c` (`GET /api/firewall/capabilities`). On a kernel
without one (the Slate image has no connection counting) a rule that needs it
is refused with the reason (400), the page greys out those fields with the
reason, and a stored rule that needs it is skipped with a warning when the
ruleset is rendered, instead of failing the whole load.

## Limiters

`PUT /api/firewall/limiters/NAME {"rate_kbit", "burst_kb", "per_source"}`; a
rule names one in `limiter`. A limiter caps the data rate of the traffic the
rule matches, for each source address (`per_source`) or for all of it together.
It renders into a `lim_<hook>` chain at priority -10 so established flows are
counted too (the normal chains accept established traffic early). The burst
is at least 70 kB so a 64 kB GSO packet fits; a smaller bucket makes TCP crawl.
A limiter that a rule uses cannot be deleted.

## Security notes

- Every name that reaches an nft script is validated: interface names (at most
  15 characters, no quotes), group, limiter and overload names (a letter, then
  letters, digits or `_`), numbers are typed. A category is only a label and
  never reaches nft. Values read back from the store are validated again when
  the ruleset is rendered.
- A pass rule that cannot be rendered is skipped with a warning (never widened);
  a block rule that cannot be rendered (for example one on a group that no
  longer exists) refuses the whole ruleset, as every other block rule does.
- Quick floating rules never come before the anti-lockout system rules.
  Limiters apply to forwarded and outgoing traffic only: their chain runs
  before the anti-lockout rule, so a limiter on traffic for the router itself
  is refused. A source in an overload table is dropped on the interfaces of the
  rule that fed it, after the system rules.
- An overload table keys on the source address, so a source that can spoof
  addresses (TCP SYNs from the WAN) could get a victim's address blocked until
  its entry times out. Use overload tables on rules for networks you control
  (LAN, VPN), keep the WAN source checks on, keep the timeout short, and release
  an entry from the page when needed.
- Group changes, limiter changes, overload releases, limit settings and rule
  changes are recorded as configuration revisions and in the audit log.

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
