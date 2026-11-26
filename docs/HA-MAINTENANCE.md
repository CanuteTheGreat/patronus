# HA maintenance mode and configuration sync (lane G)

Code: `crates/patronus-network/src/ha.rs` (VRRP, settings), `ha_maint.rs` (the hand-off procedure),
`crates/patronus-web/src/state/ha_maint.rs` (wiring), netlab `ci/netlab/ha-services-test.sh` (claim C87).

## Maintenance mode is a confirmed hand-off

`POST /api/ha/maintenance {"enabled": true, "force": false}`:

1. **Peer check.** The peer is watched for `ha.peer_check_secs` (default 4 s). It must prove it is alive:
   VRRP adverts keep arriving (this node is BACKUP), or the conntrackd sync channel receives packets
   (state sync on), or - unicast peer, this node MASTER - the peer's web port answers. With state sync on,
   a silent sync channel is a refusal too (established connections would be cut). If nothing can be
   proven the answer is HTTP 400 with the reasons; `force: true` skips the check and the wait.
2. **Lower the priority** (`ha.maintenance`, advertised priority 1).
3. **Wait** up to `ha.handoff_timeout` (default 60 s) until this node is BACKUP and carries none of the
   carp virtual IPs. Progress: `GET /api/ha/maintenance` (phase, virtual IPs left, message), the banner on
   the HA page, and `ha_maintenance` events in the event log. On timeout the priority is put back and
   the answer is an error: no half hand-over is left behind.
4. `{"enabled": false}` restores the priority and waits (`ha.rejoin_timeout`, default 300 s) until the node
   is serving again and its peer is visible.

## Automatic maintenance

With `ha.auto_maintenance` on (default), these actions on an HA node enter maintenance first
(refused with HTTP 409 and the reasons when the peer is not healthy; `?force=true` overrides):
firmware install, package update (`updates/apply`), reboot, shutdown.
After a reboot or firmware install the node comes back with `ha.maintenance_auto` set and leaves
maintenance by itself once healthy (at web start); after a package update the job's end triggers it. If the
action itself fails the node leaves maintenance at once.

## Settings (typed, `ha.*` in the store, API `PUT /api/ha/settings`, HA page)

| key | default | range |
| --- | --- | --- |
| `ha.auto_maintenance` | on | |
| `ha.handoff_timeout` | 60 | 5-3600 s |
| `ha.peer_check_secs` | 4 | 2-60 s |
| `ha.rejoin_timeout` | 300 | 10-3600 s |

keepalived writes its counters to `/run/patronus/keepalived.stats` (SIGUSR2); `conntrackd -s network` gives the sync counters.
Note: a peer configured with `nopreempt` does not take over from a MASTER that merely lowers its priority;
use preemption on HA pairs that use maintenance mode (the default).

## Configuration sync (phase 2, claim C88)

One node is the **source** (`ha.cfgsync.push`), the other the **target** (`ha.cfgsync.accept`); a node is
never both. The source looks every `ha.cfgsync.check_secs` (default 20 s) whether the switched-on
sections changed and pushes them to `POST /api/ha/sync/receive` on the target.

- **Sections** (one switch each, `ha.cfgsync.section.<name>`, all on by default): `firewall` (rules + the
  `firewall.*` settings), `aliases`, `schedules`, `nat`, `dhcp`, `dns`, `vpn` (WireGuard, IPsec, OpenVPN, L2TP).
  Interfaces, addresses, accounts, API keys, TLS and the `ha.*` keys are never sent. Interface device names in the rows
  travel as roles (`@wan`, `@lan`, `@opt1`) so the target resolves them on its own devices.
- **Transport.** curl over HTTPS to `ha.cfgsync.peer_url` (default `https://<ha.peer>`), the target's TLS public key
  pinned (`ha.cfgsync.peer_pin`, `sha256//...`, shown on the target's HA page): the API key
  (`ha.cfgsync.api_key`, an *operator* key made on the target, write-only in the API) is never sent to a server whose key
  does not match. Key and body go to curl on stdin, never on a command line.
- **Target.** Merges the sections into its own configuration, applies it through the normal appliers
  (`SystemManager::restore`: a revision "HA sync from <source>" is kept, the previous configuration is put back and
  re-applied when an applier refuses) and answers with the result. An unchanged push is acknowledged without
  applying anything.
- **Reporting.** Every push / receive is a row in `ha_sync_history` (measured data: not exported, pruned to
  `ha.cfgsync.history_keep` rows) and an `ha_sync` event. The source's HA page shows the last failure with the target's
  own reason; a failed push is retried after `ha.cfgsync.retry_secs`.
- **Not synced yet** (pfSense/OPNsense do): users and groups, authentication servers, certificates, traffic shaper,
  captive portal, wake-on-LAN, static routes, virtual IPs.

Typed settings: `ha.cfgsync.{push,accept,peer_url,peer_pin,api_key,check_secs (5-3600),retry_secs (10-3600),timeout_secs (5-600),history_keep (10-10000)}`.
