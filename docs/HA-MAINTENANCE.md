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
