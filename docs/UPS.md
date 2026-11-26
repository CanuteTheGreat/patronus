# UPS monitoring and clean shutdown (USE=ups, claim C160)

Patronus watches an uninterruptible power supply through NUT (Network UPS
Tools, `sys-power/nut`), shows it on a status card, raises events when the
mains power fails and returns, and stops the router cleanly before the
battery runs out. Every NUT config file is rendered by Patronus from typed
settings; nothing is written to `/etc/nut`.

## Settings (Services > UPS, `/api/svc/ups`, declarative `ups.*` keys)

| key | default | meaning |
| --- | --- | --- |
| `enabled` | off | the feature switch; nothing runs while it is off |
| `mode` | `standalone` | `standalone` (upsd on loopback), `netserver` (also shares the UPS with the LAN), `netclient` (follow another NUT server) |
| `driver` | `usbhid-ups` | `usbhid-ups`, `snmp-ups`, `apcsmart`, `dummy-ups` (scripted UPS for tests) |
| `ups_name`, `port` | `ups`, `auto` | name clients use (`ups@router`); USB auto, serial device, or the `.dev` script of dummy-ups |
| `snmp_host`, `snmp_community`, `snmp_version` | none, none, `v2c` | snmp-ups only; the community is a secret and never returned |
| `server`, `server_port` | none, 3493 | netclient only |
| `listen_iface`, `listen_port` | `@lan`, 3493 | netserver only: upsd listens on that interface's own addresses, never on `0.0.0.0` |
| `monitor_user`, `monitor_password` | `patronus-mon`, generated | secret, never returned by the API |
| `shutdown_policy` | `on_low_battery` | `on_low_battery` (NUT's LB flag), `after_on_battery` (after `shutdown_after_secs`, default 300) or `charge_below` (`shutdown_charge_pct`, default 20; usbhid-ups only) |
| `shutdown_command` | `/usr/bin/patronus poweroff-request` | what upsmon runs; absolute program and plain arguments only. Tests point it at a script that writes a marker file |
| `poll_secs`, `retention_days` | 5, 30 | status poll interval; history retention |
| `run_user` | `nut` | the unprivileged account the NUT daemons run as |

The daemons run under the Patronus supervisor (`patronus-daemon@nut-driver`,
`nut-upsd`, `nut-upsmon`) on OpenRC and systemd alike.

## Status API and card

- `GET /api/v1/ups` (alias `GET /api/ups`): `{enabled, installed, mode, ups_name, state, reading, message, events}`.
  `state` is `online`, `on_battery`, `low_battery` or `unknown`; `reading` holds charge, runtime, load, input/output/battery
  voltage, model and the raw flags (`OL OB LB RB CHRG DISCHRG`). With the feature off, NUT missing or no UPS answering,
  `reading` is null and `message` says why (honest empty state).
- `GET /api/v1/ups/history?hours=24&limit=2000`: samples from `ups_samples` (one a minute while steady, one per poll during an outage).
- The card (`templates/ups_card.html`) is a self-contained partial that fetches the API. It is shown on the UPS page and is the
  piece the dashboard widget registry embeds.

## Events

`ups_on_battery` (warning), `ups_low_battery` (critical), `ups_online`, `ups_replace_battery`, `ups_unreachable` and
`ups_reachable` go through the normal event log and the notification matchers and webhooks. Each is raised once per change; the
first look after boot only reports a problem.

## Clean stop at low battery

upsmon runs `SHUTDOWNCMD` when the policy fires. The default, `patronus poweroff-request`, asks the init system for an ordered
power-off (OpenRC `poweroff`, systemd `systemctl poweroff`). The netlab replaces the command by a marker script and asserts the
marker appears exactly when the low-battery state is reached and not before. CI never powers anything off.

## Sharing the UPS with LAN hosts (`netserver`)

upsd listens on the LAN interface's own addresses on port 3493 and the firewall accepts that port from the LAN interface only;
the WAN neither listens nor accepts. A LAN host runs `upsc ups@<router>` or points its own upsmon at the router with the monitor
user and password.

## Tiers

Standard (Gentoo) tier: the `ups` USE flag pulls `sys-power/nut[usb,snmp,serial]`; the Packages page can also install the
component. The embedded router tier (access points, Slate) has no NUT: the feature is absent and the System page says "not
included in this router-tier image". `ci/check-image-ebuild-parity.sh` checks that the real ebuild, the Packages catalog and
the image agree on the NUT package.

## Proof

Unit tests on captured `upsc` output (`crates/patronus-network/tests/fixtures/ups/`), the firewall rule test, the web recorder
tests, and `ci/netlab/lane-u-ups.sh` (NUT `dummy-ups` stepping online, on battery, low battery).
