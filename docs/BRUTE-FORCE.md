# Brute-force protection

Patronus bans addresses that keep guessing passwords, the job sshguard, fail2ban
or a CrowdSec bouncer does on other firewalls. It is built in (USE=bruteforce,
on by default in the package; no extra daemon), cheap enough for small boxes,
and **off until you turn it on** (Security > Brute-force protection, or
`patronus guard set enabled=1`).

## What is counted

| Source | Where the failures come from |
|---|---|
| `sshd` (OpenSSH) | `Failed password ...`, `Failed keyboard-interactive/pam ...`, `maximum authentication attempts exceeded ...` |
| `dropbear` | `Bad password attempt for ...`, `Login attempt for nonexistent user ...` |
| `web` | every refused login of the web UI (wrong password, wrong two-factor code) |

SSH messages are read from the system log: on systemd hosts the journal
(`journalctl -f`, tags `sshd`, `sshd-session`, `sshd-auth`, `dropbear`), on other
hosts the first of `/var/log/auth.log`, `/var/log/secure`, `/var/log/messages`
that exists. `guard.log_files` names other files (for an sshd started with
`-E FILE`, say). Only lines tagged by an SSH daemon count, and the address is
read from the end of the message where sshd/dropbear put it, so a crafted user
name (`root from 192.0.2.1`) cannot get another address banned. A failed public
key does not count (every client with several keys produces one), and the
`Invalid user` line sshd writes before the `Failed password` of the same guess is
not counted twice.

## When an address is banned

An address that fails `guard.max_failures` times (default 5) within
`guard.find_secs` (600 s) is banned for `guard.ban_secs` (900 s). With
`guard.escalate` (on) every further ban of the same address within
`guard.escalate_window_secs` (1 day) doubles, up to `guard.ban_max_secs` (1 day).
IPv6 sources are banned as their `/guard.ipv6_prefix` network (default /64: one
host trivially owns a whole /64).

Never banned: loopback, the allow list `guard.allowlist` (addresses and
networks) and, while `guard.exempt_lan` is on (the default), every subnet of the
router's LAN/OPT interfaces, so a mistyped password can not lock the
administrator out of the box he sits next to. Turn it off to protect the router
from devices on its own networks too.

## Enforcement

An own nftables table `inet patronus_guard` with two sets, `ban4`
(`flags timeout`) and `ban6` (`flags interval, timeout`), and input and forward
chains at hook priority -20 (ahead of every other Patronus table) that drop
everything from a banned source: traffic to the router and through it, port
forwards included. The kernel expires each element by itself. The store
(`guard_bans`) is the source of truth: every change rewrites both sets in one
atomic `nft -f`, `patronus apply` rebuilds the table at boot with the remaining
time of each ban, and the table survives every firewall re-apply.

The engine runs in `patronus applyd` (root); without applyd (a container image)
patronus-web runs it. It checks every `guard.tick_secs` (2 s).

## Settings

All are `guard.*` keys in the configuration (exported, versioned, rolled back
like every other setting), changed through the page, `PUT /api/guard/settings`
or `patronus guard set KEY=VALUE ...`:

| Key | Default | |
|---|---|---|
| `enabled` | `0` | protection on/off |
| `sources` | `sshd,dropbear,web` | what is counted |
| `max_failures` | `5` | failures before a ban (1-1000) |
| `find_secs` | `600` | counting window |
| `ban_secs` | `900` | first ban |
| `ban_max_secs` | `86400` | longest ban |
| `escalate` | `1` | double each repeat ban |
| `escalate_window_secs` | `86400` | how long earlier bans count |
| `exempt_lan` | `1` | never ban the router's own LAN/OPT subnets |
| `allowlist` | empty | addresses/networks never banned |
| `ipv6_prefix` | `64` | IPv6 ban size (32-128) |
| `log_files` | `auto` | SSH log files to follow |
| `journal` | `auto` | read the journal: `auto` (systemd, no explicit files), `on`, `off` |
| `history_days` / `history_max_rows` | `30` / `5000` | ban history retention |
| `tick_secs` | `2` | check interval |

The ban history, counted failures and the web UI's reports (`guard_bans`,
`guard_failures`, `guard_reports`) are measured data: backups, restores and
rollbacks neither carry nor rewind them.

## API and CLI

- `GET /api/guard`: settings, defaults, active bans, addresses being counted, history, kernel state
- `PUT /api/guard/settings`: partial settings; refused with 400 when invalid, undone when the kernel refuses them
- `POST /api/guard/bans` `{address, secs?, reason?}`: ban by hand (`secs` omitted = until lifted)
- `DELETE /api/guard/bans?address=ADDR`: lift a ban (address or IPv6 prefix)
- `GET /api/guard/history?limit=N`
- `patronus guard status [--json] | ban ADDR [--secs N] [--reason T] | unban ADDR | set KEY=VALUE ...`

## Tiers

The standard tier builds it by default. Router-tier images (embedded) do not
carry it yet; their System page lists it under "Not available on this device".

## Proof

`ci/netlab/lane-b-guard.sh`: real sshd password failures and real web UI login
failures ban the client (kernel set, drop counter, the client reaches nothing),
the LAN exemption, a switched-off source, unban, repeat-offender doubling, a
manual IPv6 /64 ban, bans across a reboot, and turning it off removing the
table. Unit tests in `crates/patronus-firewall/src/guard.rs` cover the log
formats, injection attempts, thresholds, windows, escalation and settings
validation.
