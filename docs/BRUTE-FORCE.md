# Brute-force protection

Patronus bans addresses that keep guessing passwords, the job sshguard, fail2ban
or a CrowdSec bouncer does on other firewalls. It is built in (USE=bruteforce,
on by default in the package; no extra daemon), cheap enough for small boxes,
and **off until you turn it on** (Security > Brute-force protection, or
`patronus guard set enabled=1`).

## What is counted

| Source | Where the failures come from |
|---|---|
| `sshd` (OpenSSH) | `Failed password ...`, `Failed keyboard-interactive/pam ...`, `maximum authentication attempts exceeded ...`, and (OpenSSH 9.8+) `drop connection ... penalty: failed authentication`: with `PerSourcePenalties` (the default since 9.8) sshd refuses a guesser's next connections before they reach the password prompt, so after the first `Failed password` the further guesses show up only as these lines |
| `dropbear` | `Bad password attempt for ...`, `Login attempt for nonexistent user ...` |
| `web` | every refused login of the web UI (wrong password, wrong two-factor code) |
| `openvpn` | the OpenVPN server's `VERIFY ERROR` (a client certificate the CA did not sign) and `Auth Username/Password verification failed` |
| `strongswan` | IKEv2 logins strongSwan refused: `generating IKE_AUTH response ... N(AUTH_FAILED)` (wrong pre-shared key, unknown certificate) and `EAP-MS-CHAPv2 verification failed` (wrong password), each one a guess |
| `ids` | (off by default) alerts of the intrusion-detection engine from one source address, at or above a severity: see "IDS source" |

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

### VPN sources

Only failures that need a round trip with the peer count, so the address cannot be
forged by one UDP packet from a victim's address: OpenVPN timeouts, `tls-crypt
unwrapping failed` and HMAC failures are logged by the server but never counted;
strongSwan's refusals come after the IKE_SA_INIT exchange (the peer had to read the
reply). The address of a strongSwan failure is the one charon logged itself in the
`<name|id> received packet: from <ip>[<port>]` line of the same IKE_SA, matched by
the SA's id, so interleaved logins of several peers are never mixed up; an SA with no
such line (charon restarted in between) blames nobody.

OpenVPN's output is read from the file the daemon supervisor writes it to
(`<run dir>/patronus-daemon.openvpn-server.log`, `guard.openvpn_log` = `auto`), or
from `guard.openvpn_log`, whatever the init system. strongSwan is read from the same
system log as SSH (the journal tags `charon` / `charon-systemd`, the syslog files), at
charon's default log level. A VPN daemon of your own that logs under another syslog
name (`--syslog NAME`) is added with `guard.log_tags`. A line counts only when it is
written by the VPN daemon (an anchored prefix: empty, a timestamp, or a syslog tag
that is the daemon's), so text another program or a user name repeats cannot get an
address banned.

### IDS source

With `ids` among the sources, an address the intrusion-detection engine keeps alerting
on is banned like a password guesser. The guard reads the engine's alert history
(`ids_alerts`); alerts that were already there when the protection started are history
and count as nothing. An alert counts when its severity is `guard.ids_severity` or more
serious (1 = high .. 4 = informational; default 1) and, with `guard.ids_action` =
`blocked`, only when the IPS dropped the packet (`any` counts every alert, default).
`guard.ids_max_alerts` (default 10) counted alerts within `guard.find_secs` ban the
source. The router's own addresses are never banned and the usual exemptions apply, so
an alert caused by a LAN device does not ban it while the LAN exemption is on. The
source is only useful with the engine running (USE=intrusion-detection); without the
history table there is nothing to read and nothing happens.

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
| `sources` | `sshd,dropbear,web,openvpn,strongswan` | what is counted (`ids` is added by hand) |
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
| `openvpn_log` | `auto` | OpenVPN server output: the supervisor's file or an absolute path |
| `log_tags` | empty | extra syslog names of VPN daemons whose lines may count |
| `journal` | `auto` | read the journal: `auto` (systemd, no explicit files), `on`, `off` |
| `ids_severity` / `ids_action` / `ids_max_alerts` | `1` / `any` / `10` | IDS source: severity (1-4), `any` or `blocked`, alerts before a ban (1-100000) |
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
  (`patronus` is the standard tier's link to `patronus-cli`; the router images ship only `patronus-cli`, so there it is
  `patronus-cli guard ...`)

## Tiers

The standard tier builds it by default. The router tier carries it too, on both
images: the AX1800 access points (aarch64) and the Slate (MIPS). Dropbear is the SSH
server there; its failures go through the busybox syslog into `/var/log/messages`,
which `guard.log_files = auto` follows (no journal on the OpenRC variant). The
engine is part of the multi-call binary (`bruteforce` in the image's `FEATURES=`),
off until switched on, and costs:

| Image | What it costs |
|---|---|
| AX1800 access point, release build (aarch64 musl, the CI recipe) | binary 16,048,944 -> 16,311,328 bytes (+262,384, +1.6 %); xz-compressed 5,823,408 -> 5,891,964 (+68,556) |
| Slate, release build (mips musl, size-optimised, the CI recipe) | binary 15,189,872 -> 15,321,084 bytes (+131,212, +0.9 %); xz-compressed 4,110,180 -> 4,148,504 (+38,324) |
| any router image, guard on | measured by the QEMU gates as `GATEMETRIC guard_applyd_rss_*` (applyd resident memory before and with a ban) |

The IDS source is for the standard tier (the router tier has no IDS engine) and the
System page of a router image lists it under "Not available on this device".

## Proof

`ci/netlab/lane-b-guard-vpn.sh`: a real OpenVPN client with a certificate from another CA
(refused, banned, even the legitimate profile cannot connect from that address until the
unban), tls-crypt failures in the server log that are not counted, a real strongSwan road
warrior with wrong EAP passwords (attributed to its address through the IKE_SA, banned, the
right password does not get in while banned and does after the unban), and successful
logins that count as nothing. The unit tests parse the real logs of OpenVPN 2.6 and 2.7 (2.7 writes the
transport in front of the peer: `udp4:198.51.100.10:45905`), OpenSSH 10.2 (`sshd -E`, CRLF line ends, penalty
lines) and strongSwan 6.0 (`crates/patronus-firewall/tests/fixtures/`) and the forged-line attempts.

`ci/netlab/lane-b-guard.sh`: real sshd password failures and real web UI login
failures ban the client (kernel set, drop counter, the client reaches nothing),
the LAN exemption, a switched-off source, unban, repeat-offender doubling, a
manual IPv6 /64 ban, bans across a reboot, and turning it off removing the
table. Unit tests in `crates/patronus-firewall/src/guard.rs` cover the log
formats, injection attempts, thresholds, windows, escalation and settings
validation.

Router tier: the AX1800 gate (`ci/embedded-aarch64/ax1800/qemu-gate.sh`) and the
Slate gate (`ci/embedded-mips/slate/qemu-gate.py`) boot the real image under QEMU
and make four real failed Dropbear logins from a second network: the attacker's
address lands in the kernel set, its packets are dropped, the control channel is not
touched and an unban gives access back. The IDS source has unit tests against a
real alert history (`ids_alerts_ban_by_severity_apart_from_failed_logins`).
