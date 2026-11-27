# TFTP server (USE=tftp)

A built-in TFTP server for network boot (PXE/iPXE boot loaders, kernels, answer
files), firmware and configuration transfers for devices that speak nothing else
(IP phones, switches, access points, embedded boards). It is the Patronus
equivalent of the TFTP packages of pfSense and OPNsense and of OpenWrt's dnsmasq
TFTP. Read only by default.

* Page: **Services -> TFTP server** (`/svc/tftp`, API `/api/svc/tftp`).
* CLI: `patronus tftp show` prints the configuration the stored settings resolve
  to; `patronus tftp run --conf FILE` is the daemon (below).
* Settings (all typed, in the declarative configuration, export/import/GitOps and
  rollback cover them; defaults in brackets):
  `enabled` (off), `interfaces` (`@lan`), `port` (69), `root`
  (`/var/lib/patronus/tftp`), `allow_write` (off), `overwrite` (off),
  `max_write_kb` (16384), `blksize_max` (1468), `timeout` (5 s), `retries` (5),
  `max_sessions` (16), `data_ports` (`49152-49407`), `run_as` (`nobody`),
  `ui_upload_kb` (1024).
* Client networks (table `tftp_clients`): IPv4 networks that may use the server.
  With none listed, every client on the serving interfaces may. The firewall rule
  is limited to the same networks.
* File manager on the page and in the API (`POST /api/svc/tftp/action/files`,
  `upload` with `{name, data: base64, overwrite}`, `delete` with `{name}`). The
  page takes files up to `ui_upload_kb`; bigger ones are copied into the root
  directory. Names are letters, digits and `. _ + -` in up to three parts.

## Protocol

RFC 1350 over IPv4 with the option extensions of RFC 2347/2348/2349: `blksize`
(clamped to `blksize_max`), `timeout`, `tsize` (answered for reads, checked
against `max_write_kb` for writes). Binary (`octet`) mode only; `netascii` and
`mail` are answered with "illegal operation". Unknown options are ignored (the
extension allows it), so a client that sends `windowsize` gets a plain transfer.
A transfer continues from a fresh UDP port of the `data_ports` range on both
sides; a packet from any other port gets ERROR 5. IPv6 is not served.

## Safety (TFTP has no login)

* **Read only** until `allow_write` is switched on. An upload creates new files
  only unless `overwrite` is on, is written to a hidden `.NAME.part` file,
  published atomically after the last block (the client sees success only for a
  stored file), capped by `max_write_kb`, and removed again when it fails.
* **A jail, not a filter:** every name is resolved *beneath* the root with
  `openat2(2)` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`)
  against a directory descriptor opened before privileges are dropped. `..`,
  absolute names, symlinks (file or directory) and hidden names (a leading dot)
  are refused, and only regular files are served (no FIFO, device or directory).
  The kernel must be 5.6 or newer (`patronus tftp run` says so otherwise).
* **Unprivileged:** the daemon drops to `run_as` (default `nobody`) after
  binding, keeping only `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW` (late binds when
  an interface address appears, `SO_BINDTODEVICE`) and sets no-new-privileges.
* **Scoped:** it listens on the IPv4 addresses of the chosen interfaces, bound to
  the device, and re-reads them every two seconds. The firewall opens the
  request port and the data range on those interfaces only
  (`patronus-firewall/src/svc_rules.rs`). `max_sessions` bounds concurrent
  transfers (further requests get "Server busy").
* The root must be below `/var/lib`, `/srv`, `/mnt`, `/media`, `/opt` or be
  `/tftpboot`; the Patronus state directory (configuration database, keys) is
  refused (`/var/lib/patronus/tftp` is the one allowed place under it).

When Patronus creates the default root it is owned by the web account (uploads
from the page) and grouped with the `run_as` account (the server), mode 0775;
files are created 0644 so the unprivileged server can read them.

## How it runs

`patronus tftp run --conf /var/lib/patronus/net/tftp.json --stats <run dir>/tftp.stats`,
supervised as `patronus-daemon@tftp` (OpenRC `patronus-daemon.tftp`, systemd
`patronus-daemon@tftp.service`), started by `patronus apply` (boot) and by every
change through the API. No extra package: the engine is in the `patronus` binary
(USE flag `tftp` of `net-firewall/patronus`, on in the live image's default
feature set). Counters and the last 20 transfers are in the status card and in
`GET /api/svc/tftp` (`status.stats`).

## Proof

* Unit tests (`patronus-network/src/tftp.rs`): protocol parsing and option
  negotiation, name checks, settings validation, the file manager, and the engine
  over real UDP on loopback (read sizes around block boundaries, option
  negotiation, retransmission, jail escapes, symlinks, FIFOs, uploads, size cap,
  client networks, busy server, wrong transfer ID).
* Firewall rule test: `tftp_opens_request_and_data_ports_on_the_serving_interfaces_only`.
* Netlab `ci/netlab/lane-j-tftp.sh`: curl and tftp-hpa on a LAN client against the
  shipped daemon, with the second segment (OPT1) refused; `lane-j-tftp-ui.sh`: the
  page in Firefox, driven through to a real fetch; accessibility of the page at
  desktop and phone width, light and dark, is in `ci/a11y`.
