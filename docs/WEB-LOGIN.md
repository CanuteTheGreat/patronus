# Web UI login = system users

The Patronus web UI has no account set of its own and no built-in `admin`
or default password. You sign in with a **system user** of the box
(the same model as Proxmox's PAM realm); rights come from group membership
(`/etc/patronus/web-auth.toml`):

| System group                    | Web role   |
|---------------------------------|------------|
| `patronus-admin`, `wheel`       | admin      |
| `operator_groups` (empty)       | operator   |
| `readonly_groups` (empty)       | read-only  |
| none of them                    | refused    |

The highest role wins. `root` is refused unless `allow_root = true`.
Create the group once (`groupadd -r patronus-admin`) and add users with
`usermod -aG patronus-admin <user>`; the live installer creates the first
administrator for you. A system user's password is changed on the system
(`passwd`), not in the web UI.

## How the password is checked

The web UI runs unprivileged, so the check runs as root in
`patronus applyd` (new `auth` op on its Unix socket; passwords are never
logged). Mechanisms, in `patronus_network::sysauth`:

* **PAM** (full Linux tier): libpam is loaded at run time (no link-time
  dependency), service `patronus` (`/etc/pam.d/patronus`, mirrors the
  system login: lockout, expiry and `pam_faillock` apply). Groups come from
  NSS (`getgrouplist`).
* **Shadow files** (embedded MIPS / OpenWrt-style tier, no PAM): pure Rust
  over `/etc/passwd`, `/etc/group`, `/etc/shadow`. Verifies md5-crypt
  (`$1$`, busybox), sha256/512-crypt (`$5$`/`$6$`) and bcrypt. Locked
  (`!`, `*`), empty and expired accounts never verify; yescrypt (`$y$`)
  fails closed (use PAM there). `PATRONUS_AUTH_ETC` points the same code
  at another directory.
* **Container image** (no root broker): accounts are passwd/group/shadow
  files in `/var/lib/patronus/auth`; add one with
  `echo 'a-long-password' | patronus users add-local-account alice`.
  `PATRONUS_ADMIN_PASSWORD` (+ `PATRONUS_ADMIN_USER`, default `admin`)
  seeds one at start for CI/headless use; never set by default.

## Failure behaviour

Wrong password, unknown user, locked account, no group, root, an
unreachable broker: the same `401` after the same minimum time (4 s), a
per-address throttle, a per-name back-off (5 failures), and an audit row
(`login`, `login_failed` with the reason) plus a log line. The reason
never reaches the client.

## Migration (one release)

Accounts created by older releases (own password stored in Patronus) can
still sign in but **read-only** (audit warning each time). The first
system administrator who signs in retires the old built-in `admin`.
`legacy_local_login = false` ends it immediately. Directory (LDAP/RADIUS)
users are unchanged.
