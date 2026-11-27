# Patronus threat model

Status: **first written version, 2026-11-23, by the maintainers. It is not an independent review.** An independent review is still open (item R1 below). What this document does have is a code review done while writing it, covering five areas (web login/session/setup code, signed-image verification, firewall default policy and anti-lockout, configuration backup/restore, update feed); the two findings that review turned up are fixed (section "Review findings"). Every control named here points at the file that implements it and at the test that proves it. A control with no test is marked **UNTESTED**. `ci/check-threat-model.py` (run by CI) fails when a cited file or test no longer exists, or a row has neither a test nor an UNTESTED mark.

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).

## What is covered

Patronus ships in three tiers; all of them are Gentoo-based, with OpenRC and systemd variants.

| Tier | What it is | Where it runs |
|---|---|---|
| Standard | Full Linux router/firewall: `patronus-web` (unprivileged), `patronus applyd` (root broker), nftables, PAM logins, Portage updates | x86_64, aarch64 appliances and VMs |
| Embedded | Whole-image firmware for small access points and routers (GL-AX1800 class; MIPS tier for the GL-AR750S): shadow-file logins, flash images with a boot rollback guard | consumer router hardware |
| Installer / live ISO | The signed ISO that installs the standard tier: answer file, partitioning, first-run claim | any machine the owner boots it on |

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Router configuration (rules, NAT, routes, VLANs, segments) | SQLite store `/var/lib/patronus/config.db`, backups under `/var/lib/patronus/backups` (0600, directory 0700) | whoever can change it controls every packet |
| Administrator credentials | system accounts: PAM on the standard tier (yescrypt hashes in `/etc/shadow`), shadow files on the embedded tier; TOTP secrets and hashed recovery codes in the store; API-key digests | full control of the box |
| WireGuard, IPsec and Wi-Fi secrets | store rows and 0600 files in the state directory; never returned by the API (client configs only for peers whose key pair Patronus generated, operators and admins only) | decrypt or join the networks |
| Web session ids | process memory of `patronus-web`; cookie `session_id` (HttpOnly, SameSite=Strict, Secure over TLS) | act as an administrator for up to 24 hours |
| First-run setup code | `/run/patronus/first-run-code` (0600) and the console | claims an unconfigured router |
| DHCP leases, DNS state, firewall logs, traffic insight | daemon state and store tables | tells an attacker who and what is on the network |
| TLS private key of the web UI | `/etc/patronus/tls` (0600) | impersonate the router to its administrators |
| Release signing key (public half is on every box) | `keys/release-signing.asc`, built into the embedded firmware, installed by `sec-keys/openpgp-keys-errantsolutions` | root of trust for images, ISOs and the update feed |
| Update channel | Gentoo binary host (standard tier), signed image feed and uploaded images (embedded tier), published ISOs | code that runs as root on every box |

## Actors

1. Unauthenticated attacker on the WAN (the internet).
2. Unauthenticated attacker on a LAN, guest, quarantine or Wi-Fi segment.
3. Authenticated low-privilege user (read-only or operator role, an API key, an RBAC group).
4. A compromised or hostile device inside a segment (a camera, a guest phone).
5. Network attacker between the router and its update or backup servers.
6. Supply-chain attacker (binary host, feed host, ISO mirror).
7. Someone with brief physical access (console, USB stick, power).
8. A rogue neighbour access point (embedded tier, over the air).

Out of scope: a malicious administrator (administrators are fully trusted: the API can reconfigure the whole box by design), malicious hardware or firmware below Patronus, volumetric denial of service, and a guest owner attacking their own device.

## Trust boundaries

| # | Boundary | What crosses it |
|---|---|---|
| B1 | WAN to router | all inbound internet traffic; DHCP/DHCPv6 replies from the ISP |
| B2 | LAN to router management | HTTPS on 443 (HTTP on 80 only redirects), SSH on 22, DHCP, DNS |
| B3 | Guest, quarantine and other segments to the LAN and to the router | forwarded traffic, DHCP/DNS to the router |
| B4 | Browser/API client to the web UI | login, session cookie, API keys, JSON and form bodies, the first-run claim |
| B5 | SSH client to the managed sshd | keys signed by the trusted user CA |
| B6 | Update sources to the box | the signed firmware feed, uploaded images, Portage binary packages, the ISO |
| B7 | Backup files and remote backup targets | the full configuration, including secrets |
| B8 | Optional remote management (an outbound client of an operator-run service) | commands and telemetry |
| B9 | Access point to access point (over the air, embedded tier) | beacons and scan results used for channel coordination |
| B10 | Installer media and first boot | the ISO, the answer file, the first-run claim |

## Threats and controls (STRIDE per boundary)

Letters: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege. The last column names the test that proves the control; **UNTESTED** means no automated test covers it.

### B1 WAN to router

| # | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T1 | E | Inbound connection to a management service from the internet | Base ruleset has `policy drop` on input and forward; only established/related, loopback, ICMP and DHCPv6 replies are accepted (`crates/patronus-firewall/src/nftables.rs`, `base_table_script`). Anti-lockout opens SSH and the web UI on the LAN role only. | `ci/netlab/lane-a-foundation.sh` (WAN to router SSH dropped, anti-lockout not open on the WAN) |
| T2 | S | Spoofed private or bogon sources on the WAN | Optional "block private/bogon networks" rules on the WAN; off by default so a lab ISP behind NAT keeps working. | `ci/netlab/lane-b-wanguard.sh` |
| T3 | T | A rule value breaks out of its nft operand (ruleset injection) | Addresses, interface names and MACs are validated before they are put in an `nft -f` script. | `crates/patronus-firewall/src/nftables.rs::is_valid_address_spec_rejects_injection_payloads`, `crates/patronus-firewall/src/seg_rules.rs::hostile_input_is_rejected` |
| T4 | E | Fail-open when the stored rules cannot be applied | Apply is one atomic `nft -f`; a rejected rule leaves the old ruleset; an unreadable store at boot loads the lockdown ruleset (policy drop plus anti-lockout, no NAT, no forwarding) and, if even that fails, forwarding is switched off. | `ci/netlab/failure-atomic-apply.sh`, `crates/patronus-firewall/src/applier.rs::lockdown_renders_even_when_stored_rules_are_unreadable` |
| T5 | I | DHCPv6/RA from an attacker on the WAN side | Only DHCPv6 replies addressed to a link-local client address are accepted on input. | **UNTESTED** against a hostile server (the accept rule is covered by rendering tests only) |
| T6 | D | Management exposed on the WAN of a box with no LAN role (single-NIC router, or nothing assigned yet) | By design `@mgmt` falls back to the WAN role, then to every interface, so a box can always be reached to finish setup (finding L1). Compensating controls: login throttle and per-name back-off (T11), setup code (T24). | `crates/patronus-firewall/src/applier.rs::single_nic_box_keeps_anti_lockout_on_wan_and_skips_lan_rules` (behaviour only; the exposure itself is accepted) |

### B2, B3 LAN, guest and segment boundaries

| # | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T7 | E | Guest or quarantined device reaches the LAN or the router's management ports | Guest network and device segmentation render their own nft tables at an earlier hook priority than the main table; quarantine members forward nothing and reach the router only for DHCP/DNS/ICMP; bridge ports are isolated at layer 2 and `br_netfilter` keys are zeroed so frames between members never meet the routed policy by accident. | `ci/netlab/lane-t-guest.sh`, `ci/netlab/lane-s-segmentation.sh` |
| T8 | E | Unknown device joins the home segment | Segmentation is opt-in per segment; unbound (interface, MAC, IPv4) sources are treated as unknown and forward nothing. Wired devices behind an unmanaged switch cannot be isolated from each other (documented limit). | `ci/netlab/lane-s-segmentation.sh` |
| T9 | S | DNS rebinding or DNS bypass from a segment | DNS policy and rebinding protection in the router's resolver; plaintext DNS from restricted segments is redirected and DoT is refused. | `ci/netlab/lane-s-dns-rebind.sh`, `ci/netlab/lane-s-dns-dot.sh` |
| T10 | D | Rogue DHCP server or ARP spoofing on the LAN | Not mitigated at layer 2 beyond isolated bridge ports on segmented networks. Accepted risk (R3). | **UNTESTED** |

### B4 Web UI and API

| # | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T11 | S | Password guessing | Login is a system account (PAM, or shadow files on the embedded tier); no built-in admin or default password. Same 401 after the same minimum time for every failure; per-address throttle (5 failures per 15 minutes, IPv6 by /64, refused even with the right password while locked); per-name back-off after 5 failures; re-entering a password for own-account changes uses the same throttle; second factor (TOTP, recovery codes) is optional per account. `crates/patronus-web/src/auth.rs`, `crates/patronus-web/src/syslogin.rs`. | `crates/patronus-web/src/auth.rs::locks_out_after_max_failures_until_the_window_passes`, `crates/patronus-web/src/syslogin.rs::per_name_backoff_after_five_failures_even_for_the_right_password` |
| T12 | S | Password hash handling: locked, empty, expired or damaged accounts | Pure-Rust shadow verifier (yescrypt, sha-crypt, bcrypt, md5-crypt); locked, empty, expired and unknown accounts never verify and a damaged hash fails closed. | `crates/patronus-network/src/sysauth.rs::damaged_or_foreign_yescrypt_strings_fail_closed`, `crates/patronus-network/src/sysauth.rs::locked_empty_expired_and_unknown_accounts_never_verify` |
| T13 | S | Stolen or copied session cookie | Cookie is HttpOnly and SameSite=Strict, and Secure on every TLS listener; a session ends 24 hours after login even if it keeps being used; a restore that replaces the accounts ends every other session; logout deletes the session. No per-address binding (a cookie stolen from a LAN client works from another address): accepted, see R4. | `crates/patronus-web/src/lib.rs::the_tls_app_sets_secure_session_cookies`, `crates/patronus-web/src/auth.rs::a_session_ends_a_day_after_login_even_if_it_keeps_being_used`, `crates/patronus-web/src/routes/lane_fh_tests.rs::a_restore_that_replaces_the_accounts_ends_the_other_sessions` |
| T14 | S | Cross-site request forgery and cross-site WebSocket use | SameSite=Strict session cookie and JSON bodies (a cross-origin form post cannot set the content type). There is no separate CSRF token or Origin check, so a same-site attacker (another port or sibling name on the same host) is not stopped. | **UNTESTED** (no test posts from a foreign origin) |
| T15 | E | A low-privilege user reaches an administrator route | Every route is behind the session gate (`require_session` in `crates/patronus-web/src/routes/mod.rs`); only login, first-run and static assets are public. Administrator-only handlers take the `AdminUser` extractor; RBAC groups map to per-area privileges; API keys are read-only or operator, never administrator, and cannot reach accounts, groups, key management, backup targets or factory reset. | `ci/netlab/lane-n-rbac.sh`, `ci/netlab/lane-h-apikeys.sh` |
| T16 | I | Secrets leaving through the API | WireGuard/IPsec secrets and Wi-Fi passphrases are never returned; client configs (they carry a private key) need operator or admin; history diffs show secret columns as hidden. | `ci/netlab/lane-f-wireguard.sh`, `ci/netlab/lane-n-backup.sh` |
| T17 | S | Claiming an unconfigured router | A router with no administrator serves only `/first-run`. The claim needs a random 12-character setup code (60 bits) printed on the console and in a 0600 file, valid for one hour after the service starts, closed after 10 wrong tries; root's existing password is the alternative proof. The code is compared in constant time, a new code is made at every service start, the file is removed once the administrator exists, and the account is created in one step (a second claim is refused). | `crates/patronus-web/src/routes/first_run.rs::first_run_needs_the_setup_code_and_closes_after_wrong_tries`, `crates/patronus-web/src/routes/first_run.rs::first_run_window_expires`, `crates/patronus-web/src/routes/first_run.rs::first_run_creates_one_system_admin_and_never_ships_a_default`, `ci/netlab/journey-first-boot.sh` |
| T18 | D | Locking the owner out of first run (10 wrong codes closes the window) | Any LAN host can burn the 10 tries on a router that is still unclaimed; the owner restarts the web service (or the router) to get a new code. Accepted (L2). | **UNTESTED** as an attack; the lock itself is covered by the T17 test |
| T19 | T | HTTP interception of the login | HTTPS on 443 by default (self-generated certificate, replaceable, key 0600); HTTP on 80 only redirects. | `ci/netlab/lane-n-tls.sh`, `ci/netlab/lane-w-web-ports.sh` |
| T20 | R | Administrator denies a change | Audit log rows for login, failed login (with reason), restore, firmware and every configuration change; every change is also a configuration revision with who and what. | `ci/netlab/lane-h-system.sh` (configuration history and restore); the audit rows themselves are **UNTESTED** |

### B5 SSH

| # | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T21 | S, E | Password or unsigned-key SSH login | The managed sshd listens only on the configured address and port, accepts keys signed by the trusted user CA with the right principal, refuses passwords, and presents a CA-signed host certificate. The anti-lockout rule follows the configured port. | `ci/netlab/lane-h-ssh.sh` |

### B6 Updates and image verification

| # | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T22 | T | Unsigned, foreign-signed or modified firmware flashed (embedded tier) | `fw_check_parts` (`ci/embedded-aarch64/ax1800/overlay/usr/libexec/patronus/fwcheck.sh`) checks, before the root image is opened: the OpenPGP signature of `patronus.sha256` against the keyring built into the firmware, then sha256 of kernel and root, board, FIT and squashfs magic, UBI room. Unsigned, foreign-key and tampered images are refused; the early-boot installer re-checks the staged parts and the exact RAM copy before writing. Nothing is written to flash on a failed check. | `ci/embedded-aarch64/ax1800/tests/run.sh` (unsigned, foreign key, tampered root with remade sha256, missing keyring) |
| T23 | T | Image signed by a **revoked** release key | Finding F1, fixed 2026-11-23: gpgv prints `REVKEYSIG` followed by a normal `VALIDSIG` and exits 0 for a revoked key, so the signature was accepted. `fw_sig_ok`, the feed check (`validsig_fpr`) and the Slate kernel-slot check (`nor-kernel`) now refuse `REVKEYSIG`. | `ci/embedded-aarch64/ax1800/tests/run.sh` ("refuses an image signed by a REVOKED release key", a real revoked key), `crates/patronus-network/src/apdev.rs::feed_is_verified_before_anything_is_trusted`. The Slate path is **UNTESTED** (its test tool set has no gpgv). |
| T24 | T | Replayed or stale update feed offers an old, vulnerable build | Finding F2, fixed 2026-11-23: the signed `latest.json` must carry a valid `date`, and `feed_check` refuses a list dated before the running firmware's `BUILD_DATE`. | `crates/patronus-network/src/apdev.rs::feed_is_verified_before_anything_is_trusted` |
| T25 | T | Feed names an image that differs from the signed list, or a path outside the feed directory | Image name must be a plain `.tar` file name; size and sha256 from the signed list are checked on download and a mismatch removes the file; only then does the normal image check run. Installing stays a separate, explicit step. | `crates/patronus-network/src/apdev.rs::feed_is_verified_before_anything_is_trusted` |
| T26 | T | A bad firmware bricks the unit | The running image is kept as the rollback; the new one is trial-booted and the bootloader puts the old one back unless the health checks pass in time (`patronus-guard`). | `ci/embedded-aarch64/ax1800/qemu-gate.sh`, `ci/embedded-aarch64/ax1800/tests/run.sh` |
| T27 | T | Downgrade to an older, validly signed image by an administrator or by someone who can reach the upload page | The image check does not compare versions, so a signed older image installs (rollback is a feature). Needs an administrator session, so it is not an escalation; a later version may add a signed minimum build. Accepted (R5). | **UNTESTED** |
| T28 | T | Malicious or tampered Portage packages (standard tier) | The Gentoo binary host is configured with `verify-signature = true` (`gentoo/live-iso/common/arch/*.binrepos.conf`) and the image runs `getuto`; the web UI can only emerge atoms from a fixed component catalog (`crates/patronus-network/src/packages.rs`, `only_catalog_atoms_and_known_actions_reach_emerge`). | `crates/patronus-network/src/packages.rs::only_catalog_atoms_and_known_actions_reach_emerge`. That an installed system **rejects an unsigned binary package** has no test: **UNTESTED**. |
| T29 | T | Tampered ISO or release file | Every published file has a detached OpenPGP signature by the Errant Solutions release key plus a CycloneDX SBOM; CI refuses to publish anything it could not sign and verify (`gentoo/live-iso/common/verify-artifacts.sh`, `publish-github.sh`). | `gentoo/live-iso/common/tests/test_release_signing.py` |
| T30 | T | Vulnerable dependency or a leaked secret reaches a release | `cargo-deny` and a security audit run in `.forgejo/workflows/rust-ci.yml`; the public-leak guard (`ci/check-public-leaks.py`) blocks owner-specific material in the public repository. | `.forgejo/workflows/rust-ci.yml` (jobs `dependency-licenses`, `lint-test-audit`, `public-leak-guard`) |

### B7 Backup and restore

| # | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T31 | I | Backup file readable by another local user | Backups are written 0600 in a 0700 directory with `create_new`; the download route is administrator-only; remote backup targets can be passphrase-encrypted so the server holds no readable configuration, and their credentials are never returned. | `crates/patronus-web/src/state/system.rs::backups_are_real_files_with_real_sizes`, `ci/netlab/lane-n-backup.sh` |
| T32 | T | Path traversal through a backup name | Names must start with `patronus-config-`, end with `.json` and contain only `[A-Za-z0-9._-]` with no `..`. | `crates/patronus-web/src/state/system.rs::backup_names_cannot_escape_the_directory` |
| T33 | T, E | A crafted backup injects SQL, writes unknown tables or locks everyone out | Import accepts only tables the store already has and column names of `[A-Za-z0-9_]`, binds every value, runs in one transaction with deferred foreign keys and takes a revision first; a backup with no enabled administrator keeps the current accounts; a failed apply puts the previous configuration back; a restore that replaces accounts ends every other session. Restore needs an administrator (the account material in a backup is already administrator-level). | `ci/netlab/journey-backup-restore.sh`, `crates/patronus-web/src/routes/lane_fh_tests.rs::a_restore_that_replaces_the_accounts_ends_the_other_sessions` |
| T34 | I | Uploaded backup too large | Upload and firmware bodies have explicit size limits (`MAX_UPLOAD`, `MAX_FIRMWARE`). | **UNTESTED** (no oversize request test) |

### B8 Remote management

| # | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T35 | E | A compromised remote-management service controls every unit that enrolled in it | The client on the embedded tier is outbound-only and optional; the trust decision is the operator's. Patronus adds no inbound management port for it. This review did not audit the client or its protocol: it is a separate project with its own tests. Accepted (R6). | **UNTESTED** here |

### B9 Access point coordination

| # | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T36 | S, D | A rogue neighbour access point imitates a peer (same SSID or listed BSSID) to push a unit's channel choice | There is no controller and no authenticated AP-to-AP channel: units read scan results. A peer is accepted only by its SSID or an explicit BSSID list and a minimum signal; a unit re-checks on an interval, and a move that would drop stations waits for the configured quiet hours. The worst effect is a worse channel, not access to the network. | `ci/embedded-aarch64/ax1800/tests/coord-scenario.sh` (real scan parsing; no hostile-beacon case: **UNTESTED**) |

### B10 Installer and first boot

| # | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T37 | T | Tampered installer media | Signed ISO, checksums and SBOM (T29); the ISO carries no personal data and no private image variant exists. Secure Boot is not supported yet (documented in [ISO-INSTALL.md](ISO-INSTALL.md)). | `gentoo/live-iso/common/tests/test_release_signing.py` |
| T38 | I | Secrets in the unattended-install answer file | The answer file lives on the install USB, not in the image; the installer's secret rules are enforced on the answer file (for example a disk passphrase equal to the root password is refused). | `gentoo/live-iso/common/tests/test_harness_answer_secrets.py` |
| T39 | D | A firewall that waits for a disk passphrase at boot | The installer encrypts only when an unattended unlock works on that box (TPM2-sealed key or a proven remote unlock); otherwise it installs unencrypted and says so. | `gentoo/live-iso/common/zfs-enc-test.py` |
| T40 | E | Default credentials on a fresh install | None exist: the live installer creates the first administrator, and a router without one serves only the first-run claim (T17). | `ci/netlab/journey-first-boot.sh` |
| T41 | I | Physical access (console, disk) | Out of scope beyond the above: console login needs a system account; disk encryption is the owner's choice (T39). | **UNTESTED** |
| T42 | S/E | A captive portal client that spoofs another client's address, guesses voucher codes or attacks the unauthenticated sign-in listener | A session is keyed on MAC + IPv4 as the router's neighbour table sees them (no cookie or form field decides who is signed in) and lives in the kernel set `inet patronus_portal`; a device on the same link that copies both a signed-in client's MAC and address can share its session, as with every MAC-based portal (encrypted Wi-Fi with per-client keys limits this); voucher codes are random from a 32-letter alphabet (10 characters by default), portal passwords are argon2id hashes and unknown users cost the same work; RADIUS replies are checked by their authenticator and Message-Authenticator; the listener only signs in/out the caller and a GET never signs anyone out; a portal zone reaches nothing beyond the router (TCP reset, drop) except passthrough. | `ci/netlab/lane-x-captive-portal.sh` |

## Review findings (code review done while writing this document)

Reviewed on 2026-11-23: `crates/patronus-web/src/{auth.rs,syslogin.rs,routes/first_run.rs,routes/mod.rs,routes/api/system.rs,state/system.rs}`, `ci/embedded-aarch64/ax1800/overlay/usr/libexec/patronus/{fwcheck.sh,upgrade-install}`, `ci/embedded-aarch64/ax1800/overlay/usr/sbin/patronus-flash`, `crates/patronus-network/src/apdev.rs` (feed), `crates/patronus-firewall/src/{nftables.rs,applier.rs}`, `crates/patronus-config/src/{defaults.rs,store.rs}` (import), and the binary-host configuration in `gentoo/live-iso`.

| ID | Severity | Finding | Status |
|---|---|---|---|
| F1 | Medium | A signature made by a revoked release key was accepted (gpgv exits 0 and prints VALIDSIG next to REVKEYSIG), by the image check, the update-feed check and the Slate kernel-slot check. A revoked key could keep signing images that boxes accept. | **Fixed**, with a regression test that builds a real revoked key (red before the change, green after) |
| F2 | Medium | The signed update feed had no freshness: an old, validly signed list could be replayed to offer a vulnerable build as the update. | **Fixed**: signed `date` required, refused when older than the running firmware (`BUILD_DATE`, new in the image's release file); regression test in `apdev.rs` |
| L1 | Low (by design) | `@mgmt` (the anti-lockout rule) widens to the WAN, then to every interface, when no LAN role exists. A single-NIC or unassigned box exposes SSH and the web UI on that interface. This is the stated design (a box must stay reachable to be set up) and is guarded by throttling and the setup code. Recommended later: ask for the LAN role in the wizard before enabling WAN management. | Accepted, tracked as R2 |
| L2 | Low | Ten wrong first-run codes close the window for everyone until the service restarts (a LAN host can deny the claim). | Accepted |
| L3 | Low | Binary-host entries and overlays written by the machine-profile installer feature (`horcrux_profile.py`, vendored from the sibling project) carry no `verify-signature` line, and a git overlay is fetched with `StrictHostKeyChecking=accept-new`. Not on the default Patronus install path (the Gentoo host entry has `verify-signature = true`). The vendored tree is owned by the sibling project, so the fix goes there first. | Open, R7 |
| L4 | Low | No Origin check or CSRF token (T14); no session address binding (T13). | Accepted, R4 |

Nothing High was found. No finding was left unfixed at Medium.

## Residual risks and open items

| ID | Item | Status |
|---|---|---|
| R1 | **Independent review.** This document is a first written version by the maintainers, together with a code review by the same team. It is not an independent review. Until an independent reviewer has gone through it and every critical and high finding is fixed or accepted in writing, the threat-model criterion is "written, not independently reviewed". | **Open** |
| R2 | Management exposure on a box with no LAN role (T6, L1): decide whether the wizard should require a LAN role before the WAN carries SSH and the web UI. | Open |
| R3 | No layer-2 protections on unsegmented LANs (rogue DHCP, ARP spoofing). | Accepted |
| R4 | No CSRF token or Origin check; sessions are not bound to an address. | Accepted, candidate for the next hardening item |
| R5 | Signed older images can be installed (no minimum-build floor). | Accepted |
| R6 | The remote-management client and service are outside this review. | Accepted |
| R7 | Signature and host-key checks in the vendored machine-profile installer (L3). | Open (fix in the sibling project, then re-vendor) |
| R8 | Tests missing for T5, T10, T14, T18, T27, T34, T36 (hostile beacons), T41, the Slate revoked-key path, and for an installed system rejecting an unsigned binary package (T28). | Open |

Administrators are fully trusted and everything below the kernel (firmware, hardware) is out of scope.

## Keeping this current

Change a control and its row in the same commit. `ci/check-threat-model.py` checks that every file path and `file::test` reference above exists, and that every threat row cites a test or says UNTESTED. New boundaries (a new remote service, a new update path) need a row before they ship.
