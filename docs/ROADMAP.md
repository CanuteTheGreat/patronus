# Patronus roadmap to a stable 1.0 and a stable channel

Last reviewed: 2026-10-28. This page is the live checklist: update the status lines in the same commit that changes the evidence.

**Status today: pre-1.0 (Patronus 0.1.x).** Patronus is a Gentoo-based firewall/router with an SD-WAN dashboard (Rust, nftables). It is not ready for production use. APIs, configuration and on-disk formats can still change. Daily ISOs exist for testing; they are not releases.

## What stays free

The community channel is, and stays, fully functional: every feature, the daily ISOs, the community binhost, the source (GPL-3.0). Nothing is held back or crippled to sell a subscription. A paid channel, if it ever exists, sells a tested, delayed stable stream of the same software plus best-effort email support. See [stable-channel.md](stable-channel.md).

## Order of work

1. Reach **stable 1.0** (criteria below).
2. Run it with **real free users** and a community (issue tracker, docs, feedback).
3. Only then build the **stable channel subscription**. Nothing in phase 3 is built before phases 1 and 2 are done.

## Phase 1: stable 1.0 exit criteria

All nine must be met. Status is checked against the repository, not against intentions.

| # | Criterion (measurable exit) | Status | Evidence |
|---|---|---|---|
| 1 | **Installer, GUI and TUI, complete on every supported architecture.** Supported set: x86_64 and aarch64 (riscv64 listed as unsupported unless a native builder exists). Exit: both installers pass the full QEMU matrix (UEFI, and BIOS on x86_64; unattended, serial, VGA/GUI) on each supported arch, daily, for 14 days running. | Partial. Guided installer is a text-mode wizard (VGA + serial). x86_64 and aarch64 ISOs are both published by the `daily` release and both pass their QEMU runs (aarch64 under TCG, no KVM). riscv64 is not built. The graphical installer is in progress and not in the repo yet. | [ISO-INSTALL.md](ISO-INSTALL.md), [live-iso.yml](../.forgejo/workflows/live-iso.yml), [daily release](https://git.canutethegreat.com/CanuteTheGreat/patronus/releases/tag/daily) |
| 2 | **Unattended install, upgrade and rollback tested in CI.** Exit: a CI job installs the previous stable release, upgrades in place to the candidate, then rolls back, and asserts services, config and data are intact at each step. | Partial. Unattended install is tested on every daily build. The nightly netlab boots a store created by the previous release with HEAD (upgrade of the config store). No in-place package upgrade test and no rollback test of an installed appliance. | [ISO-INSTALL.md](ISO-INSTALL.md#what-is-tested-automatically), [nightly-test-depth.yml](../.forgejo/workflows/nightly-test-depth.yml) (`netlab-deep`, previous-release) |
| 3 | **Reboot and upgrade survival tests.** Exit: CI power-cuts or reboots an installed system at least 30 times, including right after an upgrade, and every service comes back with its configuration. | Partial, with an open bug. The installer runs reboot from disk and probe the web UI, and `netlab-deep` runs 30 power-cut rounds. On 2026-10-28 real hardware showed `patronus-firewall` not starting after a reboot; a fix is in progress elsewhere and this item stays open until a CI test covers that exact path. | [live-iso.yml](../.forgejo/workflows/live-iso.yml), [nightly-test-depth.yml](../.forgejo/workflows/nightly-test-depth.yml), [nightly-firewall-traffic-test.yml](../.forgejo/workflows/nightly-firewall-traffic-test.yml) |
| 4 | **Portable binaries.** Exit: no build uses `target-cpu=native`; the shipped baseline runs on the oldest supported x86_64 (x86-64-v2) and a generic aarch64; CI boots the ISO on a restricted CPU model and a lab machine from each of Intel and AMD. | Partial. [.cargo/config.toml](../.cargo/config.toml) pins `x86-64-v2` / generic arm64 and forbids `target-cpu=native`. A native build crashed on an Intel machine on 2026-10-28; the pin is in `main` but not yet confirmed on that hardware. | [.cargo/config.toml](../.cargo/config.toml) |
| 5 | **Lab deployment, N weeks without a P1 bug.** N = 8. The clock starts when the lab runs a build that contains every fix for known P1 bugs, and resets on any P1. P1 = data loss, a security hole, a service that does not come back after reboot, or an install that fails on supported hardware. | Not met. A `patronus-lab` VM (forwarding firewall for test traffic) exists on azkaban, but it had been up for about two hours when checked (2026-10-28) and the reboot bug above was just found. The clock has not started. | azkaban VM 107 `patronus-lab` |
| 6 | **Documentation complete.** Exit: install, upgrade/rollback, backup/restore, every UI page and CLI command documented; no page describes a feature that does not exist; stale session notes removed from the repo root; a link checker passes in CI. | Partial. `docs/` is broad (install, HA, DR, operations runbook, API) and the README ties every claim to a CI test via a claims ledger. The repo root holds dozens of historical sprint summaries that need pruning, and some docs describe features that are not finished. | [claims-ledger.txt](claims-ledger.txt), [README](../README.md), [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) |
| 7 | **Security review done.** Exit: written threat model; `cargo audit`/`cargo deny` clean in CI; an independent review (third party, or at minimum a reviewer who did not write the code) with every critical and high finding fixed or explicitly accepted in writing. | Not met. [SECURITY-AUDIT.md](../SECURITY-AUDIT.md) (2025-10-08) is an automated static analysis with 78 findings; the fix status of each finding is not recorded here, and it is not an independent review. `cargo audit` is part of the release checklist. | [SECURITY-AUDIT.md](../SECURITY-AUDIT.md), [RELEASE-PROCESS.md](../RELEASE-PROCESS.md) |
| 8 | **Signed release process.** Exit: signed git tags, a signed checksum file for each ISO and tarball, packages signed with a documented key, and a documented rotation and revocation procedure; CI refuses to publish an unsigned stable release. | Not met. [RELEASE-PROCESS.md](../RELEASE-PROCESS.md) describes a manual checklist and `release.yml` builds artifacts. Nothing is cryptographically signed. | [RELEASE-PROCESS.md](../RELEASE-PROCESS.md), [release.yml](../.forgejo/workflows/release.yml) |
| 9 | **Published support policy and EOL.** Exit: a public page stating which versions get fixes, for how long, how to report bugs and security issues, and what is out of scope. | Not met. No support policy and no version EOL policy exist. | none yet |

Summary at last review: 0 of 9 met, 5 partial, 4 not met. Known open bugs behind the partials are listed in the evidence column; none is hidden here.

## Phase 2: free users and community

Starts after 1.0. Exit before phase 3: the issue tracker is being used by people other than the maintainers, there is a documented way to ask for help, and the release cadence has held through at least two stable point releases. No user counts are claimed on this page; none exist yet.

## Phase 3: stable channel subscription (planned, after 1.0)

Model, agreed 2026-10-28, in the style of Proxmox:

- A paid, tested **stable update channel** (a subscription binhost/repo), plus **email support during business hours, best effort**. There is **no 24/7 SLA** and no response-time guarantee.
- The free community channel stays fully functional. No feature is removed or locked.
- Billing through Errant Solutions' Stripe account (test mode only until this phase starts).

What it requires technically (design in [stable-channel.md](stable-channel.md)):

- [ ] A separate binhost/repo with a **delayed, extra-tested promotion pipeline** from the community channel.
- [ ] **Per-subscription repo credentials** (revocable, rotatable).
- [ ] A **Stripe subscription wired to key issuance** (webhooks create, suspend and revoke keys).
- [ ] A **support inbox** through the Errant Solutions mail flow.
- [ ] A **published support policy**: business hours, best effort, scope, exclusions.
- [ ] **Terms of service with a limitation of liability.** A lawyer must review these before anything is sold. Nothing in this repository is legal advice or a final text.
- [ ] A signed release process (criterion 8) and the EOL policy (criterion 9), which phase 3 depends on.

## Not planned

Feature-gating the free channel, per-feature licensing, 24/7 coverage, telemetry as a condition of use.
