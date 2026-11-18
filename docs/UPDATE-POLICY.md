# Versions, updates and rollback

This page is the policy for how Patronus is versioned, which versions get fixes, how a device is
updated and how to go back when an update goes wrong. The release history is in
[CHANGELOG.md](../CHANGELOG.md). Patronus is pre-1.0: see [ROADMAP.md](ROADMAP.md) for what is still
open before a stable release, and the sections below for what exists today and what does not.

## Version numbers

Patronus uses [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`, tagged in git as
`vMAJOR.MINOR.PATCH` (pre-releases: `v1.0.0-rc.1`). The workspace version in `Cargo.toml`, the tag
and the CHANGELOG entry always match; CI refuses a release tag where they don't.

| Change | Before 1.0 (now) | From 1.0 on |
|---|---|---|
| API, CLI or configuration-format change that breaks existing callers or needs manual edits; removed feature or USE flag | minor (`0.x` -> `0.x+1`) | major |
| New feature, new API endpoint, new USE flag, additive configuration-store migration | minor or patch | minor |
| Bug fix, security fix, packaging fix | patch | patch |

Before 1.0 a minor release may break compatibility; the CHANGELOG says so under that release. The
configuration store of an older release is migrated in place when the new version starts (migrations
only add tables or columns unless the CHANGELOG marks the release as breaking); the nightly CI run
`netlab-deep` boots a store written by the previous release with the new code.

## Supported versions

Only the newest release and the current daily build get fixes. There are no long-term-support
branches before 1.0.

| Version | Fixes | Notes |
|---|---|---|
| `main` / daily build / live ebuild (`9999`) | yes, fixes land here first | Rolling test builds, not releases |
| Newest tagged release (`v0.2.x`) | security and data-loss fixes as patch releases | |
| Older tagged releases (`v0.1.x`) | no | update to the newest release |

Security fix targets (best effort, one maintainer, not a contract):

| Severity | Fix on `main` | Patch release |
|---|---|---|
| Critical: remote code execution, authentication bypass, a firewall that fails open | within 72 hours of confirmation | within 7 days, or sooner when ready |
| High: privilege escalation, data exposure, denial of service by an unauthenticated peer | within 14 days | with the next patch release |
| Moderate and low | next release | next minor release |

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md); do not open a public issue for
them. Fixes are named in the CHANGELOG under "Security" once a release carries them.

## Release channels

| Channel | What it is | When |
|---|---|---|
| Tagged release `vX.Y.Z` | Release archives (`patronus-web`, `patronus-cli`) for x86_64 and aarch64 with detached OpenPGP signatures, the third-party license list, release notes from the CHANGELOG, and a stable live ISO when the criteria in [ISO-INSTALL.md](ISO-INSTALL.md#stable-iso-criteria) pass | When a maintainer cuts a release from a green `main` with `ci/release.sh` |
| Daily | Rolling ISOs of `main` (OpenRC and, once published, systemd; x86_64 and aarch64), replaced in place, published only after the QEMU boot, install, reboot and web tests passed | After each passing daily build |
| Live ebuild | `net-firewall/patronus-9999`, built from `main` | Every commit |

A daily build is a test build, not a release. A paid or delayed stable update stream is only a design
([stable-channel.md](stable-channel.md)); it does not exist and nothing is for sale.

## How a device is updated

Verify the file you download against its `.sha256` and `.asc` signature ("Verify your download" on the
product site's download section; the signing key is `keys/release-signing.asc` in the repository).

### Standard tier (x86_64 / aarch64 installs, Gentoo packages)

* There is **no unattended update service today**: Patronus never updates itself and never contacts a
  Patronus server to look for a new version (see [PRIVACY.md](PRIVACY.md)). The administrator updates the
  installed packages with Portage (`emerge -uDN @world`) or reinstalls from a newer ISO and imports the
  exported configuration.
* The Packages page of the web UI installs and updates the optional daemons only (it runs `emerge` with
  binary packages on an administrator's click).
* On a ZFS root (the installer's default), an `emerge` run first takes a boot-environment snapshot
  `pre-upgrade-<date>-<time>` (at most one per 30 minutes). Updates never reboot the
  device; reboot when it suits you. Restart `patronus-web` (and `patronus applyd`) after updating the
  package so the new version runs.
* An in-place upgrade-then-rollback test of an installed appliance does not exist yet; it is exit
  criterion 2 of the roadmap.

### Router tier (embedded images, A/B slots)

Router-tier boards (for example the GL-AR750S) keep the system twice, in slots A and B, and the
configuration store on its own partition that every update keeps ([embedded-routers.md](embedded-routers.md)).
A new image is written to the inactive slot and the boot loader switches to it for a trial boot. If the new
slot does not mark itself good (a configuration apply and a reachability probe) before the boot counter
runs out, the boot loader returns to the previous slot by itself. Firmware images carry an OpenPGP
signature and a device refuses an unsigned or wrongly signed image. Which board has the A/B layout, and
which does not (some boards have no automatic rollback), is listed per board in that document; the System
page shows what the device in front of you offers.

## Rolling back

### Configuration

Every configuration change is kept in the history. Roll back with `patronus config history` and
`patronus config rollback <id>`, or from the System page. An import that does not apply is reverted
automatically.

### Whole system on ZFS: boot environments

Before an update the root file system is snapshotted, so the system as it was can be booted again:

* `patronus-be rollback` (the previous version) or `patronus-be rollback <name>`, then reboot;
* `patronus-be snapshot|create|activate` manage boot environments by hand; the GRUB menu lists them.

User data datasets (`home`, `var/log`, `var/lib/*`) are separate from the boot environment and are not
rolled back. Without ZFS (the XFS fallback or a manual ext4 choice) there are no boot environments: export
the configuration before updating and roll back by reinstalling the previous package or ISO.

### Router tier

Power-cycle the device when the new slot does not come up: the previous slot returns by itself after the
trial boots. To go back deliberately after a good update, install the previous image through the same
firmware page; the configuration store is kept.

## Cutting a release (maintainers)

```
ci/release.sh 0.3.0        # on an up-to-date main whose rust-ci.yml run is green
git push origin main v0.3.0
```

`ci/release.sh` sets the workspace version, regenerates `CHANGELOG.md` from the commits since the last
tag (`ci/changelog.py`), commits `release: v0.3.0` and creates the annotated tag. The tag push runs
`release.yml`, which checks that the tag, `Cargo.toml` and the CHANGELOG agree, builds the release
archives for both architectures, signs them, generates `THIRD-PARTY-LICENSES.txt` and publishes
everything with the CHANGELOG section as release notes. Never create a `v*` tag by hand.
