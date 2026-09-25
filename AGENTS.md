# Patronus -- Instructions for AI Coding Agents

## Platform: Gentoo Linux, from the ground up

Patronus is built specifically for Gentoo Linux. This is not incidental --
it is the core design point of the project, alongside Portage's USE-flag
model (fine-grained feature selection at build time, embracing source-based
compilation). Do NOT default to generic/Debian/Ubuntu conventions just
because they are common boilerplate for a Rust project. Specifically:

- The canonical install path is the real Gentoo overlay at `gentoo/` (a
  full, self-contained Portage repo: `metadata/layout.conf`,
  `profiles/repo_name`, `net-firewall/patronus/patronus-9999.ebuild`,
  `net-firewall/patronus-installer/`). Any packaging or install-flow change
  belongs there first.
- `Dockerfile` builds through real Portage (`emerge` against that same
  overlay), NOT `cargo build` directly against a generic Debian/Ubuntu base
  image. If you ever see a Dockerfile in this repo doing `FROM rust:*` ->
  `cargo build` -> `FROM debian:*-slim`, that is WRONG and a regression --
  it was fixed once already (2026-09-24) after being silently introduced by
  an earlier AI coding session that defaulted to boilerplate instead of
  checking the project's actual target platform.
- USE flags (see `gentoo/net-firewall/patronus/patronus-9999.ebuild`'s
  `IUSE`) are a core selling point over competitors like pfSense/OPNsense --
  they let an installer choose exactly which features (web UI, eBPF/XDP,
  SD-WAN, AI detection, cloud integrations, etc.) get compiled in. Any
  container or CI build path MUST preserve this (pass USE flags through as
  a build arg to `emerge`), not silently compile a fixed feature set.
- `gentoo/catalyst/` and `gentoo/build-bootable-iso.sh` / `build-minimal-iso.sh`
  build a real bootable Gentoo installer ISO -- this is a SEPARATE, dedicated
  path from the app Dockerfile, also Gentoo-based (`gentoo/stage3`), and
  should stay that way.
- Any new documentation, README section, CI workflow, or install script
  should assume Gentoo as the primary/default target. Non-Gentoo Linux can
  be mentioned as "also runs on any modern distro" but must never replace
  or overshadow the Gentoo-first framing.

If you are an AI coding agent working on this repo and are unsure whether
something should be Gentoo-specific, ask -- do not assume "generic Linux
container" is a safe default here. It has caused real, silent architectural
drift before (same class of bug hit Horcrux, a sibling project, on the same
day).
