# Headless first: Patronus is an appliance, not a desktop

Owner rule (2026-11-03, after the Horcrux rule "it should work on a headless server too, it shouldn't be a desktop-only OS"):
**"Same for Patronus."** A Patronus box is installed, operated and recovered with a console (serial or VGA), SSH and the web UI.
No part of that needs a display server, a compositor, a toolkit or a desktop account.

## Layers

| layer | what it is | where it lives | public? |
|---|---|---|---|
| **core** | the headless appliance: kernel, OpenRC, `patronus-{firewall,applyd,web}`, chrony, dhcpcd, sshd, console menu, the text installers (serial + VGA) and the unattended answer-file install, every shared fix | `gentoo/live-iso/{common,project}` -> `patronus-server-openrc-<channel>-<arch>.iso` | yes |
| live-only installer GUI | cage + GTK4 + PyGObject (+ seatd, dbus, fonts, mesa stubs) for the *graphical installer on the stick*; recorded in `/etc/live-installer/live-only-packages` and **removed from every installed Server** (`strip_live_gui`) | `common/packages-gui.txt` | yes, on the media only |
| optional desktop | **none exists for Patronus** and none is planned (a firewall has no user session). The vendored installer still carries the Workstation/Desktop type, but `AVAILABLE_TYPES = ("server",)`, the profile offers no desktop and `ci/check-headless-image.sh` fails if a desktop package or install type appears in the Patronus inputs | - | - |
| **per-device private** | the owner's own boxes: SSH keys, root hash, host name, WAN/LAN assignment, Wi-Fi, per-box `patronus.toml`/GitOps repo | **outside the repo and outside the image**: the answer file on the install USB (`PATRONUS-ANSWERS`) plus `patronus gitops` for configuration. Nothing personal is baked into any ISO | never |

There is deliberately **no private image variant** for Patronus: everything a box needs that is its own travels in the answer file or the
GitOps repo, so the public ISO is the only ISO. (Horcrux's per-machine private images exist because it has desktop machines with firmware blobs;
Patronus has no equivalent need.) `common/Dockerfile.private` is Horcrux's Surface recipe and is not used here.

## Audit of what the Patronus image / profile contains (2026-11-03)

Inputs audited: `common/packages{,-extra,-gui,-late}.txt`, `project/packages{,-late}.txt`, `project/portage`, both overlays, the vendored installer,
the ebuild's `IUSE`/`RDEPEND`, `profile.toml`, the live boot menu, the matrix. Images: `patronus-server-openrc-daily-{x86_64,aarch64}.iso` (only variants; riscv64 is not in the matrix).

**Desktop-only things**
* The graphical installer stack (`gui-wm/cage`, `gui-libs/gtk`, `dev-python/pygobject`, `pycairo`, `at-spi2-core`, `adwaita-icon-theme`, `seatd`, `dbus`,
  `xkeyboard-config`, `dejavu`, mesa stubs): on the **ISO only**; stripped from the installed system by `strip_live_gui`. Gate: `graphical-installer-stack-removed-from-server`
  (cage/gtk/pygobject absent) and, new, `no-gui-stack-installed-headless-first-class` (below). On aarch64/riscv64 the stack may fail to build; the image then has the text installer only (that is fine).
* The boot menu default entry is the graphical installer (6 s countdown). On a box without a display use the **Serial console** submenu (`s`) - the same
  menu is mirrored on the UART - or the **Automated install** entry with an answer file. Both are gated on both architectures.
* Dormant vendored installer code for a desktop profile (`desktop.py`, `t2.py`, Surface/T2 hardware profiles, GNOME stages, `horcrux-t2-firmware`): shared with Horcrux,
  never reachable on Patronus (`AVAILABLE_TYPES`, no hardware profile ships a desktop, no GNOME packages in the image). Left to the Horcrux core/desktop restructuring to move
  out of the shared core (tracked in `~/.hermes/state/patronus-coord.md`).

**Personal to the owner**
* In the Patronus image inputs: **none found** (no Tailscale, Nextcloud, browser, Rustinion agent, SSH key, auth key; `ci/check-headless-image.sh` now fails the build on any of them).
* In the vendored shared code (`common/`, comments and Horcrux-only recipes, never installed on a Patronus box): `Dockerfile.private` (the Surface private layer), `publish-github.sh`
  repo names, hogshead/gringotts mentions in comments and tests, `vdb-prune.py` group `gringotts-fw`. Public, no secrets; the Horcrux restructuring moves the private recipes out of `common/`.
* `HOME_URL` in `/etc/os-release` is the project's public repo.

**Machine-specific**
* Hardware profiles (Surface/T2 detection in `hwprofile.py`/`t2.py`) are hardware-triggered and inert on other machines. Nothing in `project/` is tied to one machine.

## What core now guarantees (all shared with Horcrux core through `common/`)

| fix | where | gate (installed system) |
|---|---|---|
| hardware clock written from a verified clock at the end of an install | `liveinst/rtc.py` | `installer-writes-rtc-from-a-synced-clock` (the live boot starts 120 days off) |
| chrony steps a months-off clock: `makestep 1.0 3` + `rtcsync` enforced, `/etc/dhcpcd.exit-hook` (dhcpcd = the OpenRC equivalent of the NetworkManager dispatcher hook) tells chronyd the link is up, re-resolves the pool and bursts | `setup-rootfs.sh`, `overlay/etc/dhcpcd.exit-hook` | `months-off-rtc-clock-stepped-by-chrony-after-the-late-network` |
| `hwclock` (not `swclock`) on installed systems that have an RTC, `clock="UTC"` | `liveinst/system.py cfg_clock` | rc-update list printed with the clock gate |
| boot never waits for the network: the NIC links stay **down** until the login prompt, then come up | harness (QMP `set_link`) | `installed-boots-with-the-network-links-down`, `boot-reaches-the-console-without-a-network`, `wan-dhcp-lease-after-the-late-link-up`, web UI + SSH checks after |
| no password reuse, no autologin | installer + harness | `no-empty-password-no-console-autologin`, `root-password-is-not-the-web-admin-or-disk-secret`, `web-admin-refuses-the-root-login-password` |
| package database matches the disk (kept dev files, `tar --anchored`), a kernel module builds | `vdb-prune.py`, `build.sh` | `package-contents-complete-no-missing-files`, `kernel-module-builds-against-running-kernel` |
| reboot into the installed system | harness | `installed-boots-to-login`, `--restarts N` runs |
| no GUI dependency on the installed system | harness | `no-gui-stack-installed-headless-first-class`: every package in `/var/db/pkg` (the closure of `@world`) is checked against a deny list (X/Wayland/toolkits/desktops/browsers/mesa), plus no compositor/display-manager process, enabled service or binary |

`emerge -pv @world` cannot run on an installed Patronus box (the Portage tree is not shipped, a deliberate size decision); the package-database scan is the equivalent
and is stricter: it checks what **is** installed, transitive dependencies included. `qdepends`-style questions ("what pulled X?") are answered from the `RDEPEND` files in `/var/db/pkg`.

## Headless install, per architecture

| | x86_64 | aarch64 |
|---|---|---|
| serial console install | `Serial console (ttyS0 115200)` submenu, `--flow tui` | `ttyAMA0`, `--flow tui` |
| unattended | answer file on a volume labelled `PATRONUS-ANSWERS`, `--flow auto` | same |
| web UI after install | `https://<LAN address>:8443` (WAN closed) | same |
| firmware | UEFI and BIOS | UEFI |
| QEMU | KVM | TCG (no `/dev/kvm` on Graviton), time budget x3 |

The matrix is `common/ci-run.sh` + `project/ci-matrix.sh`; every run uses the conservative x86-64-v2 CPU model (x86) / cortex-a72 (aarch64). Runs carrying `--headless-gates` also
start every boot with an RTC 120 days in the past and boot the installed system with the links down. They add **no extra boot**, so the aarch64 time budget (178 min) is unchanged apart from the
wait for the login prompt, which already existed.

## Operating it headless

* Console: serial or VGA, login prompt (or the opt-in open console menu), `console-menu` for the web-UI password, network roles, reset.
* SSH: key-only root by default, `ssh_password_auth = true` is an explicit opt-in.
* Web UI: `https://<LAN IP>:8443`; sign in with a system user of the `patronus-admin` group (the installer creates the first one; see `docs/WEB-LOGIN.md`). There is no built-in `admin` and no generated password file.
* Configuration as code: `patronus gitops` (a private repo per site).
