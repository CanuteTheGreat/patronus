# Installing Patronus from the live ISO

Patronus ships a Gentoo-based **live + installer ISO** (x86_64 UEFI **and** legacy BIOS, aarch64 UEFI; hybrid:
the same file boots from a CD/VM *and* from a USB stick; see "Architectures"). It contains a **guided installer** (a text-mode wizard that works on a VGA/laptop screen and on a serial
console), an **unattended installer** driven by an answer file, and a live system you can look around in.
There is no default password anywhere: the installer makes you set one, and SSH on the installed system is
key-only unless you opt in.

## Download

| | URL |
|---|---|
| Latest **daily** test build (rolling pre-release, replaced after the QEMU test passed) | `https://patronus.errant.solutions/download/patronus-daily-x86_64.iso` |
| SHA256 of the daily | `https://patronus.errant.solutions/download/patronus-daily-x86_64.iso.sha256` |
| **Stable** build (only for `v*` releases that met the criteria below) | `https://patronus.errant.solutions/download/patronus-<tag>-x86_64.iso` |

Always verify: `sha256sum -c patronus-daily-x86_64.iso.sha256` (run it next to the downloaded files).

## Architectures

| arch | boot | serial console | built on | tested with | assets |
|---|---|---|---|---|---|
| **x86_64** | UEFI **and** legacy BIOS (hybrid ISO) | `ttyS0` | rw-man-01 (`kvm-x86_64` runner) | QEMU/KVM, OVMF + SeaBIOS | `patronus-daily-x86_64.iso` |
| **aarch64** | UEFI only (GRUB `arm64-efi`, `EFI/BOOT/BOOTAA64.EFI`); there is no BIOS on arm64 | `ttyAMA0` (PL011) | rw-man-04/05 (`arm64` runner, native Graviton build, no emulation) | QEMU `virt` + AAVMF; **TCG** (the Graviton hosts have no `/dev/kvm`), timeouts x3 | `patronus-daily-aarch64.iso` |
| riscv64 | UEFI only (GRUB `riscv64-efi`) | `ttyS0` | not built in CI yet | not tested | - |

Per-architecture facts (stage3 tag, GRUB target, EFI file name, serial device, squashfs filter, the **per-arch
binhost**) live in `build/live-iso/common/arch/<arch>.env|.binrepos.conf|.make.conf`. The rootfs build checks that
the binhost serves the rootfs's own `CHOST` (so an aarch64 build can never pull x86 packages or silently fall back
to compiling everything), and the BuildKit cache mounts are keyed by arch. Download URLs:

| | URL |
|---|---|
| daily aarch64 | `https://patronus.errant.solutions/download/patronus-daily-aarch64.iso` (+ `.sha256`) |
| stable aarch64 | `https://patronus.errant.solutions/download/patronus-<tag>-aarch64.iso` |

Each architecture has its own job, its own assets and its own status marker (`daily-status` for x86_64,
`daily-status-aarch64`), so a failing arch never blocks the other. Test evidence is attached per arch
(`patronus-daily-<arch>-test-evidence.tgz`). Build one yourself on a native host: `ARCH=aarch64 build/live-iso/build.sh -o ./iso`
(`ALLOW_EMULATED=1` is needed to build a foreign arch under qemu-user; not supported for the app stage).
On arm64 machines the ISO is written to the stick exactly as on x86 (`dd`); firmware must be UEFI (Secure Boot off).
Test it in QEMU: `qemu-system-aarch64 -machine virt -cpu max -m 4G -drive if=pflash,format=raw,readonly=on,file=AAVMF_CODE.fd -drive if=pflash,format=raw,file=VARS.fd -device qemu-xhci -device usb-storage,drive=iso -drive if=none,id=iso,file=patronus-daily-aarch64.iso,format=raw -device virtio-gpu-pci -device usb-kbd -serial stdio`.

**riscv64** is not in CI: there is no RISC-V runner, the official binhost has only ~600 riscv64 packages (about 40 of the
ones the image needs would compile from source under emulation: QEMU, libvirt, docker, ZFS, GRUB, dracut, ...), no
`rust:bookworm` image and no `trunk` binary exist for it, and the registered binfmt handler needed for emulated builds is not present on the
runners. The code paths are ready (`arch/riscv64.env`, harness `--arch riscv64`); what is missing is a native builder or a
cross-compile stage for the app plus a long-running weekly emulated job.

## Write it to a USB stick (this ERASES the stick)

Linux (replace `/dev/sdX` - check with `lsblk`; **not** a partition like `sdX1`):

    sudo dd if=patronus-daily-x86_64.iso of=/dev/sdX bs=4M conv=fsync status=progress
    sync

macOS: `diskutil list`, `diskutil unmountDisk /dev/diskN`, then
`sudo dd if=patronus-daily-x86_64.iso of=/dev/rdiskN bs=4m`.

Windows: [Rufus](https://rufus.ie) -> select the ISO -> when asked choose **"Write in DD Image mode"**
(not "ISO Image mode"), or use balenaEtcher / `dd` for Windows. Ventoy also works.

The stick is a GPT disk with an EFI System Partition plus the ISO9660 data, so it boots on UEFI
machines (via `EFI/BOOT/BOOTX64.EFI`) and on BIOS machines (GRUB in the MBR).

## Boot menu

1. **Install Patronus (guided installer)** - the default entry; starts the wizard on the screen (tty1).
2. *Install Patronus - serial console (ttyS0 115200)* - the same wizard on the serial port (headless boxes, QEMU).
3. *Automated install from an answer file (ERASES the target disk)* - see "Unattended install"; if no
   answer file is found it falls back to the guided installer.
4. *Patronus - live system (no install)*, *live system, serial console* - a root shell on the console
   (no password: physical access only; **sshd is off** and root's password is locked).
5. *Install Patronus - safe graphics (nomodeset)* - the wizard with `nomodeset` for odd GPUs.

Pick the entry with the arrow keys within 5 s, otherwise the guided installer starts.

## The guided installer

Keys: **Tab / Shift-Tab / Up / Down** move between fields, **Enter** goes to the next field (and presses the
highlighted button), **Left / Right / Space** change a choice or tick a box, in a list **type to filter**,
**Ctrl-U** clears a field, **Ctrl-L** repaints, **Esc** asks whether to abort. Nothing is written to a disk
before you type `ERASE` on the summary screen.

1. **Language, keyboard and time zone** - installed-system locale, console keymap, time zone (type to filter the list).

   ![language, keyboard, time zone](images/installer/patronus/01-language-keyboard-timezone.png)

2. **Target disk** - every internal disk with model, size, bus type and its existing partitions; the USB stick you booted from is hidden.

   ![target disk](images/installer/patronus/03b-target-disk-selected.png)

3. **Interface assignment** (like OPNsense option 1) - choose the WAN and LAN interface from the list of NICs with link state, MAC and driver, or pick *Auto-detect* and unplug/replug the cable to identify a port. A Wi-Fi adapter can be the WAN (scan, SSID, passphrase) on NIC-less devices.

   ![interface assignment](images/installer/patronus/04b-interface-assignment-filled.png)

4. **WAN / LAN addressing** - host name (FQDN); WAN by DHCP or static address / gateway / DNS; the LAN address (default `192.168.1.1/24`), which is also where the web UI listens.

   ![WAN / LAN addressing](images/installer/patronus/05b-wan-lan-addressing-filled.png)

5. **Administrator account** - REQUIRED password (min. 12 characters, mixed, no guessable words; confirm; strength meter), an optional SSH public key, the notification e-mail, and the opt-in for SSH password login (off by default, with a warning when ticked). The one password protects console login (`root`) and the web UI (`admin`).

   ![administrator account](images/installer/patronus/06b-administrator-account-filled.png)

6. **Summary** - everything you chose; you must type `ERASE` to confirm the wipe.

   ![summary](images/installer/patronus/07b-summary-confirmed.png)

7. **Installing** - progress bar and live log (full log: `/var/log/live-installer.log`).

   ![installing](images/installer/patronus/08-installing.png)

8. **Finished** - the web UI URL, how to log in, and a *Reboot* button (remove the stick first).

   ![finished](images/installer/patronus/09-finished.png)

The screenshots are real QEMU screen captures of the VGA console (`qemu-test.py --flow tui-vga`), taken by
the nightly test.

After the install: remove the stick and boot. The web UI is at `https://<ip>:8443` (self-signed
certificate; user `admin`, the password you set). The first-boot ruleset puts anti-lockout (SSH + web UI) on the LAN; the WAN drops everything inbound.

## Graphical installer (default)

The default boot entry, **Graphical install**, starts a kiosk (the `cage` Wayland compositor, one fullscreen window) running a
GTK4 installer. It is the same installer as the text one - both walk the same *stages* and write the same answer-file model - with:

* one screen per stage, a **step sidebar**, **Back / Next** (Alt+Left / Alt+Right), and an **Advanced options** expander on every screen that has expert settings;
* a **live disk-layout preview** (ESP/BIOS-boot, `/boot`, swap, root drawn to scale, next to the partitions that will be destroyed);
* **link state per NIC** (up / no link / Wi-Fi, address) refreshed live on the network screen;
* **mouse, keyboard and touch**: large hit targets, an **on-screen keyboard** (top right) for machines without a keyboard, a searchable list instead of drop-downs for long lists (time zone, keyboard layout);
* **HiDPI**: the interface scales with the screen (override with `LIVEINST_SCALE=2`), plus **High contrast** and **Larger text** switches (top right);
* product branding (colour and monogram from the product profile).

If there is no usable display (no DRM device, `nomodeset`, a serial console, or the GUI cannot start) the installer **falls back to the text
installer automatically**. The text installer can also be chosen directly: boot entry *Install (text mode)* (hotkey `2`). In the *Serial console* submenu the
*Graphical install* entry keeps the GUI on the screen and gives the UART a root shell (support, tests). The keyboard layout chosen on the first screen is applied to the compositor too.

Support and tests: `/usr/libexec/live-installer-atspi tree|press|focus|settext` talks to the GUI through AT-SPI (the accessibility tree
is complete: every control has a name), and `/run/live-installer/gui-status.json` records the current screen.

### Install stages

The installer is a list of small stages, like FreeBSD's `bsdinstall`. Each stage can describe what it will do (`plan`) without touching
anything, and applies it in sequence. The GUI, the text installer and the answer file all run the same list; `live-installer --plan --answers
answer.toml` prints the plan of an answer file.

| stage | what it does |
|---|---|
| `keymap` | install type (**Server**, default; *Workstation* is reserved for a later desktop profile), language, keyboard layout, time zone |
| `hostname` | host name (FQDN) |
| `disk` | file system, disk(s), partition layout (ext4, XFS, ZFS single/mirror) |
| `extract` | copy the system image to the new root |
| `rootpass` | administrator password (web `admin` + console `root`), e-mail, optional SSH key |
| `netconfig` | interfaces and addressing (link state live; Wi-Fi) |
| `services` | which optional services start at boot |
| `hardening` | SSH on/off, key-only (password login is an opt-in with a warning), kernel/network sysctl hardening, login-first vs open console menu |
| `use_flags` | Portage USE flags (below) |
| `finish` | boot loader, unmount |

On a **Server** install the graphical stack is removed again from the installed system (it is live-only); a future Workstation install keeps it.

### USE flags

The **Software** screen (graphical and text) lists *every* Portage USE flag with its description, grouped (security, networking,
virtualization, storage, graphics, audio/video, hardware, compression, languages, documentation/development, internationalization) and searchable by flag, description or package.

* **Presets**: *Recommended* (the tested image defaults; every package stays a pre-built binary), *Minimal* (no desktop/sound/docs/debug features), *Full* (extra protocols, compression, hardware features).
* **Portage sanity check**, live while you click: `REQUIRED_USE` violations are explained in plain language ("because 'c' is on, 'a' must be on"), USE-dependency and blocker conflicts between installed packages are reported the way Portage would, **product-critical flags** (listed in the profile, e.g. the QEMU/libvirt flags Patronus needs) are hard errors, and **security warnings** appear when a protective flag (`pam`, `ssl`, `seccomp`, ...) is switched off or a risky one (`debug`, `X` on a server) is switched on. Errors block *Next*.
* **Binary or source?** The installed system boots from the image's binaries. Every package whose USE set you change must be rebuilt from source later (`emerge`); the page shows how many, with a time and build-space estimate (heuristic, 4 cores). The choices are written to `/etc/portage/package.use/00-live-installer` and the package list to `/etc/live-installer/use-rebuild-pending`.
* Data source: `/usr/share/live-installer/portage-meta.json.xz` (about 37 KiB), generated at build time from the Portage tree (`use.desc`, `use.local.desc`) and the installed-package database (IUSE, USE, REQUIRED_USE, USE-dependent dependencies, blockers); the Portage tree itself is not shipped.

Answer file keys (all optional; see also the examples above):

```toml
[global]
install_type = "server"            # only "server" today

[services]
disable = ["docker"]               # optional services only (see the services screen)

[hardening]
ssh = true                         # false = no SSH server
sysctl = true                      # kernel/network hardening
ssh_password_auth = false
console_menu_open = false

[use_flags]
preset = "minimal"                 # recommended | minimal | full
enable  = ["spice"]
disable = ["debug"]                # checked with the same sanity check as the GUI; errors abort with ANSWER-FILE-ERROR
```

## Unattended install (answer file)

Boot the *Automated install* entry with an **answer file** available in one of two ways:

* a volume (USB stick, disk, virtual disk) whose file-system label is **`PATRONUS-ANSWERS`** (ext4, FAT or ISO9660) holding `answer.toml`; or
* the kernel argument `patronus.answers=https://server/answer.toml` (press `e` on the GRUB entry).

The file **must** carry a root password **hash** (never a plain password) and/or an SSH public key - without
either the installer refuses, because the system would be unreachable. Make a hash with
`openssl passwd -6` or `mkpasswd -m sha-512`.

```toml
[global]
keyboard = "us"
timezone = "Europe/Berlin"
hostname = "patronus-1.example.com"
email = "ops@example.com"
root_password_hash = "$6$....."          # console login; omit if you only want key login
ssh_keys = ["ssh-ed25519 AAAA... admin@laptop"]
ssh_password_auth = false                 # default false: key-only root SSH

[disk]
filesystem = "ext4"                       # ext4
disks = ["first"]                         # or ["/dev/nvme0n1"]; "first" = first internal non-USB disk >= 8 GB

[network.wan]
iface = "auto"                            # NIC name, or auto = first wired NIC with a link
mode = "dhcp"                             # or static: address / gateway / dns

[network.lan]
iface = "auto"                            # auto = the next wired NIC
address = "192.168.1.1/24"
```

The installed system's web-UI `admin` password is generated on first start into
`/var/lib/patronus/initial-admin-password` (root-readable) - read it over SSH or the console, and change it.
The installer powers the machine off when it is done (`AUTOINSTALL-OK` on the console and in
`/var/log/autoinstall.log`). Invalid answer files stop with `ANSWER-FILE-ERROR ...` lines and start the guided installer instead.

## Security defaults

* **No default password.** The live image has root locked (the consoles auto-login for physical access; **sshd is off**). The guided installer requires a password (>= 12 characters); the answer file requires a hash and/or an SSH key.
* **Installed system:** `PermitRootLogin prohibit-password` and `PasswordAuthentication no` - root can log in over SSH only with the key you gave. If you tick *Allow SSH password login* (or set `ssh_password_auth = true`) the installer sets `PermitRootLogin yes` + `PasswordAuthentication yes` and warns you.
* The web-UI admin password you type is stored only as a first-boot file that is deleted once the service is up.

## Secure Boot

**Not supported yet - turn Secure Boot OFF in the firmware setup before booting this ISO.**
The ISO uses an unsigned GRUB and an unsigned Gentoo distribution kernel; no shim/MOK chain is
shipped. With Secure Boot on, firmware will refuse `BOOTX64.EFI` ("Secure Boot violation" /
"Access Denied"). Nothing else needs to change in the firmware. The installed system is also
unsigned, so keep Secure Boot off after installing.

## Target-hardware notes

**ThinkPad 21KH (i5-1335U, 16 GB, NVMe, Intel I219 wired, UEFI)** - expected to work, **not yet tested on the real laptop**:
firmware setup (F1) -> Security -> Secure Boot -> *Disabled*; F12 for the one-time boot menu, pick the USB stick (UEFI entry).
The kernel is Gentoo's generic distribution kernel with the full `linux-firmware` set (I219 uses the in-kernel `e1000e`;
the AX211 Wi-Fi needs `iwlwifi` firmware, included; use `iwctl` (or the installer's Wi-Fi screen)). NVMe installs as `/dev/nvme0n1`.
Hybrid graphics/touchpad/suspend were not exercised; the installer image is console-only (no desktop).

**Surface Pro (gen 1, Ivy Bridge i5-3317U, 4 GB, UEFI + Secure Boot, no Ethernet)** - **not tested on the real device**:
power off, hold *Volume Down* while pressing power to boot from USB (use a USB hub/adapter for the stick);
to disable Secure Boot hold *Volume Up* while powering on -> Security -> Secure Boot -> Disabled.
The ISO is built for generic x86-64 (no AVX2 requirement), so it runs on Ivy Bridge. 4 GB RAM is enough for the live
system and installer (the live root is a RAM overlay; the 1.5 GB image is read from the stick). There is **no wired NIC**: the
installer works offline (installs from the image), but the web UI needs the network afterwards - plug a USB Ethernet
adapter or join Wi-Fi with `iwctl` (or the installer's Wi-Fi screen) (the Marvell 88W8797 `mwifiex_pcie` firmware ships in `linux-firmware`; unverified on this unit).
The Type Cover keyboard works if it presents as USB-HID (use a USB keyboard if the console does not react).

Patronus specifics: it is a firewall/router appliance. A laptop with one wired NIC needs a second (USB Ethernet) for a real WAN/LAN split; with a single port assign it as WAN and the anti-lockout rule lands there. The Surface Pro has no wired NIC: use Wi-Fi as WAN (installer Wi-Fi screen) plus a USB NIC for the LAN.

## What is tested automatically

`.forgejo/workflows/live-iso.yml` (daily, and on every `v*` tag) builds the ISO on a rw-man host and runs
`gentoo/live-iso/common/qemu-test.py` under QEMU/KVM. Five QEMU runs per build (four full installs plus the no-answer-file check):

| run | firmware / media | installer | WAN / LAN | SSH |
|---|---|---|---|---|
| 1 | BIOS + CD | answer file (unattended) | DHCP / `10.77.0.1/24` | **password opt-in** |
| 2 | BIOS + CD | guided TUI over the **serial** console (scripted keystrokes) | DHCP / `10.77.0.1/24` | key-only |
| 3 | UEFI + USB stick | guided TUI on the **VGA** console (QMP keystrokes + screenshots) | DHCP / `10.77.0.1/24` | key-only |
| 4 | UEFI + USB stick | answer file (unattended) | DHCP / `10.77.0.1/24` | key-only |
| 5 | BIOS + CD | *Automated install* entry **without** an answer file: must refuse and start the guided installer on the VGA screen; the disk stays untouched | - | - |

Every run then reboots from the installed disk alone (no ISO) and asserts:

* the live system's sshd is **off** (nothing answers on port 22 while installing);
* the old default root password (`patronus`) is **rejected** on the console, the chosen one works;
* SSH **refuses password root login** (offered auth methods are `publickey` only; a real `sshpass` attempt is refused), **accepts the configured key**, and `sshd -T` shows `permitrootlogin without-password` / `passwordauthentication no` (runs with the opt-in: password login works and the config says `yes`);
* the web UI/API answers over HTTPS **on the chosen IP** (QEMU forwards to that exact guest address; the LAN address on the second NIC, while the WAN address does not answer), the admin login works (with the password typed in the wizard, or the generated first-boot password for answer-file runs);
* host name, time zone, root file system type.

Publishing happens only when all of that passed. The run's serial logs, per-screen text captures and PNG
screenshots are attached to the release as `patronus-daily-test-evidence.tgz`. The workflow never turns the job
red on a failure (that would e-mail the owner); the result is recorded in the `daily-status` release marker instead.
Unit tests of the installer's validation rules (`common/tests`) run first.

Build it yourself on any x86_64 Docker host: `gentoo/live-iso/build.sh -o ./iso` (BuildKit required; a
first build compiles QEMU/libvirt and takes ~1 hour, cached rebuilds take minutes).

## Stable ISO criteria

A `v*` release gets a stable ISO attached (non-pre-release asset
`patronus-<tag>-x86_64.iso` + `.sha256`) only when, on the **tagged commit**:

1. the repository's own CI is not red (`failure`/`error`) for that commit;
2. the ISO builds from the tag from scratch-equivalent inputs (Gentoo stage3 + binhost, the tag's source);
3. ISO size < 2 GiB (release asset limit) and its SHA256 verifies;
4. **all five** QEMU runs above pass (both firmware types, both media types, unattended + serial wizard + VGA wizard), including the SSH/web assertions;
5. no step reported `FAIL` in the evidence bundle (attached to the release).

If any criterion fails, nothing is attached and the failure is recorded in the `daily-status` marker
(mode `stable`). The previous release stays as is. Tags must be cut by the maintainers; the workflow
never creates tags or bumps versions.

## Console menu (installed system)

After the install, the system console (VGA tty1, and the serial line `ttyS0` when the install was done from a
serial/automated boot entry) shows an OPNsense-style menu instead of a bare shell. By default the console asks for
the root password first (log in, the menu starts); tick **Open console menu** in the installer (or
`console_menu_open = true` in `answer.toml` `[global]`) for the OPNsense behaviour where anyone at the console gets
the menu without a login. tty2-6 and SSH always give a normal login shell. `touch /etc/live-installer/no-console-menu`
turns the menu off.

| Option | What it does |
|---|---|
| 1 Assign interfaces | Pick WAN and LAN (written to `/etc/patronus/patronus.toml`, firewall re-applied). Link state is shown per NIC; `d` = identify a port by unplug/replug. |
| 2 Set interface IP address | DHCP or static (address/prefix, gateway, DNS) for one NIC; Wi-Fi NICs can (re)connect through iwd. Written to `/etc/dhcpcd.conf` (managed block) and applied at once. |
| 3 Reset the admin password | Sets a new web `admin` password directly in the product's database (argon2id), drops web sessions, optionally also sets the root console password. |
| 4 Reset to factory defaults | Type `RESET` to confirm; first writes a backup, then deletes the configuration database, re-applies the product's boot units and starts it with a new password. Interface roles and addresses are kept. |
| 5 / 6 | Power off / restart the machine (asks first). |
| 7 Ping host | Validated host name or address only (no shell metacharacters). |
| 8 Shell | Root shell; `exit` returns to the menu. |
| 9 Web UI URL and status | URL, uptime, service states, root fs, effective SSH settings, latest backups. |
| 10 Restore a configuration backup | Lists `/var/backups/patronus/*.tar.gz` and `*.tar.gz` on any attached USB stick. Refuses archives of another product, with paths outside the product's config paths, or with links; takes a `pre-restore` backup first. |
| 11 Create a configuration backup | `/var/backups/patronus/patronus-config-manual-<time>.tar.gz` (consistent SQLite copy while the service runs), optionally copied to a USB stick. |

Screens (real QEMU captures from the CI run, UEFI, VGA console): the login on a protected console, then the menu.

![VGA login](images/console-menu/vga-login.png)
![VGA console menu](images/console-menu/vga-menu.png)

Tests (QEMU, UEFI + BIOS, serial and VGA): the serial runs drive options 9, 7 (including a rejected `x;reboot`), 2,
3, 11, 4, 10 and 5, and log in to the web UI with the new password after each reset (the old one must fail); the VGA run
logs in on tty1 by keyboard and checks that `console-menu` is the process on tty1. Both products.

## Shared installer source

`build/live-iso/common` in Horcrux is the master; Patronus `gentoo/live-iso/common` is a vendored copy.
`sync-common.sh --write-hash` (Horcrux, after editing) records `common/TREE.sha256`; `sync-common.sh --from <horcrux checkout>`
(Patronus) copies it. CI runs `--check` in both repos (and `--upstream` in Patronus) before the unit tests, so hand edits or a
stale copy are caught.

## Known gaps

* **Secure Boot**: not supported (see above). A shim + MOK-enrolment chain (own signing key for GRUB and the kernel) is the next step.
* **Real hardware**: only QEMU/KVM (OVMF + SeaBIOS, USB-storage and CD boot) is tested automatically. The ThinkPad and Surface Pro notes above are expectations, not results. In particular untested: Wi-Fi scan/connect (needs a real adapter; the code path is exercised only by unit logic), the *Auto-detect (replug the cable)* link detection (real PHYs only), NVMe/eMMC device naming (`part_path` is unit-tested), the large console font on high-DPI panels (`setfont ter-v32n` when the framebuffer is >= 1600 px wide), touch/Type Cover input.
* The installer is text mode (curses). A graphical installer is not provided.
* Installer language: only the *installed system's* locale/keymap are selectable; the wizard text is English.
* No ZFS install for Patronus yet (XFS by default, ext4 as a manual choice); no LVM/RAID layout.
* The notification e-mail is recorded in `/etc/patronus/notify-email`; the product does not read it yet.
* The live image has no desktop; the Portage tree is stripped from the image, so run `emerge-webrsync` before using `emerge` on a live/installed system.

## Legacy catalyst / `patronus-install` paths

The catalyst stage3/livecd scripts no longer set `root:patronus` / `patronus:patronus` (accounts are locked, sshd is `PermitRootLogin prohibit-password` + `PasswordAuthentication no`), and `patronus-install` writes `PasswordAuthentication no` and refuses a plaintext user password shorter than 12 characters.
