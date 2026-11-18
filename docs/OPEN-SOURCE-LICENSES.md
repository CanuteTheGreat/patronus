# Open-source licenses

## Patronus

Patronus is free software, released under the **GNU General Public License, version 3 or (at your option)
any later version** (`GPL-3.0-or-later`). You may use, study, change and redistribute it under those terms.
It comes without any warranty. The full license text is the file `LICENSE` in the source code, and the
source of every release and of the daily builds is public (see the "Source" link in the page footer).

## Third-party software

The Rust programs (`patronus-web`, `patronus-cli`) are built from the Patronus source and a set of Rust
libraries ("crates"), each under its own license. The accepted licenses are listed in
`.cargo/deny.toml` and checked by CI on every change: permissive licenses (MIT, Apache-2.0, BSD, ISC, Zlib,
Unicode) plus the file-level copyleft MPL-2.0 and public-domain dedications, all compatible with the GPL.
Anything else fails the build until it is reviewed.

The complete list of those crates with their license texts and copyright notices is generated from the
dependency lock file of each release by `ci/third-party-licenses.py`. It is attached to every release as
`THIRD-PARTY-LICENSES.txt`, installed on a device as `/usr/share/doc/patronus/THIRD-PARTY-LICENSES.txt.gz`
and shown by the "Open-source licenses" page of the web UI, which works without internet access. Router-tier
images leave the file out to fit their flash budget and the UI page says so.

The operating system on the image (Gentoo Linux, the Linux kernel, nftables, Unbound, chrony, hostapd and
the other packages) consists of separate programs, each under its own license. The license of every
installed Gentoo package is in `/var/db/pkg/*/*/LICENSE` on the device.
