# Copyright 2025 Gentoo Authors
# Distributed under the terms of the GNU General Public License v3

EAPI=8

CRATES=""

inherit cargo

DESCRIPTION="Full-featured installer for Patronus firewall/SD-WAN system"
HOMEPAGE="https://github.com/yourusername/patronus"

if [[ ${PV} == 9999 ]]; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/yourusername/patronus.git"
else
	SRC_URI="https://github.com/yourusername/patronus/archive/v${PV}.tar.gz -> ${P}.tar.gz"
	KEYWORDS="~amd64 ~arm64 ~riscv"
fi

LICENSE="GPL-3+"
SLOT="0"

RDEPEND="
	sys-apps/util-linux
	sys-block/parted
	sys-apps/gptfdisk
	sys-fs/dosfstools
	sys-fs/e2fsprogs
	sys-fs/btrfs-progs
	sys-fs/xfsprogs
	net-misc/rsync
	sys-boot/grub:2
"

DEPEND="${RDEPEND}"
BDEPEND="
	>=virtual/rust-1.75
"

QA_FLAGS_IGNORED="usr/bin/patronus-install"

src_unpack() {
	if [[ ${PV} == 9999 ]]; then
		git-r3_src_unpack
	else
		default
	fi
}

src_compile() {
	cd "${S}/crates/patronus-installer" || die

	export CARGO_PROFILE_RELEASE_OPT_LEVEL=3
	export CARGO_PROFILE_RELEASE_LTO=true
	export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

	# Build for generic x86-64 (baseline SSE2 only) for maximum compatibility
	# This ensures the installer works on any x86-64 CPU from 2003+
	export RUSTFLAGS="-C target-cpu=x86-64"

	cargo build --release || die "Cargo build failed"
}

src_install() {
	# Install binary
	dobin "${S}/target/release/patronus-install"

	# Documentation
	dodoc "${S}/README.md"
}

pkg_postinst() {
	elog "Patronus Installer has been installed."
	elog ""
	elog "Usage:"
	elog "  patronus-install          - Start interactive TUI installer"
	elog "  patronus-install --help   - Show all options"
	elog "  patronus-install --list-disks  - List available disks"
	elog ""
	elog "For unattended installation, use:"
	elog "  patronus-install --config /path/to/config.toml --yes"
}
