# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v3

# net-firewall/patronus as installed on the Patronus live/installer image.
#
# The ISO build compiles the binaries in its application stage (a glibc older than Gentoo's, so they run on the live system)
# and stages them, together with this repository's own files/ directory, under /usr/share/patronus-image/payload. This ebuild
# installs that payload through Portage, so every file of the product (binaries, OpenRC scripts, systemd units, config, PAM
# service, state directories) is owned by a package on the installed system: `qfile`, `qcheck`, `emerge --depclean`, file
# collisions and later `emerge -1u net-firewall/patronus` (the web UI's updater) all work. Before this the image copied the
# files by hand, which silently lost the ones nobody listed (patronus-dhcpc: the setup wizard failed with "service does not
# exist" on the installed system).
#
# The init scripts and units are installed by GLOB over files/, never by a hand-kept list, so a service file added to the
# real ebuild's files/ directory lands on the image without touching this file (ci/check-image-ebuild-parity.sh).
#
# This file is a template: the application stage copies it to net-firewall/patronus/patronus-<version>_p<build>.ebuild in
# the image-local repository; the live ebuild in the overlay (patronus-9999 / 0.x) is what builds from source.

EAPI=8

inherit pam systemd

DESCRIPTION="Modern firewall and network security platform (prebuilt binaries of the Patronus live image)"
HOMEPAGE="https://patronus.errant.solutions/"

LICENSE="GPL-3+"
SLOT="0"
KEYWORDS="amd64 arm64 riscv"
# neovim: optional editor (the default editor can be set to neovim; vim stays the default, see docs/DEFAULT-EDITOR.md)
IUSE="neovim"
# No init USE flags: the image ships BOTH init systems' files (the one it does not run is inert), whatever the profile's USE says. The
# image is built once per init variant from the same payload, and an installed system keeps both so a later switch needs no re-merge.

# Prebuilt, already stripped; there is nothing to fetch.
RESTRICT="strip mirror"
QA_PREBUILT="usr/bin/patronus-cli usr/bin/patronus-web usr/bin/patronus-install"

RDEPEND="
	app-editors/vim
	neovim? ( app-editors/neovim )
	acct-user/patronus
	acct-group/patronus
	sec-keys/openpgp-keys-errantsolutions
	sys-auth/pambase
	sys-libs/pam
	sys-apps/iproute2
	net-firewall/nftables
"
# src_install chowns to patronus:patronus, so the account must exist while it runs (the real ebuild does the same)
DEPEND="${RDEPEND}"

# Where the application stage left the files (overridable for a test build).
PATRONUS_IMAGE_PAYLOAD="${PATRONUS_IMAGE_PAYLOAD:-/usr/share/patronus-image/payload}"

S="${WORKDIR}/payload"

src_unpack() {
	[[ -d ${PATRONUS_IMAGE_PAYLOAD}/files && -x ${PATRONUS_IMAGE_PAYLOAD}/bin/patronus-cli ]] \
		|| die "no Patronus payload in ${PATRONUS_IMAGE_PAYLOAD}: this ebuild only installs what the live-ISO build staged (bin/ and files/)"
	mkdir -p "${S}" || die
	cp -a "${PATRONUS_IMAGE_PAYLOAD}/." "${S}/" || die
}

src_install() {
	local f n

	dobin bin/patronus-cli bin/patronus-web bin/patronus-install
	dosym patronus-cli /usr/bin/patronus

	for f in files/*.service files/*.timer; do
		[[ -e ${f} ]] || continue
		case ${f##*/} in patronus-dashboard.*) continue ;; esac
		systemd_dounit "${f}"
	done
	# unbound keeps /var/lib/unbound (root:unbound 0775): the vendor unit would chown it to root and DNSSEC autotrust fails
	systemd_install_dropin unbound.service files/unbound-patronus.conf

	for f in files/*.initd; do
		n=${f##*/}; n=${n%.initd}
		case ${n} in patronus-dashboard) continue ;; esac
		newinitd "${f}" "${n}"
	done
	newconfd files/patronus.confd patronus
	# monthly DB-IP country/ASN refresh behind the traffic insight page (the systemd twin is the .timer above)
	exeinto /etc/cron.monthly
	newexe files/patronus-ipdb.cron patronus-ipdb

	insinto /etc/patronus
	doins files/patronus.toml files/web-auth.toml
	# web login = system users: the "patronus" PAM service mirrors the system login
	pamd_mimic_system patronus auth account

	# kernel install/removal rewrites grub.cfg on installs without boot environments (mirrors net-firewall/patronus)
	exeinto /etc/kernel/postinst.d
	newexe files/patronus-boot-entry 91-patronus-boot-entry
	exeinto /etc/kernel/postrm.d
	newexe files/patronus-boot-entry 91-patronus-boot-entry
	exeinto /etc/grub.d
	newexe files/patronus-grub-unattended 11_patronus_unattended
	insinto /etc/conf.d
	newins files/patronus-boot-entry.confd patronus-boot-entry

	keepdir /var/lib/patronus /var/log/patronus /var/lib/patronus/feeds \
		/etc/patronus/rules.d /etc/patronus/openvpn /etc/patronus/ipsec /etc/patronus/unbound \
		/etc/patronus/certificates /etc/patronus/tls

	fowners patronus:patronus /var/lib/patronus /var/log/patronus /var/lib/patronus/feeds \
		/etc/patronus/openvpn /etc/patronus/ipsec /etc/patronus/unbound /etc/patronus/certificates /etc/patronus/tls
	# group patronus so the unprivileged web service can read the config and reach its TLS directory
	fowners root:patronus /etc/patronus /etc/patronus/patronus.toml /etc/patronus/web-auth.toml
	fperms 0750 /etc/patronus /etc/patronus/openvpn /etc/patronus/ipsec
	fperms 0640 /etc/patronus/patronus.toml /etc/patronus/web-auth.toml
	fperms 0700 /etc/patronus/certificates /etc/patronus/tls
}
