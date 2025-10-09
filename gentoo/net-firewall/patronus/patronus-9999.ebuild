# Copyright 2025 Gentoo Authors
# Distributed under the terms of the GNU General Public License v3

EAPI=8

CRATES=""

inherit cargo systemd

DESCRIPTION="Modern firewall and network security platform built with Rust"
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

# USE flags matching Patronus feature set (The Gentoo Way - OPTIONS!)
IUSE="
	+web +cli +api
	+nftables iptables
	+dhcp +dns +unbound bind dnsmasq
	+vpn wireguard openvpn ipsec
	+multiwan
	+ha ucarp keepalived vrrpd
	+monitoring prometheus ntopng netflow collectd
	+captive-portal
	+intrusion-detection suricata snort
	vlan qos +tc
	+certificates acme certbot
	ldap radius totp
	geoip geoip2
	+aliases
	scheduled-rules
	pppoe
	wireless hostapd iwd
	squid tinyproxy
	+backup
	+systemd +openrc
	test
"

REQUIRED_USE="
	|| ( nftables iptables )
	|| ( systemd openrc )
	dns? ( || ( unbound bind dnsmasq ) )
	vpn? ( || ( wireguard openvpn ipsec ) )
	intrusion-detection? ( || ( suricata snort ) )
	ha? ( || ( ucarp keepalived vrrpd ) )
	certificates? ( || ( acme certbot ) )
	wireless? ( || ( hostapd iwd ) )
	squid? ( !tinyproxy )
	tinyproxy? ( !squid )
	geoip2? ( !geoip )
	bind? ( !unbound !dnsmasq )
	unbound? ( !bind !dnsmasq )
	dnsmasq? ( !bind !unbound )
"

RDEPEND="
	acct-user/patronus
	acct-group/patronus
	nftables? ( net-firewall/nftables )
	iptables? ( net-firewall/iptables )
	dhcp? ( net-misc/dhcp )
	dns? (
		unbound? ( net-dns/unbound )
		bind? ( net-dns/bind )
		dnsmasq? ( net-dns/dnsmasq )
	)
	vpn? (
		wireguard? ( net-vpn/wireguard-tools )
		openvpn? ( net-vpn/openvpn )
		ipsec? ( net-vpn/strongswan )
	)
	multiwan? ( sys-apps/iproute2 )
	ha? (
		ucarp? ( net-misc/ucarp )
		keepalived? ( sys-cluster/keepalived )
		vrrpd? ( net-misc/vrrpd )
	)
	monitoring? (
		prometheus? ( app-metrics/prometheus )
		ntopng? ( net-analyzer/ntopng )
		netflow? ( net-analyzer/softflowd )
		collectd? ( app-metrics/collectd )
	)
	intrusion-detection? (
		suricata? ( net-analyzer/suricata )
		snort? ( net-analyzer/snort )
	)
	vlan? ( sys-apps/iproute2 )
	qos? ( sys-apps/iproute2 )
	tc? ( sys-apps/iproute2 )
	certificates? (
		acme? ( app-crypt/acme-sh )
		certbot? ( app-crypt/certbot )
	)
	ldap? ( net-nds/openldap )
	radius? ( net-dialup/freeradius )
	geoip? ( dev-libs/geoip )
	geoip2? ( dev-libs/libmaxminddb )
	pppoe? ( net-dialup/ppp )
	squid? ( net-proxy/squid )
	tinyproxy? ( net-proxy/tinyproxy )
	wireless? (
		hostapd? ( net-wireless/hostapd )
		iwd? ( net-wireless/iwd )
	)
	systemd? ( sys-apps/systemd )
	openrc? ( sys-apps/openrc )
"

DEPEND="${RDEPEND}"
BDEPEND="
	>=virtual/rust-1.75
"

QA_FLAGS_IGNORED="usr/bin/patronus.*"

src_configure() {
	local myfeatures=(
		$(usex web "web" "")
		$(usex cli "cli" "")
		$(usex api "api" "")
		$(usex dhcp "dhcp" "")
		$(usex dns "dns" "")
		$(usex unbound "dns" "")
		$(usex wireguard "wireguard" "")
		$(usex openvpn "openvpn" "")
		$(usex ipsec "ipsec" "")
		$(usex multiwan "multiwan" "")
		$(usex ha "ha" "")
		$(usex carp "carp" "")
		$(usex monitoring "monitoring" "")
		$(usex prometheus "prometheus" "")
		$(usex ntopng "ntopng" "")
		$(usex netflow "netflow" "")
		$(usex captive-portal "captive-portal" "")
		$(usex suricata "suricata" "")
		$(usex vlan "vlan" "")
		$(usex qos "qos" "")
		$(usex tc "tc" "")
		$(usex certificates "certificates" "")
		$(usex acme "acme" "")
		$(usex ldap "ldap" "")
		$(usex radius "radius" "")
		$(usex totp "totp" "")
		$(usex geoip "geoip" "")
		$(usex aliases "aliases" "")
		$(usex scheduled-rules "scheduled-rules" "")
		$(usex pppoe "pppoe" "")
		$(usex wireless "wireless" "")
		$(usex backup "backup" "")
	)

	cargo_src_configure --no-default-features
}

src_compile() {
	export CARGO_PROFILE_RELEASE_OPT_LEVEL=3
	export CARGO_PROFILE_RELEASE_LTO=true
	export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

	# Architecture-specific optimizations
	if use amd64; then
		export RUSTFLAGS="${RUSTFLAGS} -C target-cpu=native"
	elif use arm64; then
		export RUSTFLAGS="${RUSTFLAGS} -C target-cpu=native"
	elif use riscv; then
		export RUSTFLAGS="${RUSTFLAGS} -C target-cpu=generic-rv64"
	fi

	cargo_src_compile
}

src_install() {
	cargo_src_install

	# Install init scripts based on USE flags
	if use systemd; then
		systemd_dounit "${FILESDIR}/patronus-web.service"
		systemd_dounit "${FILESDIR}/patronus-firewall.service"
	fi

	if use openrc; then
		newinitd "${FILESDIR}/patronus-web.initd" patronus-web
		newinitd "${FILESDIR}/patronus-firewall.initd" patronus-firewall
		newconfd "${FILESDIR}/patronus.confd" patronus
	fi

	# Install configuration files
	insinto /etc/patronus
	doins "${FILESDIR}/patronus.toml"

	# Create necessary directories
	keepdir /var/lib/patronus
	keepdir /var/log/patronus
	keepdir /etc/patronus/rules.d
	keepdir /etc/patronus/openvpn
	keepdir /etc/patronus/ipsec
	keepdir /etc/patronus/unbound
	keepdir /etc/patronus/certificates

	# Install web assets if web USE flag is enabled
	if use web; then
		insinto /usr/share/patronus/web
		doins -r "${S}/web/static" 2>/dev/null || true
	fi

	# Documentation
	dodoc README.md
	dodoc QUICKSTART.md
	dodoc GENTOO-INTEGRATION.md
	dodoc COMPETITIVE-ANALYSIS.md
	dodoc INNOVATION-ROADMAP.md
	dodoc -r docs/ 2>/dev/null || true

	# Set permissions
	fowners patronus:patronus /var/lib/patronus
	fowners patronus:patronus /var/log/patronus
	fowners patronus:patronus /etc/patronus/openvpn
	fowners patronus:patronus /etc/patronus/ipsec
	fowners patronus:patronus /etc/patronus/unbound
	fowners patronus:patronus /etc/patronus/certificates
	fperms 0750 /etc/patronus
	fperms 0750 /etc/patronus/openvpn
	fperms 0750 /etc/patronus/ipsec
	fperms 0700 /etc/patronus/certificates
}

pkg_postinst() {
	elog "Patronus firewall has been installed."
	elog ""
	if use systemd; then
		elog "To start the web interface (systemd):"
		elog "  systemctl start patronus-web"
		elog "  systemctl enable patronus-web"
		elog ""
		elog "To start the firewall (systemd):"
		elog "  systemctl start patronus-firewall"
		elog "  systemctl enable patronus-firewall"
	fi
	if use openrc; then
		elog "To start the web interface (OpenRC):"
		elog "  rc-service patronus-web start"
		elog "  rc-update add patronus-web default"
		elog ""
		elog "To start the firewall (OpenRC):"
		elog "  rc-service patronus-firewall start"
		elog "  rc-update add patronus-firewall default"
	fi
	elog ""
	elog "Default web interface: http://localhost:8080"
	elog "Configuration: /etc/patronus/patronus.toml"
	elog ""
	elog "Features enabled:"
	use web && elog "  ✓ Web interface"
	use cli && elog "  ✓ CLI tool"
	use api && elog "  ✓ REST API"
	use vpn && use wireguard && elog "  ✓ WireGuard VPN"
	use vpn && use openvpn && elog "  ✓ OpenVPN"
	use vpn && use ipsec && elog "  ✓ IPsec VPN"
	use dns && elog "  ✓ DNS Resolver (Unbound)"
	use dhcp && elog "  ✓ DHCP Server"
	use multiwan && elog "  ✓ Multi-WAN with failover"
	use ha && elog "  ✓ High Availability"
	use intrusion-detection && elog "  ✓ IDS/IPS (Suricata)"
	use qos && elog "  ✓ Traffic Shaping/QoS"
	use certificates && use acme && elog "  ✓ ACME/Let's Encrypt"
	use geoip && elog "  ✓ GeoIP blocking"
	elog ""
	elog "See documentation in /usr/share/doc/${PF}/"
	elog ""
	elog "Quick start guide: /usr/share/doc/${PF}/QUICKSTART.md"
	elog "Gentoo integration: /usr/share/doc/${PF}/GENTOO-INTEGRATION.md"
}
