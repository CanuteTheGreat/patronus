# Gentoo test image for the lane D (LAN services) netlab: a real Gentoo
# stage3 with the daemons Patronus drives installed from Gentoo's official
# binary package host, so the test exercises the SAME OpenRC scripts /
# systemd units and config paths a Gentoo box uses.
#
#   INIT=openrc   -> gentoo/stage3:amd64-openrc  (rc-service path)
#   INIT=systemd  -> gentoo/stage3:amd64-systemd (systemctl path, PID 1 = systemd)
#
# Built by ci/netlab/lan-services.sh only when the tag for this file's hash
# is not in the registry yet (then pushed), so per-commit runs just pull it.
ARG INIT=openrc
FROM gentoo/stage3:amd64-${INIT}

# Same reason as Dockerfile/Dockerfile.ci-base: Portage's namespace sandboxes
# need unshare(2), which a docker build layer does not allow.
RUN echo 'FEATURES="${FEATURES} -sandbox -usersandbox -ipc-sandbox -network-sandbox -pid-sandbox"' \
      >> /etc/portage/make.conf

RUN emerge-webrsync -q

# Daemons Patronus manages (kea, dnsmasq, radvd, unbound, chrony; lane F:
# strongSwan for IPsec, wireguard-tools) + test
# clients (dhcpcd for DHCPv4/v6, dig from bind, rdisc6 from ndisc6, curl,
# python for the fake DDNS endpoint) + nftables/iproute2 for patronus apply.
RUN emerge --getbinpkg --usepkg --quiet-build --noreplace \
      net-misc/kea net-dns/dnsmasq net-misc/radvd net-dns/unbound net-misc/chrony \
      net-misc/dhcpcd net-dns/bind net-firewall/nftables sys-apps/iproute2 \
      net-misc/curl dev-lang/python \
      net-vpn/strongswan net-vpn/wireguard-tools \
 && emerge --quiet-build --noreplace net-misc/ndisc6 \
 && rm -rf /var/cache/distfiles/* /var/cache/binpkgs/*

RUN for b in kea-dhcp4 kea-dhcp6 dnsmasq radvd unbound chronyd dhcpcd dig rdisc6 nft ip curl python3 swanctl wg nsenter; do \
      command -v "$b" >/dev/null || { echo "missing $b"; exit 1; }; done
