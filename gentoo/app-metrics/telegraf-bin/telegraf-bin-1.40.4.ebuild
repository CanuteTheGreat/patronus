# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v3

EAPI=8

inherit unpacker

DESCRIPTION="Plugin-driven metrics collection agent (official prebuilt release)"
HOMEPAGE="https://www.influxdata.com/time-series-platform/telegraf/"
SRC_URI="
	amd64? ( https://dl.influxdata.com/telegraf/releases/telegraf-${PV}_linux_amd64.tar.gz )
	arm64? ( https://dl.influxdata.com/telegraf/releases/telegraf-${PV}_linux_arm64.tar.gz )
"
S="${WORKDIR}/telegraf-${PV}"

LICENSE="MIT"
SLOT="0"
KEYWORDS="-* amd64 arm64"
RESTRICT="strip mirror"
QA_PREBUILT="usr/bin/telegraf"

# Patronus runs the daemon itself (patronus-daemon@telegraf, under this account), so only the
# binary is installed: no service files, no default config that would start collecting.
RDEPEND="
	acct-group/telegraf
	acct-user/telegraf
"
BDEPEND="$(unpacker_src_uri_depends)"

src_install() {
	dobin usr/bin/telegraf
}
