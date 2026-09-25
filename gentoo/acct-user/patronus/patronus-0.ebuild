# Copyright 2025 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit acct-user

DESCRIPTION="System user for net-firewall/patronus"

ACCT_USER_ID="-1"
ACCT_USER_GROUPS=( patronus )
ACCT_USER_HOME="/var/lib/patronus"
ACCT_USER_HOME_OWNER="patronus:patronus"
ACCT_USER_HOME_PERMS="0750"
ACCT_USER_SHELL="/sbin/nologin"

DEPEND="acct-group/patronus"
RDEPEND="${DEPEND}"
