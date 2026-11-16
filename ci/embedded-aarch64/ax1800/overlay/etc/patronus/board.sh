# GL.iNet GL-AX1800 (Flint, IPQ6018) board facts (sourced by early, board-network, ap, apply).
# Role: a wired "dumb" access point: every Ethernet port bridged into br-lan, address by DHCP (or AP_ADDR), no DHCP/DNS
# server, Wi-Fi from /etc/patronus/ap.env. Per-unit values (address, SSIDs, passphrases) are never part of the image
# source: assemble.sh installs them from the unit's private directory (UNIT_DIR/ap.env), see ap.env.example.
ROLE=ap
LAN_IF=br-lan
PORTS="lan1 lan2 lan3 lan4 wan"      # DT labels of the QCA8075 ports (qca-nss-dp names them like this)
OWLIB=/usr/lib/openwrt
AP_COUNTRY=00                         # 00 = world regulatory domain until ap.env sets one
AP_CHAN24=auto AP_CHAN5=auto AP_HT5=80 AP_FT=0
AP_SSIDS= AP_ADDR= AP_GW= AP_DNS=
[ -f /etc/patronus/ap.env ] && . /etc/patronus/ap.env
