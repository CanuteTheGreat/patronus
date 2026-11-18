# GL.iNet GL-AX1800 (Flint, IPQ6018) board facts (sourced by early, board-network, ap, apply).
# Role: a wired "dumb" access point: every Ethernet port bridged into br-lan, address by DHCP (or AP_ADDR), no DHCP/DNS
# server, Wi-Fi from /etc/patronus/ap.env. Per-unit values (address, SSIDs, passphrases) are never part of the image
# source: assemble.sh installs them from the unit's private directory (UNIT_DIR/ap.env), see ap.env.example.
ROLE=ap
LAN_IF=br-lan
PORTS="lan1 lan2 lan3 lan4 wan"      # DT labels of the QCA8075 ports (qca-nss-dp names them like this)
OWLIB=/usr/lib/openwrt
AP_COUNTRY=00                         # 00 = world regulatory domain until ap.env sets one
AP_CHAN24=auto AP_CHAN5=auto AP_HT5=80 AP_FT=0 AP_HE=1   # AP_HE=0: no 802.11ax (see libexec/patronus/ap)
# channel plan defaults (libexec/patronus/ap header): ACS picks among 1/6/11 on 2.4 GHz and the non-DFS 5 GHz channels
AP_HT24=20 AP_DFS=0 AP_UNII4=0 AP_CHANLIST24="1 6 11" AP_CHANLIST5= AP_ACS_SCANS=5
# channel coordination between this network's access points (libexec/patronus/ap-coord): ACS avoids the blocks the other units use
AP_COORD24=1 AP_COORD5=1 AP_COORD_PEERS= AP_COORD_MIN_SIGNAL=-90 AP_COORD_DELAY=120 AP_COORD_INTERVAL=3600 AP_COORD_QUIET=1-5 AP_COORD_SCAN_SECS=25
# the radios' HT/VHT capabilities as OpenWrt 25.12 derives them from `iw phy info` on this board (IPQ6018 ath11k)
AP_HTCAPS24='[LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1][DSSS_CCK-40]'
AP_HTCAPS5='[LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1][MAX-AMSDU-7935][DSSS_CCK-40]'
AP_VHTCAPS5='[RXLDPC][SHORT-GI-80][TX-STBC-2BY1][SU-BEAMFORMER][SU-BEAMFORMEE][MU-BEAMFORMER][MU-BEAMFORMEE][RX-ANTENNA-PATTERN][TX-ANTENNA-PATTERN][RX-STBC-1][SOUNDING-DIMENSION-2][BF-ANTENNA-4][MAX-MPDU-11454][MAX-A-MPDU-LEN-EXP7]'
AP_SSIDS= AP_ADDR= AP_GW= AP_DNS=
[ -f /etc/patronus/ap.env ] && . /etc/patronus/ap.env
