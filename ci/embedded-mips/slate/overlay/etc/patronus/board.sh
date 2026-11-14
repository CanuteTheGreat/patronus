# GL-AR750S board facts (sourced by rcS and the init scripts). Per-unit values (MACs that match DHCP
# reservations, the management subnet allowed in over the WAN, the guard's gateway) come from
# /etc/patronus/unit.conf, which assemble.sh installs from the unit's private directory.
WAN_IF=wl24-sta                # Wi-Fi client uplink (repeater) on the 2.4 GHz ath9k radio
LAN_IF=br-lan
phy_of() { for p in /sys/class/ieee80211/*; do readlink -f $p/device | grep -q "$1" && basename $p && return; done; }
PHY24=$(phy_of 18100000.wmac)  # ath9k (SoC)
PHY5=$(phy_of 0000:00:00.0)    # ath10k QCA9887 (PCIe)
OWLIB=/usr/lib/openwrt         # swconfig + its libs, copied from OpenWrt 25.12.6
STA_MAC= AP5_MAC= AP24_MAC= MGMT_NET= GUARD_GW=
[ -f /etc/patronus/unit.conf ] && . /etc/patronus/unit.conf
