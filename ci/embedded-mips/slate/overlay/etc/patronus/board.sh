# GL-AR750S board facts (sourced by rcS and the init scripts). Per-unit values (MACs that match DHCP
# reservations, the management subnet allowed in over the WAN, the guard's gateway) come from
# /etc/patronus/unit.conf, which assemble.sh installs from the unit's private directory.
WAN_IF=wl24-sta                # Wi-Fi client uplink (repeater) on the 2.4 GHz ath9k radio
LAN_IF=br-lan
phy_of() { for p in /sys/class/ieee80211/*; do readlink -f $p/device | grep "$1" >/dev/null && basename $p && return; done; }
PHY24=$(phy_of 18100000.wmac)  # ath9k (SoC)
PHY5=$(phy_of 0000:00:00.0)    # ath10k QCA9887 (PCIe)
OWLIB=/usr/lib/openwrt         # swconfig + its libs, copied from OpenWrt 25.12.6
# Uplink on BOTH bands: the 5 GHz client is the preferred uplink (metric 100), the 2.4 GHz one the fallback (150).
# Each radio runs one channel, so every AP follows the client of its own radio (wifi-follow: "sta:ap:hostapd-conf").
WAN5_IF=wl5-sta                # 5 GHz client (ath10k): same networks as the 2.4 GHz one, pinned to the 5 GHz channels
AP5_IF=wl5-ap
AP24_IF=wl24-ap
FOLLOW="wl5-sta:wl5-ap:ap5 wl24-sta:wl24-ap:ap24"
FREQ5="5180 5200 5220 5240 5260 5280 5300 5320 5500 5520 5540 5560 5580 5600 5620 5640 5660 5680 5700 5720 5745 5765 5785 5805 5825"
STA_MAC= STA5_MAC= AP5_MAC= AP24_MAC= MGMT_NET= GUARD_GW=
[ -f /etc/patronus/unit.conf ] && . /etc/patronus/unit.conf
