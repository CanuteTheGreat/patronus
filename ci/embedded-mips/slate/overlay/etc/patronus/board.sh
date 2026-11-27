# GL-AR750S board facts (sourced by rcS and the init scripts). Per-unit values (MACs that match DHCP
# reservations, the management subnet allowed in over the WAN, the guard's gateway) come from
# /etc/patronus/unit.conf, which assemble.sh installs from the unit's private directory.
WAN_IF=wl24-sta                # Wi-Fi client uplink (repeater) on the 2.4 GHz ath9k radio
LAN_IF=br-lan
phy_of() { for p in /sys/class/ieee80211/*; do readlink -f $p/device | grep "$1" >/dev/null && basename $p && return; done; }
PHY24=$(phy_of 18100000.wmac)  # ath9k (SoC)
RADIO5_PCI=0000:00:00.0        # ath10k QCA9887 (PCIe): its PCI address (kernel log tag, driver rebind)
RADIO5_DRV_DIR=/sys/bus/pci/drivers/ath10k_pci
PHY5=$(phy_of $RADIO5_PCI)
OWLIB=/usr/lib/openwrt         # swconfig + its libs, copied from OpenWrt 25.12.6
# Uplink on BOTH bands: the 5 GHz client is the preferred uplink (metric 100), the 2.4 GHz one the fallback (150).
# Each radio runs one channel, so every AP follows the client of its own radio (wifi-follow: "sta:ap:hostapd-conf").
WAN5_IF=wl5-sta                # 5 GHz client (ath10k): same networks as the 2.4 GHz one, pinned to the 5 GHz channels
AP5_IF=wl5-ap
AP24_IF=wl24-ap
FOLLOW="wl5-sta:wl5-ap:ap5 wl24-sta:wl24-ap:ap24"
FREQ5="5180 5200 5220 5240 5260 5280 5300 5320 5500 5520 5540 5560 5580 5600 5620 5640 5660 5680 5700 5720 5745 5765 5785 5805 5825"
# Both clients usually join the SAME upstream network, so the box is multi-homed in one subnet (two addresses, two MACs).
# Each uplink then answers ARP only for its own address and replies leave by the uplink their address belongs to
# (source routing: one table + one `ip rule from <addr>` per uplink, kept by wifi-follow). UPLINK_TABLES lists
# "<sta_if>:<table>:<rule pref>"; the defaults stay clear of the Patronus routes applier (table 4250, prefs 31000-31999).
UPLINKS="$WAN5_IF $WAN_IF"
UPLINK_TABLES="$WAN5_IF:4241:30241 $WAN_IF:4242:30242"
STA_MAC= STA5_MAC= AP5_MAC= AP24_MAC= MGMT_NET= GUARD_GW=
# 5 GHz Wi-Fi uplink (typed: on|off; per unit in unit.conf, shown on System > Hardware settings with this reason).
# Board default OFF (docs/embedded-routers.md 6h): the QCA9887's firmware stalls when its one radio is a client AND an access
# point (beacon overruns, firmware restarts every 1-2 min in bursts, and once a firmware that answered nothing until a restart),
# and while the AP holds a channel the client cannot join a better network on another one. The 2.4 GHz client is the uplink
# and the 5 GHz radio serves the access point only. With UPLINK5=on, wifi-follow's radio watchdog drops the 5 GHz client when
# its firmware restarts or wedges (RADIO_* there) and the 2.4 GHz client carries on.
UPLINK5_DEFAULT=off
UPLINK5=$UPLINK5_DEFAULT
UPLINK5_REASON="Off by default on this board: the 5 GHz radio (QCA9887) cannot reliably be a Wi-Fi client and an access point at the same time; its firmware stalls and restarts, and the client can only join networks on the access point's channel. The 2.4 GHz client carries the uplink."
UPLINK5_HOW="Set UPLINK5=on in /etc/patronus/unit.conf (or the unit's image settings) and restart; a radio watchdog then drops the 5 GHz client if its firmware fails."
# Management address failover (typed: on|off; per unit in unit.conf; docs/embedded-routers.md 6i). The primary client's address (the
# upstream reservation the house reaches the unit by) moves to a surviving uplink within seconds when the primary loses its Wi-Fi
# link (e.g. the upstream access point restarts that radio) and moves back when the primary is up again. It needs a second
# connected uplink (UPLINK5=on): with one uplink there is nothing to move to.
MGMT_FAILOVER_DEFAULT=on
MGMT_FAILOVER=$MGMT_FAILOVER_DEFAULT
MGMT_FAILOVER_AFTER=4          # seconds the primary must be down before its address moves (typed number, 1-600)
MGMT_FAILOVER_REASON="On by default: with two Wi-Fi uplinks the unit's reserved address belongs to one of them, and it would vanish with that uplink (an upstream access point restarting a radio takes it away for ~35 s) although the other uplink is up. The address is carried by the surviving uplink and announced with gratuitous ARP."
MGMT_FAILOVER_HOW="Set MGMT_FAILOVER=off (or MGMT_FAILOVER_AFTER=<seconds>) in /etc/patronus/unit.conf (or the unit's image settings) and restart. It only acts while a second uplink is connected (UPLINK5=on)."
# NOR kernel slots (patronus-flash kernel ..., /usr/libexec/patronus/nor-kernel; docs/embedded-routers.md 6e). GL's U-Boot always
# boots the uImage at KSLOT_P_ADDR (the `kernel` partition); the trial kernel and the previous kernel live in OpenWrt's unused
# `nor_reserved` partition. Only these partitions are ever written; u-boot and art never are (KSLOT_NEVER).
KSLOT_P_MTD=kernel           KSLOT_P_OFF=0         KSLOT_P_ADDR=0x9f060000   # the committed kernel (what U-Boot boots)
KSLOT_T_MTD=nor_reserved     KSLOT_T_OFF=0         KSLOT_T_ADDR=0x9f460000   # trial kernel (booted by the U-Boot script while armed)
KSLOT_K_MTD=nor_reserved     KSLOT_K_OFF=0x400000  KSLOT_K_ADDR=0x9f860000   # previous kernel (kept by a commit: kernel-rollback)
KSLOT_SIZE=0x400000          # bytes per slot (= the kernel partition)
KSLOT_ENV_MTD=u-boot-env     KSLOT_ENV_SIZE=0x10000  KSLOT_ENV_CRC=be        # U-Boot 1.1.4 CFG_ENV_SIZE, CRC stored big-endian
KSLOT_WRITABLE="u-boot-env kernel nor_reserved"
KSLOT_NEVER="u-boot art"
KSLOT_UBOOT_MTD=u-boot
KSLOT_REQUIRE_REHEARSAL=1    # `install` needs a passed `rehearse` on this unit's bootloader (proves U-Boot's counter on the real flash)
KSLOT_TRIES=3                # trial boots U-Boot gives a new kernel before it falls back to the committed one
# bootloader builds whose boot flow (`run lf` before `bootm KSLOT_P_ADDR`) the trial script was proven against: sha256 of the
# whole u-boot partition, and that build's default environment (used when the unit never saved one: bad CRC on the stock unit)
KSLOT_UBOOT_PROVEN="6788d77c975e4e7c1020ea70aec0a19cc270ec899f968734854394b93027d2b7:/usr/share/patronus/uboot/gl-ar750s-1.1.4-gcf378d80.env"
KSLOT_KERNEL_DIR=/usr/share/patronus/kernel   # kernels this root may install (<name>.uImage + SHA256SUMS); the root has their modules
KSLOT_STATE=/data/kernel     # events + trial record (persistent)
[ -f /etc/patronus/unit.conf ] && . /etc/patronus/unit.conf
case "$UPLINK5" in on|off) ;; *) echo "board.sh: UPLINK5=$UPLINK5 is not on|off: using $UPLINK5_DEFAULT" >&2; UPLINK5=$UPLINK5_DEFAULT ;; esac
case "$MGMT_FAILOVER" in on|off) ;; *) echo "board.sh: MGMT_FAILOVER=$MGMT_FAILOVER is not on|off: using $MGMT_FAILOVER_DEFAULT" >&2; MGMT_FAILOVER=$MGMT_FAILOVER_DEFAULT ;; esac
case "$MGMT_FAILOVER_AFTER" in ''|*[!0-9]*) MGMT_FAILOVER_AFTER=4 ;; *) [ "$MGMT_FAILOVER_AFTER" -ge 1 ] && [ "$MGMT_FAILOVER_AFTER" -le 600 ] || MGMT_FAILOVER_AFTER=4 ;; esac
# neither the SoC Wi-Fi radio nor a device-tree Ethernet port = not a Slate (an emulator, the QEMU gate): no switch, no Wi-Fi uplinks or APs to
# follow (board-network bridges eth0 flat). A real unit whose radio driver failed still has its device-tree eth0 and keeps the switch setup.
# unit.conf can force either way with NO_BOARD=0|1.
[ -n "${NO_BOARD:-}" ] || { { [ -n "$PHY24" ] || [ -e /sys/class/net/eth0/device/of_node ]; } && NO_BOARD=0 || NO_BOARD=1; }
[ "$NO_BOARD" = 1 ] && FOLLOW=
