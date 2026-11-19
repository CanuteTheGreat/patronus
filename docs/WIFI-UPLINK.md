# Wi-Fi uplink (station mode WAN)

With `USE=wifi-client` (on by default) a wireless device can join an upstream
access point and become an uplink like a wired WAN: the typical use is the
backup line of a router whose second internet connection only exists as a
Wi-Fi network (a satellite or mobile router's own Wi-Fi), the way an OpenWrt
router uses a `wifi-iface` in `mode sta` behind mwan3. `patronus import-uci`
imports such an OpenWrt setup.

## Layering

The Wi-Fi uplink only **associates** the device (one `wpa_supplicant` per
device, `crates/patronus-network/src/wifi_client.rs`, table `wifi_clients`).
Everything else is the normal uplink machinery, with no Wi-Fi special case:

| What | Where |
|---|---|
| association (SSID, WPA2/WPA3 passphrase, optional BSSID) | `PUT /api/wifi/uplinks/<device>` |
| address (DHCP), role (`wan` / `optN`), metric | Interfaces page / `PUT /api/interfaces/<device>` |
| gateway (dynamic: learned from the DHCP default route) + monitor | Routing page / `POST /api/routing/gateways` |
| failover / load balancing | gateway group (USE=multiwan) as the default gateway |
| outbound NAT | automatic for every interface that carries a gateway |

## API

- `GET /api/wifi/uplinks`: `available` (wpa_supplicant installed),
  `iwd_running`, and per uplink: `device`, `ssid`, `security`, `has_psk`
  (the passphrase is never returned), `running`, `connected`, `wpa_state`,
  `bssid` (the configured pin, if any), `ap_bssid` (the access point it is
  associated with), `freq`, `signal`, `ip_address` and `problem`: one sentence when it
  is not connected ("authentication with ... keeps failing ... most likely a
  wrong passphrase", "no access point named ... in range", "the wireless device
  is down or blocked (rfkill)", "wpa_supplicant is not installed").
- `PUT /api/wifi/uplinks/<device>` (admins): `{"ssid", "security":
  "wpa2|wpa3|wpa2-wpa3|open", "psk", "bssid", "enabled", "description"}`. An
  empty `psk` keeps the stored one. The change is snapshotted in the config
  history, applied at once, and undone if the apply fails.
- `DELETE /api/wifi/uplinks/<device>` (admins): wpa_supplicant stops and its
  config (which holds the passphrase) is removed.

## iwd

The Gentoo image also carries iwd (the live system uses it to join Wi-Fi
during installation). iwd takes every wireless device it sees, so it and
wpa_supplicant must never run on the same radio. When a Wi-Fi uplink is
configured, the apply stops iwd, removes it from the boot runlevel / disables
the unit (OpenRC and systemd) and says so in its output ("iwd stopped,
disabled at boot: Patronus runs wpa_supplicant on wlan0"). If iwd is still
running afterwards, no wpa_supplicant is started and the apply warns. When
the last uplink is removed, iwd is enabled and started again, but only if
Patronus was the one that stopped it and no Patronus access point uses a
radio.

iwd also deletes the kernel's device of every radio it takes and creates its
own (named `wlan<phy number>`); when it stops, the kernel removes those, so
the radio is left with no device at all. The apply then creates the uplink's
device again on its radio (`iw phy <phy> interface add <device> type
managed`): the radio named like the device (`wlanN` = `phyN`), else the only
radio without a device; with several candidates it refuses and says why.
After that it applies the interface settings again so the DHCP client runs on
the new device.

## Lost default route after a link bounce

When a device goes administratively down and up (wpa_supplicant takes its
device down when it restarts, e.g. after a passphrase change), the kernel
drops every route of the device while the DHCP address stays. busybox udhcpc
does not watch the link, so the default route would only come back at the
next lease renewal, hours later, and the gateway would stay down. The gateway
monitor therefore asks the DHCP client of a dynamic IPv4 gateway's device for
a renew (udhcpc: SIGUSR1, dhcpcd: `-n`) when the device has carrier and a DHCP
address but no default route, at most once per `routing.dhcp_renew_secs`
(`system_config`, default 30, 0 = never). This applies to every DHCP uplink,
wired or not.

## Services

`patronus-wpa@<device>.service` (systemd) and `/etc/init.d/patronus-wpa.<device>`
(OpenRC, a symlink to `patronus-wpa`, supervise-daemon) run the command line
and the 0600 config that `patronus apply` writes under
`/var/lib/patronus/net`. Do not enable them by hand: the boot apply starts
them (services phase), and the DHCP client started in the interfaces phase
gets its lease once the association completes.

## Proof

`ci/netlab/lane-s-wifi-client-hwsim.sh` (run by `ci/netlab/wifi-hwsim.sh`):
an upstream WPA2 access point with a DHCP server on one simulated radio, the
router's uplink on another, a gateway group with the wired WAN as tier 1 and
the Wi-Fi uplink as tier 2; the wired WAN's link goes down and up, a wrong
passphrase, a reboot. The upstream network routes without NAT, so the
internet host seeing the router's Wi-Fi lease address proves the router's own
NAT on the wlan.

Not proven: real radio hardware (driver quirks, roaming, power saving,
regulatory limits of a specific card).
