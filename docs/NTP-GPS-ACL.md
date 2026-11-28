# NTP server: access list and GPS/PPS reference clock

The NTP page (`/ntp`, API `/api/ntp`, USE=ntp) runs chrony. Two things were added to the LAN time server
(claim C1304): a real access list and a GPS receiver (with optional PPS pulse) as a local time source.

## Access list

| Setting (config key) | API field | Meaning |
| --- | --- | --- |
| `ntp.interfaces` | `interfaces` | Served interfaces (`@lan`, `@guest`, a port name). Their subnets become `allow` lines. |
| `ntp.acl_mode` | `acl_mode` | `interfaces` (default): served subnets plus the explicit allow list. `explicit`: ONLY the explicit allow list. |
| `ntp.acl_allow` | `acl_allow` | Extra addresses or CIDR blocks to answer (`allow` lines). |
| `ntp.acl_deny` | `acl_deny` | Addresses or blocks never answered (`deny` lines, written after the allows). |
| `ntp.ratelimit` | `ratelimit` | chrony response rate limiting (`ratelimit interval 3 burst 8 leak 2`), off by default. |

* chrony applies the MOST SPECIFIC matching entry, so a `deny` for one host inside an allowed /24 blocks that host only.
* `/0` blocks are refused (that would serve the internet); a bare address is a host entry; IPv4 and IPv6 both work.
* The ACL decides who chrony answers. Whether packets reach the router at all is the firewall's decision (the
  served-interface rule), so an explicit allow for a network behind another port also needs that port in `interfaces`.
* Entries are validated, sorted and de-duplicated when stored; a bad entry answers 400 and stores nothing.

## GPS / PPS reference clock

| Setting | API field | Default | Meaning |
| --- | --- | --- | --- |
| `ntp.gps.enabled` | `gps_enabled` | off | Use the receiver. |
| `ntp.gps.device` | `gps_device` | `/dev/ttyUSB0` | Serial port (`/dev/tty*`, `/dev/serial/by-id/*`, `/dev/serial/by-path/*`, `/dev/gps*`). |
| `ntp.gps.baud` | `gps_baud` | 9600 | One of 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800. |
| `ntp.gps.pps_device` | `gps_pps_device` | empty | Kernel PPS device (`/dev/pps0`); empty = NMEA time only. |
| `ntp.gps.offset` | `gps_offset` | 0 | Seconds added to the NMEA time (serial latency), -1..1. |
| `ntp.gps.prefer` | `gps_prefer` | off | Prefer the clock over network sources. |

How it works: Patronus writes `/etc/conf.d/gpsd` (read by Gentoo's gpsd OpenRC script and systemd unit:
`GPSD_OPTIONS="-n -s <baud>"`, `DEVICES="<serial> [<pps>]"`) and starts gpsd; chrony reads gpsd's time through
shared-memory segment 0 (`refclock SHM 0`). With a PPS device chrony locks the pulse to the NMEA second
(`refclock PPS /dev/pps0 lock NMEA`), which gives microsecond accuracy; without it the accuracy is a few
milliseconds. With a clock the router serves stratum 1 and keeps serving exact time while the internet is down.

* chronyd refuses to start when a `refclock PPS` names a missing device, which would also stop the router's own
  time sync. A missing PPS device therefore falls back to NMEA only, with a warning in the apply report, until the
  next apply finds the device (hotplug: re-apply or save the page).
* Turning the GPS off removes the refclock lines and stops and disables gpsd.
* USE=gps pulls `sci-geosciences/gpsd` (needs USE=ntp). Without gpsd installed, enabling the GPS answers an
  error naming the package; nothing is half-applied.
* The page shows gpsd (installed/running), whether the serial port and the PPS device exist, and a phone-width layout.

## Both init systems

gpsd and chronyd are driven through the same service abstraction as every LAN daemon: OpenRC (`rc-service`,
`rc-update`) or systemd (`systemctl`), detected at runtime. The config file is shared by both.

## Proof

* Unit tests: `patronus-network` `ntp::tests` (validation, rendering, gpsd follows the setting, missing gpsd, missing PPS).
* Netlab `lane-j-ntp.sh`: a real chronyd answers a LAN client; a denied host gets no answer, `explicit` mode answers
  only the listed hosts and blocks; a fake NMEA receiver on a pty drives a real gpsd whose time chrony reads as the
  `GPS` source; GPS off removes it. `lane-j-ntp-ui.sh` drives the page in Firefox (`ci/ntp-page-e2e.py`).
* Not proven in CI: a real PPS pulse needs hardware (`/dev/pps0`); the rendered `refclock PPS` line and the
  fallback are unit-tested, the pulse itself is not.
