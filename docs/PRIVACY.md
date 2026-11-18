# Privacy: what a Patronus device sends out

Patronus is a firewall: it should not talk about you. This page lists every connection the software
itself starts (not your own traffic that it forwards), what is sent, and how to turn it off. It was
read from the source code of this version, not a marketing claim; where something could not be confirmed
from the code it says so. A packet-capture test of an idle fresh image is not part of CI yet, so the list
is what the code can do, not a measured trace.

**The short version**

* Patronus sends **no analytics, no usage statistics, no crash reports and no "check-in" or version check
  to the Patronus project or to Errant Solutions**. There is no account, licence key or device identifier.
  Nothing in the code is addressed to a server run by the project.
* **Two background downloads are on by default** (full builds, not router-tier images): an hourly list of
  known-bad addresses, and country and network-owner databases for Traffic Insight. They are plain
  downloads from third-party servers; they send nothing about you, but those servers see your public IP
  address. How to switch each off is in the table.
* Everything else is **off until you configure it**, or only happens when an administrator presses a button.
* Your own traffic is never sent anywhere: country and network-owner lookups for your clients happen on the
  device, against the downloaded file.

Every outgoing request necessarily shows the device's public IP address to the server it contacts. No
request carries a device name, serial number, account or Patronus version; the only identifying text is
an HTTP user-agent such as `Patronus-feeds/1.0` on some requests.

## Background downloads that are on by default

| What | Contacts | Sends | How often | Turn it off |
|---|---|---|---|---|
| Threat list shown on the Monitoring page (full builds with the `threat-feeds` feature; not in router-tier images) | `rules.emergingthreats.net` (the Emerging Threats "compromised IPs" list) | A plain HTTPS GET, no identifiers | At start and then hourly | There is no setting yet. Block the address at the firewall, or build without the `threat-feeds` feature. This is tracked as a gap: every network feature should have an off switch. |
| Country and network-owner (ASN) databases for Traffic Insight and GeoIP aliases (full builds, the `insight` feature, default on) | `download.db-ip.com` (DB-IP "Lite", CC BY 4.0) | A plain GET, user-agent `Patronus-feeds/1.0` | Checked hourly, downloaded again when the file is older than 30 days (setting `refresh_days`); the monthly `patronus-ipdb` job (USE `insight`) does the same | Turn Traffic Insight off in its settings (`insight.enabled`), or point `firewall.geoip.db_url` / `insight.asn.db_url` at your own mirror |

## Only when you configure it or press the button

| Feature | Contacts | When |
|---|---|---|
| Firewall alias feeds (URL tables, GeoIP and threat catalogue entries such as Spamhaus DROP, FireHOL, abuse.ch) | The address of each feed you enable | Only for feeds an administrator created and enabled; refresh interval is per feed (default 24 hours) |
| DNS block lists and family-safe lists | The list addresses you set; the Family policy adds two public lists (StevenBlack hosts, URLhaus filter) | Only when set or when that policy is enabled |
| Router-tier firmware feed | The feed address you enter (there is no default); the request path contains the board name and init type | Only when an administrator clicks "check" or "download"; the image is verified with an OpenPGP signature before use |
| Package install and update (standard tier) | The Portage binary package servers configured on the system (the images are configured for the official Gentoo binary host) | Only when an administrator uses the Packages page or runs `emerge`. Patronus never syncs the package tree or updates itself |
| Internet speed test | `speed.cloudflare.com` by default (editable) | Only when you run it; a schedule is off unless you set `interval_hours` |
| Dynamic DNS | The provider you pick (DynDNS-compatible, DuckDNS, Cloudflare, custom) | Sends the hostname, your WAN address and your credentials to that provider when the address changes; no "what is my IP" service is used |
| Notifications (webhook, ntfy, Telegram, Discord, Slack, email) | The endpoint you configure | An event text (gateway, tunnel, HA, configuration change) when an event matches an enabled hook |
| Remote backups | The address you give (HTTPS PUT, SFTP, FTPS) | On the schedule you set; encrypt the export with a passphrase, the plain export contains secrets |
| Zero-touch provisioning, GitOps | The URL in `patronus.toml` | Only when configured (no default URL) |
| LDAP and RADIUS sign-in | The authentication server you configure | Your login credentials go to that server at sign-in |
| NTP | `pool.ntp.org` when you turn the NTP service on (setting `ntp.servers`) | Standard NTP packets; off by default in Patronus |
| Uplink health probes | Targets you choose (gateway ping; optional TCP, HTTP, DNS probes) | Every few seconds while configured |

## DNS and time defaults

* The DNS resolver defaults to `auto` with **no upstream servers**: Unbound resolves from the root servers
  itself, so no third-party resolver sees your queries. DNS over TLS is off until you set an upstream and its
  certificate name. Router-tier images start in forwarder mode and use the resolver the provider hands out.
* NTP: Patronus writes its own NTP configuration only when you enable the NTP service. The time
  servers an image's own `chrony` package uses are the package defaults, and were not verified here.

## The installer

The live installer, at the end of an install and only if the machine is online, makes plain HTTP `HEAD`
requests to well-known public sites to read the `Date` header and set the clock. Offline, it skips this.
Nothing else leaves the machine during an install.

## Router-tier images and other software on the image

Router-tier images also run an optional management client and agent that are separate products with their
own documentation; what they contact is not described here. The operating system packages on the image
(Gentoo Linux, Unbound, chrony, ...) behave as their own documentation says.

## This website

The product website is static files: no scripts, no cookies, no trackers and no third-party fonts or
images (its content security policy forbids them). Downloads are redirected to the public source host's
release assets.

## How to check this yourself

Watch the device's own outgoing connections for a few hours on a fresh install (for example with
`ss -tnp` or a packet capture on the WAN interface): going by the code you should see the two default
downloads above, DNS, time and nothing else. If you see anything not listed here, that is a bug: report it as described in
[SECURITY.md](../SECURITY.md).
