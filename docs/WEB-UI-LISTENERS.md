# Where the web UI listens

A router's UI is expected at `https://router-address` (and `http://router-address` should lead there), like OpenWrt,
pfSense and OPNsense. Patronus does this by default, on every tier, and every part of it is a setting.

| What | Default | Setting |
|---|---|---|
| HTTPS port | 443 | `web.https_port` |
| Plain HTTP port (only redirects to HTTPS, serves nothing else, sets no cookie) | 80 | `web.http_redirect_port`, 0 = off |
| Extra HTTPS ports (an opt-in, e.g. `8443` for old bookmarks and scripts) | none | `web.extra_https_ports`, `none` = off |
| Listen addresses (literal IPs) | `0.0.0.0` | `web.listen` |
| TLS certificate and key (PEM paths, both or neither) | the generated self-signed one in `/etc/patronus/tls` | `web.tls_cert`, `web.tls_key` |

## Layers

Each layer replaces the one before it, key by key:

1. built-in defaults (above): the standard ports only, 443 and 80;
2. environment: `PATRONUS_HTTPS_PORT`, `PATRONUS_HTTP_REDIRECT_PORT`, `PATRONUS_WEB_EXTRA_HTTPS_PORTS`,
   `PATRONUS_WEB_LISTEN`, `PATRONUS_TLS_CERT`, `PATRONUS_TLS_KEY` (images and containers; the router tier's
   `embedded.env` sets 443 / 80);
3. `[web]` in `/etc/patronus/patronus.toml` (`listen_addr`, `https_port`, `http_redirect_port`, `extra_https_ports`,
   `tls_cert`, `tls_key`). The old `listen_port` and `use_tls` keys were never read and are gone: TLS is always on;
4. the config store (`system_config` `web.*`): the System page, `GET/PUT /api/system/web`, export/plan/apply,
   backups and GitOps all use it.

`patronus-web --help` prints the same list; `--version` prints the version. Neither starts a server.

## Other service ports

Two more listeners are settings with the same layers (built-in < environment < `patronus.toml` < config store) and
the same API/UI path (`GET/PUT /api/system/ports`, System page card "Service ports"; export, backups and GitOps carry the
`system_config` keys):

| What | Default | Setting | Environment | `patronus.toml` |
|---|---|---|---|---|
| Parental time limits: the "time's up" page (plain HTTP) | 8081 | `time.portal_port` | `PATRONUS_TIMEUP_PORT` | `[time] portal_port` |
| HAProxy statistics page (HA setups, admin password required) port | 8404 | `haproxy.stats_port` | `PATRONUS_HAPROXY_STATS_PORT` | `[haproxy] stats_port` |
| HAProxy statistics page bind address | `127.0.0.1` | `haproxy.stats_bind` | `PATRONUS_HAPROXY_STATS_BIND` | `[haproxy] stats_bind` |

The time's-up page is its own listener and does not default to a standard port on purpose: it is an HTTP landing page,
and port 80 is the web UI's HTTP -> HTTPS redirect listener (`web.http_redirect_port`); two listeners cannot share a port.
It therefore stays on 8081 unless you set it. Validation refuses 0, any port the web UI uses, and the SSH / DNS / DHCP / NTP
ports. The firewall follows the value: the `inet patronus_time` table redirects blocked devices' HTTP to it and lets
`tcp dport { 53, <port> }` through, and the main table's input accept for the page opens the same port. The old
`lan_settings` key `seg.time_portal_port` is still read when `time.portal_port` is unset. The listener moves when the web
UI restarts. `docker-compose.ha.yml` takes the HAProxy port from `HAPROXY_STATS_PORT` (default 8404) and the address from
`HAPROXY_STATS_BIND` (default `*` inside the container); `haproxy/haproxy.cfg` reads both.

## Changing it safely

`PUT /api/system/web` validates the combination (ports differ, certificate and key come as a pair, addresses are IPs),
stores it and re-applies the firewall, so the anti-lockout rule opens the new ports immediately. The listeners move
when the web UI is restarted (System page button, or `POST /api/system/services/patronus-web/restart`): a wrong value
can still be corrected on the old address first. Keep the old port as an extra HTTPS port until the new one works (e.g. `extra_https_ports` = `8443`).

The anti-lockout rule (SSH port + every web port, LAN only) is rendered from these settings on every apply, in the
normal ruleset and in the lockdown fallback.

## Privileges

The web UI runs as the unprivileged `patronus` user. Ports below 1024 need `CAP_NET_BIND_SERVICE`, which both init
systems grant next to `CAP_NET_ADMIN` / `CAP_NET_RAW` (OpenRC `capabilities="^cap_net_admin,^cap_net_raw,^cap_net_bind_service"`,
systemd `AmbientCapabilities=` and `CapabilityBoundingSet=`). `ci/check-web-listen-units.sh` fails the build when either
file loses it. A listener that cannot be bound is logged and skipped; the process exits only when no HTTPS listener could
be bound at all.

## Proof

`ci/netlab/lane-w-web-ports.sh` (real binary as an unprivileged user with exactly those capabilities), the
`patronus-web` listener tests, `patronus-config` `webui` tests, and the `installed-firstrun` VM gate (OpenRC and systemd
installed images answer on 443, redirect on 80 and still serve 8443).

## The container image

The image runs as the unprivileged `patronus` user, which cannot bind ports below 1024, so its `Dockerfile` sets the
deployment default through the environment layer (`PATRONUS_HTTPS_PORT=8443`, `PATRONUS_HTTP_REDIRECT_PORT=0`) and
`docker-compose.yml` publishes it on the standard port (`443:8443`). A host install listens on 443 and 80 itself.
