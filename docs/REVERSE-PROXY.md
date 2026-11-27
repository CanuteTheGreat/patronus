# Reverse proxy / load balancer

Page: **Reverse proxy** (`/svc/revproxy`), API `/api/svc/revproxy`, USE flag / cargo feature `reverse-proxy`
(Gentoo: `net-proxy/haproxy`; the Packages page can install it on an image). The embedded router images do not
carry it (flash size); the System page lists it as left out and says why.

## Model

| Table | What it is |
|---|---|
| Frontends | A listener: name, firewall interface, listen address, port, mode (http/tcp), TLS + PEM file, HTTP-to-HTTPS redirect, default backend |
| Backends | A server pool: mode, balance (roundrobin, leastconn, source, uri, random), health check (none/tcp/http + path, interval, rise, fall), sticky cookie |
| Servers | Members of a backend: address, port, weight, backup |
| Rules | Host name and/or path prefix on a frontend -> backend (lowest order first). In tcp mode the host is the TLS server name (SNI), so TLS can be routed without terminating it |

Every operational value is a typed setting (timeouts, maximum connections, oldest TLS version, check
intervals, ...), stored in the configuration (export / plan / apply / history / rollback).

## Rules of the road

* **Publish a LAN service** creates frontend, backend, server, optional host rule and switches the feature on;
  the firewall opens exactly each enabled frontend's port on its interface (`svc_rules.rs`).
* The generated `haproxy.cfg` is written as a candidate and checked with `haproxy -c` first. A refused
  configuration is an error, the change is undone and the running proxy is not touched.
* A listener on a port the web UI uses (any address overlap), or on another frontend's port, is refused when it
  is saved, with the reason. Move the web UI (System > Web UI) to a management address or port first.
* Statistics are haproxy's own (`show stat` on its local admin socket), never invented. Nothing is exposed on
  the network for them.
* Certificates: one PEM file (chain + key) per TLS frontend today. Certificates from the ACME / CA manager
  plug in here once that manager lands.

## Tests

* Unit: `patronus-network` `revproxy::tests` (config rendering, problems, stats parsing, publish),
  `patronus-firewall` `svc_rules` (reverse proxy rule).
* Netlab `lane-n-reverse-proxy.sh`: internet client -> LAN servers by host name, balancing, health-check
  failover and recovery, TLS frontend certificate, refused invalid config keeps the old one serving, web UI port
  conflict, reboot, off. `lane-n-reverse-proxy-ui.sh`: the page in Firefox (phone width, light and dark).
* a11y gate page `reverse-proxy` (axe, both widths, both colour schemes).
