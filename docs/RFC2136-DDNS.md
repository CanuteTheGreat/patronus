# RFC 2136 dynamic DNS client (USE=rfc2136)

Keeps A and AAAA records on your own authoritative DNS server (BIND, Knot,
PowerDNS, NSD) equal to the address of one of the router's interfaces, using
RFC 2136 UPDATE signed with a TSIG key. This is the Patronus equivalent of
pfSense's "RFC 2136" dynamic DNS client type and the OPNsense ddclient backend.
The provider-based client (dyndns2, DuckDNS, Cloudflare, custom URL) is a
separate page, see `docs/FEATURE-PARITY.md`.

* Page: **Services -> Dynamic DNS (RFC 2136)** (`/svc/rfc2136`, API `/api/svc/rfc2136`).
* Settings (`lan_settings`, `rfc2136.*`): `enabled`, `interval` (seconds between
  address checks, default 60), `refresh` (re-send even when nothing changed,
  default 86400, 0 = only on change), `timeout` (seconds one update may take, default 15).
* Clients (table `rfc2136_clients`, migration 0955): host name (must be inside the
  zone), zone, server, port (53), TCP, TSIG key name, algorithm (`hmac-sha256`,
  `hmac-sha384`, `hmac-sha512`), TSIG secret (base64, write-only), interface
  (`@wan`, `@lan`, `@optN` or a device), records (`ipv4`, `ipv6`, `both`), TTL, enabled.
  A host name can appear once.
* Engine: `patronus rfc2136 run --conf FILE` under the daemon supervisor
  (`patronus-daemon@rfc2136`, OpenRC and systemd). Every `interval` seconds it reads
  the interface addresses (a public IPv4 is preferred over a private one; for IPv6 a
  global address, a /128 from DHCPv6 first) and runs `nsupdate` (net-dns/bind-tools)
  when an address changed, the `refresh` is due, or the last attempt failed (back-off
  `interval * 2^n`, at most 15 minutes). The update deletes the host's A/AAAA RRset
  and adds the current address in one signed message.
* Secrets: the engine file is mode 0600 (it carries the secrets); nsupdate gets a key
  file in the run directory (mode 0600, removed after every call), never a command-line
  secret. The API, the page, `patronus rfc2136 show` and the rendered view show `********`.
* Status: the page lists one line per client (`ok`, `FAILED` with the server's answer
  such as `tsig verify failure`, or `waiting: no address on the interface yet`).
* The router only needs outbound reachability to the server (UDP/TCP 53); no firewall rule is added.
* Server side: allow the key for the zone, e.g. BIND `allow-update { key "ddns-key"; };`,
  Knot `acl: - id: ddns / key: ddns-key / action: update`.
* Not supported: GSS-TSIG, SIG(0), updating a different primary per record type.
* Embedded (AP/Slate) images: not included (nsupdate is not in the explicit feature list);
  the standard tier is the target of this feature.
* Proof: unit tests in `patronus-network/src/rfc2136.rs`; netlab lane
  `ci/netlab/lane-j-rfc2136.sh` (real BIND, TSIG enforced), UI lane
  `ci/netlab/lane-j-rfc2136-ui.sh` (Firefox, `ci/rfc2136-page-e2e.py`), a11y page `rfc2136-ddns`.
