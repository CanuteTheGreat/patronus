# Dynamic DNS: an unreachable provider never fails the apply

A DDNS update that fails because the provider cannot be reached (timeout, DNS, connect refused, HTTP 5xx, an unknown answer) is a
warning of `patronus apply`, not a failure. A router that boots with a WAN lease but no working uplink therefore finishes its boot
pass at once, and the OpenRC/systemd second boot pass (`patronus-services`) does not retry. Only a provider that refuses the
settings themselves (bad credentials, unknown host: dyndns2 `badauth`/`nohost`, DuckDNS `KO`) still fails the apply, and that
client is then held until it is edited or "Update now" is pressed.

The failed client is retried with exponential backoff (kept as `fails` / `next_try` in `/var/lib/patronus/ddns-status.json`);
a changed address or "Update now" ends the backoff.

Settings (`lan_settings`, defaults in brackets):

- `ddns.connect_timeout_secs` (5): TCP connect timeout of one request
- `ddns.max_time_secs` (15): whole-request limit of one request
- `ddns.run_budget_secs` (30): total time one apply run may spend on all clients; clients left over are tried on the next run
- `ddns.retry_min_secs` (60), `ddns.retry_max_secs` (3600): backoff bounds

Boot ordering: `patronus-services.initd` starts `after *` (behind every other service of the runlevel) and no unit orders
`patronus-web` after the pass; `ci/check-boot-order.sh` guards both inits, `ci/netlab/lane-s-ddns-boot.sh` proves the behaviour with
a DROPped provider.
