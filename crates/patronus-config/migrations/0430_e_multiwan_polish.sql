-- Lane E: multi-WAN polish (gateway groups the way pfSense / OPNsense do them).
--   route_gateways.loss_warn / latency_warn  warning levels below the down
--       thresholds (0 = no warning level); a warning is shown and notified,
--       the gateway keeps carrying traffic
--   route_gateways.dns_servers   DNS servers that belong to this uplink; they
--       are pinned to it with host routes and used as resolver upstreams while
--       the gateway is usable
--   route_gateway_groups.sticky_secs   load-balancing groups: seconds a client
--       address keeps the WAN it was given (0 = off, flows are hashed)
--   route_gateway_groups.kill_states   'none' | 'down' | 'down_recovery':
--       delete the tracked connections of a gateway that left service, and
--       (down_recovery) of the fallback members when a better one returns
ALTER TABLE route_gateways ADD COLUMN loss_warn INTEGER NOT NULL DEFAULT 0;
ALTER TABLE route_gateways ADD COLUMN latency_warn INTEGER NOT NULL DEFAULT 0;
ALTER TABLE route_gateways ADD COLUMN dns_servers TEXT NOT NULL DEFAULT '';
ALTER TABLE route_gateway_groups ADD COLUMN sticky_secs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE route_gateway_groups ADD COLUMN kill_states TEXT NOT NULL DEFAULT 'down';
