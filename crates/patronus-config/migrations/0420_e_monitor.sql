-- Lane e: mwan3-style gateway health tracking. A gateway is probed through
-- several targets and judged per round:
--   monitor_ip (0400) + monitor_ips   comma-separated extra monitor targets
--   monitor_reliability               how many targets must answer for a round to be good (>= 1)
--   monitor_interval                  seconds between rounds (1 = every monitor tick)
--   monitor_down                      consecutive failed rounds before the gateway is down (1-10)
--   monitor_up                        consecutive good rounds before a down gateway is up again (1-10)
-- Defaults reproduce the earlier behaviour (one target, every tick, down after 5 lost, up at once).
ALTER TABLE route_gateways ADD COLUMN monitor_ips TEXT NOT NULL DEFAULT '';
ALTER TABLE route_gateways ADD COLUMN monitor_reliability INTEGER NOT NULL DEFAULT 1;
ALTER TABLE route_gateways ADD COLUMN monitor_interval INTEGER NOT NULL DEFAULT 1;
ALTER TABLE route_gateways ADD COLUMN monitor_down INTEGER NOT NULL DEFAULT 5;
ALTER TABLE route_gateways ADD COLUMN monitor_up INTEGER NOT NULL DEFAULT 1;
