-- Lane e: gradual failback. After a recovered gateway is usable again its group
-- moves traffic back over this many seconds (weighted multipath that shifts
-- from the fallback tier to the recovered one) instead of all at once (0 = at once).
ALTER TABLE route_gateways ADD COLUMN failback_ramp INTEGER NOT NULL DEFAULT 0;
