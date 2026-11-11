-- Lane e: failback hold-down. A gateway that was down/lossy/slow must stay
-- healthy this many seconds before its group uses it again (0 = at once).
ALTER TABLE route_gateways ADD COLUMN failback_delay INTEGER NOT NULL DEFAULT 0;
