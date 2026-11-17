-- Notification channels (lane H, patronus-web/src/state/telemetry.rs): an
-- event hook is now one of several channel types. `webhook` keeps the signed
-- JSON POST; ntfy / telegram / discord / slack / email send a readable
-- message. `target` = Telegram chat id or email recipients (comma separated),
-- `sender` = email From, `username` = SMTP login (password in `secret`),
-- `min_severity` = info | warning | critical.
ALTER TABLE event_hooks ADD COLUMN channel TEXT NOT NULL DEFAULT 'webhook';
ALTER TABLE event_hooks ADD COLUMN target TEXT NOT NULL DEFAULT '';
ALTER TABLE event_hooks ADD COLUMN sender TEXT NOT NULL DEFAULT '';
ALTER TABLE event_hooks ADD COLUMN username TEXT NOT NULL DEFAULT '';
ALTER TABLE event_hooks ADD COLUMN min_severity TEXT NOT NULL DEFAULT 'info';
