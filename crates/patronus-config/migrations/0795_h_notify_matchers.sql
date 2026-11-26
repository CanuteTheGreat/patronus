-- Notification matchers (lane H, docs/NOTIFY-MATCHERS.md): a tree of
-- all / any / not groups over event kind, severity, subject glob and a
-- calendar window. `tree` is the JSON of patronus_config::notify_matcher::Matcher.
-- A channel (event_hooks) names one matcher; '' = the channel's own legacy
-- kinds + min_severity (documents exported before this migration).
CREATE TABLE IF NOT EXISTS notify_matchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    tree TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT 0
);
ALTER TABLE event_hooks ADD COLUMN matcher TEXT NOT NULL DEFAULT '';
-- today's kinds + minimum severity become an equivalent matcher per channel
INSERT INTO notify_matchers (name, description, tree, updated_at)
SELECT 'auto-' || name,
       'Converted from the channel''s event kinds and minimum severity',
       '{"op":"all","items":[' ||
         CASE WHEN kinds <> '' THEN '{"op":"kind","kinds":["' || replace(kinds, ',', '","') || '"]}' ELSE '' END ||
         CASE WHEN kinds <> '' AND min_severity <> 'info' THEN ',' ELSE '' END ||
         CASE WHEN min_severity <> 'info' THEN '{"op":"severity","min":"' || min_severity || '"}' ELSE '' END ||
       ']}',
       strftime('%s', 'now')
FROM event_hooks;
UPDATE event_hooks SET matcher = 'auto-' || name;
