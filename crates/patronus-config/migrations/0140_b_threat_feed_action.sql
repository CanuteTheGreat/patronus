-- Lane B: a threat feed can run in "alert only" mode (count + log matches, never drop) so a
-- feed can be tried before it blocks anything (docs/FIREWALL-FEEDS.md, docs/SECURITY-OVERVIEW.md).
ALTER TABLE firewall_alias_sources ADD COLUMN action TEXT NOT NULL DEFAULT 'drop';
