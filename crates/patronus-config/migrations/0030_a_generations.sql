-- Configuration generations (NixOS-style): every applied change set is a
-- numbered generation. Builds on config_revisions: the old rows are copied in
-- with their ids (so `config rollback N` keeps meaning the same thing) and
-- the old table stays as it was, unused. `id` is AUTOINCREMENT: an id is
-- never reused, not even after pruning.
CREATE TABLE IF NOT EXISTS config_generations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',      -- web user, cli, gitops, system
    message TEXT NOT NULL DEFAULT '',          -- the commit message
    kind TEXT NOT NULL DEFAULT 'change',       -- change | baseline | migrated | rollback | import | revert
    content_hash TEXT NOT NULL DEFAULT '',     -- sha256 of the canonical document ('' = computed on first read)
    pinned INTEGER NOT NULL DEFAULT 0,         -- pinned generations are never pruned
    config_json TEXT NOT NULL                  -- ConfigStore::export_json()
);

CREATE INDEX IF NOT EXISTS idx_config_generations_created ON config_generations(created_at DESC);

-- live bookkeeping: open change set, boot default, pending commit-confirm
CREATE TABLE IF NOT EXISTS config_generation_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO config_generations (id, created_at, actor, message, kind, content_hash, config_json)
    SELECT id, created_at, user, summary, 'migrated', '', config_json FROM config_revisions;
