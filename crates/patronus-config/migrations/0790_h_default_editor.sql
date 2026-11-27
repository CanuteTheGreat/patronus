-- System default text editor (lane H, patronus-config/src/editor.rs): the declarative key
-- `system.editor` (patronus.toml [system] editor, PUT /api/system/editor, GitOps kind DefaultEditor).
-- One row at most; no row = unmanaged (the system keeps its own /etc/default-editor.conf).
CREATE TABLE IF NOT EXISTS system_editor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    choice TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
