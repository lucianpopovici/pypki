-- Backup registry, restore log, and emergency halt state (CLAUDE-backup-restore.md)

-- Backup registry: one row per (target_uri, backup_file) pair written.
CREATE TABLE IF NOT EXISTS backups (
    id                   {{auto_pk}},
    created_at           TEXT NOT NULL,
    manifest_hash        TEXT NOT NULL,
    target_uri           TEXT NOT NULL,
    size_bytes           INTEGER NOT NULL,
    upload_duration_ms   INTEGER NOT NULL,
    upload_status        TEXT NOT NULL,
    audit_final_id       INTEGER,
    audit_final_hash     TEXT
);
CREATE INDEX IF NOT EXISTS idx_backups_created_at ON backups(created_at);
CREATE INDEX IF NOT EXISTS idx_backups_status     ON backups(upload_status);

-- Restore events: one row per restore operation (including dry-runs).
CREATE TABLE IF NOT EXISTS restore_events (
    id                   {{auto_pk}},
    started_at           TEXT NOT NULL,
    completed_at         TEXT,
    manifest_hash        TEXT NOT NULL,
    dry_run              INTEGER NOT NULL DEFAULT 0,
    initiator            TEXT NOT NULL DEFAULT 'cli',
    selective_tables     TEXT,
    outcome              TEXT
);
CREATE INDEX IF NOT EXISTS idx_restore_events_started ON restore_events(started_at);

-- Emergency halt state: a single row controls issuance halt globally.
-- The row is seeded at migration time; UPDATE is the only valid write.
CREATE TABLE IF NOT EXISTS emergency_state (
    state                TEXT PRIMARY KEY,
    halted               INTEGER NOT NULL DEFAULT 0,
    halt_reason          TEXT,
    halted_at            TEXT,
    halted_by            TEXT
);
INSERT OR IGNORE INTO emergency_state (state, halted) VALUES ('global', 0);
