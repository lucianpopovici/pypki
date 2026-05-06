-- ---------------------------------------------------------------------------
-- audit/001_initial.sql — Audit log schema (initial)
--
-- Captures the schema previously created inline by AuditLog._init in
-- pki_server.py. Append-only table; no UPDATEs in the codebase.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit (
    id     {{auto_pk}},
    ts     TEXT NOT NULL,
    event  TEXT NOT NULL,
    detail TEXT,
    ip     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
