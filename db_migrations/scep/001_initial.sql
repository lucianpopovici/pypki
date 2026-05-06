-- ---------------------------------------------------------------------------
-- scep/001_initial.sql — SCEP transactions schema (initial)
--
-- Captures the schema previously created inline by SCEPDatabase._init
-- in scep_server.py.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scep_transactions (
    transaction_id TEXT PRIMARY KEY,
    status         TEXT NOT NULL DEFAULT 'pending',
    subject        TEXT,
    csr_pem        TEXT,
    cert_pem       TEXT,
    fail_info      TEXT,
    fail_reason    TEXT,
    requester_ip   TEXT,
    created_at     REAL,
    updated_at     REAL
);

CREATE INDEX IF NOT EXISTS idx_scep_status ON scep_transactions(status);
