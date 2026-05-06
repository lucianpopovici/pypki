-- ---------------------------------------------------------------------------
-- pki/001_initial.sql — CA state schema (initial)
--
-- Captures the schema previously created inline by:
--   pki_server.CertificateAuthority._init_db          (certificates, serial_counter, crl_base)
--   pki_server.CertificateAuthority._init_key_archive_table  (key_archive)
--   ipsec_server.IPsecHandler._init_db                (ipsec_pending_requests, ipsec_cert_confirmations)
--
-- Columns mirror the existing live schema EXACTLY, including the
-- "profile TEXT DEFAULT 'default'" column on certificates that older
-- deployments added via inline ALTER TABLE.
--
-- This migration must remain behavior-preserving against existing
-- deployments — every CREATE uses IF NOT EXISTS, every INSERT uses
-- INSERT OR IGNORE / ON CONFLICT DO NOTHING.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS certificates (
    serial      INTEGER PRIMARY KEY,
    subject     TEXT NOT NULL,
    not_before  TEXT NOT NULL,
    not_after   TEXT NOT NULL,
    der         {{blob}} NOT NULL,
    revoked     INTEGER DEFAULT 0,
    revoked_at  TEXT,
    reason      INTEGER,
    profile     TEXT DEFAULT 'default'
);

CREATE TABLE IF NOT EXISTS serial_counter (
    id    INTEGER PRIMARY KEY,
    value INTEGER NOT NULL
);

-- Seed the counter only on first init. ON CONFLICT DO NOTHING is
-- supported on both backends since SQLite 3.24 and Postgres 9.5.
INSERT INTO serial_counter (id, value)
VALUES (1, 1000)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS crl_base (
    id          INTEGER PRIMARY KEY,
    issued_at   TEXT NOT NULL,
    this_update TEXT NOT NULL,
    next_update TEXT NOT NULL,
    der         {{blob}} NOT NULL
);

CREATE TABLE IF NOT EXISTS key_archive (
    serial      INTEGER PRIMARY KEY,
    archived_at TEXT NOT NULL,
    encrypted   {{blob}} NOT NULL,
    subject     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ipsec_pending_requests (
    request_id      TEXT PRIMARY KEY,
    state           TEXT NOT NULL DEFAULT 'pending',
    created_at      TEXT NOT NULL,
    decided_at      TEXT,
    confirmed_at    TEXT,
    requester_ip    TEXT,
    request_json    TEXT NOT NULL,
    result_serial   INTEGER,
    result_cert_pem TEXT,
    reject_reason   TEXT
);

CREATE TABLE IF NOT EXISTS ipsec_cert_confirmations (
    serial       INTEGER PRIMARY KEY,
    confirmed_at TEXT NOT NULL,
    requester_ip TEXT
);
