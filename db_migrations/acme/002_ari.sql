-- db_migrations/acme/002_ari.sql — ACME Renewal Information (RFC 9773)
--
-- acme_renewal_overrides: admin-writable table for mass-revocation incidents.
--   certId (base64url(AKI).base64url(serial)) maps to an override window that
--   takes precedence over the default computed window.
--
-- acme_replacements: records which new cert replaced which old cert.
--   UNIQUE(old_serial) prevents a cert from being the predecessor of two
--   different replacement orders.
--
-- orders.replaces: stores the certId from the newOrder `replaces` field so
--   _handle_finalize can revoke the predecessor without requiring the client
--   to send it again.
--
-- These tables are also created inline by ACMEDatabase._init() so the server
-- starts correctly on fresh databases that haven't run migrations.

CREATE TABLE IF NOT EXISTS acme_renewal_overrides (
    cert_id      TEXT PRIMARY KEY,
    window_start TEXT NOT NULL,
    window_end   TEXT NOT NULL,
    retry_after  INTEGER NOT NULL DEFAULT 21600,
    explanation  TEXT,
    set_at       INTEGER NOT NULL,
    set_by       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_replacements (
    new_serial   TEXT NOT NULL,
    old_serial   TEXT NOT NULL,
    account_id   TEXT NOT NULL,
    replaced_at  INTEGER NOT NULL,
    PRIMARY KEY (new_serial),
    UNIQUE (old_serial)
);
CREATE INDEX IF NOT EXISTS idx_acme_repl_old ON acme_replacements(old_serial);

ALTER TABLE orders ADD COLUMN replaces TEXT;
