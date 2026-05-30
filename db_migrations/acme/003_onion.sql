-- RFC 9799 — ACME for .onion: in-band CAA tracking table.
--
-- Records asserted caaIdentities from onion-csr-01 challenge responses.
-- The CA still makes the final issuance decision per its CPS; this table
-- provides an audit trail.

CREATE TABLE IF NOT EXISTS acme_onion_caa (
    cert_id        TEXT PRIMARY KEY,    -- AKI.serial string (same format as ARI)
    onion_address  TEXT NOT NULL,       -- SHA-256 truncated or full (see --acme-onion-audit-full)
    caa_identities TEXT NOT NULL,       -- JSON array of asserted CA identity strings
    asserted_at    INTEGER NOT NULL,    -- unix seconds
    asserted_via   TEXT NOT NULL        -- "in-band"
);

CREATE INDEX IF NOT EXISTS idx_acme_onion_addr ON acme_onion_caa(onion_address);
