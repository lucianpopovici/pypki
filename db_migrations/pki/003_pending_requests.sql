-- ---------------------------------------------------------------------------
-- pki/003_pending_requests.sql — RA / approval workflow (§5.4)
--
-- Stores certificate requests awaiting human or policy-driven approval.
-- Requests flow through: pending → issued (approved) or denied.
-- The cert_der column is populated on approval; protocol_ref links back
-- to the originating protocol object (ACME order_id, CMP txid, etc.).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pending_requests (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id           TEXT    NOT NULL UNIQUE,   -- UUID
    protocol             TEXT    NOT NULL,           -- acme/cmp/est/scep/ipsec/rest
    profile              TEXT    NOT NULL DEFAULT 'default',
    subject_dn           TEXT    NOT NULL,
    san_dns              TEXT,                       -- JSON array
    san_ips              TEXT,                       -- JSON array
    san_emails           TEXT,                       -- JSON array
    san_uris             TEXT,                       -- JSON array
    public_key_der       BLOB,                       -- SubjectPublicKeyInfo DER
    csr_der              BLOB,                       -- original CSR DER (when available)
    validity_days        INTEGER,                    -- NULL = use CA default
    requester_ip         TEXT,
    status               TEXT    NOT NULL DEFAULT 'pending',  -- pending/issued/denied
    approver             TEXT,
    deny_reason          TEXT,
    decided_at           INTEGER,
    created_at           INTEGER NOT NULL,
    protocol_ref         TEXT,                       -- ACME order_id, CMP txid, etc.
    cert_der             BLOB,                       -- populated after approval + issuance
    auto_approval_reason TEXT                        -- non-NULL when auto-approved
);

CREATE INDEX IF NOT EXISTS idx_pr_status      ON pending_requests(status);
CREATE INDEX IF NOT EXISTS idx_pr_created     ON pending_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_pr_protocol_ref ON pending_requests(protocol_ref);
