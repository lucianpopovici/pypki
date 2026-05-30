-- SSH Certificate Authority — issued certificate ledger.
--
-- SSH serials are uint64 monotonic (separate space from X.509 random serials).
-- cert_blob stores the raw signed cert bytes (not base64) for KRL generation.

CREATE TABLE IF NOT EXISTS ssh_certificates (
    id              {{auto_pk}},
    serial          INTEGER NOT NULL UNIQUE,
    key_id          TEXT    NOT NULL,
    cert_type       INTEGER NOT NULL,           -- 1 = user, 2 = host
    principals      TEXT    NOT NULL,           -- JSON array
    valid_after     INTEGER NOT NULL,           -- unix seconds
    valid_before    INTEGER NOT NULL,           -- unix seconds
    public_key_fpr  TEXT    NOT NULL,           -- SHA256:... of subject public key
    ca_key_fpr      TEXT    NOT NULL,           -- SHA256:... of signing CA public key
    cert_blob       {{blob}} NOT NULL,           -- raw signed cert bytes
    revoked         INTEGER NOT NULL DEFAULT 0,
    revoked_at      INTEGER,
    revoke_reason   TEXT,
    profile         TEXT    NOT NULL,
    issued_at       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ssh_certs_key_id      ON ssh_certificates(key_id);
CREATE INDEX IF NOT EXISTS idx_ssh_certs_principal   ON ssh_certificates(principals);
CREATE INDEX IF NOT EXISTS idx_ssh_certs_ca_key_fpr  ON ssh_certificates(ca_key_fpr);
CREATE INDEX IF NOT EXISTS idx_ssh_certs_valid_before ON ssh_certificates(valid_before);

-- Monotonic serial counter (separate from X.509 random serials)
CREATE TABLE IF NOT EXISTS ssh_serial_counter (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    counter INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO ssh_serial_counter (id, counter) VALUES (1, 0);
