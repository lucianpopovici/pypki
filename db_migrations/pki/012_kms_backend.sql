-- Cloud KMS backend tracking for CA signing keys.
-- The ca_keys table registers every CA key and its protection backend.
-- Existing file-backed keys get backend='file'; cloud-KMS keys get their ARN/ref in backend_ref.

CREATE TABLE IF NOT EXISTS ca_keys (
    id                  {{auto_pk}},
    name                TEXT    NOT NULL UNIQUE,    -- human name, e.g. "root-2026"
    backend             TEXT    NOT NULL DEFAULT 'file',  -- 'file' | 'pkcs11' | 'aws-kms' | 'gcp-kms' | 'azure-kv'
    backend_ref         TEXT,                       -- ARN / resource path / vault URL
    backend_meta_json   TEXT,                       -- algorithm hints, cached public key hash, etc.
    created_at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ca_keys_backend ON ca_keys(backend);
