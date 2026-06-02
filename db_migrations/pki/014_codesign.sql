-- Code-signing portal transparency log.
-- Append-only log with Merkle tree inclusion proofs.

CREATE TABLE IF NOT EXISTS codesign_log_entries (
    id                  TEXT    PRIMARY KEY,        -- "<sequence>-<digest_prefix>"
    sequence            INTEGER NOT NULL UNIQUE,    -- monotonic tree leaf index
    logged_at           INTEGER NOT NULL,
    artifact_digests    TEXT    NOT NULL,           -- JSON: [{"sha256": "..."}, ...]
    signing_identity    TEXT    NOT NULL,           -- OIDC sub claim
    issuer              TEXT    NOT NULL,           -- OIDC iss claim
    ephemeral_cert_pem  TEXT    NOT NULL,
    ephemeral_serial    TEXT    NOT NULL,           -- hex cert serial
    signature           {{blob}} NOT NULL,          -- ECDSA signature over DSSE PAE
    attestation_chain   TEXT    NOT NULL,           -- JSON array of envelope sha256 hashes
    policy_decisions    TEXT    NOT NULL DEFAULT '[]',  -- JSON array
    tree_node_hash      {{blob}} NOT NULL,          -- Merkle leaf hash for this entry
    tenant_id           TEXT    NOT NULL DEFAULT '__system'
);

CREATE INDEX IF NOT EXISTS idx_codesign_digest   ON codesign_log_entries(artifact_digests);
CREATE INDEX IF NOT EXISTS idx_codesign_identity ON codesign_log_entries(signing_identity);
CREATE INDEX IF NOT EXISTS idx_codesign_logged   ON codesign_log_entries(logged_at);
CREATE INDEX IF NOT EXISTS idx_codesign_tenant   ON codesign_log_entries(tenant_id);

CREATE TABLE IF NOT EXISTS codesign_attestations (
    hash                TEXT    PRIMARY KEY,         -- sha256(envelope_json)
    envelope_json       TEXT    NOT NULL,
    predicate_type      TEXT    NOT NULL,
    received_at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS codesign_tree_nodes (
    level               INTEGER NOT NULL,           -- 0 = leaf level
    idx                 INTEGER NOT NULL,           -- index at this level
    hash                {{blob}} NOT NULL,
    PRIMARY KEY (level, idx)
);

CREATE TABLE IF NOT EXISTS codesign_checkpoints (
    tree_size           INTEGER PRIMARY KEY,
    root_hash           {{blob}} NOT NULL,
    signed_at           INTEGER NOT NULL,
    signature           {{blob}} NOT NULL,           -- signed by CA key
    anchor_uri          TEXT
);
