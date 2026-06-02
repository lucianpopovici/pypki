-- Matter / Thread device certificate authority tables.
-- PAA = Product Attestation Authority (root)
-- PAI = Product Attestation Intermediate
-- DAC = Device Attestation Certificate (leaf, one per device)

CREATE TABLE IF NOT EXISTS matter_authorities (
    id              {{auto_pk}},
    name            TEXT    NOT NULL,           -- "paa-acme-root", "pai-acme-q3-2026"
    role            TEXT    NOT NULL,           -- 'paa' | 'pai'
    vendor_id_hex   TEXT    NOT NULL,           -- '0xFFF1'
    product_ids_hex TEXT,                       -- JSON array or NULL
    serial          TEXT    NOT NULL UNIQUE,    -- hex cert serial
    not_after       INTEGER NOT NULL,
    parent_id       INTEGER,                    -- NULL for PAA
    tenant_id       TEXT    NOT NULL DEFAULT '__system'
);

CREATE TABLE IF NOT EXISTS matter_dacs (
    serial          TEXT    PRIMARY KEY,        -- hex cert serial
    vendor_id_hex   TEXT    NOT NULL,           -- '0xFFF1'
    product_id_hex  TEXT    NOT NULL,           -- '0x8000'
    subject_serial  TEXT    NOT NULL,           -- device-unique string
    issuer_pai_id   INTEGER NOT NULL,
    issued_at       INTEGER NOT NULL,
    not_after       INTEGER NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_matter_dacs_vendor ON matter_dacs(vendor_id_hex, product_id_hex);
