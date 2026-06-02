-- Cryptographic agility dashboard (CLAUDE-crypto-agility-dashboard.md)
-- Denormalized classification column on certificates.
-- Populated at issuance; backfillable by 'agility-reclassify' admin command.
-- Enum values (stable API surface -- only add, never rename/remove):
--   classical-rsa | classical-ec | classical-eddsa
--   hybrid-9763   | composite-mldsa | mldsa-only | slhdsa-only | unknown

ALTER TABLE certificates ADD COLUMN crypto_class TEXT DEFAULT 'unknown';

CREATE INDEX IF NOT EXISTS idx_certs_crypto_class ON certificates(crypto_class);
CREATE INDEX IF NOT EXISTS idx_certs_not_before   ON certificates(not_before);
