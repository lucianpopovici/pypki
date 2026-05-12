-- ---------------------------------------------------------------------------
-- pki/002_crl_number.sql — monotonic CRL number counter (RFC 5280 §5.2.3)
--
-- RFC 5280 §5.2.3 / RFC 6818: every CRL MUST carry a cRLNumber extension
-- whose value strictly increases for each CRL issued by a given issuer.
-- Both base and delta CRLs share the same counter; a delta CRL's number
-- is greater than the base CRL it supplements.
--
-- Single-row table keyed on id=1; allocation must be done under an
-- advisory lock or BEGIN IMMEDIATE so concurrent CRL generation never
-- assigns the same number twice.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS crl_number (
    id    INTEGER PRIMARY KEY,
    value INTEGER NOT NULL
);

-- Seed at 0 on first init. The first allocated CRL number is 1.
INSERT INTO crl_number (id, value)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;
