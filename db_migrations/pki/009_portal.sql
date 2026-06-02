-- Self-service portal: certificate ownership table.
-- Each row links a certificate serial to an owner identity.
-- A cert can have multiple owners (ACME + OIDC, etc.); ownership is additive.

CREATE TABLE IF NOT EXISTS cert_owners (
    serial      INTEGER NOT NULL,
    owner_kind  TEXT    NOT NULL,   -- 'oidc' | 'pam' | 'acme' | 'scep' | 'est' | 'cmp' | 'ssh' | 'static'
    owner_id    TEXT    NOT NULL,   -- sub / email / username / account_id / etc.
    granted_at  INTEGER NOT NULL,
    PRIMARY KEY (serial, owner_kind, owner_id)
);
CREATE INDEX IF NOT EXISTS idx_cert_owners_lookup ON cert_owners(owner_kind, owner_id);
