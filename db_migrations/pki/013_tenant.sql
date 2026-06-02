-- Multi-tenancy schema.
-- Tenants are software-defined isolation boundaries; the system tenant
-- ('__system') is the default. Existing rows get DEFAULT '__system'.

CREATE TABLE IF NOT EXISTS tenants (
    slug                TEXT    PRIMARY KEY,            -- 'acme-corp', '__system'
    display_name        TEXT    NOT NULL,
    created_at          INTEGER NOT NULL,
    created_by          TEXT    NOT NULL DEFAULT 'system',
    isolation_level     TEXT    NOT NULL DEFAULT 'strict',   -- 'strict' | 'linked'
    suspended           INTEGER NOT NULL DEFAULT 0,
    suspended_reason    TEXT,
    config_json         TEXT                            -- per-tenant settings (JSON)
);

-- Seed the system tenant (idempotent)
INSERT OR IGNORE INTO tenants (slug, display_name, created_at, created_by)
VALUES ('__system', 'System', 0, 'system');

CREATE TABLE IF NOT EXISTS tenant_dns_aliases (
    hostname            TEXT PRIMARY KEY,
    tenant_slug         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_admins (
    tenant_slug         TEXT    NOT NULL,
    identity            TEXT    NOT NULL,
    role                TEXT    NOT NULL DEFAULT 'operator',  -- 'admin' | 'operator' | 'viewer'
    granted_at          INTEGER NOT NULL,
    granted_by          TEXT    NOT NULL DEFAULT 'system',
    PRIMARY KEY (tenant_slug, identity)
);

CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_slug                 TEXT    PRIMARY KEY,
    max_active_certs            INTEGER,
    max_issuances_per_day       INTEGER,
    max_sub_cas                 INTEGER,
    max_acme_accounts           INTEGER
);

-- Seed system tenant quota (unlimited by default)
INSERT OR IGNORE INTO tenant_quotas (tenant_slug) VALUES ('__system');

-- Add tenant_id to main user-data tables.
-- Note: wg_peers/wg_servers already have tenant_id (added in 010_wireguard.sql).
-- These ADD COLUMNs are idempotent at the migration level (each migration
-- runs exactly once, tracked in schema_migrations).

ALTER TABLE certificates ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__system';
ALTER TABLE ca_keys       ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__system';
ALTER TABLE cert_owners   ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__system';
ALTER TABLE sso_sessions  ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__system';
ALTER TABLE matter_dacs   ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__system';

CREATE INDEX IF NOT EXISTS idx_certificates_tenant  ON certificates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cert_owners_tenant2  ON cert_owners(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_tenant  ON sso_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_matter_dacs_tenant   ON matter_dacs(tenant_id);
