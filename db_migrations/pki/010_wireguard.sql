-- WireGuard peer identity registry.
-- WireGuard uses Curve25519 keys; no X.509 is involved.
-- "Revocation" means removing the peer from distributed server configs.

CREATE TABLE IF NOT EXISTS wg_peers (
    id                  {{auto_pk}},
    peer_id             TEXT    UNIQUE NOT NULL,        -- "wg-2026-0042"
    peer_name           TEXT    NOT NULL,               -- human label
    public_key          TEXT    NOT NULL,               -- base64 Curve25519
    allowed_ips         TEXT    NOT NULL DEFAULT '[]',  -- JSON array of CIDRs
    endpoint            TEXT,                           -- null for client peers
    persistent_keepalive INTEGER,
    profile_name        TEXT    NOT NULL DEFAULT 'wg_user_vpn',
    valid_after         INTEGER NOT NULL,
    valid_before        INTEGER NOT NULL,
    revoked             INTEGER NOT NULL DEFAULT 0,
    revoked_at          INTEGER,
    tenant_id           TEXT    NOT NULL DEFAULT '__system',
    created_at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wg_peers_active ON wg_peers(revoked, valid_before);

CREATE TABLE IF NOT EXISTS wg_servers (
    server_id       TEXT    PRIMARY KEY,
    public_key      TEXT    NOT NULL,   -- base64 Curve25519
    endpoint        TEXT    NOT NULL,   -- "vpn.example.com:51820"
    listen_port     INTEGER NOT NULL DEFAULT 51820,
    network_cidr    TEXT    NOT NULL,   -- "10.10.0.0/24"
    tenant_id       TEXT    NOT NULL DEFAULT '__system'
);

CREATE TABLE IF NOT EXISTS wg_assignments (
    peer_id     TEXT    NOT NULL,
    server_id   TEXT    NOT NULL,
    assigned_at INTEGER NOT NULL,
    PRIMARY KEY (peer_id, server_id)
);
