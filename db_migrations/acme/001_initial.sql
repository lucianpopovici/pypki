-- ---------------------------------------------------------------------------
-- acme/001_initial.sql — ACME state schema (initial)
--
-- Captures the schema previously created inline by ACMEDatabase._init in
-- acme_server.py. Six tables: nonces, accounts, orders, authorizations,
-- challenges, certificates.
--
-- Note on time columns: ACME uses REAL (unix-seconds with fractional
-- precision) for created_at/expires_at, and TEXT (ISO-8601) for
-- not_before/not_after. Preserved verbatim — modernization to INTEGER
-- unix-seconds belongs in a future migration, not this one.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS nonces (
    value      TEXT PRIMARY KEY,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    kid        TEXT PRIMARY KEY,
    jwk_json   TEXT NOT NULL,
    thumbprint TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'valid',
    contact    TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id          TEXT PRIMARY KEY,
    account_kid TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    identifiers TEXT NOT NULL,
    not_before  TEXT,
    not_after   TEXT,
    cert_id     TEXT,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS authorizations (
    id         TEXT PRIMARY KEY,
    order_id   TEXT NOT NULL,
    identifier TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    id           TEXT PRIMARY KEY,
    auth_id      TEXT NOT NULL,
    type         TEXT NOT NULL,
    token        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    validated_at REAL,
    error        TEXT
);

CREATE TABLE IF NOT EXISTS certificates (
    id         TEXT PRIMARY KEY,
    order_id   TEXT NOT NULL,
    pem_chain  TEXT NOT NULL,
    serial     INTEGER,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_orders_account   ON orders(account_kid);
CREATE INDEX IF NOT EXISTS idx_auths_order      ON authorizations(order_id);
CREATE INDEX IF NOT EXISTS idx_challenges_auth  ON challenges(auth_id);
CREATE INDEX IF NOT EXISTS idx_acme_certs_order ON certificates(order_id);
