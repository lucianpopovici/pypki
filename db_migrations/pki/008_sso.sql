-- SSO session store and JWKS cache
-- Replaces the in-memory SessionStore in web_ui.py.
-- PAM logins use auth_backend='pam'; OIDC logins use 'oidc'; API tokens use 'token'.

CREATE TABLE IF NOT EXISTS sso_sessions (
    session_id      TEXT    PRIMARY KEY,
    auth_backend    TEXT    NOT NULL DEFAULT 'pam',
    identity        TEXT    NOT NULL,
    idp_subject     TEXT,
    idp_issuer      TEXT,
    roles           TEXT    NOT NULL DEFAULT '[]',
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_identity ON sso_sessions(identity);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_expires  ON sso_sessions(expires_at);

CREATE TABLE IF NOT EXISTS sso_jwks_cache (
    issuer      TEXT    PRIMARY KEY,
    jwks_json   TEXT    NOT NULL,
    fetched_at  INTEGER NOT NULL
);
