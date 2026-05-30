# CLAUDE-sso.md — OIDC and SAML SSO for the Admin UI and API

Companion to `CLAUDE.md`. Follow all conventions there. PAM stays the
default for homelab; this adds enterprise auth without new pip deps.
OIDC ships in phase 1; SAML is sketched in phase 2 because it needs
XML-DSIG, which is heavier.

---

## What this is

Today, `web_ui.py` and the REST API authenticate against the system's
PAM stack with a session cookie. Enterprises run Okta, Entra ID,
Auth0, Keycloak, Ping, or Google Workspace — none of which speak PAM.
This adds OIDC (and later SAML) as alternative auth backends behind
the same session abstraction.

Goals:

- Zero new pip dependencies. JWS verification uses `cryptography` +
  stdlib JSON.
- Existing PAM path untouched. `--auth pam` (default) keeps current
  behavior bit-for-bit.
- Role / permission mapping from IdP claims to PyPKI's existing
  authorization tags.
- Auditable: every login records the IdP, the claim payload hash, and
  the resulting PyPKI session.

Non-goals:

- SCIM provisioning (out of scope; admins are still locally
  authorized).
- IdP-initiated SSO (security footgun; only SP-initiated supported).

---

## OIDC (phase 1)

### Flow

Authorization Code Flow with PKCE (RFC 7636). The legacy implicit flow
is not implemented — RFC 9700 (OAuth 2.0 BCP) explicitly deprecates it
and modern IdPs default to code+PKCE.

```
Browser                  PyPKI                    IdP
   |                        |                       |
   |--- GET /login -------->|                       |
   |                        |--- gen state+PKCE     |
   |<-- 302 to IdP/authorize|                       |
   |--- GET /authorize ---->|---------------------->|
   |<-- redirect ----------------------------------- (user authenticates)
   |--- GET /cb?code=... -->|                       |
   |                        |--- POST /token ------>|
   |                        |<-- id_token, access -----|
   |                        |--- verify id_token sig|
   |                        |--- map claims to role |
   |                        |--- create session     |
   |<-- 302 to / + cookie --|                       |
```

### Implementation

JWS verification: RS256, ES256, EdDSA. JWKS fetched once at startup and
cached; refreshed every 24h or on `kid` miss (then back off 5 min if
refresh fails to avoid hammering the IdP).

```python
def verify_id_token(token: str, jwks: list[dict], issuer: str, audience: str) -> dict:
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))
    sig = _b64url_decode(sig_b64)

    if header["alg"] not in {"RS256", "ES256", "EdDSA"}:
        raise AuthError("unsupported alg")
    key = _find_jwk(jwks, header["kid"])
    _verify_jws_sig(key, header["alg"], f"{header_b64}.{payload_b64}".encode(), sig)

    if payload["iss"] != issuer:                       raise AuthError("iss")
    if audience not in _aud_list(payload.get("aud")):  raise AuthError("aud")
    now = int(time.time())
    if payload["exp"] < now:                           raise AuthError("expired")
    if payload.get("nbf", 0) > now + 30:               raise AuthError("not yet valid")
    if payload["iat"] > now + 300:                     raise AuthError("iat in future")

    return payload
```

`alg: none` and unknown algs are rejected before any signature check.

### Discovery

Fetch `{issuer}/.well-known/openid-configuration` once at startup. The
returned object names the `authorization_endpoint`, `token_endpoint`,
and `jwks_uri`. If discovery fails, fail-closed and stay on PAM until
the next restart.

### Claim mapping

Identity comes from one of `email`, `preferred_username`, `sub`
(operator picks via flag). Roles come from a configurable claim path:

```
--oidc-roles-claim "groups"              # claim name (top-level or dotted path)
--oidc-role-map admins=pki:admin,pki-ops=pki:operator
```

Default mapping for unknown groups: read-only viewer. Admin override:
`--oidc-default-role pki:none` to fail-closed instead.

### State store

OIDC needs to remember per-request `state` and PKCE `code_verifier`
between the `/login` redirect and the `/callback`. Encode them in a
short-lived encrypted cookie (HS256 over a CA-derived key, 10-minute
TTL) rather than a DB table — keeps the request path stateless and
the schema clean.

---

## SAML (phase 2 — sketched only)

SAML needs XML-DSIG, which requires careful c14n (Canonical XML 1.0
or 1.1) handling. Two options when this becomes priority:

1. Hand-roll a minimal SAML 2.0 SP. ~2000 LoC including c14n. Painful
   but matches the project's no-dep philosophy.
2. Make `python-saml` an optional dep activated only when
   `--auth saml` is selected. Operators who need SAML accept the dep;
   homelab users never see it.

Recommend (2). Document the dep clearly. Out of scope for the initial
SSO PR.

---

## Schema

```sql
-- db_migrations/pki/00X_sso.sql
CREATE TABLE sso_sessions (
    session_id      TEXT PRIMARY KEY,           -- random 32 bytes, base64url
    auth_backend    TEXT NOT NULL,              -- 'pam' | 'oidc' | 'saml'
    identity        TEXT NOT NULL,              -- email / username
    idp_subject     TEXT,                       -- sub claim, for audit
    idp_issuer      TEXT,                       -- iss claim
    roles           TEXT NOT NULL,              -- JSON array
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_sso_sessions_identity ON sso_sessions(identity);
CREATE INDEX idx_sso_sessions_expires  ON sso_sessions(expires_at);

CREATE TABLE sso_jwks_cache (
    issuer          TEXT PRIMARY KEY,
    jwks_json       TEXT NOT NULL,
    fetched_at      INTEGER NOT NULL
);
```

Schema replaces today's in-memory session dict in `pki_server.py`.
Existing PAM logins also flow through `sso_sessions` with
`auth_backend='pam'` — keeps audit unified.

---

## CLI flags

```
--auth pam                          # default
--auth oidc
--oidc-issuer https://accounts.example.com
--oidc-client-id pypki
--oidc-client-secret-file /etc/pypki/oidc.secret
--oidc-redirect-uri https://pki.example.com/callback
--oidc-identity-claim email         # email | preferred_username | sub
--oidc-roles-claim groups
--oidc-role-map admins=pki:admin,pki-ops=pki:operator
--oidc-default-role pki:viewer      # or pki:none for fail-closed
--oidc-session-ttl 28800            # seconds, default 8h
--oidc-jwks-refresh-interval 86400
```

API tokens for service accounts stay first-class (`pypki_admin.py
token-create --role pki:operator --ttl 365d`) — automation shouldn't
go through OIDC.

---

## Tests

```
class TestOIDCDiscovery(unittest.TestCase):
    def test_well_known_fetched_at_startup(self): ...
    def test_discovery_failure_falls_back_to_pam(self): ...
    def test_jwks_refreshed_on_kid_miss(self): ...
    def test_jwks_refresh_failure_backoff(self): ...

class TestOIDCTokenVerification(unittest.TestCase):
    def test_rs256_signature_verifies(self): ...
    def test_es256_signature_verifies(self): ...
    def test_eddsa_signature_verifies(self): ...
    def test_alg_none_rejected(self): ...
    def test_unknown_alg_rejected(self): ...
    def test_expired_token_rejected(self): ...
    def test_wrong_issuer_rejected(self): ...
    def test_wrong_audience_rejected(self): ...
    def test_iat_in_future_rejected(self): ...
    def test_aud_list_supported(self): ...

class TestOIDCFlow(unittest.TestCase):
    def test_login_redirects_to_authorize_with_state_and_pkce(self): ...
    def test_callback_without_state_rejected(self): ...
    def test_callback_with_wrong_state_rejected(self): ...
    def test_pkce_verifier_mismatch_rejected(self): ...
    def test_successful_callback_creates_session(self): ...
    def test_unknown_group_gets_default_role(self): ...
    def test_role_map_applied(self): ...
    def test_audit_log_records_login(self): ...

class TestSessionStore(unittest.TestCase):
    def test_session_persists_across_restart(self): ...
    def test_expired_session_rejected(self): ...
    def test_revoked_session_rejected(self): ...
    def test_pam_sessions_share_table_with_oidc(self): ...
```

Use a local Keycloak in a container for integration tests; the static
JWKS test vectors come from RFC 7515/7517 examples.

---

## Per-change checklist

- [ ] `auth.py` — new module: backend interface, PAM + OIDC implementations
- [ ] `oidc.py` — new module: discovery, JWS verify, PKCE
- [ ] `pki_server.py` — wire `auth.py` into request middleware, replace
      in-memory session dict
- [ ] `web_ui.py` — `/login`, `/callback`, `/logout` routes
- [ ] `db_migrations/pki/00X_sso.sql` — new tables
- [ ] `pypki_admin.py` — `session-list`, `session-revoke`,
      `token-create`, `token-list`
- [ ] `test_pki_server.py` — four new test classes
- [ ] `README.md` — auth backend table, OIDC setup section,
      service-account / API token docs
- [ ] `CHANGELOG.md` — `### Added`, `### Security` for the JWS algo
      allowlist
- [ ] `docs/SSO.md` — operator runbook: Keycloak, Okta, Entra ID,
      Google Workspace setup examples
- [ ] `pypki-flows.html` — OIDC code+PKCE flow

Run `./run_tests.sh`.

---

## Open questions

1. **Refresh tokens**: out of scope for v1. PyPKI sessions don't need
   refresh — re-login is fine for an admin UI. Skip the refresh token
   dance entirely; only consume `id_token`.

2. **Backchannel logout (`RP-Initiated Logout` / `Backchannel Logout`)**:
   skip in v1. Operators can revoke via `pypki_admin.py session-revoke`.
   Add if a user requests; needs an unauthenticated POST endpoint with
   a signed logout token, which expands attack surface.

3. **Step-up auth for sensitive ops (root CA key export, RA bypass)**:
   AAL2/ACR claims aren't standardized enough across IdPs to enforce.
   Use the existing admin re-confirm modal instead, but plumb the
   `acr` claim through the session record so audit log entries
   include it.

4. **mTLS admin auth**: separate from OIDC. Could co-exist as a third
   `--auth mtls` backend that verifies client certs against a configured
   trust store. Useful for fully air-gapped deployments. Sketch only;
   ship in a later phase.
