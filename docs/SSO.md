# PyPKI SSO — OIDC Setup Guide

<!-- Last reviewed: 2026-06-02 -->

PyPKI supports OIDC Authorization Code + PKCE (RFC 7636) as an alternative
to PAM authentication. The default remains system PAM (`--auth pam`). OIDC
is opt-in via `--auth oidc`.

No new pip dependencies are required. JWS verification (RS256, ES256, EdDSA)
uses the `cryptography` library already present, plus stdlib JSON.

---

## Architecture

```
Browser              PyPKI                     IdP (Okta / Entra / Keycloak…)
  |                    |                          |
  |-- GET /login ----->|                          |
  |                    |-- generate state+PKCE    |
  |<-- 302 IdP --------|                          |
  |-- GET /authorize -->------------------------>|
  |<-- redirect --------------------------------- (user authenticates)
  |-- GET /callback?code&state -->|              |
  |                    |-- POST /token ---------->|
  |                    |<-- id_token -------------|
  |                    |-- verify JWS sig         |
  |                    |-- map groups → roles     |
  |                    |-- create DB session      |
  |<-- 302 / + cookie -|                          |
```

Sessions are stored in the `sso_sessions` table (persistent across restarts).
PAM sessions also use this table (`auth_backend='pam'`).

---

## CLI flags

```
--auth oidc
--oidc-issuer              <URL>     # IdP issuer (discovery doc fetched automatically)
--oidc-client-id           <ID>      # client_id registered with the IdP
--oidc-client-secret-file  <FILE>    # path to a file containing the client secret
--oidc-redirect-uri        <URL>     # must match what's registered in the IdP
--oidc-identity-claim      <CLAIM>   # JWT claim used as username (default: email)
--oidc-roles-claim         <CLAIM>   # JWT claim containing groups (default: groups)
--oidc-role-map            <MAP>     # group=role pairs, e.g. admins=pki:admin
--oidc-default-role        <ROLE>    # fallback role (default: pki:viewer; pki:none = fail-closed)
--oidc-session-ttl         <SEC>     # session lifetime in seconds (default: 28800)
--oidc-jwks-refresh-interval <SEC>  # how often to refresh JWKS (default: 86400)
```

---

## Keycloak

1. Create a realm and a client:
   - **Client ID**: `pypki`
   - **Access Type**: confidential
   - **Valid Redirect URIs**: `https://pki.example.com/callback`
   - **Standard Flow**: enabled
   - **PKCE**: enabled (code_challenge_method = S256)

2. Add a client scope `groups` that includes the `groups` claim in the ID token.

3. Create roles/groups and assign users.

4. Download the client secret from the **Credentials** tab.

5. Start PyPKI:

```bash
echo "my-client-secret" > /etc/pypki/oidc.secret
chmod 600 /etc/pypki/oidc.secret

pypki serve \
  --auth oidc \
  --oidc-issuer https://keycloak.example.com/realms/myrealm \
  --oidc-client-id pypki \
  --oidc-client-secret-file /etc/pypki/oidc.secret \
  --oidc-redirect-uri https://pki.example.com/callback \
  --oidc-roles-claim groups \
  --oidc-role-map pki-admins=pki:admin,pki-operators=pki:operator \
  --oidc-default-role pki:viewer \
  --web-prefix /
```

---

## Okta

1. Create an OIDC Web Application in your Okta org:
   - **Sign-in redirect URIs**: `https://pki.example.com/callback`
   - **PKCE**: enabled
   - **Grant type**: Authorization Code

2. Assign groups and add a `groups` claim to the ID token in the **Token
   Preview** → **Groups Claim** section.

3. Note the **Client ID**, **Client Secret**, and **Issuer** (e.g.
   `https://<your-org>.okta.com`).

4. Start PyPKI (same as Keycloak example, substituting your Okta issuer).

---

## Microsoft Entra ID (Azure AD)

1. Register an application in the Azure Portal:
   - **Redirect URI**: `https://pki.example.com/callback` (type: Web)
   - Enable **PKCE** (Azure supports it automatically)

2. Add group claims: **Token configuration** → **Add groups claim** →
   select **Security groups**. Groups arrive as Object IDs.

3. Create a client secret in **Certificates & secrets**.

4. Your issuer is: `https://login.microsoftonline.com/<tenant-id>/v2.0`

5. Use `--oidc-identity-claim preferred_username` (email claim may not be
   present by default in Entra).

6. Map group Object IDs in `--oidc-role-map`:
   ```
   --oidc-role-map "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx=pki:admin"
   ```

---

## Google Workspace

1. In Google Cloud Console → APIs & Services → Credentials, create an
   **OAuth 2.0 Client ID** (type: Web application):
   - **Authorized redirect URIs**: `https://pki.example.com/callback`

2. Google does not provide a `groups` claim in standard OIDC. Use
   `--oidc-identity-claim email` and `--oidc-default-role pki:viewer`
   (everyone who can authenticate gets viewer access).
   For role differentiation, use a directory-synced IdP (Okta, Keycloak)
   in front of Google.

3. Issuer: `https://accounts.google.com`

---

## API tokens (service accounts)

Automation should not go through OIDC. Use long-lived API tokens instead:

```bash
# Create a token
pypki_admin token-create --identity "ci-bot" --role pki:operator --ttl 365

# List tokens
pypki_admin token-list

# Revoke a token
pypki_admin session-revoke <SESSION_ID>
```

Tokens are passed as a Bearer token header:

```
Authorization: Bearer <token>
```

---

## Session management

```bash
# List active sessions (PAM + OIDC + tokens)
pypki_admin session-list

# Include expired and revoked sessions
pypki_admin session-list --all

# Force-revoke a session (e.g. suspected account compromise)
pypki_admin session-revoke <SESSION_ID>
```

---

## Security notes

- **SP-initiated only**: PyPKI does not support IdP-initiated SSO.
- **Refresh tokens**: not used. Sessions expire after `--oidc-session-ttl`
  seconds and users must re-authenticate.
- **Backchannel logout**: not supported in v1. Use `session-revoke` for
  manual revocation.
- **JWKS refresh**: JWKS is cached in the `sso_jwks_cache` table and
  refreshed every `--oidc-jwks-refresh-interval` seconds. On a `kid` miss,
  one forced refresh is attempted immediately (with a 5-minute backoff on
  failure).
- **Flow cookie**: the PKCE code_verifier and state are encoded in a
  short-lived (10-minute), HMAC-signed `pypki_flow` cookie. The signing key
  is derived from a random secret stored in `<ca_dir>/.oidc_flow_key`
  (mode 0600, generated on first use).
- **Audit log**: every OIDC login records `identity`, `roles`, and a
  SHA-256 prefix of the raw id_token in the PyPKI audit log. Claim payloads
  are never stored in plain text.
