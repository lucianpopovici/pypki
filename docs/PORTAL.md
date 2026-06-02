# PyPKI Self-Service Portal

<!-- Last reviewed: 2026-06-02 -->

The portal lets end users manage their own certificates without contacting the
PKI operator. Each user sees only the certificates they own.

---

## Enabling the portal

Add `--portal-prefix /portal` to the server command:

```bash
pypki serve \
  --web-prefix /     \        # admin UI
  --portal-prefix /portal \   # user portal
  [--portal-owner-mapping-file /etc/pypki/owners.json]
```

The portal reuses the same auth session as the admin UI (PAM or OIDC via
`--auth`). Any authenticated user can reach `/portal/`.

---

## Ownership model

Each certificate can have one or more owners. A user can view, renew, or
revoke a cert if they match at least one of its owners.

| Owner kind | Matched from                      | Example owner_id               |
|------------|-----------------------------------|--------------------------------|
| `oidc`     | OIDC `sub` claim or identity claim | `sub-abc123` or `alice@corp`  |
| `pam`      | PAM username                      | `alice`                        |
| `acme`     | ACME account ID                   | `acct-7f3a`                   |
| `static`   | Explicit grant via `link-account` | any string                     |

### Granting ownership manually

```bash
# Grant alice ownership of serial 1042
pypki_admin link-account --serial 1042 --identity alice --kind pam

# Grant via OIDC subject
pypki_admin link-account --serial 1042 --identity sub-abc123 --kind oidc
```

### Static mapping file (bulk legacy certs)

Create `/etc/pypki/owners.json`:

```json
{
  "mappings": [
    {
      "subject_regex": "CN=.*\\.web\\.example\\.com,",
      "owner_kind": "oidc",
      "owner_id": "web-team@example.com"
    },
    {
      "subject_regex": "CN=.*\\.api\\.example\\.com,",
      "owner_kind": "oidc",
      "owner_id": "api-team@example.com"
    }
  ]
}
```

Apply to all existing certs:

```bash
pypki_admin portal-remap --mapping-file /etc/pypki/owners.json
```

Mappings are re-applied on server start when `--portal-owner-mapping-file` is set.

---

## Profile-level access control

The `portal_self_revoke` and `portal_self_renew` flags control whether a
profile's certs can be self-managed. Both default to `True`.

| Profile        | Self-revoke | Self-renew | Rationale                          |
|----------------|-------------|------------|------------------------------------|
| `tls_server`   | ✓           | ✓          | Routine operations                 |
| `tls_client`   | ✓           | ✓          | Routine operations                 |
| `email_signing`| ✓           | ✓          | User-controlled                    |
| `code_signing` | ✗           | ✗          | Requires admin sign-off for audit  |
| `sub_ca`       | ✓ (default) | ✓ (default)| Sub-CA holders are trusted         |

---

## Renewal semantics

`POST /portal/certs/<serial>/renew` performs same-key renewal:

1. Loads the existing certificate's public key from the DB.
2. Issues a new certificate with the same Subject and profile.
3. Tags the new cert with the same portal ownership.
4. Revokes the predecessor with reason `superseded` (RFC 5280 §5.3.1 code 4).

The user is redirected to the new cert's detail page on success.

---

## Troubleshooting

**"No certificates found for your identity"** — the user has no ownership
entries. Use `pypki_admin link-account` or configure the static mapping file.

**"Self-service renewal is not permitted for this certificate profile"** —
the profile has `portal_self_renew: false` (e.g. `code_signing`). The admin
must renew manually.

**Portal shows stale session after OIDC logout** — the session cookie has not
expired. Use `pypki_admin session-revoke <SESSION_ID>` to force expiry.
