# CLAUDE-portal.md — Self-Service End-User Portal

Companion to `CLAUDE.md`. Follow all conventions there. Adds a scoped
view layer over the existing CA so non-admin users can manage their
own certificates without bothering the PKI operator. Reuses the auth
backend defined in `CLAUDE-sso.md` (PAM, OIDC, or service-account
tokens scoped to a single identity).

---

## What this is

Today, `web_ui.py` is admin-focused: anyone with a session sees every
cert and every action. That's fine for homelab and acceptable for small
ops teams, but in larger orgs it pushes every renewal request through
the PKI admin's inbox. The portal solves this by exposing a
scope-restricted view at `/portal/` where each authenticated user sees
only certs they own.

What "ownership" means is configurable but defaults to "issued to my
ACME account, my SCEP enrollment, my OIDC identity, or my SSH key
fingerprint."

---

## Surface

A separate URL prefix, separate templates, no admin endpoints
reachable. Every request goes through `require_portal_session` which
asserts the session is not an admin escalation and tags the request
with the user's identity for filtering downstream.

### Routes

| Path                                | Purpose                                    |
| ----------------------------------- | ------------------------------------------ |
| `GET  /portal/`                     | Dashboard: counts, expiring soon, recent activity |
| `GET  /portal/certs`                | List of certs owned by the user            |
| `GET  /portal/certs/<serial>`       | Detail view: SANs, expiry, download links  |
| `POST /portal/certs/<serial>/renew` | Trigger renewal (rekey or same-key)        |
| `POST /portal/certs/<serial>/revoke`| Self-service revocation (with confirmation)|
| `GET  /portal/acme`                 | ACME account info, EAB credentials manager |
| `POST /portal/acme/eab/new`         | Generate new EAB key + MAC                 |
| `POST /portal/acme/eab/<id>/revoke` | Revoke an EAB credential                   |
| `GET  /portal/ssh`                  | SSH certs issued to my keys (if SSH CA shipped) |
| `GET  /portal/audit`                | My own audit trail — only events I caused  |
| `GET  /portal/api-tokens`           | Personal API tokens                        |

No `/portal/profiles/`, `/portal/sub-cas/`, `/portal/system/` — those
stay on the admin UI at `/admin/` (rename the existing routes to make
the separation visible).

### Authorization model

Each cert has zero or more owners. An owner is one of:

- An OIDC identity (`iss` + `sub` pair, or `email`).
- An ACME account ID.
- A SCEP enrollment ID.
- An SSH user principal (if SSH CA shipped).
- A static `--portal-owner-mapping` rule (regex over Subject DN, for
  legacy certs).

A user can view a cert iff they match at least one of its owners. This
is a *view* permission. Renewal and revocation may be additionally
gated by profile (e.g. `tls_server` allows owner-initiated renewal;
`code_signing` requires admin sign-off).

---

## Implementation

### Files touched

| File                | Change                                            |
| ------------------- | ------------------------------------------------- |
| `portal.py`         | New module: route handlers, ownership resolver    |
| `pki_server.py`     | Mount `/portal/` namespace, owner-tag every issuance |
| `web_ui.py`         | Rename admin routes from `/` to `/admin/`         |
| `acme_server.py`    | Stamp `owner_acme_account_id` at issuance         |
| `scep_server.py`    | Stamp `owner_scep_enrollment` at issuance         |
| `est_server.py`     | Stamp `owner_est_identity` at issuance            |
| `cmp_server.py`     | Stamp `owner_cmp_identity` at issuance            |
| `db_migrations/pki/00X_portal.sql` | Owner-tag table                    |
| `test_pki_server.py` | `TestPortalOwnership`, `TestPortalRenewal`, `TestPortalRevocation`, `TestPortalScopeIsolation` |
| `README.md`         | New "Self-service portal" section                 |
| `CHANGELOG.md`      | `### Added`, `### Changed` (admin URL move)       |

### Schema

```sql
-- db_migrations/pki/00X_portal.sql
CREATE TABLE cert_owners (
    serial          TEXT NOT NULL,
    owner_kind      TEXT NOT NULL,    -- 'oidc' | 'acme' | 'scep' | 'est' | 'cmp' | 'ssh' | 'static'
    owner_id        TEXT NOT NULL,    -- subject/email/account_id/etc
    granted_at      INTEGER NOT NULL,
    PRIMARY KEY (serial, owner_kind, owner_id),
    FOREIGN KEY (serial) REFERENCES certificates(serial)
);
CREATE INDEX idx_cert_owners_lookup ON cert_owners(owner_kind, owner_id);
```

A cert can have multiple owners (e.g. an ACME-issued cert with the
ACME account *and* the email-from-OIDC of the requester). Ownership
is additive; revocation of one ownership doesn't revoke the cert.

### Ownership resolution flow

```python
def resolve_owners(session: Session) -> list[tuple[str, str]]:
    """Returns list of (owner_kind, owner_id) tuples this session can claim."""
    owners = []
    if session.auth_backend == "oidc":
        owners.append(("oidc", session.idp_subject))
        if session.email:
            owners.append(("oidc", session.email))   # email also matches static rules
    elif session.auth_backend == "pam":
        owners.append(("pam", session.identity))
    for acme_acct in db.fetchall(
        "SELECT id FROM acme_accounts WHERE linked_identity = ?",
        (session.identity,),
    ):
        owners.append(("acme", acme_acct["id"]))
    # ... similar for SCEP, EST, CMP, SSH
    return owners

def my_certs(session: Session) -> list[Certificate]:
    owners = resolve_owners(session)
    if not owners:
        return []
    placeholders = ",".join(["(?, ?)"] * len(owners))
    flat_params = [v for pair in owners for v in pair]
    return db.fetchall(
        f"""SELECT c.* FROM certificates c
            JOIN cert_owners o ON o.serial = c.serial
            WHERE (o.owner_kind, o.owner_id) IN ({placeholders})
            ORDER BY c.not_after DESC""",
        flat_params,
    )
```

Linking ACME/SCEP/EST/CMP accounts to a PyPKI identity is a one-time
operator step (`pypki_admin.py link-account --identity alice@corp
--acme-account-id <id>`) or self-service via a portal flow that
challenges the user to prove they hold the ACME account key.

### Renewal semantics

`POST /portal/certs/<serial>/renew` supports two modes:

- **Same key**: re-issue with the existing subject pubkey, same SANs,
  new validity window. Used by long-lived service identities.
- **Rekey**: user uploads a new CSR; PyPKI validates SANs match the
  predecessor and issues.

In both cases the predecessor is auto-revoked with reason `superseded`
on successful issuance — same machinery as ACME `replaces`.

### Revocation semantics

Self-service revocation is allowed for owner-controlled certs by
default, but profile-gated. Add to `CertProfile`:

```python
@dataclass(frozen=True)
class CertProfile:
    # ... existing fields ...
    portal_self_revoke: bool = True
    portal_self_renew: bool = True
```

`code_signing` profile sets both to `False` — code signing certs need
human review on lifecycle changes for audit reasons.

---

## CLI flags

```
--portal-enabled                            # default false initially
--portal-prefix /portal                     # URL prefix
--portal-session-ttl 3600                   # seconds, shorter than admin
--portal-self-revoke-default true
--portal-owner-mapping-file /etc/pypki/owners.yaml
```

Static owner mapping file format:

```yaml
# Map subject DN regex to OIDC identity. Useful for migrating legacy certs
# issued before the portal existed.
mappings:
  - subject_regex: "^CN=.*\\.web\\.example\\.com,"
    owner_kind: oidc
    owner_id: web-team@example.com
  - subject_regex: "^CN=.*\\.api\\.example\\.com,"
    owner_kind: oidc
    owner_id: api-team@example.com
```

Mappings re-evaluated on startup and on `pypki_admin.py portal-remap`.

---

## Tests

```
class TestPortalOwnership(unittest.TestCase):
    def test_user_sees_own_acme_certs(self): ...
    def test_user_does_not_see_other_acme_certs(self): ...
    def test_oidc_session_resolves_to_oidc_owner(self): ...
    def test_static_mapping_applied_to_legacy_certs(self): ...
    def test_multiple_owners_per_cert(self): ...
    def test_unauthenticated_request_rejected(self): ...

class TestPortalRenewal(unittest.TestCase):
    def test_same_key_renewal_preserves_subject_and_sans(self): ...
    def test_rekey_renewal_requires_matching_sans(self): ...
    def test_renewal_revokes_predecessor(self): ...
    def test_renewal_blocked_when_profile_self_renew_false(self): ...
    def test_renewal_audit_log_records_portal_user(self): ...

class TestPortalRevocation(unittest.TestCase):
    def test_owner_can_revoke_own_cert(self): ...
    def test_non_owner_cannot_revoke(self): ...
    def test_revocation_blocked_when_profile_self_revoke_false(self): ...

class TestPortalScopeIsolation(unittest.TestCase):
    def test_portal_session_cannot_reach_admin_endpoints(self): ...
    def test_admin_session_can_reach_admin_endpoints(self): ...
    def test_portal_user_cannot_see_other_users_audit_log(self): ...
    def test_portal_does_not_leak_internal_serial_numbers(self): ...
```

The scope-isolation tests are non-negotiable. Privilege escalation in
this layer is the worst possible failure for a CA's adoption.

---

## Per-change checklist

- [ ] `portal.py` — new module
- [ ] `pki_server.py` — `/portal/` mount, owner tagging at issuance,
      `CertProfile` self-revoke/self-renew fields
- [ ] `web_ui.py` — admin URLs moved to `/admin/` (with 301s from `/`)
- [ ] `acme_server.py`, `scep_server.py`, `est_server.py`,
      `cmp_server.py` — owner tagging at issuance
- [ ] `db_migrations/pki/00X_portal.sql` — `cert_owners` table
- [ ] `pypki_admin.py` — `link-account`, `portal-remap`,
      `portal-disable-user`
- [ ] `test_pki_server.py` — four new test classes
- [ ] `README.md` — portal section, migration note for the URL move
- [ ] `CHANGELOG.md` — `### Added` (portal), `### Changed` (admin URL)
- [ ] `docs/PORTAL.md` — operator setup, ownership model, troubleshooting
- [ ] `pypki-flows.html` — portal renewal + revocation flow

Run `./run_tests.sh`.

---

## Open questions

1. **Bulk operations**: the portal might want "renew all my certs
   expiring in 14 days." Implement as a single endpoint
   (`POST /portal/certs/bulk-renew`) gated by a profile-level
   `portal_bulk_ops_max` count. Skip in v1; add when a user asks.

2. **Email notifications on expiry**: noisy and email is fraught. Out
   of scope. Operators integrate via the existing webhook (`hooks.py`
   already fires `cert.expiring`) plus their notification stack
   (PagerDuty, Slack, email). Document the recipe in
   `docs/NOTIFICATIONS.md`.

3. **Cross-tenant isolation in multi-tenant deployments**: this spec
   doesn't define tenants. Multi-tenancy probably needs its own design
   doc; for now, treat the portal as single-tenant where every
   authenticated identity is its own tenant.

4. **Approval workflow integration**: if RA is enabled (`docs/RA.md`),
   self-service renewal still needs RA approval for sensitive
   profiles. The RA workflow already supports this; the portal just
   exposes the pending-approval state in the cert detail view. Verify
   the existing RA endpoints accept a portal-scoped requester.

5. **Static asset CSP**: the portal is the most exposed surface. Set
   `Content-Security-Policy: default-src 'self'; img-src 'self' data:;
   script-src 'self'; style-src 'self'` and verify no inline event
   handlers slip in. Existing `web_ui.py` has CSP wiring; reuse it.
