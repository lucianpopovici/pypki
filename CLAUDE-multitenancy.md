# CLAUDE-multitenancy.md — Multi-Tenancy

Companion to `CLAUDE.md`. Follow all conventions there. Adds tenant
isolation as a first-class concept: each tenant has its own admins,
ACME accounts, profiles, rate limits, sub-CAs, and audit-log scope.
Builds on `CLAUDE-portal.md` (ownership) and `CLAUDE-sso.md` (auth);
they're prerequisites.

---

## What this is

The portal spec gave individual users scoped views. Multi-tenancy
generalizes that to organizational units. A tenant is a hard isolation
boundary: tenant A's admins cannot see tenant B's certs, accounts,
audit log, or even confirmation that tenant B exists.

Use cases:

- **MSP deployment**: one PyPKI instance serves N customer companies.
- **Internal platform team**: one PyPKI serves N business units in a
  large org, each with their own PKI policy.
- **Cell-based architecture**: tenants = environments (prod, staging,
  dev) on shared infrastructure.

Non-goal: PyPKI as SaaS. The deployment topology is still
operator-controlled; tenants are software-defined.

---

## Tenant model

```
System tenant ("__system")
  └── created by ca-init, holds the platform CA
        └── may issue sub-CAs to tenants
Tenant A ("tenant-acme")
  ├── admins (OIDC group: tenant-acme-admins)
  ├── sub-CAs: A-Intermediate (signed by system root or A's own root)
  ├── ACME accounts
  ├── profiles (may inherit system profiles or define own)
  ├── policy file (own policy, applied after system policy)
  ├── rate limits
  └── audit log scope
Tenant B ("tenant-corp")
  └── (same structure, fully isolated)
```

Every tenant has:

- A short slug (`[a-z][a-z0-9-]{1,30}`), used in URLs and DNS.
- A display name.
- An owning identity (the OIDC group or static user that bootstrapped it).
- An isolation level: `strict` (default) or `linked` (can cross-sign
  with another tenant's CA, opt-in per pair).

---

## URL and routing

Tenant scope is in the URL path:

```
/api/v1/t/<tenant-slug>/issue
/api/v1/t/<tenant-slug>/certs/<serial>
/acme/t/<tenant-slug>/directory
/scep/t/<tenant-slug>/pkiclient.exe
/portal/t/<tenant-slug>/
```

The system tenant is implicit when no `/t/<slug>/` segment is present:

```
/api/v1/issue                  → system tenant
/api/v1/t/__system/issue       → equivalent, explicit
/api/v1/t/acme/issue           → tenant "acme"
```

DNS-based routing also supported (preferred for ACME clients that don't
handle URL prefixes well):

```
acme.pki.example.com           → tenant "acme"
corp.pki.example.com           → tenant "corp"
pki.example.com                → system tenant
```

Resolved via `Host` header against `tenant_dns_aliases` table. DNS
routing is a configuration convention, not a security boundary —
authorization still checks the resolved tenant against the session's
roles.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `tenant.py`       | New module: resolution, isolation enforcement                |
| `pki_server.py`   | Route prefix handling, tenant injection into every request   |
| `db.py`           | Query rewriter: append `WHERE tenant_id = ?` to tenant-scoped queries |
| `acme_server.py`, `scep_server.py`, `est_server.py`, `cmp_server.py`, `ocsp_server.py`, `tsa_server.py` | Tenant-aware routing |
| `web_ui.py`       | Tenant picker for cross-tenant admins, tenant-scoped views   |
| `policy.py`       | Per-tenant policy file resolution                            |
| `db_migrations/*/00X_tenant.sql` | `tenant_id` columns + indexes everywhere  |
| `pypki_admin.py`  | `tenant-create`, `tenant-list`, `tenant-delete`, etc.        |
| `test_pki_server.py` | `TestTenantIsolation`, `TestTenantRouting`, `TestTenantQuotas` |

### Schema additions

```sql
-- db_migrations/pki/00X_tenant.sql
CREATE TABLE tenants (
    slug                TEXT PRIMARY KEY,
    display_name        TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    created_by          TEXT NOT NULL,
    isolation_level     TEXT NOT NULL DEFAULT 'strict',
    suspended           INTEGER NOT NULL DEFAULT 0,
    suspended_reason    TEXT,
    config_json         TEXT                            -- per-tenant settings
);

CREATE TABLE tenant_dns_aliases (
    hostname            TEXT PRIMARY KEY,
    tenant_slug         TEXT NOT NULL,
    FOREIGN KEY (tenant_slug) REFERENCES tenants(slug)
);

CREATE TABLE tenant_admins (
    tenant_slug         TEXT NOT NULL,
    identity            TEXT NOT NULL,
    role                TEXT NOT NULL,         -- 'admin' | 'operator' | 'viewer'
    granted_at          INTEGER NOT NULL,
    granted_by          TEXT NOT NULL,
    PRIMARY KEY (tenant_slug, identity),
    FOREIGN KEY (tenant_slug) REFERENCES tenants(slug)
);

CREATE TABLE tenant_quotas (
    tenant_slug         TEXT PRIMARY KEY,
    max_active_certs            INTEGER,
    max_issuances_per_day       INTEGER,
    max_sub_cas                 INTEGER,
    max_acme_accounts           INTEGER,
    FOREIGN KEY (tenant_slug) REFERENCES tenants(slug)
);

-- Every user-data table gets a tenant_id column:
ALTER TABLE certificates ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__system';
ALTER TABLE ca_keys ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__system';
ALTER TABLE audit_log ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__system';
ALTER TABLE acme_accounts ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__system';
-- ... and so on for every table that holds user data

CREATE INDEX idx_certificates_tenant ON certificates(tenant_id);
CREATE INDEX idx_audit_log_tenant ON audit_log(tenant_id);
-- ... index every tenant_id column
```

The `DEFAULT '__system'` lets existing single-tenant deployments
migrate without touching their data — every existing row becomes
system-tenant.

### Query enforcement (the critical layer)

Bare SQL is unsafe in multi-tenant code: forget one `WHERE tenant_id = ?`
and you've leaked across the boundary. The DAL gets a `tenant_scoped`
mode:

```python
# db.py
class TenantScopedConnection:
    def __init__(self, conn: Connection, tenant_id: str):
        self.conn = conn
        self.tenant_id = tenant_id

    def fetchall(self, sql: str, params: tuple = ()) -> list[Row]:
        sql, params = _inject_tenant_filter(sql, params, self.tenant_id)
        return self.conn.fetchall(sql, params)
    # ... fetchone, execute, executemany ...

def _inject_tenant_filter(sql: str, params: tuple, tenant_id: str
                          ) -> tuple[str, tuple]:
    """Inject `AND tenant_id = ?` into the WHERE clause of every SELECT,
    UPDATE, DELETE against a tenant-scoped table.
    Pure SQL parser, no regex hacks. ~200 LoC."""
    parsed = _parse_sql(sql)
    if _references_tenant_scoped_table(parsed):
        parsed = _add_tenant_predicate(parsed, "tenant_id")
        params = params + (tenant_id,)
    return _serialize_sql(parsed), params
```

`TENANT_SCOPED_TABLES` is a hard-coded allowlist; any new table either
joins the list (tenant-scoped, auto-injected) or is exempted by name
(global tables: `tenants`, `tenant_dns_aliases`, `schema_migrations`,
the system tenant's CA store).

Two-layer defense: the DAL injects the filter, **and** each query also
declares `# tenant_scoped` in a comment so reviewers can see intent.
A linter run in CI rejects bare `db.fetchall(...)` against a
tenant-scoped table without `tenant_scoped` annotation.

### System tenant privileges

The system tenant is special:

- `__system` admins can list (but not read) other tenants' data.
- `__system` can issue sub-CAs into other tenants.
- `__system`'s policy file applies to every tenant as a baseline; each
  tenant may further restrict.
- `__system` can suspend a tenant (`pypki_admin.py tenant-suspend
  --slug X --reason ...`); suspended tenants are read-only.

Cross-tenant operations are explicit and audit-logged with both
tenant IDs.

---

## CLI flags and commands

```
--multi-tenant-enabled true              # default false; once true, can't be flipped back
--tenant-default-quotas-active-certs 1000
--tenant-default-quotas-issuances-per-day 500
--tenant-dns-routing-enabled true
```

`pypki_admin.py`:

- `tenant-create --slug acme --display-name "Acme Corp" --owner-identity acme-admins@oidc`
- `tenant-list [--include-suspended]`
- `tenant-show --slug acme`
- `tenant-set-quota --slug acme --max-active-certs 5000`
- `tenant-add-admin --slug acme --identity user@example.com --role operator`
- `tenant-remove-admin --slug acme --identity user@example.com`
- `tenant-add-dns-alias --slug acme --hostname acme.pki.example.com`
- `tenant-suspend --slug acme --reason "non-payment"`
- `tenant-resume --slug acme`
- `tenant-delete --slug acme --confirm` (hard-deletes; only when empty)

---

## Tests

```
class TestTenantIsolation(unittest.TestCase):
    # The critical category — every test here protects against
    # cross-tenant data leaks
    def test_tenant_a_admin_cannot_list_tenant_b_certs(self): ...
    def test_tenant_a_admin_cannot_revoke_tenant_b_cert(self): ...
    def test_tenant_a_admin_cannot_read_tenant_b_audit_log(self): ...
    def test_tenant_a_acme_account_cannot_issue_under_tenant_b(self): ...
    def test_bare_sql_against_scoped_table_rejected_in_ci_lint(self): ...
    def test_query_injection_does_not_escape_tenant_filter(self): ...

class TestTenantRouting(unittest.TestCase):
    def test_url_path_routing_resolves_tenant(self): ...
    def test_dns_routing_resolves_tenant(self): ...
    def test_url_and_dns_conflict_resolves_to_explicit_url(self): ...
    def test_unknown_tenant_returns_404(self): ...
    def test_suspended_tenant_returns_503_with_reason(self): ...
    def test_system_tenant_implicit_at_root_path(self): ...

class TestTenantQuotas(unittest.TestCase):
    def test_quota_blocks_issuance_above_limit(self): ...
    def test_daily_quota_resets_at_midnight_utc(self): ...
    def test_active_certs_quota_excludes_revoked_and_expired(self): ...
    def test_per_tenant_rate_limit_independent(self): ...

class TestTenantLifecycle(unittest.TestCase):
    def test_create_tenant_provisions_default_quotas(self): ...
    def test_delete_tenant_refuses_non_empty(self): ...
    def test_suspend_then_resume_round_trip(self): ...
    def test_dns_alias_collision_rejected(self): ...
    def test_audit_log_records_cross_tenant_admin_actions(self): ...
```

The isolation tests are non-negotiable. Multi-tenancy without provably
correct isolation is worse than no multi-tenancy.

---

## Per-change checklist

- [ ] `tenant.py` — new module
- [ ] `db.py` — `TenantScopedConnection`, SQL rewriter, tenant-scoped
      table allowlist
- [ ] `pki_server.py` — tenant resolution middleware
- [ ] `acme_server.py`, `scep_server.py`, `est_server.py`,
      `cmp_server.py`, `ocsp_server.py`, `tsa_server.py` — tenant
      routing
- [ ] `web_ui.py` — tenant picker, scoped views
- [ ] `policy.py` — per-tenant policy resolution
- [ ] `db_migrations/*/00X_tenant.sql` — schema for every DB
- [ ] `pypki_admin.py` — tenant subcommands
- [ ] `test_pki_server.py` — four test classes; isolation is critical
- [ ] `scripts/lint_tenant_scoping.py` — CI lint enforcing
      `# tenant_scoped` annotation on bare-SQL callers
- [ ] `.github/workflows/lint.yml` — wire in the tenant-scoping lint
- [ ] `README.md` — multi-tenancy section
- [ ] `CHANGELOG.md` — `### Added`, `### Security`
- [ ] `docs/MULTITENANCY.md` — architecture, threat model, deployment
      patterns
- [ ] `pypki-flows.html` — tenant resolution + isolation flow

Run `./run_tests.sh`. The bare-SQL lint must be a hard CI failure;
otherwise the second layer of defense decays.

---

## Open questions

1. **Tenant-specific CA roots vs shared root**: two operational patterns:
   (a) shared system root → tenant intermediates (default; one root
   ceremony covers everyone), (b) tenant-owned roots (no shared trust;
   each tenant is a fully separate PKI hosted on shared infrastructure).
   Support both; default (a). Document the tradeoffs.

2. **Migration from single-tenant**: existing rows get `tenant_id =
   '__system'` automatically. Operators wanting to split out a tenant
   post-hoc need `pypki_admin.py tenant-migrate --from __system
   --to acme --filter <sql>` to move a set of rows. Reversible until
   the next backup is taken.

3. **Cross-tenant features**: cross-signing (tenant A's root signs
   tenant B's intermediate) and federation (one tenant's ACME accounts
   recognized by another) are useful for org structures with shared
   trust. Both are explicit opt-in pairs in `tenant_links` table, and
   every cross-tenant operation is audit-logged with both tenant IDs
   visible to both sides' admins.

4. **Per-tenant resource limits enforcement**: quotas above are
   advisory by default — rate limits are hard, cert counts are soft
   (warn at 80%, block at 100%). Hard-block as a flag for MSPs who
   bill per cert. Verify quota enforcement happens *before* sub-CA
   constraints and *before* policy evaluation so denied requests
   don't waste cycles.

5. **Tenant audit log inheritance**: system tenant admins seeing
   redacted summaries of tenant activity (counts, but not contents) is
   a useful default. Full visibility requires an explicit
   `--system-can-read-tenant-audit-log` flag and per-tenant opt-in.
   Avoid a model where the operator silently sees everything; that
   destroys the trust story for MSP customers.
