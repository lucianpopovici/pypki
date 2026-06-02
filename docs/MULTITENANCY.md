# PyPKI Multi-Tenancy

<!-- Last reviewed: 2026-06-02 -->

Multi-tenancy gives each organizational unit a hard isolation boundary:
tenant A's admins cannot see tenant B's certificates, accounts, audit log,
or even confirm that tenant B exists.

Disabled by default. Enable with `--multi-tenant-enabled`.

---

## Architecture

```
System tenant ("__system")
  └── Platform CA, created by ca-init
        └── May issue sub-CAs to tenants

Tenant A ("acme-corp")
  ├── Sub-CAs signed by system root (or tenant's own root)
  ├── Certificates (isolated via tenant_id column)
  ├── ACME/SCEP/EST accounts
  ├── Portal ownership records
  ├── SSO sessions
  └── Admins

Tenant B ("acme-corp-2")
  └── Same structure, fully isolated
```

---

## Isolation mechanism

**Primary defense: `TenantScopedConnection`**

Every query against a tenant-scoped table (see `tenant.TENANT_SCOPED_TABLES`)
automatically has `AND tenant_id = ?` injected by `_inject_tenant_filter()`.
The tenant_id is always a bound parameter — never interpolated into the SQL
string — preventing SQL injection via tenant_id values.

```python
from tenant import TenantScopedConnection
scoped = TenantScopedConnection(db, "acme-corp")
certs = scoped.fetchall("SELECT * FROM certificates WHERE revoked = 0")
# → SELECT * FROM certificates WHERE revoked = 0 AND tenant_id = ?
#   params: ("acme-corp",)
```

**Secondary defense: `# tenant_scoped` annotation**

Any bare SQL call against a tenant-scoped table in non-test code must either
use `TenantScopedConnection` or carry a `# tenant_scoped` comment so reviewers
can verify intent. The CI lint (`scripts/lint_tenant_scoping.py`) enforces this.

**Fail-safe for JOIN queries**: JOINs are passed through with a debug log; the
caller must include tenant_id explicitly. The test suite verifies isolation end-to-end.

---

## URL routing

Tenant scope is in the URL path:

```
/api/v1/t/<slug>/issue        → tenant <slug>
/acme/t/<slug>/directory      → tenant <slug>
/portal/t/<slug>/             → tenant <slug>
/api/v1/issue                 → __system (default)
```

DNS-based routing (when `--tenant-dns-routing-enabled`):

```
acme.pki.example.com          → resolved via tenant_dns_aliases table
pki.example.com               → __system
```

---

## Setup

**1. Enable multi-tenancy**

```bash
pypki serve --multi-tenant-enabled ...
```

**2. Create a tenant**

```bash
pypki_admin tenant-create \
  --slug acme-corp \
  --display-name "Acme Corporation" \
  --owner-identity acme-admins@oidc

# Set quota (optional)
pypki_admin tenant-set-quota \
  --slug acme-corp \
  --max-active-certs 10000 \
  --max-issuances-per-day 1000

# Add admins
pypki_admin tenant-add-admin \
  --slug acme-corp \
  --identity alice@acme.com \
  --role admin

# Add DNS alias
pypki_admin tenant-add-dns-alias \
  --slug acme-corp \
  --hostname acme.pki.example.com
```

**3. Issue a cert under a tenant**

```bash
curl -X POST https://pki.example.com/api/v1/t/acme-corp/issue \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"subject": "CN=web01.acme.example.com", "profile": "tls_server"}'
```

---

## System tenant privileges

- `__system` admins can list (but not read content of) other tenants' data.
- `__system` can issue sub-CAs into other tenants.
- `__system`'s policy applies to every tenant as a baseline.
- `__system` can suspend tenants (`tenant-suspend`).

---

## Tenant management

```bash
pypki_admin tenant-list [--include-suspended]
pypki_admin tenant-show     --slug acme-corp
pypki_admin tenant-suspend  --slug acme-corp --reason "non-payment"
pypki_admin tenant-resume   --slug acme-corp
pypki_admin tenant-delete   --slug acme-corp --confirm  # only if empty
```

---

## CI lint

Run `scripts/lint_tenant_scoping.py` to detect bare SQL calls against
tenant-scoped tables that lack `TenantScopedConnection` or annotation:

```bash
python scripts/lint_tenant_scoping.py *.py
```

---

## Migration from single-tenant

All existing rows automatically belong to `__system` (via `DEFAULT '__system'`
on all `tenant_id` columns). No data migration required.

To move certs to a tenant post-hoc:

```bash
# Identify serials to move, then:
sqlite3 ca/certificates.db \
  "UPDATE certificates SET tenant_id = 'acme-corp' WHERE subject LIKE '%.acme.%'"
```
