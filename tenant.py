#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Multi-tenancy for PyPKI.

Core concepts
-------------
- Tenant:  A hard isolation boundary identified by a slug (e.g. 'acme-corp').
           The system tenant ('__system') is the default for single-tenant
           deployments; every existing row belongs to it.
- TenantScopedConnection: wraps a Database and injects ``AND tenant_id = ?``
           into every SELECT/UPDATE/DELETE against a tenant-scoped table.
           This is the primary defense against cross-tenant data leaks.
- TenantManager: CRUD operations and quota enforcement.

Load-bearing rules (from CLAUDE.md §1.2)
-----------------------------------------
- Do NOT change TENANT_SCOPED_TABLES, _inject_tenant_filter, or
  TenantScopedConnection without a sidecar PR documenting the change.
  Bugs here are cross-tenant data leaks.
- The query rewriter uses parameterized queries; tenant_id is always a
  bound parameter, never interpolated into the SQL string.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("pypki.tenant")

SYSTEM_TENANT = "__system"

# ---------------------------------------------------------------------------
# TENANT_SCOPED_TABLES — allowlist for query injection
# ---------------------------------------------------------------------------

# Tables whose rows belong to a specific tenant.
# Every SELECT/UPDATE/DELETE against these tables gets an injected
# ``AND tenant_id = ?`` clause by TenantScopedConnection.
# ADD new tables here when they carry per-tenant data;
# DO NOT add global/config tables (tenants, tenant_*, schema_migrations, etc.).
TENANT_SCOPED_TABLES: frozenset = frozenset({
    "certificates",
    "key_archive",
    "ca_keys",
    "cert_owners",
    "sso_sessions",
    "wg_peers",
    "matter_dacs",
    "matter_authorities",
    "policy_decisions",
    "policy_versions",
    "pending_requests",
})

# Uppercase version for case-insensitive matching
_TENANT_SCOPED_UPPER: frozenset = frozenset(t.upper() for t in TENANT_SCOPED_TABLES)

# Trailing clauses that come after the WHERE clause in a SELECT
_TRAILING_CLAUSES = (
    " ORDER BY ", " LIMIT ", " GROUP BY ", " HAVING ", " UNION ", " INTERSECT ", " EXCEPT ",
)


# ---------------------------------------------------------------------------
# SQL filter injection
# ---------------------------------------------------------------------------

def _extract_primary_table(upper_sql: str) -> str:
    """
    Extract the first referenced table name from an uppercase SQL statement.

    Handles:
      SELECT ... FROM table [alias] [JOIN ...]
      UPDATE table SET ...
      DELETE FROM table ...
      INSERT INTO table ...

    Returns '' if the table cannot be determined.
    """
    # FROM clause (covers SELECT and DELETE)
    m = re.search(r'\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)', upper_sql)
    if m:
        return m.group(1).upper()

    # UPDATE table
    m = re.match(r'\s*UPDATE\s+([A-Za-z_][A-Za-z0-9_]*)', upper_sql)
    if m:
        return m.group(1).upper()

    # INSERT INTO table
    m = re.search(r'\bINTO\s+([A-Za-z_][A-Za-z0-9_]*)', upper_sql)
    if m:
        return m.group(1).upper()

    return ""


def _is_join_query(upper_sql: str) -> bool:
    return bool(re.search(r'\bJOIN\b', upper_sql))


def _inject_tenant_filter(
    sql: str,
    params: Sequence[Any],
    tenant_id: str,
) -> Tuple[str, tuple]:
    """
    Inject ``tenant_id = ?`` into a SQL statement against a tenant-scoped table.

    Safety properties
    -----------------
    * tenant_id is always a bound parameter; never interpolated into SQL.
    * Only tables in TENANT_SCOPED_TABLES are modified.
    * INSERT statements are passed through unchanged (callers must supply
      tenant_id in the values list, or the DEFAULT '__system' applies).
    * JOIN queries are passed through with a warning; the caller must
      include the tenant filter explicitly.
    * Unknown/complex patterns: passed through with a debug log.

    Returns (modified_sql, modified_params).
    """
    upper = sql.upper().strip()
    params = tuple(params)

    # INSERT: tenant_id must be in the values; skip filter injection.
    if upper.startswith("INSERT"):
        return sql, params

    table = _extract_primary_table(upper)
    if not table or table not in _TENANT_SCOPED_UPPER:
        return sql, params

    # JOIN queries: caller must handle tenant_id explicitly.
    if _is_join_query(upper):
        log.debug(
            "TenantScopedConnection: JOIN on tenant-scoped table %s; "
            "tenant_id filter NOT auto-injected — caller must include it.",
            table,
        )
        return sql, params

    has_where = bool(re.search(r'\bWHERE\b', upper))

    if has_where:
        # Append to the end of the WHERE conditions (before trailing clauses)
        # to avoid altering any existing subquery structure.
        return sql + " AND tenant_id = ?", params + (tenant_id,)
    else:
        # No WHERE — insert before ORDER BY / LIMIT / GROUP BY etc.
        for clause in _TRAILING_CLAUSES:
            pos = upper.find(clause)
            if pos != -1:
                return (
                    sql[:pos] + " WHERE tenant_id = ?" + sql[pos:],
                    params + (tenant_id,),
                )
        # No trailing clause: append
        return sql + " WHERE tenant_id = ?", params + (tenant_id,)


# ---------------------------------------------------------------------------
# TenantScopedConnection
# ---------------------------------------------------------------------------

class TenantScopedConnection:
    """
    Wraps a Database and automatically injects ``tenant_id = ?`` filters
    into queries against tenant-scoped tables.

    Thread-safety: the underlying Database is thread-safe; this class adds
    no shared mutable state.

    Usage::

        db = make_db(url)
        scoped = TenantScopedConnection(db, "acme-corp")
        certs = scoped.fetchall("SELECT * FROM certificates WHERE revoked = 0")
        # → executes: SELECT * FROM certificates WHERE revoked = 0 AND tenant_id = ?
        #   with params: (0, "acme-corp")
    """

    COOKIE_NAME = "pypki_session"   # mirror SessionStore for compat

    def __init__(self, db: Any, tenant_id: str) -> None:
        self._db        = db
        self.tenant_id  = tenant_id

    # ---- Delegating query interface ----

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> List[Any]:
        sql2, p2 = _inject_tenant_filter(sql, params, self.tenant_id)
        return self._db.fetchall(sql2, p2)

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Optional[Any]:
        sql2, p2 = _inject_tenant_filter(sql, params, self.tenant_id)
        return self._db.fetchone(sql2, p2)

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        sql2, p2 = _inject_tenant_filter(sql, params, self.tenant_id)
        self._db.execute(sql2, p2)

    def executemany(self, sql: str, seq_params) -> None:
        # executemany is typically for bulk INSERTs; pass through unchanged
        self._db.executemany(sql, seq_params)

    def transaction(self):
        return self._db.transaction()

    def advisory_lock(self, key: str):
        return self._db.advisory_lock(key)

    # ---- Unscoped escape hatch (for cross-tenant admin operations) ----

    def unscoped(self, sql: str, params: Sequence[Any] = ()) -> List[Any]:
        """Execute without tenant filter. Requires explicit justification at call site."""
        return self._db.fetchall(sql, params)

    @property
    def backend(self):
        return self._db.backend

    def now(self):
        return self._db.now()


# ---------------------------------------------------------------------------
# Tenant dataclass
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Tenant:
    slug:            str
    display_name:    str
    created_at:      int
    created_by:      str
    isolation_level: str  = "strict"
    suspended:       bool = False
    suspended_reason: Optional[str] = None
    config:          dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class TenantQuota:
    tenant_slug:            str
    max_active_certs:       Optional[int] = None
    max_issuances_per_day:  Optional[int] = None
    max_sub_cas:            Optional[int] = None
    max_acme_accounts:      Optional[int] = None


# ---------------------------------------------------------------------------
# TenantManager — CRUD, quota, URL/DNS resolution
# ---------------------------------------------------------------------------

class TenantManager:
    """
    Operations on tenants: create, list, suspend, delete, quota management,
    URL path and DNS Host-header resolution.

    All mutating operations go through the PKI database (unscoped — the
    tenants table is a global/config table, not per-tenant data).
    """

    SLUG_RE = re.compile(r'^[a-z][a-z0-9-]{1,30}$')

    def __init__(self, db: Any, audit_log: Any = None) -> None:
        self._db        = db
        self._audit_log = audit_log

    # ---- CRUD ----

    def create(
        self,
        slug: str,
        display_name: str,
        created_by: str = "system",
        isolation_level: str = "strict",
        max_active_certs: Optional[int] = None,
        max_issuances_per_day: Optional[int] = None,
    ) -> Tenant:
        if slug != SYSTEM_TENANT and not self.SLUG_RE.match(slug):
            raise ValueError(
                f"Invalid tenant slug {slug!r}. Must match [a-z][a-z0-9-]{{1,30}}."
            )
        now = int(time.time())
        self._db.execute(
            "INSERT INTO tenants (slug, display_name, created_at, created_by, isolation_level) "
            "VALUES (?, ?, ?, ?, ?)",
            (slug, display_name, now, created_by, isolation_level),
        )
        self._db.execute(
            "INSERT OR IGNORE INTO tenant_quotas "
            "(tenant_slug, max_active_certs, max_issuances_per_day) VALUES (?, ?, ?)",
            (slug, max_active_certs, max_issuances_per_day),
        )
        if self._audit_log:
            try:
                self._audit_log.record("tenant.create", f"slug={slug}", created_by)
            except Exception:
                pass
        log.info("Tenant created: %s", slug)
        return self.get(slug)

    def get(self, slug: str) -> Optional[Tenant]:
        row = self._db.fetchone("SELECT * FROM tenants WHERE slug = ?", (slug,))
        if row is None:
            return None
        return Tenant(
            slug=row["slug"],
            display_name=row["display_name"],
            created_at=row["created_at"],
            created_by=row["created_by"],
            isolation_level=row["isolation_level"],
            suspended=bool(row["suspended"]),
            suspended_reason=row["suspended_reason"],
            config=json.loads(row["config_json"] or "{}"),
        )

    def list(self, include_suspended: bool = False) -> List[Tenant]:
        if include_suspended:
            rows = self._db.fetchall("SELECT * FROM tenants ORDER BY slug")
        else:
            rows = self._db.fetchall(
                "SELECT * FROM tenants WHERE suspended = 0 ORDER BY slug"
            )
        return [
            Tenant(
                slug=r["slug"],
                display_name=r["display_name"],
                created_at=r["created_at"],
                created_by=r["created_by"],
                isolation_level=r["isolation_level"],
                suspended=bool(r["suspended"]),
                suspended_reason=r["suspended_reason"],
                config=json.loads(r["config_json"] or "{}"),
            )
            for r in rows
        ]

    def suspend(self, slug: str, reason: str = "", by: str = "system") -> None:
        self._db.execute(
            "UPDATE tenants SET suspended = 1, suspended_reason = ? WHERE slug = ?",
            (reason, slug),
        )
        if self._audit_log:
            try:
                self._audit_log.record("tenant.suspend", f"slug={slug} reason={reason!r}", by)
            except Exception:
                pass

    def resume(self, slug: str, by: str = "system") -> None:
        self._db.execute(
            "UPDATE tenants SET suspended = 0, suspended_reason = NULL WHERE slug = ?",
            (slug,),
        )
        if self._audit_log:
            try:
                self._audit_log.record("tenant.resume", f"slug={slug}", by)
            except Exception:
                pass

    def delete(self, slug: str, by: str = "system") -> None:
        if slug == SYSTEM_TENANT:
            raise ValueError("Cannot delete the system tenant.")
        # Refuse if tenant has any certificates
        row = self._db.fetchone(
            "SELECT COUNT(*) AS n FROM certificates WHERE tenant_id = ?", (slug,)
        )
        if row and row["n"] > 0:
            raise ValueError(
                f"Cannot delete tenant {slug!r}: it has {row['n']} certificate(s). "
                "Revoke and purge them first."
            )
        self._db.execute("DELETE FROM tenant_admins WHERE tenant_slug = ?", (slug,))
        self._db.execute("DELETE FROM tenant_quotas WHERE tenant_slug = ?", (slug,))
        self._db.execute("DELETE FROM tenant_dns_aliases WHERE tenant_slug = ?", (slug,))
        self._db.execute("DELETE FROM tenants WHERE slug = ?", (slug,))
        if self._audit_log:
            try:
                self._audit_log.record("tenant.delete", f"slug={slug}", by)
            except Exception:
                pass

    # ---- Quota management ----

    def get_quota(self, slug: str) -> Optional[TenantQuota]:
        row = self._db.fetchone(
            "SELECT * FROM tenant_quotas WHERE tenant_slug = ?", (slug,)
        )
        if row is None:
            return None
        return TenantQuota(
            tenant_slug=row["tenant_slug"],
            max_active_certs=row["max_active_certs"],
            max_issuances_per_day=row["max_issuances_per_day"],
            max_sub_cas=row["max_sub_cas"],
            max_acme_accounts=row["max_acme_accounts"],
        )

    def set_quota(self, slug: str, **kwargs) -> None:
        """Update one or more quota fields. Keys match TenantQuota field names."""
        self._db.execute(
            "INSERT OR IGNORE INTO tenant_quotas (tenant_slug) VALUES (?)", (slug,)
        )
        for col in ("max_active_certs", "max_issuances_per_day",
                    "max_sub_cas", "max_acme_accounts"):
            if col in kwargs:
                self._db.execute(
                    f"UPDATE tenant_quotas SET {col} = ? WHERE tenant_slug = ?",
                    (kwargs[col], slug),
                )

    def check_active_cert_quota(self, slug: str) -> None:
        """Raise PermissionError if the tenant has hit its active-cert quota."""
        quota = self.get_quota(slug)
        if quota is None or quota.max_active_certs is None:
            return
        row = self._db.fetchone(
            "SELECT COUNT(*) AS n FROM certificates "
            "WHERE tenant_id = ? AND revoked = 0",
            (slug,),
        )
        n = row["n"] if row else 0
        if n >= quota.max_active_certs:
            raise PermissionError(
                f"Tenant {slug!r} has reached its active-cert quota "
                f"({n}/{quota.max_active_certs}). Revoke unused certs or request a quota increase."
            )

    # ---- Admin management ----

    def add_admin(self, slug: str, identity: str, role: str = "operator",
                  by: str = "system") -> None:
        now = int(time.time())
        self._db.execute(
            "INSERT OR REPLACE INTO tenant_admins "
            "(tenant_slug, identity, role, granted_at, granted_by) VALUES (?, ?, ?, ?, ?)",
            (slug, identity, role, now, by),
        )

    def remove_admin(self, slug: str, identity: str) -> None:
        self._db.execute(
            "DELETE FROM tenant_admins WHERE tenant_slug = ? AND identity = ?",
            (slug, identity),
        )

    def list_admins(self, slug: str) -> List[Dict]:
        rows = self._db.fetchall(
            "SELECT * FROM tenant_admins WHERE tenant_slug = ? ORDER BY granted_at",
            (slug,),
        )
        return [dict(r) for r in rows]

    # ---- DNS alias management ----

    def add_dns_alias(self, slug: str, hostname: str) -> None:
        existing = self._db.fetchone(
            "SELECT tenant_slug FROM tenant_dns_aliases WHERE hostname = ?", (hostname,)
        )
        if existing and existing["tenant_slug"] != slug:
            raise ValueError(
                f"Hostname {hostname!r} is already an alias for tenant {existing['tenant_slug']!r}"
            )
        self._db.execute(
            "INSERT OR REPLACE INTO tenant_dns_aliases (hostname, tenant_slug) VALUES (?, ?)",
            (hostname, slug),
        )

    def remove_dns_alias(self, hostname: str) -> None:
        self._db.execute(
            "DELETE FROM tenant_dns_aliases WHERE hostname = ?", (hostname,)
        )

    # ---- Resolution ----

    def resolve_from_path(self, path: str) -> str:
        """
        Resolve the tenant slug from a URL path.

        /api/v1/t/<slug>/...  → slug
        /acme/t/<slug>/...    → slug
        /portal/t/<slug>/...  → slug
        anything else         → '__system'
        """
        # Match /t/<slug> anywhere in the path (supports /api/v1/t/slug, /acme/t/slug, etc.)
        m = re.search(r'/t/([a-z][a-z0-9-]{1,30})(?:/|$)', path)
        if m:
            return m.group(1)
        return SYSTEM_TENANT

    def resolve_from_host(self, host: str) -> str:
        """
        Resolve the tenant slug from the HTTP Host header.
        Returns '__system' if no alias matches.
        """
        hostname = host.split(":")[0].lower()  # strip port
        row = self._db.fetchone(
            "SELECT tenant_slug FROM tenant_dns_aliases WHERE hostname = ?", (hostname,)
        )
        return row["tenant_slug"] if row else SYSTEM_TENANT

    def require_not_suspended(self, slug: str) -> None:
        """Raise PermissionError if the tenant is suspended."""
        t = self.get(slug)
        if t is None:
            raise LookupError(f"Tenant not found: {slug!r}")
        if t.suspended:
            raise PermissionError(
                f"Tenant {slug!r} is suspended"
                + (f": {t.suspended_reason}" if t.suspended_reason else "")
            )
