# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
migration.py — one-shot SQLite ↔ Postgres data migration.

This is the operator-side "switch backends without rebuilding state" tool.
It assumes the DAL refactor (db.py + migrations.py) has shipped and that
the destination already has the same schema_version applied as the source.

Shape of the tool:

    from migration import migrate_all, verify_all

    migrate_all(src_root="ca/", dst_factory=lambda ns: make_db(f"postgresql://.../{ns}"))
    errors = verify_all(src_root="ca/", dst_factory=...)

Or via the CLI in pypki_admin.py:

    pypki-admin migrate-data    --ca-dir ./ca --to-db-url postgresql://...
    pypki-admin verify-migration --ca-dir ./ca --to-db-url postgresql://...

Design notes
------------

The schema decisions in db.py + db_migrations/* were specifically made to
keep this migration mechanical:

  * BLOB ↔ BYTEA — psycopg accepts Python ``bytes`` directly.
  * No DB-specific functions, triggers, or stored procedures.
  * Token substitution at apply-time means schema is identical post-bootstrap.

The only meaningful divergence is auto-increment sequence state for the
two tables that use ``{{auto_pk}}``: ``audit.audit`` and ``pki.crl_base``
(SQLite ROWID alias is NOT auto-PK, so crl_base is special-cased — its
``id INTEGER PRIMARY KEY`` happens to auto-increment on SQLite via ROWID
but on Postgres it's a plain integer; this is a pre-existing schema gap
we work around by passing explicit ids during migration).

We use ``INSERT ... ON CONFLICT (pk) DO UPDATE`` for every table, making
the migration idempotent. Destination rows already populated by schema
seeds (``serial_counter`` id=1 value=1000, ``crl_number`` id=1 value=0)
are overwritten by source values rather than producing PK conflicts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger("pypki.migration")


# =============================================================================
# Table catalog
# =============================================================================

@dataclass(frozen=True)
class TableSpec:
    """One canonical (non-ephemeral) table to migrate."""

    name: str
    pk: Tuple[str, ...]                 # one or more columns forming the PK
    auto_pk: bool = False               # true if PK is BIGSERIAL/AUTOINCREMENT
    has_blob: bool = False              # true if any column is BLOB/BYTEA


# Tables intentionally NOT migrated. ACME nonces are minted with sub-second
# expiry and re-generated on the fly; carrying them across is meaningless.
EPHEMERAL_TABLES: Dict[str, set] = {
    "acme": {"nonces"},
}

# The schema_migrations table tracks which migrations have been applied.
# The destination has its own (set by `pypki migrate` against the dst URL),
# so we never copy it.
INTERNAL_TABLES: set = {"schema_migrations"}


TABLE_CATALOG: Dict[str, List[TableSpec]] = {
    "pki": [
        TableSpec("certificates",            pk=("serial",),     has_blob=True),
        TableSpec("serial_counter",          pk=("id",)),
        TableSpec("crl_base",                pk=("id",), auto_pk=True, has_blob=True),
        TableSpec("crl_number",              pk=("id",)),
        TableSpec("key_archive",             pk=("serial",), has_blob=True),
        TableSpec("ipsec_pending_requests",  pk=("request_id",)),
        TableSpec("ipsec_cert_confirmations", pk=("serial",)),
    ],
    "audit": [
        TableSpec("audit", pk=("id",), auto_pk=True),
    ],
    "acme": [
        TableSpec("accounts",       pk=("kid",)),
        TableSpec("orders",         pk=("id",)),
        TableSpec("authorizations", pk=("id",)),
        TableSpec("challenges",     pk=("id",)),
        TableSpec("certificates",   pk=("id",)),
    ],
    "scep": [
        # SCEP transactions are persistent records of completed enrollments,
        # used for the CertRep retry flow. NOT ephemeral despite the name.
        TableSpec("scep_transactions", pk=("transaction_id",)),
    ],
}


# =============================================================================
# Errors
# =============================================================================

class MigrationError(RuntimeError):
    """Raised when migration cannot proceed safely."""


# =============================================================================
# Schema-version preflight
# =============================================================================

def _read_schema_version(db: Any, namespace: str) -> Optional[int]:
    """Return the highest applied migration version for ``namespace``, or None.

    NOTE: PyPKI's ``schema_migrations`` table is per-database-file (each of
    the four logical DBs has its own), with columns ``version, name,
    applied_at`` and NO ``namespace`` column. The ``namespace`` argument
    here is informational only — it labels which logical DB ``db`` is
    expected to represent, used in error messages.
    """
    try:
        row = db.fetchone("SELECT MAX(version) AS v FROM schema_migrations")
    except Exception:
        return None
    if row is None:
        return None
    v = row["v"] if hasattr(row, "__getitem__") else row[0]
    return int(v) if v is not None else None


def _assert_schema_versions_match(src: Any, dst: Any, namespace: str) -> None:
    sv = _read_schema_version(src, namespace)
    dv = _read_schema_version(dst, namespace)
    if sv is None:
        raise MigrationError(
            f"[{namespace}] source has no applied migrations — is the path correct?"
        )
    if dv is None:
        raise MigrationError(
            f"[{namespace}] destination has no migrations applied. "
            f"Run `pypki migrate` against the destination first."
        )
    if sv != dv:
        raise MigrationError(
            f"[{namespace}] schema_version mismatch: src={sv} dst={dv}. "
            f"Run `pypki migrate` against whichever side lags."
        )


# =============================================================================
# Per-table migration
# =============================================================================

def _list_columns(db: Any, table: str) -> List[str]:
    """Return ordered column names for ``table`` on this backend.

    Implementation is portable: try Postgres' information_schema first, fall
    back to SQLite's PRAGMA. The Database abstraction doesn't expose this
    natively, so we sniff.
    """
    # Try Postgres first.
    try:
        rows = db.fetchall(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = ? ORDER BY ordinal_position",
            (table,),
        )
        if rows:
            return [(r["column_name"] if hasattr(r, "__getitem__")
                     else r[0]) for r in rows]
    except Exception:
        pass

    # Fall back to SQLite's PRAGMA.
    try:
        rows = db.fetchall(f"PRAGMA table_info({table})")
        # PRAGMA returns: cid, name, type, notnull, dflt_value, pk
        out = []
        for r in rows:
            try:
                out.append(r["name"])
            except Exception:
                out.append(r[1])
        return out
    except Exception as e:
        raise MigrationError(f"could not introspect columns for {table}: {e}")


def _coerce_value(v: Any) -> Any:
    """Normalize values for cross-backend INSERT.

    psycopg3 returns ``memoryview`` for ``BYTEA``; sqlite3 won't accept it.
    Coerce to bytes. Other types pass through unchanged.
    """
    if isinstance(v, memoryview):
        return bytes(v)
    return v


def _quote_ident(backend_dialect: str, ident: str) -> str:
    """Conservative identifier quoting. Both SQLite and Postgres accept "..".

    Identifiers in TABLE_CATALOG are all simple snake_case so this is mostly
    belt-and-braces, but it costs nothing.
    """
    return '"' + ident.replace('"', '""') + '"'


def _detect_dialect(db: Any) -> str:
    """Return 'sqlite' or 'postgres'."""
    cls = type(db).__name__.lower()
    if "sqlite" in cls:
        return "sqlite"
    if "postgres" in cls or "psycopg" in cls:
        return "postgres"
    # Fall back to a probe: SQLite has sqlite_master; Postgres has pg_catalog.
    try:
        db.fetchone("SELECT 1 FROM sqlite_master LIMIT 1")
        return "sqlite"
    except Exception:
        return "postgres"


def _build_upsert_sql(table: str, cols: Sequence[str], pk: Sequence[str]) -> str:
    """Produce an INSERT ... ON CONFLICT DO UPDATE that works on both backends.

    SQLite and Postgres both support this since SQLite 3.24 / Postgres 9.5.
    Placeholders use ``?`` — db.py's PostgresDB rewrites to ``%s`` internally.
    """
    col_list = ",".join(_quote_ident("any", c) for c in cols)
    placeholders = ",".join(["?"] * len(cols))
    pk_list = ",".join(_quote_ident("any", c) for c in pk)
    update_cols = [c for c in cols if c not in pk]
    if update_cols:
        set_clause = ", ".join(
            f"{_quote_ident('any', c)} = excluded.{_quote_ident('any', c)}"
            for c in update_cols
        )
        return (
            f"INSERT INTO {_quote_ident('any', table)} ({col_list}) "
            f"VALUES ({placeholders}) "
            f"ON CONFLICT ({pk_list}) DO UPDATE SET {set_clause}"
        )
    # PK-only table (no other columns to update on conflict).
    return (
        f"INSERT INTO {_quote_ident('any', table)} ({col_list}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT ({pk_list}) DO NOTHING"
    )


def _copy_table(src: Any, dst: Any, spec: TableSpec, batch: int) -> int:
    """Copy one table, returning the number of rows copied.

    Uses LIMIT/OFFSET pagination over the source. For tables with
    ``auto_pk=True`` we order by ``id``; otherwise we order by the first
    PK column — both are deterministic enough for a one-shot migration.
    """
    table = spec.name
    order_col = spec.pk[0]

    total = src.fetchone(f"SELECT COUNT(*) AS c FROM {table}")
    n = total["c"] if hasattr(total, "__getitem__") else total[0]
    if n == 0:
        logger.info(f"  {table}: empty, nothing to copy")
        return 0

    cols = _list_columns(src, table)
    if not cols:
        raise MigrationError(f"could not discover columns for {table}")

    sql_select = (
        f"SELECT {','.join(_quote_ident('any', c) for c in cols)} "
        f"FROM {table} "
        f"ORDER BY {_quote_ident('any', order_col)} "
        f"LIMIT ? OFFSET ?"
    )
    sql_insert = _build_upsert_sql(table, cols, spec.pk)

    copied = 0
    offset = 0
    while True:
        rows = src.fetchall(sql_select, (batch, offset))
        if not rows:
            break
        payload = []
        for r in rows:
            try:
                payload.append(tuple(_coerce_value(r[c]) for c in cols))
            except (KeyError, IndexError):
                # Row is positional — psycopg3 with row_factory off would do this.
                payload.append(tuple(_coerce_value(r[i]) for i in range(len(cols))))
        dst.executemany(sql_insert, payload)
        copied += len(rows)
        offset += len(rows)
        if copied % (batch * 5) == 0 or copied == n:
            logger.info(f"  {table}: {copied}/{n} rows")
        if len(rows) < batch:
            break

    return copied


def _resync_sequence(dst: Any, namespace: str, spec: TableSpec) -> None:
    """After a bulk INSERT with explicit ids, reset the auto-PK sequence.

    On Postgres, BIGSERIAL creates an implicit sequence ``<table>_id_seq``.
    On SQLite, autoincrement is tracked via ``sqlite_sequence``.
    Idempotent: a no-op for tables without an auto-PK.
    """
    if not spec.auto_pk:
        return

    dialect = _detect_dialect(dst)
    table = spec.name
    pk = spec.pk[0]

    if dialect == "sqlite":
        row = dst.fetchone(f"SELECT MAX({pk}) AS m FROM {table}")
        max_id = row["m"] if hasattr(row, "__getitem__") else row[0]
        if max_id is None:
            return
        # Upsert into sqlite_sequence; this controls the NEXT autoincrement.
        # Note: sqlite_sequence rows only exist for AUTOINCREMENT tables; a
        # plain INTEGER PRIMARY KEY (rowid alias) self-manages without us.
        try:
            existing = dst.fetchone(
                "SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)
            )
        except Exception:
            existing = None
        if existing is None:
            try:
                dst.execute(
                    "INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)",
                    (table, max_id),
                )
            except Exception:
                # No sqlite_sequence row exists because this is a ROWID-alias
                # table. SQLite picks max(rowid)+1 automatically — nothing to do.
                pass
        else:
            try:
                dst.execute(
                    "UPDATE sqlite_sequence SET seq = ? WHERE name = ?",
                    (max_id, table),
                )
            except Exception:
                pass
    else:
        # Postgres. ``pg_get_serial_sequence`` returns NULL if there is no
        # implicit sequence (e.g. INTEGER PRIMARY KEY without BIGSERIAL).
        try:
            row = dst.fetchone(
                f"SELECT pg_get_serial_sequence(?, ?) AS s",
                (table, pk),
            )
            seq_name = row["s"] if hasattr(row, "__getitem__") else row[0]
            if not seq_name:
                logger.info(f"  {table}: no implicit sequence, skipping resync")
                return
            row = dst.fetchone(f"SELECT MAX({pk}) AS m FROM {table}")
            max_id = row["m"] if hasattr(row, "__getitem__") else row[0]
            if max_id is None:
                return
            # ``setval(seq, value, true)`` makes nextval() return value+1.
            dst.execute(
                "SELECT setval(?, ?, true)",
                (seq_name, max_id),
            )
            logger.info(f"  {table}: sequence resynced to {max_id}")
        except Exception as e:
            logger.warning(f"  {table}: sequence resync skipped: {e}")


# =============================================================================
# Per-namespace orchestration
# =============================================================================

def migrate_namespace(
    src: Any,
    dst: Any,
    namespace: str,
    *,
    batch: int = 10_000,
) -> Dict[str, int]:
    """Copy all canonical tables for ``namespace`` from src → dst.

    Returns a dict ``{table_name: rows_copied}``. Raises ``MigrationError``
    on schema-version mismatch.
    """
    if namespace not in TABLE_CATALOG:
        raise MigrationError(f"unknown namespace: {namespace}")

    _assert_schema_versions_match(src, dst, namespace)

    counts: Dict[str, int] = {}
    logger.info(f"[{namespace}] migrating {len(TABLE_CATALOG[namespace])} tables")
    for spec in TABLE_CATALOG[namespace]:
        if spec.name in EPHEMERAL_TABLES.get(namespace, set()):
            logger.info(f"  {spec.name}: ephemeral, skipping")
            continue
        n = _copy_table(src, dst, spec, batch)
        counts[spec.name] = n
        _resync_sequence(dst, namespace, spec)
    return counts


# =============================================================================
# Per-namespace verification
# =============================================================================

def verify_namespace(
    src: Any,
    dst: Any,
    namespace: str,
    *,
    sample: int = 100,
) -> List[str]:
    """Return a list of human-readable errors. Empty list = verified OK.

    Performs four checks:
      1. Row counts match per table.
      2. A random sample of rows is byte-identical between src and dst.
      3. Schema version matches.
      4. For auto-PK tables, the sequence is at-or-above MAX(id).
    """
    errors: List[str] = []

    # 3 — schema version (first; if mismatch, the rest is meaningless)
    sv = _read_schema_version(src, namespace)
    dv = _read_schema_version(dst, namespace)
    if sv != dv:
        errors.append(f"[{namespace}] schema_version: src={sv} dst={dv}")
        return errors

    for spec in TABLE_CATALOG[namespace]:
        if spec.name in EPHEMERAL_TABLES.get(namespace, set()):
            continue
        table = spec.name

        # 1 — row counts
        sc_row = src.fetchone(f"SELECT COUNT(*) AS c FROM {table}")
        dc_row = dst.fetchone(f"SELECT COUNT(*) AS c FROM {table}")
        sc = sc_row["c"] if hasattr(sc_row, "__getitem__") else sc_row[0]
        dc = dc_row["c"] if hasattr(dc_row, "__getitem__") else dc_row[0]
        if sc != dc:
            errors.append(f"[{namespace}.{table}] row count: src={sc} dst={dc}")
            # Don't bother sampling if the totals don't match.
            continue
        if sc == 0:
            continue

        # 2 — random sample (use the source's rows; assert dst has them all)
        cols = _list_columns(src, table)
        pk_col = spec.pk[0]
        sample_rows = src.fetchall(
            f"SELECT {','.join(_quote_ident('any', c) for c in cols)} "
            f"FROM {table} ORDER BY RANDOM() LIMIT ?",
            (sample,),
        )
        for sr in sample_rows:
            try:
                pk_val = sr[pk_col]
            except (KeyError, IndexError):
                pk_val = sr[cols.index(pk_col)]
            dr = dst.fetchone(
                f"SELECT {','.join(_quote_ident('any', c) for c in cols)} "
                f"FROM {table} WHERE {_quote_ident('any', pk_col)} = ?",
                (pk_val,),
            )
            if dr is None:
                errors.append(
                    f"[{namespace}.{table}] PK={pk_val!r} missing from dst"
                )
                continue
            for c in cols:
                try:
                    s_val = _coerce_value(sr[c])
                    d_val = _coerce_value(dr[c])
                except (KeyError, IndexError):
                    idx = cols.index(c)
                    s_val = _coerce_value(sr[idx])
                    d_val = _coerce_value(dr[idx])
                if s_val != d_val:
                    errors.append(
                        f"[{namespace}.{table}] PK={pk_val!r} column {c!r}: "
                        f"src={s_val!r} dst={d_val!r}"
                    )
                    break  # one mismatch per row is enough

        # 4 — sequence safety for auto-PK tables (Postgres-only)
        if spec.auto_pk and _detect_dialect(dst) == "postgres":
            try:
                row = dst.fetchone(
                    "SELECT pg_get_serial_sequence(?, ?) AS s",
                    (table, spec.pk[0]),
                )
                seq_name = row["s"] if hasattr(row, "__getitem__") else row[0]
                if seq_name:
                    nx = dst.fetchone(f"SELECT last_value AS v FROM {seq_name}")
                    last_val = nx["v"] if hasattr(nx, "__getitem__") else nx[0]
                    mx = dst.fetchone(f"SELECT MAX({spec.pk[0]}) AS m FROM {table}")
                    max_id = mx["m"] if hasattr(mx, "__getitem__") else mx[0]
                    if max_id is not None and last_val < max_id:
                        errors.append(
                            f"[{namespace}.{table}] sequence at {last_val}, "
                            f"MAX({spec.pk[0]})={max_id} — next INSERT will collide"
                        )
            except Exception as e:
                logger.warning(f"[{namespace}.{table}] sequence check skipped: {e}")

    return errors


# =============================================================================
# Multi-namespace orchestration
# =============================================================================

DBFactory = Callable[[str], Any]
"""(namespace: str) -> Database. Caller decides URL scheme per namespace."""


def migrate_all(
    src_factory: DBFactory,
    dst_factory: DBFactory,
    *,
    batch: int = 10_000,
    namespaces: Optional[Iterable[str]] = None,
) -> Dict[str, Dict[str, int]]:
    """Run migrate_namespace for every namespace, in deterministic order."""
    ns_list = list(namespaces) if namespaces is not None else list(TABLE_CATALOG.keys())
    out: Dict[str, Dict[str, int]] = {}
    for ns in ns_list:
        src = src_factory(ns)
        dst = dst_factory(ns)
        out[ns] = migrate_namespace(src, dst, ns, batch=batch)
    return out


def verify_all(
    src_factory: DBFactory,
    dst_factory: DBFactory,
    *,
    sample: int = 100,
    namespaces: Optional[Iterable[str]] = None,
) -> Dict[str, List[str]]:
    """Run verify_namespace for every namespace; return error map."""
    ns_list = list(namespaces) if namespaces is not None else list(TABLE_CATALOG.keys())
    out: Dict[str, List[str]] = {}
    for ns in ns_list:
        src = src_factory(ns)
        dst = dst_factory(ns)
        out[ns] = verify_namespace(src, dst, ns, sample=sample)
    return out


__all__ = [
    "MigrationError",
    "TableSpec",
    "TABLE_CATALOG",
    "EPHEMERAL_TABLES",
    "migrate_namespace",
    "verify_namespace",
    "migrate_all",
    "verify_all",
]
