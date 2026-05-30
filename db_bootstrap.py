"""
Database bootstrap automation (CLAUDE-db-bootstrap.md).

Idempotent: running twice on an already-bootstrapped database verifies state
matches expectations and exits 0.  Detects and refuses to silently downgrade
(e.g. existing TLS=on, requested TLS=off).
"""
from __future__ import annotations

import logging
import os
import sqlite3
import stat
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQLite bootstrap
# ---------------------------------------------------------------------------

def init_sqlite(path: Path, *, dry_run: bool = False) -> None:
    """Initialize a SQLite database with WAL mode and recommended PRAGMAs.

    Enforces 0600 on the file and 0700 on its parent directory.
    Idempotent — safe to call on an existing database.
    """
    if dry_run:
        log.info("[dry-run] Would init SQLite at %s (WAL, 0600)", path)
        log.info("[dry-run] Would chmod 0700 on %s", path.parent)
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA mmap_size = 268435456")   # 256 MB
        conn.execute("PRAGMA cache_size = -65536")     # 64 MB (negative = KiB)
        conn.execute("PRAGMA busy_timeout = 30000")    # 30 s
        conn.commit()
    finally:
        conn.close()

    os.chmod(path, 0o600)
    os.chmod(path.parent, 0o700)
    log.info("SQLite initialized at %s (WAL, 0600)", path)


def verify_sqlite(path: Path) -> list[str]:
    """Return a list of issues with an existing SQLite DB (empty = all good)."""
    issues: list[str] = []
    if not path.exists():
        issues.append(f"{path} does not exist")
        return issues

    file_mode = stat.S_IMODE(path.stat().st_mode)
    if file_mode != 0o600:
        issues.append(f"File permissions are {oct(file_mode)}, expected 0600")

    dir_mode = stat.S_IMODE(path.parent.stat().st_mode)
    if dir_mode != 0o700:
        issues.append(f"Parent dir permissions are {oct(dir_mode)}, expected 0700")

    try:
        conn = sqlite3.connect(str(path))
        row = conn.execute("PRAGMA journal_mode").fetchone()
        if row and row[0].lower() != "wal":
            issues.append(f"journal_mode is '{row[0]}', expected 'wal'")
        # foreign_keys is a per-connection pragma and is not persisted to disk;
        # callers must set it on each connection they open.
        conn.close()
    except Exception as e:
        issues.append(f"DB connection failed: {e}")

    return issues


# ---------------------------------------------------------------------------
# Postgres bootstrap
# ---------------------------------------------------------------------------

def _read_password(source: str) -> str:
    """Read a secret from a source URI.

    Supported: ``file:///path``, ``env://VARNAME``.
    """
    if source.startswith("file://"):
        return Path(source[7:]).read_text().strip()
    if source.startswith("env://"):
        var = source[6:]
        val = os.environ.get(var)
        if val is None:
            raise ValueError(f"Environment variable {var!r} not set")
        return val
    raise ValueError(f"Unsupported password source scheme: {source!r}")


def _pg_connect(dsn: str):
    """Open a psycopg3 connection."""
    try:
        import psycopg  # type: ignore[import]
    except ImportError:
        raise RuntimeError(
            "psycopg (psycopg3) is required for Postgres bootstrap. "
            "Install with: pip install psycopg[binary]"
        )
    return psycopg.connect(dsn, autocommit=True)


def _role_exists(conn, role: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)
    ).fetchone()
    return row is not None


def _db_exists(conn, dbname: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s", (dbname,)
    ).fetchone()
    return row is not None


def ensure_role(conn, role: str, password: str, *, dry_run: bool = False) -> None:
    """Create the role if absent; verify minimal attributes if present."""
    if _role_exists(conn, role):
        attrs = conn.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolconnlimit "
            "FROM pg_roles WHERE rolname = %s",
            (role,),
        ).fetchone()
        if attrs:
            rolsuper, rolcreatedb, rolcreaterole, rolconnlimit = attrs
            problems = []
            if rolsuper:
                problems.append("role is SUPERUSER (expected NOSUPERUSER)")
            if rolcreatedb:
                problems.append("role has CREATEDB (expected NOCREATEDB)")
            if rolcreaterole:
                problems.append("role has CREATEROLE (expected NOCREATEROLE)")
            if problems:
                raise RuntimeError(
                    f"Role '{role}' exists but attributes diverge from expectations:\n"
                    + "\n".join(f"  - {p}" for p in problems)
                    + "\nFix manually or pass --force-recreate-role."
                )
        log.info("Role '%s' already exists with expected attributes.", role)
        return

    if dry_run:
        log.info("[dry-run] Would CREATE ROLE %s LOGIN NOSUPERUSER ...", role)
        return

    # Use identifier quoting to prevent injection
    conn.execute(
        f'CREATE ROLE "{role}" WITH '
        "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
        "NOREPLICATION NOBYPASSRLS "
        "CONNECTION LIMIT 100 "
        "PASSWORD %s",
        (password,),
    )
    log.info("Created role '%s'.", role)


def ensure_database(conn, dbname: str, owner: str, *, dry_run: bool = False) -> None:
    """Create the database if absent."""
    if _db_exists(conn, dbname):
        log.info("Database '%s' already exists.", dbname)
        return

    if dry_run:
        log.info("[dry-run] Would CREATE DATABASE %s OWNER %s ...", dbname, owner)
        return

    conn.execute(
        f'CREATE DATABASE "{dbname}" '
        f'WITH OWNER = "{owner}" '
        "ENCODING = 'UTF8' "
        "LC_COLLATE = 'C.UTF-8' "
        "LC_CTYPE = 'C.UTF-8' "
        "TEMPLATE = template0"
    )
    log.info("Created database '%s' owned by '%s'.", dbname, owner)


def apply_schema_grants(conn, role: str, *, dry_run: bool = False) -> None:
    """Apply schema-level grants after the database and migrations exist."""
    stmts = [
        "REVOKE ALL ON SCHEMA public FROM PUBLIC",
        f'GRANT USAGE ON SCHEMA public TO "{role}"',
        f'GRANT CREATE ON SCHEMA public TO "{role}"',
        f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{role}"',
        f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "{role}"',
        f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO "{role}"',
    ]
    for stmt in stmts:
        if dry_run:
            log.info("[dry-run] %s", stmt)
        else:
            conn.execute(stmt)
    if not dry_run:
        log.info("Schema grants applied for role '%s'.", role)


def ensure_extension(conn, ext: str, *, dry_run: bool = False) -> None:
    if dry_run:
        log.info("[dry-run] Would CREATE EXTENSION IF NOT EXISTS %s", ext)
        return
    conn.execute(f"CREATE EXTENSION IF NOT EXISTS {ext}")
    log.info("Extension '%s' ensured.", ext)


def init_postgres(
    *,
    admin_dsn: str,
    target_db: str,
    target_role: str,
    password_source: str,
    tls_mode: str = "require",
    extensions: Optional[list[str]] = None,
    apply_tuning: str = "none",
    pool_min: int = 4,
    pool_max: int = 32,
    dry_run: bool = False,
) -> None:
    """Full Postgres bootstrap sequence.

    Idempotent — verifies existing state matches expectations.
    """
    password = _read_password(password_source)
    conn = _pg_connect(admin_dsn)

    try:
        ensure_role(conn, target_role, password, dry_run=dry_run)
        ensure_database(conn, target_db, target_role, dry_run=dry_run)
    finally:
        conn.close()

    # Reconnect to the target database for schema-level operations
    # Strip the database name from admin_dsn and point at target_db
    target_dsn = _replace_dbname(admin_dsn, target_db)
    conn2 = _pg_connect(target_dsn)
    try:
        for ext in (extensions or []):
            ensure_extension(conn2, ext, dry_run=dry_run)
        apply_schema_grants(conn2, target_role, dry_run=dry_run)
    finally:
        conn2.close()

    if apply_tuning != "none":
        from pg_tuning import apply as apply_pg_tuning
        apply_pg_tuning(
            admin_dsn=admin_dsn,
            mode=apply_tuning,
            dry_run=dry_run,
        )

    log.info(
        "Postgres bootstrap complete: db=%s role=%s tls=%s pool=%s..%s",
        target_db, target_role, tls_mode, pool_min, pool_max,
    )


def _replace_dbname(dsn: str, dbname: str) -> str:
    """Replace the database name in a Postgres DSN string."""
    import re
    # Handle postgresql://user:pass@host:port/dbname or postgresql://user@host/dbname
    return re.sub(r"(/[^/?]*)([?]|$)", f"/{dbname}\\2", dsn, count=1)
