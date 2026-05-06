"""
migrations.py — Schema migration runner for PyPKI
==================================================

Applies versioned SQL migration files to a Database instance.

PyPKI uses **four separate logical databases** today (pki, audit, acme,
scep). Each has its own migration namespace. The runner is invoked once
per database at startup; it records what's been applied in a tiny
``schema_migrations`` table inside each DB.

Layout
------
::

    db_migrations/
    ├── pki/
    │   └── 001_initial.sql       # CA state, certs, CRL, key archive, IPsec
    ├── audit/
    │   └── 001_initial.sql       # audit log
    ├── acme/
    │   └── 001_initial.sql       # ACME state
    └── scep/
        └── 001_initial.sql       # SCEP transactions

Filename format: ``NNN_<description>.sql`` where NNN is a zero-padded
integer ≥1. The runner sorts by NNN and applies any not-yet-recorded
migrations in order.

Tokens
------
For cross-backend SQL portability the migration files may use these
tokens, substituted at apply-time:

  ``{{auto_pk}}``  →  ``INTEGER PRIMARY KEY AUTOINCREMENT`` (sqlite)
                       ``BIGSERIAL PRIMARY KEY``             (postgresql)
  ``{{blob}}``     →  ``BLOB``  (sqlite)  /  ``BYTEA``  (postgresql)

Backend-specific blocks are not yet supported. If a future migration
requires fully divergent SQL per backend, add ``-- @sqlite`` / ``-- @end``
parsing here. For the current set of initial migrations, tokens are
sufficient.

Public API
----------
::

    from db import make_db
    from migrations import MigrationRunner

    db = make_db("sqlite:///./pki.db")
    runner = MigrationRunner(db, "db_migrations/pki", namespace="pki")
    applied = runner.apply_pending()
    # applied is a list of filenames just applied; empty if up-to-date
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from db import Database, MigrationError

logger = logging.getLogger("pypki.migrations")


# ---------------------------------------------------------------------------
# Token substitution per backend
# ---------------------------------------------------------------------------

_BACKEND_TOKENS = {
    "sqlite": {
        "{{auto_pk}}": "INTEGER PRIMARY KEY AUTOINCREMENT",
        "{{blob}}":    "BLOB",
    },
    "postgresql": {
        "{{auto_pk}}": "BIGSERIAL PRIMARY KEY",
        "{{blob}}":    "BYTEA",
    },
}


def render(sql: str, backend: str) -> str:
    """Substitute {{tokens}} for the target backend."""
    tokens = _BACKEND_TOKENS.get(backend)
    if tokens is None:
        raise MigrationError(f"Unknown backend for token substitution: {backend!r}")
    out = sql
    for tok, repl in tokens.items():
        out = out.replace(tok, repl)
    # Surface unsubstituted tokens early.
    leftover = re.findall(r"\{\{[^}]+\}\}", out)
    if leftover:
        raise MigrationError(f"Unknown migration tokens: {sorted(set(leftover))}")
    return out


# ---------------------------------------------------------------------------
# Statement splitter
# ---------------------------------------------------------------------------

def split_statements(sql: str) -> List[str]:
    """
    Split a SQL script into individual statements on top-level semicolons.

    Strips ``-- ...`` line comments and ``/* ... */`` block comments before
    splitting. Does not handle dollar-quoted strings or PL/pgSQL bodies —
    PyPKI's migrations are pure DDL + INSERT and don't need them.
    """
    # Remove line comments
    no_line = re.sub(r"--[^\n]*", "", sql)
    # Remove block comments
    no_block = re.sub(r"/\*.*?\*/", "", no_line, flags=re.DOTALL)
    parts = [s.strip() for s in no_block.split(";")]
    return [s for s in parts if s]


# ---------------------------------------------------------------------------
# MigrationRunner
# ---------------------------------------------------------------------------

_FILE_RE = re.compile(r"^(\d+)_([A-Za-z0-9_\-]+)\.sql$")


class MigrationRunner:
    """
    Apply pending migrations from a directory to a single logical DB.

    A "logical DB" maps to one ``Database`` instance and one namespace
    name. The runner is idempotent: calling ``apply_pending()`` repeatedly
    is safe and a no-op once everything is up-to-date.
    """

    def __init__(self, db: Database, migrations_dir: str | Path, *, namespace: str):
        self.db = db
        self.dir = Path(migrations_dir)
        self.namespace = namespace
        if not self.dir.is_dir():
            raise MigrationError(f"Migrations dir not found: {self.dir}")

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #

    def apply_pending(self) -> List[str]:
        """
        Apply every migration whose version is greater than the highest
        recorded for this DB. Each migration runs inside its own
        transaction; partial failures roll back cleanly.

        Returns the list of filenames just applied (empty if up-to-date).
        """
        self._ensure_table()
        applied = self._applied_versions()
        all_files = self._discover()

        pending = [(v, name, p) for (v, name, p) in all_files if v not in applied]
        pending.sort(key=lambda t: t[0])

        if not pending:
            logger.info(f"[{self.namespace}] schema up-to-date")
            return []

        logger.info(
            f"[{self.namespace}] applying {len(pending)} migration(s): "
            + ", ".join(f"{v:03d}_{name}" for v, name, _ in pending)
        )
        for version, name, path in pending:
            self._apply_one(version, name, path)
        return [f"{v:03d}_{n}.sql" for v, n, _ in pending]

    def current_version(self) -> int:
        """Return the highest applied version; 0 if none."""
        self._ensure_table()
        applied = self._applied_versions()
        return max(applied, default=0)

    def list_pending(self) -> List[Tuple[int, str]]:
        """List (version, name) of migrations not yet applied. Read-only."""
        self._ensure_table()
        applied = self._applied_versions()
        return sorted(
            [(v, n) for (v, n, _) in self._discover() if v not in applied]
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _ensure_table(self) -> None:
        # The bookkeeping table itself. Identical on both backends.
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "  version    INTEGER PRIMARY KEY, "
            "  name       TEXT NOT NULL, "
            "  applied_at INTEGER NOT NULL"
            ")"
        )

    def _applied_versions(self) -> set[int]:
        rows = self.db.fetchall("SELECT version FROM schema_migrations")
        return {int(r["version"]) for r in rows}

    def _discover(self) -> List[Tuple[int, str, Path]]:
        out: List[Tuple[int, str, Path]] = []
        for path in self.dir.iterdir():
            if not path.is_file():
                continue
            m = _FILE_RE.match(path.name)
            if not m:
                logger.warning(
                    f"[{self.namespace}] ignoring non-migration file: {path.name}"
                )
                continue
            version = int(m.group(1))
            name = m.group(2)
            out.append((version, name, path))
        # Detect duplicate version numbers — common cause of drift.
        seen: dict[int, str] = {}
        for v, n, _ in out:
            if v in seen and seen[v] != n:
                raise MigrationError(
                    f"[{self.namespace}] duplicate migration version {v}: "
                    f"{seen[v]!r} vs {n!r}"
                )
            seen[v] = n
        return out

    def _apply_one(self, version: int, name: str, path: Path) -> None:
        raw_sql = path.read_text(encoding="utf-8")
        rendered = render(raw_sql, self.db.backend)
        statements = split_statements(rendered)
        if not statements:
            logger.warning(f"[{self.namespace}] {version:03d}_{name}: empty migration")

        # Note: many engines (SQLite, Postgres) cannot run certain DDL
        # inside an explicit transaction (e.g., CREATE INDEX CONCURRENTLY
        # on Postgres). For the initial migrations we have only
        # transaction-safe DDL; if a future migration needs special
        # handling, add a "-- @no-transaction" marker and special-case it.
        with self.db.transaction():
            for stmt in statements:
                self.db.execute(stmt)
            self.db.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) "
                "VALUES (?, ?, ?)",
                (version, name, self.db.now()),
            )
        logger.info(f"[{self.namespace}] applied {version:03d}_{name}")


# ---------------------------------------------------------------------------
# Convenience for the four PyPKI logical databases
# ---------------------------------------------------------------------------

# Default mapping: (namespace, default-relative-filename, migrations subdir)
PYPKI_NAMESPACES: List[Tuple[str, str, str]] = [
    ("pki",   "pki.db",   "db_migrations/pki"),
    ("audit", "audit.db", "db_migrations/audit"),
    ("acme",  "acme.db",  "db_migrations/acme"),
    ("scep",  "scep.db",  "db_migrations/scep"),
]


def apply_all(
    ca_dir: str | Path,
    *,
    migrations_root: str | Path = "db_migrations",
    db_factory=None,
) -> dict[str, List[str]]:
    """
    Apply pending migrations to every PyPKI logical database under ``ca_dir``.

    ``db_factory`` defaults to ``db.make_db`` with ``sqlite:///<ca_dir>/<file>``.
    Override for tests or non-default DSN sources.

    Returns a dict ``{namespace: [applied_files]}``.
    """
    from db import make_db
    if db_factory is None:
        def db_factory(ns: str, default_file: str):  # type: ignore[misc]
            return make_db(f"sqlite:///{Path(ca_dir) / default_file}")

    results: dict[str, List[str]] = {}
    for namespace, default_file, sub in PYPKI_NAMESPACES:
        sub_path = Path(migrations_root)
        # Allow either a single combined dir (db_migrations/pki/) or a
        # different root for tests.
        if not (sub_path / namespace).is_dir():
            # Caller passed a fully-qualified path? Try as-is.
            mig_dir = sub_path
        else:
            mig_dir = sub_path / namespace

        if not mig_dir.is_dir():
            logger.warning(
                f"[{namespace}] no migrations directory at {mig_dir} — skipping"
            )
            results[namespace] = []
            continue

        d = db_factory(namespace, default_file)
        try:
            runner = MigrationRunner(d, mig_dir, namespace=namespace)
            results[namespace] = runner.apply_pending()
        finally:
            d.close()
    return results


__all__ = [
    "MigrationRunner",
    "PYPKI_NAMESPACES",
    "apply_all",
    "render",
    "split_statements",
]
