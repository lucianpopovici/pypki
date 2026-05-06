"""
db.py — Database Abstraction Layer for PyPKI
=============================================

Pure transport layer over SQLite and PostgreSQL. No schema opinions; the
schema lives in migration files (see ``migrations.py`` / ``db_migrations/``).

Why this exists
---------------
Today PyPKI calls ``sqlite3.connect(...)`` from 15+ sites scattered across
``pki_server.py``. That makes it impossible to switch backends without
auditing every site, and impossible to test the issuance code against a
backend other than SQLite. This module collapses all DB access to a
single interface so:

  * SQLite remains the default (homelab, single-node).
  * PostgreSQL is selectable via ``--db-url postgresql://...`` when HA,
    multi-node, or regulated deployments need it.
  * Switching is a one-line config change — see CLAUDE.md
    "SQLite → Postgres data migration".

Design principles (from CLAUDE.md §5.2)
---------------------------------------
1. Hand-rolled, no ORM. Every query is auditable.
2. Single SQL dialect: ``?`` placeholders everywhere; translated to ``%s``
   for psycopg at execution time.
3. Time stored as INTEGER unix-seconds. Convert at the application
   boundary.
4. JSON stored as TEXT. ``json.dumps``/``json.loads`` at the boundary.
5. Serial allocation goes through ``advisory_lock("serial-allocation")``;
   the implementation differs per backend but the call site is identical.
6. Never hold a connection across an RSA signing operation.

Public surface
--------------
::

    from db import make_db, Database

    db = make_db("sqlite:///path/to/pki.db")          # or postgresql://...
    with db.transaction():
        row = db.fetchone("SELECT value FROM ca_meta WHERE key = ?",
                          ("crl_number",))
        db.execute("UPDATE ca_meta SET value = ? WHERE key = ?",
                   (str(int(row["value"]) + 1), "crl_number"))

    with db.advisory_lock("serial-allocation"):
        ...   # body runs serialized across all PyPKI nodes
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import sqlite3
import threading
from abc import ABC, abstractmethod
from typing import Any, Iterable, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("pypki.db")

# Optional psycopg import — only required when a postgresql:// URL is used.
try:
    import psycopg
    from psycopg.rows import dict_row as _pg_dict_row
    from psycopg_pool import ConnectionPool as _PgPool
    _HAVE_PSYCOPG = True
except ImportError:
    _HAVE_PSYCOPG = False


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DatabaseError(Exception):
    """Base class for DAL errors."""


class UnsupportedBackend(DatabaseError):
    """Raised when --db-url scheme is unrecognized."""


class MissingDriver(DatabaseError):
    """Raised when a backend is selected but its driver is not installed."""


class MigrationError(DatabaseError):
    """Raised when schema or data migration fails a precondition."""


# ---------------------------------------------------------------------------
# Row — unified dict/index-style access
# ---------------------------------------------------------------------------

class Row(dict):
    """
    Dict-style row that also supports integer indexing.

    Both SQLite (via ``sqlite3.Row``) and psycopg (via ``dict_row``) yield
    rows with name-keyed access; SQLite additionally supports positional
    indexing. This wrapper unifies both for compatibility with existing
    code that uses either style.

        row["serial"]   # always works
        row[0]          # also works; first column in declaration order

    The dict is preserved by inheritance so ``dict(row)`` is a no-op.
    """

    __slots__ = ("_keys",)

    def __init__(self, mapping: dict, keys: Sequence[str]):
        super().__init__(mapping)
        # Capture column order for positional access.
        self._keys: Tuple[str, ...] = tuple(keys)

    def __getitem__(self, key):
        if isinstance(key, int):
            return super().__getitem__(self._keys[key])
        return super().__getitem__(key)

    def keys(self):  # type: ignore[override]
        return self._keys


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class Database(ABC):
    """
    Backend-agnostic database interface.

    Implementations MUST be safe to share across threads. ``execute`` and
    ``fetch*`` autocommit; multi-statement transactions go through
    ``transaction()``. Long-running serialized work (e.g., serial-number
    allocation) goes through ``advisory_lock``.
    """

    # ------------------------------------------------------------------ #
    # Core query interface
    # ------------------------------------------------------------------ #

    @abstractmethod
    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        """Execute a single statement and commit (unless inside transaction())."""

    @abstractmethod
    def executemany(self, sql: str, seq_params: Iterable[Sequence[Any]]) -> None:
        """Bulk-execute. Used by the migration tool."""

    @abstractmethod
    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Optional[Row]:
        """Run a query, return the first row or None."""

    @abstractmethod
    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> List[Row]:
        """Run a query, return all rows (list may be empty)."""

    # ------------------------------------------------------------------ #
    # Transactions and locking
    # ------------------------------------------------------------------ #

    @abstractmethod
    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        """
        Group statements into one atomic unit. Commits on clean exit;
        rolls back on exception.
        """

    @abstractmethod
    @contextlib.contextmanager
    def advisory_lock(self, name: str) -> Iterator[None]:
        """
        Cross-process / cross-node mutual exclusion keyed on a stable name.

        SQLite implementation uses BEGIN IMMEDIATE (database-wide write
        lock). Postgres implementation uses pg_advisory_xact_lock keyed on
        a stable hash of ``name``.
        """

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def now(self) -> int:
        """
        Centralized 'now' as unix-seconds. Tests can monkey-patch this on
        an instance to control time.
        """
        import time
        return int(time.time())

    @abstractmethod
    def fix_sequence(self, table: str, id_column: str = "id") -> None:
        """
        Resync the auto-increment sequence for ``table`` so the next
        INSERT does not collide with a migrated row id. Called by the
        SQLite → Postgres data migration tool.
        """

    @abstractmethod
    def has_autoincrement(self, table: str, id_column: str = "id") -> bool:
        """Return True if ``table.id_column`` is auto-incrementing."""

    @abstractmethod
    def peek_next_sequence(self, table: str, id_column: str = "id") -> int:
        """
        Return what the next auto-generated value would be, without
        consuming it. Used by ``verify-migration`` for the sequence-safety
        check.
        """

    @abstractmethod
    def close(self) -> None:
        """Release all resources. Idempotent."""

    # ------------------------------------------------------------------ #
    # Misc
    # ------------------------------------------------------------------ #

    @property
    @abstractmethod
    def backend(self) -> str:
        """Backend identifier: 'sqlite' or 'postgresql'."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stable_lock_id(name: str) -> int:
    """
    Map a string lock name to a stable signed 64-bit integer for
    ``pg_advisory_xact_lock``. Postgres bigint range is the constraint.
    """
    h = hashlib.blake2b(name.encode("utf-8"), digest_size=8).digest()
    val = int.from_bytes(h, byteorder="big", signed=True)
    return val


def _translate_params(sql: str) -> str:
    """
    Translate ``?`` placeholders to ``%s`` for psycopg.

    Naive but correct for PyPKI's SQL: we never embed literal '?' inside
    string literals or identifiers (no question-mark operators, no
    JSON-path queries). If that ever changes, switch to a real tokenizer.
    """
    return sql.replace("?", "%s")


# ---------------------------------------------------------------------------
# SQLite implementation
# ---------------------------------------------------------------------------

class SQLiteDB(Database):
    """
    SQLite backend with WAL mode and thread-local connections.

    Concurrency model:
      * One connection per thread (Python's sqlite3 is not safe to share
        connections across threads simultaneously).
      * WAL mode allows concurrent readers + one writer.
      * ``advisory_lock`` uses ``BEGIN IMMEDIATE`` to acquire the
        database write lock for the duration of the block.

    Minimum SQLite version: 3.35 (March 2021) for ``RETURNING`` support.
    """

    SQLITE_MIN_VERSION = (3, 35, 0)

    def __init__(self, path: str):
        if sqlite3.sqlite_version_info < self.SQLITE_MIN_VERSION:
            raise DatabaseError(
                f"SQLite >= {'.'.join(map(str, self.SQLITE_MIN_VERSION))} "
                f"required, found {sqlite3.sqlite_version}"
            )
        self._path = path
        self._tl = threading.local()
        self._closed = False

        # Eagerly open one connection so caller errors (bad path,
        # permissions) surface here, not on first query.
        self._conn()

    # -- internal ---------------------------------------------------- #

    def _conn(self) -> sqlite3.Connection:
        if self._closed:
            raise DatabaseError("Database closed")
        c = getattr(self._tl, "conn", None)
        if c is None:
            c = sqlite3.connect(
                self._path,
                isolation_level=None,         # autocommit; we manage tx ourselves
                detect_types=0,
                check_same_thread=True,
            )
            c.row_factory = self._row_factory
            # PRAGMAs for safety + performance
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous = FULL")
            c.execute("PRAGMA foreign_keys = ON")
            c.execute("PRAGMA busy_timeout = 5000")  # 5s
            self._tl.conn = c
        return c

    @staticmethod
    def _row_factory(cursor, row):
        cols = [d[0] for d in cursor.description]
        return Row(dict(zip(cols, row)), cols)

    # -- core API ---------------------------------------------------- #

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        c = self._conn()
        # Default mode is autocommit (isolation_level=None). If a
        # transaction is open via transaction(), the caller's BEGIN holds
        # — sqlite3 does not auto-open a new one.
        c.execute(sql, params)

    def executemany(self, sql: str, seq_params: Iterable[Sequence[Any]]) -> None:
        c = self._conn()
        c.executemany(sql, seq_params)

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Optional[Row]:
        cur = self._conn().execute(sql, params)
        return cur.fetchone()

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> List[Row]:
        cur = self._conn().execute(sql, params)
        return cur.fetchall()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        c = self._conn()
        c.execute("BEGIN")
        try:
            yield
        except BaseException:
            c.execute("ROLLBACK")
            raise
        else:
            c.execute("COMMIT")

    @contextlib.contextmanager
    def advisory_lock(self, name: str) -> Iterator[None]:
        """
        SQLite has no per-key advisory lock primitive, but ``BEGIN
        IMMEDIATE`` acquires the database-wide RESERVED lock — sufficient
        for serializing CA writes since SQLite is single-writer anyway.
        """
        del name  # accepted for API parity with PostgresDB
        c = self._conn()
        c.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            c.execute("ROLLBACK")
            raise
        else:
            c.execute("COMMIT")

    # -- migration helpers ------------------------------------------- #

    def fix_sequence(self, table: str, id_column: str = "id") -> None:
        if id_column != "id":
            raise NotImplementedError(
                "SQLite sqlite_sequence is keyed on table name only"
            )
        row = self.fetchone(f"SELECT MAX({id_column}) AS m FROM {table}")
        max_id = row["m"] if row else None
        if max_id is None:
            return
        # sqlite_sequence has no PRIMARY KEY / UNIQUE constraint on name,
        # so ON CONFLICT can't be used. Update if a row exists; insert
        # otherwise. Touching this table is supported per SQLite docs:
        # https://www.sqlite.org/autoinc.html
        existing = self.fetchone(
            "SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)
        )
        if existing is None:
            self.execute(
                "INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)",
                (table, max_id),
            )
        else:
            self.execute(
                "UPDATE sqlite_sequence SET seq = ? WHERE name = ?",
                (max_id, table),
            )

    def has_autoincrement(self, table: str, id_column: str = "id") -> bool:
        # Look for AUTOINCREMENT in the create-table SQL.
        row = self.fetchone(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        )
        if not row or not row["sql"]:
            return False
        return "AUTOINCREMENT" in row["sql"].upper()

    def peek_next_sequence(self, table: str, id_column: str = "id") -> int:
        if not self.has_autoincrement(table, id_column):
            row = self.fetchone(f"SELECT MAX({id_column}) AS m FROM {table}")
            return (row["m"] or 0) + 1
        row = self.fetchone(
            "SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)
        )
        return (row["seq"] if row else 0) + 1

    # -- lifecycle --------------------------------------------------- #

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        c = getattr(self._tl, "conn", None)
        if c is not None:
            try:
                c.close()
            finally:
                self._tl.conn = None

    @property
    def backend(self) -> str:
        return "sqlite"


# ---------------------------------------------------------------------------
# PostgreSQL implementation
# ---------------------------------------------------------------------------

class PostgresDB(Database):
    """
    PostgreSQL backend with a connection pool and ``pg_advisory_xact_lock``.

    Minimum Postgres version: 13 (September 2020).
    Driver: psycopg 3.x (psycopg2 is in maintenance mode — not supported).

    Concurrency model:
      * ``psycopg_pool.ConnectionPool`` with min=2 max=20 (configurable).
      * Every API call acquires a connection from the pool, releases on
        completion. Never hold a connection across an RSA signing op.
      * ``advisory_lock`` wraps ``pg_advisory_xact_lock`` inside a
        transaction; the lock is released when the tx ends.
    """

    POSTGRES_MIN_VERSION = 130000  # PostgreSQL server_version_num

    def __init__(self, url: str, min_size: int = 2, max_size: int = 20):
        if not _HAVE_PSYCOPG:
            raise MissingDriver(
                "psycopg is required for PostgreSQL support. "
                "Install with: pip install 'psycopg[binary]'"
            )
        self._pool: _PgPool = _PgPool(
            url,
            min_size=min_size,
            max_size=max_size,
            kwargs={"row_factory": _pg_dict_row},
        )
        self._pool.wait()
        self._closed = False

        # Version + connectivity check
        with self._pool.connection() as conn:
            n = conn.execute("SHOW server_version_num").fetchone()
            v = int(list(n.values())[0])
            if v < self.POSTGRES_MIN_VERSION:
                raise DatabaseError(
                    f"PostgreSQL >= 13 required, found server_version_num={v}"
                )

        self._tx = threading.local()  # active transaction conn, per-thread

    # -- internal ---------------------------------------------------- #

    @contextlib.contextmanager
    def _conn(self) -> Iterator[Any]:
        """
        Yield a connection. If a transaction is active on this thread, use
        it. Otherwise pull one from the pool for a single autocommitting
        statement.
        """
        if self._closed:
            raise DatabaseError("Database closed")
        active = getattr(self._tx, "conn", None)
        if active is not None:
            yield active
            return
        with self._pool.connection() as c:
            c.autocommit = True
            yield c

    @staticmethod
    def _wrap_row(rec: Optional[dict]) -> Optional[Row]:
        if rec is None:
            return None
        return Row(rec, list(rec.keys()))

    # -- core API ---------------------------------------------------- #

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        with self._conn() as c:
            c.execute(_translate_params(sql), tuple(params))

    def executemany(self, sql: str, seq_params: Iterable[Sequence[Any]]) -> None:
        with self._conn() as c:
            c.cursor().executemany(
                _translate_params(sql), [tuple(p) for p in seq_params]
            )

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Optional[Row]:
        with self._conn() as c:
            cur = c.execute(_translate_params(sql), tuple(params))
            return self._wrap_row(cur.fetchone())

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> List[Row]:
        with self._conn() as c:
            cur = c.execute(_translate_params(sql), tuple(params))
            return [self._wrap_row(r) for r in cur.fetchall()]  # type: ignore[misc]

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        if getattr(self._tx, "conn", None) is not None:
            raise DatabaseError("Nested transactions not supported")
        with self._pool.connection() as c:
            c.autocommit = False
            self._tx.conn = c
            try:
                yield
                c.commit()
            except BaseException:
                c.rollback()
                raise
            finally:
                self._tx.conn = None

    @contextlib.contextmanager
    def advisory_lock(self, name: str) -> Iterator[None]:
        lock_id = _stable_lock_id(name)
        with self.transaction():
            self.execute("SELECT pg_advisory_xact_lock(?)", (lock_id,))
            yield
        # Lock released automatically when the transaction ends.

    # -- migration helpers ------------------------------------------- #

    def fix_sequence(self, table: str, id_column: str = "id") -> None:
        # pg_get_serial_sequence returns NULL if column is not backed by
        # a sequence (e.g., GENERATED AS IDENTITY uses the same path).
        sql = (
            "SELECT setval("
            "  pg_get_serial_sequence(?, ?), "
            "  COALESCE((SELECT MAX(" + id_column + ") "
            f"           FROM {table}), 1), "
            "  true"
            ")"
        )
        self.execute(sql, (table, id_column))

    def has_autoincrement(self, table: str, id_column: str = "id") -> bool:
        row = self.fetchone(
            "SELECT pg_get_serial_sequence(?, ?) AS s",
            (table, id_column),
        )
        return bool(row and row["s"])

    def peek_next_sequence(self, table: str, id_column: str = "id") -> int:
        row = self.fetchone(
            "SELECT pg_get_serial_sequence(?, ?) AS s",
            (table, id_column),
        )
        if not row or not row["s"]:
            r = self.fetchone(f"SELECT MAX({id_column}) AS m FROM {table}")
            return ((r and r["m"]) or 0) + 1
        seq_name = row["s"]
        # last_value vs is_called: if is_called, next is last_value+1;
        # otherwise next is last_value itself.
        r = self.fetchone(
            f"SELECT last_value, is_called FROM {seq_name}"
        )
        if not r:
            return 1
        return r["last_value"] + (1 if r["is_called"] else 0)

    # -- lifecycle --------------------------------------------------- #

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._pool.close()
        except Exception:
            logger.exception("error closing pg pool")

    @property
    def backend(self) -> str:
        return "postgresql"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

DEFAULT_URL = "sqlite:///./pki.db"


def make_db(url: str = DEFAULT_URL, **kwargs: Any) -> Database:
    """
    Build a Database from a connection URL.

    Supported schemes:

      * ``sqlite:///path/to/db``   — SQLite at that path. Triple-slash for
        absolute paths; ``sqlite:///./relative/path.db`` for relative.
      * ``sqlite://`` (no path)    — equivalent to ``sqlite:///./pki.db``.
      * ``postgresql://...``       — PostgreSQL via psycopg 3.
      * ``postgres://...``         — alias for ``postgresql://``.

    ``kwargs`` are forwarded to the backend constructor (e.g.,
    ``min_size``, ``max_size`` for PostgresDB).
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme == "sqlite":
        # urllib parses sqlite:///path as netloc='' path='/path'.
        # We accept both the leading-slash absolute form and the
        # ./relative form. Also tolerate sqlite:// (empty path) →
        # default file in cwd.
        if parsed.netloc and parsed.netloc not in ("", "localhost"):
            raise UnsupportedBackend(
                f"sqlite URL must not have a netloc: {url!r}"
            )
        path = parsed.path.lstrip("/") if parsed.path else "pki.db"
        if url == "sqlite:///" or not path:
            path = "pki.db"
        # Re-resolve absolute-vs-relative: triple slash means absolute on
        # POSIX. We've stripped one leading '/' above; if the original had
        # four (sqlite:////tmp/x), what's left starts with '/' → absolute.
        if url.startswith("sqlite:////"):
            path = "/" + path
        return SQLiteDB(path, **kwargs)

    if scheme in ("postgresql", "postgres"):
        # psycopg accepts both schemes natively; pass the URL through.
        return PostgresDB(url, **kwargs)

    raise UnsupportedBackend(f"Unsupported DB URL scheme: {url!r}")


__all__ = [
    "Database",
    "DatabaseError",
    "MigrationError",
    "MissingDriver",
    "PostgresDB",
    "Row",
    "SQLiteDB",
    "UnsupportedBackend",
    "make_db",
]
