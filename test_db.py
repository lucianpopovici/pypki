"""
test_db.py — tests for the DAL.

Runs against SQLite always; runs Postgres tests only if psycopg is
installed AND the env var ``PYPKI_TEST_POSTGRES_URL`` points at a writable
test database. CI should set that against a testcontainer.

To run::

    python -m unittest test_db.py -v

    # With Postgres:
    PYPKI_TEST_POSTGRES_URL='postgresql://test:test@localhost/pypki_test' \
        python -m unittest test_db.py -v
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

import db  # local import — module under test


# ---------------------------------------------------------------------------
# Per-backend test mixin
# ---------------------------------------------------------------------------

class _DalTestsMixin:
    """
    Shared tests parametrized by backend. Concrete subclasses set
    ``self.url`` and ``self.fresh_schema()``.
    """

    url: str

    def setUp(self):
        self.db = db.make_db(self.url)
        self.fresh_schema()

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass

    def fresh_schema(self):
        """
        Create a tiny schema with one auto-increment table and one
        key/value table. Each subclass calls this in setUp via the parent.
        """
        # Drop if exists
        for tbl in ("widgets", "kv"):
            try:
                self.db.execute(f"DROP TABLE IF EXISTS {tbl}")
            except Exception:
                pass

        self.db.execute(self._widgets_ddl())
        self.db.execute(
            "CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)"
        )

    def _widgets_ddl(self) -> str:
        raise NotImplementedError

    # ---- tests ---- #

    def test_basic_crud(self):
        self.db.execute(
            "INSERT INTO widgets(name, weight) VALUES (?, ?)",
            ("first", 10),
        )
        row = self.db.fetchone(
            "SELECT id, name, weight FROM widgets WHERE name = ?", ("first",)
        )
        self.assertIsNotNone(row)
        self.assertEqual(row["name"], "first")
        self.assertEqual(row["weight"], 10)
        # positional access works too
        self.assertEqual(row[1], "first")
        # row.keys() in declaration order
        self.assertEqual(tuple(row.keys()), ("id", "name", "weight"))

    def test_fetchall_empty(self):
        rows = self.db.fetchall(
            "SELECT * FROM widgets WHERE name = ?", ("nope",)
        )
        self.assertEqual(rows, [])

    def test_fetchone_none(self):
        self.assertIsNone(
            self.db.fetchone(
                "SELECT * FROM widgets WHERE name = ?", ("nope",)
            )
        )

    def test_executemany(self):
        rows = [(f"w{i}", i) for i in range(50)]
        self.db.executemany(
            "INSERT INTO widgets(name, weight) VALUES (?, ?)", rows
        )
        result = self.db.fetchone("SELECT COUNT(*) AS c FROM widgets")
        self.assertEqual(result["c"], 50)

    def test_transaction_commit(self):
        with self.db.transaction():
            self.db.execute(
                "INSERT INTO kv(k, v) VALUES (?, ?)", ("a", "1")
            )
            self.db.execute(
                "INSERT INTO kv(k, v) VALUES (?, ?)", ("b", "2")
            )
        rows = self.db.fetchall("SELECT k FROM kv ORDER BY k")
        self.assertEqual([r["k"] for r in rows], ["a", "b"])

    def test_transaction_rollback(self):
        try:
            with self.db.transaction():
                self.db.execute(
                    "INSERT INTO kv(k, v) VALUES (?, ?)", ("a", "1")
                )
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        rows = self.db.fetchall("SELECT k FROM kv")
        self.assertEqual(rows, [])

    def test_advisory_lock_serializes_writers(self):
        """
        Two threads each enter advisory_lock and increment a counter.
        Without the lock, simultaneous read-modify-write would lose
        updates. With the lock, we always see exactly N increments.
        """
        self.db.execute(
            "INSERT INTO kv(k, v) VALUES (?, ?)", ("counter", "0")
        )

        N_THREADS = 8
        N_INCREMENTS_EACH = 25
        errors = []

        def worker():
            try:
                # Each thread needs its own connection for SQLite.
                # Postgres uses pool — both fine via a fresh handle.
                local_db = db.make_db(self.url)
                try:
                    for _ in range(N_INCREMENTS_EACH):
                        with local_db.advisory_lock("counter"):
                            row = local_db.fetchone(
                                "SELECT v FROM kv WHERE k = ?", ("counter",)
                            )
                            new = int(row["v"]) + 1
                            local_db.execute(
                                "UPDATE kv SET v = ? WHERE k = ?",
                                (str(new), "counter"),
                            )
                finally:
                    local_db.close()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"thread errors: {errors}")
        row = self.db.fetchone("SELECT v FROM kv WHERE k = ?", ("counter",))
        self.assertEqual(
            int(row["v"]),
            N_THREADS * N_INCREMENTS_EACH,
            "advisory_lock failed to serialize writers",
        )

    def test_fix_sequence_after_bulk_insert(self):
        """
        Simulate the migration path: bulk-insert rows with explicit ids
        bypassing the auto-increment, then fix_sequence so the next
        normal INSERT does not collide.
        """
        # Bulk-insert with explicit ids
        for i in (10, 11, 12):
            self.db.execute(
                "INSERT INTO widgets(id, name, weight) VALUES (?, ?, ?)",
                (i, f"bulk{i}", i),
            )
        self.db.fix_sequence("widgets")

        # Next INSERT without explicit id should get id=13
        self.db.execute(
            "INSERT INTO widgets(name, weight) VALUES (?, ?)",
            ("post-fix", 99),
        )
        row = self.db.fetchone(
            "SELECT id FROM widgets WHERE name = ?", ("post-fix",)
        )
        self.assertGreater(
            row["id"], 12, "fix_sequence did not advance the counter"
        )

    def test_peek_next_sequence(self):
        for i in range(3):
            self.db.execute(
                "INSERT INTO widgets(name, weight) VALUES (?, ?)",
                (f"w{i}", i),
            )
        # Sequence should be at 4 next.
        peek = self.db.peek_next_sequence("widgets")
        # Insert one more, then check peek advances.
        self.db.execute(
            "INSERT INTO widgets(name, weight) VALUES (?, ?)",
            ("after", 0),
        )
        peek_after = self.db.peek_next_sequence("widgets")
        self.assertGreater(peek_after, peek)

    def test_now_returns_unix_seconds(self):
        before = int(time.time()) - 1
        n = self.db.now()
        after = int(time.time()) + 1
        self.assertGreaterEqual(n, before)
        self.assertLessEqual(n, after)

    def test_now_can_be_overridden(self):
        # Tests should be able to freeze time on an instance.
        self.db.now = lambda: 42  # type: ignore[method-assign]
        self.assertEqual(self.db.now(), 42)


# ---------------------------------------------------------------------------
# SQLite tests
# ---------------------------------------------------------------------------

class TestSQLite(_DalTestsMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.mkdtemp(prefix="pypki-db-test-")

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def setUp(self):
        # Fresh path per test so state never bleeds.
        self._dbpath = Path(self._tmpdir) / f"t-{time.monotonic_ns()}.db"
        self.url = f"sqlite:///{self._dbpath}"
        super().setUp()

    def _widgets_ddl(self) -> str:
        return (
            "CREATE TABLE widgets ("
            "  id     INTEGER PRIMARY KEY AUTOINCREMENT, "
            "  name   TEXT NOT NULL, "
            "  weight INTEGER NOT NULL"
            ")"
        )


# ---------------------------------------------------------------------------
# Postgres tests — opt-in
# ---------------------------------------------------------------------------

PG_URL = os.environ.get("PYPKI_TEST_POSTGRES_URL")


@unittest.skipUnless(
    PG_URL and db._HAVE_PSYCOPG,  # type: ignore[attr-defined]
    "Set PYPKI_TEST_POSTGRES_URL and install psycopg to run Postgres tests",
)
class TestPostgres(_DalTestsMixin, unittest.TestCase):
    def setUp(self):
        self.url = PG_URL  # type: ignore[assignment]
        super().setUp()

    def _widgets_ddl(self) -> str:
        return (
            "CREATE TABLE widgets ("
            "  id     BIGSERIAL PRIMARY KEY, "
            "  name   TEXT NOT NULL, "
            "  weight INTEGER NOT NULL"
            ")"
        )


# ---------------------------------------------------------------------------
# Factory + URL parsing tests
# ---------------------------------------------------------------------------

class TestMakeDb(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="pypki-mk-test-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_sqlite_relative(self):
        # sqlite:///./relative is the documented form.
        path = Path(self._tmp) / "rel.db"
        d = db.make_db(f"sqlite:///{path}")
        self.assertEqual(d.backend, "sqlite")
        d.close()

    def test_sqlite_absolute(self):
        path = Path(self._tmp) / "abs.db"
        d = db.make_db(f"sqlite:////{path.relative_to('/')}")
        self.assertEqual(d.backend, "sqlite")
        d.close()

    def test_unsupported_scheme(self):
        with self.assertRaises(db.UnsupportedBackend):
            db.make_db("mysql://localhost/whatever")

    def test_postgres_without_driver_errors_clearly(self):
        if db._HAVE_PSYCOPG:  # type: ignore[attr-defined]
            self.skipTest("psycopg installed — can't test missing-driver path")
        with self.assertRaises(db.MissingDriver):
            db.make_db("postgresql://localhost/whatever")


class TestRow(unittest.TestCase):
    def test_dict_and_index_access(self):
        r = db.Row({"a": 1, "b": "two"}, ["a", "b"])
        self.assertEqual(r["a"], 1)
        self.assertEqual(r[0], 1)
        self.assertEqual(r["b"], "two")
        self.assertEqual(r[1], "two")
        self.assertEqual(tuple(r.keys()), ("a", "b"))
        # dict() round-trip preserves keys/values
        self.assertEqual(dict(r), {"a": 1, "b": "two"})


class TestStableLockId(unittest.TestCase):
    def test_stable_across_calls(self):
        a = db._stable_lock_id("serial-allocation")
        b = db._stable_lock_id("serial-allocation")
        self.assertEqual(a, b)

    def test_different_names_differ(self):
        self.assertNotEqual(
            db._stable_lock_id("serial-allocation"),
            db._stable_lock_id("crl-signer"),
        )

    def test_fits_in_signed_int64(self):
        v = db._stable_lock_id("anything")
        self.assertGreaterEqual(v, -(2 ** 63))
        self.assertLess(v, 2 ** 63)


class TestParamTranslation(unittest.TestCase):
    def test_translate_basic(self):
        self.assertEqual(
            db._translate_params("SELECT * FROM t WHERE a = ? AND b = ?"),
            "SELECT * FROM t WHERE a = %s AND b = %s",
        )

    def test_no_placeholders(self):
        sql = "SELECT 1"
        self.assertEqual(db._translate_params(sql), sql)


if __name__ == "__main__":
    unittest.main(verbosity=2)
