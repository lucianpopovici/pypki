"""
test_migrations.py — tests for the migration runner.

Covers:
  * Token substitution per backend
  * Statement splitter (comments, semicolons)
  * MigrationRunner: idempotence, ordering, transaction rollback,
    upgrade-from-pre-runner, duplicate-version detection
  * apply_all() against the real PyPKI initial migrations against
    a fresh CA dir layout
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import db
import migrations


# ---------------------------------------------------------------------------
# Pure-function tests
# ---------------------------------------------------------------------------

class TestRender(unittest.TestCase):
    def test_sqlite_tokens(self):
        out = migrations.render(
            "CREATE TABLE t (id {{auto_pk}}, blob {{blob}})", "sqlite"
        )
        self.assertIn("INTEGER PRIMARY KEY AUTOINCREMENT", out)
        self.assertIn("BLOB", out)

    def test_postgres_tokens(self):
        out = migrations.render(
            "CREATE TABLE t (id {{auto_pk}}, blob {{blob}})", "postgresql"
        )
        self.assertIn("BIGSERIAL PRIMARY KEY", out)
        self.assertIn("BYTEA", out)

    def test_unknown_token_raises(self):
        with self.assertRaises(migrations.MigrationError):
            migrations.render("CREATE TABLE t (id {{not_a_token}})", "sqlite")

    def test_unknown_backend_raises(self):
        with self.assertRaises(migrations.MigrationError):
            migrations.render("SELECT 1", "mysql")


class TestSplitStatements(unittest.TestCase):
    def test_simple(self):
        stmts = migrations.split_statements("CREATE TABLE a (); CREATE TABLE b();")
        self.assertEqual(len(stmts), 2)

    def test_strips_line_comments(self):
        sql = """
        -- this is a comment
        CREATE TABLE a ();  -- and this
        -- ignore me too
        CREATE TABLE b ();
        """
        stmts = migrations.split_statements(sql)
        self.assertEqual(len(stmts), 2)
        for s in stmts:
            self.assertNotIn("--", s)

    def test_strips_block_comments(self):
        sql = "CREATE TABLE a (); /* hidden */ CREATE TABLE b ();"
        stmts = migrations.split_statements(sql)
        self.assertEqual(len(stmts), 2)
        for s in stmts:
            self.assertNotIn("hidden", s)

    def test_empty_input(self):
        self.assertEqual(migrations.split_statements(""), [])
        self.assertEqual(migrations.split_statements("-- only comment"), [])
        self.assertEqual(migrations.split_statements(";;;"), [])


# ---------------------------------------------------------------------------
# MigrationRunner tests
# ---------------------------------------------------------------------------

class TestMigrationRunner(unittest.TestCase):
    """Each test uses a fresh tmpdir + fresh SQLite db + fresh migrations dir."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pypki-mig-test-"))
        self.mig_dir = self.tmp / "mig"
        self.mig_dir.mkdir()
        self.db_path = self.tmp / "test.db"
        self.db = db.make_db(f"sqlite:///{self.db_path}")

    def tearDown(self):
        try:
            self.db.close()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name: str, sql: str):
        (self.mig_dir / name).write_text(sql)

    def _runner(self, namespace: str = "test") -> migrations.MigrationRunner:
        return migrations.MigrationRunner(
            self.db, self.mig_dir, namespace=namespace
        )

    # ---- happy path ---- #

    def test_apply_single_migration(self):
        self._write(
            "001_initial.sql",
            "CREATE TABLE widgets (id {{auto_pk}}, name TEXT)",
        )
        applied = self._runner().apply_pending()
        self.assertEqual(applied, ["001_initial.sql"])
        # Verify table exists
        row = self.db.fetchone(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='widgets'"
        )
        self.assertIsNotNone(row)

    def test_apply_in_order(self):
        self._write("002_second.sql", "CREATE TABLE second (id {{auto_pk}})")
        self._write("001_first.sql",  "CREATE TABLE first  (id {{auto_pk}})")
        self._write("003_third.sql",  "CREATE TABLE third  (id {{auto_pk}})")
        applied = self._runner().apply_pending()
        self.assertEqual(
            applied, ["001_first.sql", "002_second.sql", "003_third.sql"]
        )

    def test_idempotent(self):
        self._write(
            "001_initial.sql",
            "CREATE TABLE widgets (id {{auto_pk}}, name TEXT)",
        )
        first = self._runner().apply_pending()
        second = self._runner().apply_pending()
        self.assertEqual(first, ["001_initial.sql"])
        self.assertEqual(second, [])

    def test_partial_then_resume(self):
        self._write("001_initial.sql", "CREATE TABLE a (id {{auto_pk}})")
        self._runner().apply_pending()
        # Now ship a new migration; only the new one applies.
        self._write("002_extend.sql", "CREATE TABLE b (id {{auto_pk}})")
        applied = self._runner().apply_pending()
        self.assertEqual(applied, ["002_extend.sql"])

    def test_current_version(self):
        self.assertEqual(self._runner().current_version(), 0)
        self._write("001_initial.sql", "CREATE TABLE a (id {{auto_pk}})")
        self._write("005_jump.sql", "CREATE TABLE b (id {{auto_pk}})")
        self._runner().apply_pending()
        self.assertEqual(self._runner().current_version(), 5)

    def test_list_pending(self):
        self._write("001_initial.sql", "CREATE TABLE a (id {{auto_pk}})")
        self._write("002_extend.sql",  "CREATE TABLE b (id {{auto_pk}})")
        self.assertEqual(
            self._runner().list_pending(),
            [(1, "initial"), (2, "extend")],
        )
        self._runner().apply_pending()
        self.assertEqual(self._runner().list_pending(), [])

    # ---- failure paths ---- #

    def test_failed_migration_rolls_back(self):
        # Valid migration applies first
        self._write("001_initial.sql", "CREATE TABLE a (id {{auto_pk}})")
        # Broken migration: refers to nonexistent column
        self._write(
            "002_broken.sql",
            "INSERT INTO nonexistent_table (x) VALUES (1)",
        )
        with self.assertRaises(Exception):
            self._runner().apply_pending()

        # 001 should be applied; 002 must NOT be recorded
        runner = self._runner()
        self.assertEqual(runner.current_version(), 1)
        self.assertEqual(runner.list_pending(), [(2, "broken")])

    def test_duplicate_version_detected(self):
        self._write("001_first.sql",  "CREATE TABLE a (id {{auto_pk}})")
        self._write("001_second.sql", "CREATE TABLE b (id {{auto_pk}})")
        with self.assertRaises(migrations.MigrationError) as cm:
            self._runner().apply_pending()
        self.assertIn("duplicate migration version 1", str(cm.exception))

    def test_unknown_files_ignored(self):
        self._write("001_initial.sql", "CREATE TABLE a (id {{auto_pk}})")
        self._write("README.md", "# this is not a migration")
        self._write("backup.sql.bak", "ignore me")
        applied = self._runner().apply_pending()
        self.assertEqual(applied, ["001_initial.sql"])

    def test_missing_dir_raises(self):
        with self.assertRaises(migrations.MigrationError):
            migrations.MigrationRunner(
                self.db, self.tmp / "nonexistent", namespace="test"
            )

    def test_unknown_token_in_migration(self):
        self._write("001_bad.sql", "CREATE TABLE a (id {{bogus_token}})")
        with self.assertRaises(migrations.MigrationError):
            self._runner().apply_pending()

    # ---- upgrade-from-pre-runner case ---- #

    def test_upgrade_existing_deployment(self):
        """
        Simulate an existing deployment: tables already exist (from
        pre-runner inline DDL), but schema_migrations does not. The runner
        should apply 001_initial.sql safely (CREATE TABLE IF NOT EXISTS
        is a no-op) and record it as applied.
        """
        # Pre-create the table as if pki_server had done it
        self.db.execute(
            "CREATE TABLE widgets (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT)"
        )
        self.db.execute("INSERT INTO widgets(name) VALUES ('old data')")

        # Now ship 001 as a new migration
        self._write(
            "001_initial.sql",
            "CREATE TABLE IF NOT EXISTS widgets ("
            "id {{auto_pk}}, name TEXT)",
        )
        applied = self._runner().apply_pending()
        self.assertEqual(applied, ["001_initial.sql"])

        # Old data must still be there
        rows = self.db.fetchall("SELECT name FROM widgets")
        self.assertEqual([r["name"] for r in rows], ["old data"])

        # Second startup: idempotent
        self.assertEqual(self._runner().apply_pending(), [])


# ---------------------------------------------------------------------------
# Integration: real PyPKI initial migrations
# ---------------------------------------------------------------------------

class TestPyPKIInitialMigrations(unittest.TestCase):
    """
    End-to-end: apply the actual initial migrations from db_migrations/
    against a fresh CA directory layout. This is the test that catches
    syntax errors in the SQL files themselves.
    """

    def setUp(self):
        self.ca_dir = Path(tempfile.mkdtemp(prefix="pypki-ca-test-"))

    def tearDown(self):
        shutil.rmtree(self.ca_dir, ignore_errors=True)

    def test_apply_all_creates_every_table(self):
        repo_root = Path(__file__).resolve().parent
        migrations_root = repo_root / "db_migrations"
        results = migrations.apply_all(
            self.ca_dir, migrations_root=migrations_root
        )

        # Every namespace should have applied 001_initial.sql
        for ns in ("pki", "audit", "acme", "scep"):
            self.assertEqual(
                results[ns], ["001_initial.sql"],
                f"namespace {ns} did not apply 001_initial.sql"
            )

        # Verify the expected tables exist in each DB
        EXPECTED = {
            "pki.db":   {"certificates", "serial_counter", "crl_base",
                         "key_archive", "ipsec_pending_requests",
                         "ipsec_cert_confirmations", "schema_migrations"},
            "audit.db": {"audit", "schema_migrations"},
            "acme.db":  {"nonces", "accounts", "orders", "authorizations",
                         "challenges", "certificates", "schema_migrations"},
            "scep.db":  {"scep_transactions", "schema_migrations"},
        }
        for fname, expected_tables in EXPECTED.items():
            d = db.make_db(f"sqlite:///{self.ca_dir / fname}")
            try:
                rows = d.fetchall(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
                actual = {r["name"] for r in rows}
                self.assertEqual(
                    actual, expected_tables,
                    f"{fname}: expected {expected_tables}, got {actual}"
                )
            finally:
                d.close()

    def test_serial_counter_seeded(self):
        repo_root = Path(__file__).resolve().parent
        migrations_root = repo_root / "db_migrations"
        migrations.apply_all(self.ca_dir, migrations_root=migrations_root)

        d = db.make_db(f"sqlite:///{self.ca_dir / 'pki.db'}")
        try:
            row = d.fetchone(
                "SELECT value FROM serial_counter WHERE id = 1"
            )
            self.assertEqual(row["value"], 1000)
        finally:
            d.close()

    def test_apply_all_idempotent(self):
        repo_root = Path(__file__).resolve().parent
        migrations_root = repo_root / "db_migrations"
        first = migrations.apply_all(self.ca_dir, migrations_root=migrations_root)
        second = migrations.apply_all(self.ca_dir, migrations_root=migrations_root)
        for ns in ("pki", "audit", "acme", "scep"):
            self.assertEqual(len(first[ns]), 1)
            self.assertEqual(second[ns], [])  # nothing pending


if __name__ == "__main__":
    unittest.main(verbosity=2)
