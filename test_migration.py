"""
test_migration.py — round-trip + verification tests for the SQLite ↔ Postgres
data migration tool.

Strategy: most tests run SQLite → SQLite. That's the same code path as
SQLite → Postgres for everything except sequence resync, and it doesn't
require a live Postgres at CI time. A separate ``TestPostgresMigration``
class is gated on ``PYPKI_TEST_POSTGRES_URL`` for the Postgres-specific
parts (sequence resync, BYTEA round-trip).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import db
import migrations
import migration


PG_URL = os.environ.get("PYPKI_TEST_POSTGRES_URL")
HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _seed_pki(d: db.Database) -> None:
    """Insert a representative spread of rows across the pki namespace."""
    # 3 certificates (one revoked)
    d.execute(
        "INSERT INTO certificates "
        "(serial, subject, not_before, not_after, der, revoked, revoked_at, reason, profile) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (1001, "CN=alice", "2026-01-01T00:00:00", "2027-01-01T00:00:00",
         b"\x30\x82DER1", 0, None, None, "default"),
    )
    d.execute(
        "INSERT INTO certificates "
        "(serial, subject, not_before, not_after, der, revoked, revoked_at, reason, profile) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (1002, "CN=bob", "2026-01-01T00:00:00", "2027-01-01T00:00:00",
         b"\x30\x82DER2", 1, "2026-02-15T12:00:00", 4, "default"),
    )
    d.execute(
        "INSERT INTO certificates "
        "(serial, subject, not_before, not_after, der, revoked, revoked_at, reason, profile) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (1003, "CN=carol", "2026-01-01T00:00:00", "2027-01-01T00:00:00",
         b"\x30\x82DER3", 0, None, None, "tls-server"),
    )

    # Bump the serial counter to reflect what was actually issued.
    d.execute(
        "INSERT INTO serial_counter (id, value) VALUES (?, ?) "
        "ON CONFLICT (id) DO UPDATE SET value = excluded.value",
        (1, 1003),
    )

    # CRL number bumped to 5 (relying parties have seen 5 CRLs).
    d.execute(
        "INSERT INTO crl_number (id, value) VALUES (?, ?) "
        "ON CONFLICT (id) DO UPDATE SET value = excluded.value",
        (1, 5),
    )

    # 2 historical CRLs.
    d.execute(
        "INSERT INTO crl_base (issued_at, this_update, next_update, der) "
        "VALUES (?, ?, ?, ?)",
        ("2026-01-01T00:00:00", "2026-01-01T00:00:00",
         "2026-01-08T00:00:00", b"\x30\x82CRL1"),
    )
    d.execute(
        "INSERT INTO crl_base (issued_at, this_update, next_update, der) "
        "VALUES (?, ?, ?, ?)",
        ("2026-02-01T00:00:00", "2026-02-01T00:00:00",
         "2026-02-08T00:00:00", b"\x30\x82CRL2"),
    )


def _seed_audit(d: db.Database) -> None:
    """Insert a few audit log rows."""
    for i in range(5):
        d.execute(
            "INSERT INTO audit (ts, event, detail, ip) VALUES (?, ?, ?, ?)",
            (f"2026-01-0{i+1}T00:00:00Z", "issue", f"serial=100{i+1}", "10.0.0.1"),
        )


def _seed_acme(d: db.Database) -> None:
    """Insert ACME-namespace rows including an ephemeral nonce."""
    d.execute(
        "INSERT INTO accounts (kid, jwk_json, thumbprint, status, contact, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("acct-1", "{}", "thumb1", "valid", "mailto:a@x", 1700000000.0),
    )
    d.execute(
        "INSERT INTO orders (id, account_kid, status, identifiers, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("ord-1", "acct-1", "valid", "[]", 1700000001.0, 1700001001.0),
    )
    # Ephemeral table — should NOT be migrated.
    d.execute(
        "INSERT INTO nonces (value, created_at) VALUES (?, ?)",
        ("nonce-abc-MUST-NOT-MIGRATE", 1700000002.0),
    )


def _seed_scep(d: db.Database) -> None:
    d.execute(
        "INSERT INTO scep_transactions "
        "(transaction_id, status, subject, csr_pem, cert_pem, "
        " fail_info, fail_reason, requester_ip, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("tx-1", "issued", "CN=device-1", "-----CSR-----",
         "-----CERT-----", None, None, "10.0.0.5", 1700000003.0, 1700000004.0),
    )


def _bootstrap_db(url: str, namespace: str) -> db.Database:
    """Open a Database, apply the migrations for ``namespace``, return it."""
    d = db.make_db(url)
    runner = migrations.MigrationRunner(
        d, f"db_migrations/{namespace}", namespace=namespace
    )
    runner.apply_pending()
    return d


def _open_db(url: str) -> db.Database:
    """Open without migrating (use after _bootstrap_db wrote the schema)."""
    return db.make_db(url)


# ---------------------------------------------------------------------------
# SQLite → SQLite tests (always run)
# ---------------------------------------------------------------------------

class TestMigrationCatalog(unittest.TestCase):
    """Sanity checks on the table catalog itself."""

    def test_namespaces_match_PYPKI_NAMESPACES(self):
        cat_names = set(migration.TABLE_CATALOG.keys())
        runner_names = {ns for ns, _, _ in migrations.PYPKI_NAMESPACES}
        self.assertEqual(cat_names, runner_names)

    def test_ephemeral_tables_only_in_known_namespaces(self):
        for ns in migration.EPHEMERAL_TABLES:
            self.assertIn(ns, migration.TABLE_CATALOG)

    def test_pks_are_non_empty(self):
        for ns, specs in migration.TABLE_CATALOG.items():
            for spec in specs:
                self.assertGreater(
                    len(spec.pk), 0, f"{ns}.{spec.name} has empty PK"
                )


class TestSQLiteRoundTrip(unittest.TestCase):
    """Migrate SQLite → SQLite and verify all four namespaces."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="pypki-mig-")
        self._src_dir = Path(self._tmp) / "src"
        self._dst_dir = Path(self._tmp) / "dst"
        self._src_dir.mkdir()
        self._dst_dir.mkdir()

        self._src_paths = {ns: self._src_dir / f"{ns}.db"
                           for ns in migration.TABLE_CATALOG}
        self._dst_paths = {ns: self._dst_dir / f"{ns}.db"
                           for ns in migration.TABLE_CATALOG}

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _bootstrap(self) -> None:
        """Apply schema to both src and dst, seed src with fixtures."""
        for ns in migration.TABLE_CATALOG:
            _bootstrap_db(f"sqlite:///{self._src_paths[ns]}", ns).close()
            _bootstrap_db(f"sqlite:///{self._dst_paths[ns]}", ns).close()

        src_pki = _open_db(f"sqlite:///{self._src_paths['pki']}")
        _seed_pki(src_pki)
        src_pki.close()

        src_audit = _open_db(f"sqlite:///{self._src_paths['audit']}")
        _seed_audit(src_audit)
        src_audit.close()

        src_acme = _open_db(f"sqlite:///{self._src_paths['acme']}")
        _seed_acme(src_acme)
        src_acme.close()

        src_scep = _open_db(f"sqlite:///{self._src_paths['scep']}")
        _seed_scep(src_scep)
        src_scep.close()

    def _src_factory(self, ns: str) -> db.Database:
        return _open_db(f"sqlite:///{self._src_paths[ns]}")

    def _dst_factory(self, ns: str) -> db.Database:
        return _open_db(f"sqlite:///{self._dst_paths[ns]}")

    def test_migrate_all_namespaces(self):
        self._bootstrap()
        results = migration.migrate_all(self._src_factory, self._dst_factory)
        self.assertEqual(set(results.keys()), set(migration.TABLE_CATALOG.keys()))
        self.assertEqual(results["pki"]["certificates"], 3)
        self.assertEqual(results["pki"]["serial_counter"], 1)
        self.assertEqual(results["pki"]["crl_number"], 1)
        self.assertEqual(results["pki"]["crl_base"], 2)
        self.assertEqual(results["audit"]["audit"], 5)
        self.assertEqual(results["acme"]["accounts"], 1)
        self.assertEqual(results["acme"]["orders"], 1)
        self.assertEqual(results["scep"]["scep_transactions"], 1)

    def test_verify_after_migrate_clean(self):
        self._bootstrap()
        migration.migrate_all(self._src_factory, self._dst_factory)
        errors = migration.verify_all(self._src_factory, self._dst_factory)
        for ns, errs in errors.items():
            self.assertEqual(errs, [], f"namespace {ns} errors: {errs}")

    def test_certificates_round_trip_byte_identical(self):
        """Ensure BLOB columns survive the round-trip exactly."""
        self._bootstrap()
        migration.migrate_all(self._src_factory, self._dst_factory)

        src = self._src_factory("pki")
        dst = self._dst_factory("pki")
        for serial in (1001, 1002, 1003):
            sr = src.fetchone(
                "SELECT serial, subject, der, revoked, reason "
                "FROM certificates WHERE serial = ?", (serial,)
            )
            dr = dst.fetchone(
                "SELECT serial, subject, der, revoked, reason "
                "FROM certificates WHERE serial = ?", (serial,)
            )
            self.assertIsNotNone(sr)
            self.assertIsNotNone(dr)
            self.assertEqual(sr["serial"],  dr["serial"])
            self.assertEqual(sr["subject"], dr["subject"])
            self.assertEqual(bytes(sr["der"]), bytes(dr["der"]))
            self.assertEqual(sr["revoked"], dr["revoked"])
            self.assertEqual(sr["reason"],  dr["reason"])
        src.close()
        dst.close()

    def test_singleton_seed_overwritten_with_source_value(self):
        """serial_counter ships seeded with value=1000; src has 1003.
        After migration, dst must show 1003, not 1000."""
        self._bootstrap()
        migration.migrate_all(self._src_factory, self._dst_factory)
        dst = self._dst_factory("pki")
        row = dst.fetchone("SELECT value FROM serial_counter WHERE id = 1")
        self.assertEqual(row["value"], 1003)
        dst.close()

    def test_crl_number_preserved(self):
        """The CRL counter monotonicity must survive migration —
        otherwise relying parties reject the next CRL."""
        self._bootstrap()
        migration.migrate_all(self._src_factory, self._dst_factory)
        dst = self._dst_factory("pki")
        row = dst.fetchone("SELECT value FROM crl_number WHERE id = 1")
        self.assertEqual(row["value"], 5)
        dst.close()

    def test_ephemeral_nonces_NOT_migrated(self):
        """The ACME ephemeral 'nonces' table is in the source but must
        not appear in the destination after migration."""
        self._bootstrap()
        migration.migrate_all(self._src_factory, self._dst_factory)
        dst = self._dst_factory("acme")
        rows = dst.fetchall("SELECT value FROM nonces")
        self.assertEqual(rows, [], "nonces table must be empty post-migration")
        dst.close()

    def test_idempotent_remigration(self):
        """Running migrate_all twice must yield the same destination state."""
        self._bootstrap()
        migration.migrate_all(self._src_factory, self._dst_factory)
        migration.migrate_all(self._src_factory, self._dst_factory)
        errors = migration.verify_all(self._src_factory, self._dst_factory)
        for ns, errs in errors.items():
            self.assertEqual(errs, [], f"after re-migrate, {ns}: {errs}")

    def test_verify_detects_corruption(self):
        """If destination diverges from source, verify_all must catch it."""
        self._bootstrap()
        migration.migrate_all(self._src_factory, self._dst_factory)

        dst_pki = self._dst_factory("pki")
        dst_pki.execute(
            "UPDATE certificates SET subject = ? WHERE serial = ?",
            ("CN=evil-tampered", 1001),
        )
        dst_pki.close()

        errors = migration.verify_all(self._src_factory, self._dst_factory)
        self.assertNotEqual(errors["pki"], [],
                            "verify must detect tampered subject")
        for ns in ("audit", "acme", "scep"):
            self.assertEqual(errors[ns], [], f"unexpected errors in {ns}")

    def test_verify_detects_row_count_mismatch(self):
        """If destination is missing rows, verify must report it."""
        self._bootstrap()
        migration.migrate_all(self._src_factory, self._dst_factory)

        dst_audit = self._dst_factory("audit")
        dst_audit.execute("DELETE FROM audit WHERE id = 1")
        dst_audit.close()

        errors = migration.verify_all(self._src_factory, self._dst_factory)
        self.assertTrue(any("audit" in e for e in errors["audit"]))


class TestSchemaVersionGate(unittest.TestCase):
    """Migration must refuse to run if dst schema is at a different version."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="pypki-mig-gate-")
        self._src_path = Path(self._tmp) / "src.db"
        self._dst_path = Path(self._tmp) / "dst.db"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_refuses_when_dst_unmigrated(self):
        # src has migrations applied, dst is bare.
        _bootstrap_db(f"sqlite:///{self._src_path}", "pki").close()

        bare = db.make_db(f"sqlite:///{self._dst_path}")
        bare.close()

        src = _open_db(f"sqlite:///{self._src_path}")
        dst = _open_db(f"sqlite:///{self._dst_path}")
        with self.assertRaises(migration.MigrationError):
            migration.migrate_namespace(src, dst, "pki")
        src.close()
        dst.close()

    def test_refuses_when_versions_differ(self):
        # Apply both 001 and 002 to dst, then roll dst back to v1 by
        # deleting the v2 row from schema_migrations.
        _bootstrap_db(f"sqlite:///{self._src_path}", "pki").close()
        _bootstrap_db(f"sqlite:///{self._dst_path}", "pki").close()

        # Roll dst back to "version 1 only".
        dst = _open_db(f"sqlite:///{self._dst_path}")
        dst.execute("DELETE FROM schema_migrations WHERE version = ?", (2,))
        dst.close()

        src = _open_db(f"sqlite:///{self._src_path}")
        dst = _open_db(f"sqlite:///{self._dst_path}")
        with self.assertRaises(migration.MigrationError) as cm:
            migration.migrate_namespace(src, dst, "pki")
        self.assertIn("schema_version mismatch", str(cm.exception))
        src.close()
        dst.close()


# ---------------------------------------------------------------------------
# CLI integration tests — exercise pypki_admin.py end-to-end
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):
    """The CLI is a thin wrapper, but it has its own arg-parsing and
    exit-code surface that's part of the operator interface. Test it."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="pypki-mig-cli-")
        self._src = Path(self._tmp) / "src"
        self._dst = Path(self._tmp) / "dst"
        self._src.mkdir()
        self._dst.mkdir()
        for ns, file, _ in migrations.PYPKI_NAMESPACES:
            _bootstrap_db(f"sqlite:///{self._src / file}", ns).close()
            _bootstrap_db(f"sqlite:///{self._dst / file}", ns).close()
        # Seed the source.
        _seed_pki(_open_db(f"sqlite:///{self._src / 'certificates.db'}"))
        _seed_audit(_open_db(f"sqlite:///{self._src / 'audit.db'}"))
        _seed_acme(_open_db(f"sqlite:///{self._src / 'acme.db'}"))
        _seed_scep(_open_db(f"sqlite:///{self._src / 'scep.db'}"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, args):
        """Run pypki_admin.py with args; return (rc, stderr)."""
        result = subprocess.run(
            [sys.executable, str(HERE / "pypki_admin.py")] + args,
            capture_output=True, text=True, cwd=str(HERE), timeout=60,
        )
        return result.returncode, result.stderr

    def test_help_works(self):
        rc, _ = self._run(["--help"])
        self.assertEqual(rc, 0)

    def test_migrate_then_verify_succeeds(self):
        rc, err = self._run([
            "migrate-data",
            "--from-ca-dir", str(self._src),
            "--to-ca-dir",   str(self._dst),
            "--yes",
        ])
        self.assertEqual(rc, 0, f"migrate-data should succeed; stderr:\n{err}")
        self.assertIn("migration complete", err)

        rc, err = self._run([
            "verify-migration",
            "--from-ca-dir", str(self._src),
            "--to-ca-dir",   str(self._dst),
        ])
        self.assertEqual(rc, 0, f"verify should succeed; stderr:\n{err}")
        self.assertIn("PASSED", err)

    def test_verify_returns_nonzero_on_drift(self):
        # Migrate, then deliberately corrupt the destination.
        rc, _ = self._run([
            "migrate-data",
            "--from-ca-dir", str(self._src),
            "--to-ca-dir",   str(self._dst),
            "--yes",
        ])
        self.assertEqual(rc, 0)

        # Tamper.
        d = _open_db(f"sqlite:///{self._dst / 'certificates.db'}")
        d.execute("UPDATE certificates SET subject = 'CN=tampered' WHERE serial = 1001")
        d.close()

        rc, err = self._run([
            "verify-migration",
            "--from-ca-dir", str(self._src),
            "--to-ca-dir",   str(self._dst),
        ])
        self.assertEqual(rc, 3, f"verify must return 3 on drift; stderr:\n{err}")
        self.assertIn("FAILED", err)

    def test_namespace_flag_limits_scope(self):
        """When --namespace pki is given, audit/acme/scep should NOT be touched."""
        rc, _ = self._run([
            "migrate-data",
            "--from-ca-dir", str(self._src),
            "--to-ca-dir",   str(self._dst),
            "--namespace",   "pki",
            "--yes",
        ])
        self.assertEqual(rc, 0)

        # audit table on dst should still be empty.
        d = _open_db(f"sqlite:///{self._dst / 'audit.db'}")
        rows = d.fetchall("SELECT id FROM audit")
        d.close()
        self.assertEqual(len(rows), 0,
                         "audit must be untouched when --namespace pki only")

    def test_missing_url_for_namespace_fails_clean(self):
        # Use --from-url-pki only; no audit/acme/scep URLs. Should fail.
        rc, err = self._run([
            "migrate-data",
            "--from-url-pki", f"sqlite:///{self._src / 'certificates.db'}",
            "--to-url-pki",   f"sqlite:///{self._dst / 'certificates.db'}",
            "--yes",
        ])
        self.assertNotEqual(rc, 0)
        self.assertTrue(
            "missing source or destination URL" in err
            or "no database URL configured" in err,
            f"expected friendly error; got:\n{err}",
        )


# ---------------------------------------------------------------------------
# Postgres-specific tests (gated)
# ---------------------------------------------------------------------------

@unittest.skipUnless(
    PG_URL,
    "Set PYPKI_TEST_POSTGRES_URL and install psycopg to run Postgres tests",
)
class TestPostgresMigration(unittest.TestCase):
    """SQLite → Postgres round-trip, with sequence-resync verification."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="pypki-mig-pg-")
        self._src_dir = Path(self._tmp) / "src"
        self._src_dir.mkdir()
        self._src_paths = {ns: self._src_dir / f"{ns}.db"
                           for ns in migration.TABLE_CATALOG}
        # pki + audit have no name collisions; acme + scep would clash with
        # pki on table name 'certificates' / 'scep_transactions' is unique.
        # Use only pki + audit for the Postgres test to keep the test simple.
        self._namespaces = ["pki", "audit"]
        self._dst_url = PG_URL

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)
        try:
            d = db.make_db(self._dst_url)
            for ns in self._namespaces:
                for spec in migration.TABLE_CATALOG[ns]:
                    try:
                        d.execute(f"DROP TABLE IF EXISTS {spec.name} CASCADE")
                    except Exception:
                        pass
            try:
                d.execute("DROP TABLE IF EXISTS schema_migrations CASCADE")
            except Exception:
                pass
            d.close()
        except Exception:
            pass

    def _src_factory(self, ns: str) -> db.Database:
        return _open_db(f"sqlite:///{self._src_paths[ns]}")

    def _dst_factory(self, ns: str) -> db.Database:
        return _open_db(self._dst_url)

    def test_round_trip_pki_audit(self):
        for ns in self._namespaces:
            _bootstrap_db(f"sqlite:///{self._src_paths[ns]}", ns).close()
        _seed_pki(_open_db(f"sqlite:///{self._src_paths['pki']}"))
        _seed_audit(_open_db(f"sqlite:///{self._src_paths['audit']}"))

        for ns in self._namespaces:
            d = db.make_db(self._dst_url)
            r = migrations.MigrationRunner(d, f"db_migrations/{ns}", namespace=ns)
            r.apply_pending()
            d.close()

        migration.migrate_all(
            self._src_factory, self._dst_factory,
            namespaces=self._namespaces,
        )

        errors = migration.verify_all(
            self._src_factory, self._dst_factory,
            namespaces=self._namespaces,
        )
        for ns, errs in errors.items():
            self.assertEqual(errs, [], f"{ns} errors: {errs}")

        dst = self._dst_factory("audit")
        row = dst.fetchone("SELECT MAX(id) AS m FROM audit")
        max_id = row["m"]
        seq_row = dst.fetchone(
            "SELECT pg_get_serial_sequence('audit', 'id') AS s"
        )
        seq_name = seq_row["s"]
        if seq_name:
            nx = dst.fetchone(f"SELECT last_value AS v FROM {seq_name}")
            self.assertGreaterEqual(nx["v"], max_id,
                                    "post-migration sequence must allow next INSERT")
        dst.close()


if __name__ == "__main__":
    unittest.main()
