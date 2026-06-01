"""
F02 — SIGKILL after audit-log commit, before HTTP response.

Invariants tested: 1 (audit completeness), 2 (no duplicate serials).

The audit + cert commit is atomic. If the process is killed before sending the
HTTP response, the cert is already durable in the DB. On restart, the client
may re-request the cert (or not). The cert must not be double-issued with a
new serial; the audit log must still be complete.

Test: issue many certs, then restart the CA from the same directory and verify
that all previously issued certs still have their audit entries.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import (
    ITERATIONS, ScenarioResult, make_test_ca, make_audit_log, issue_one,
)
from chaos.invariants import audit_log_complete, no_duplicate_serials


def run() -> bool:
    result = ScenarioResult("F02_kill_pre_response")
    print("\n=== F02: SIGKILL after commit, before HTTP response ===")
    print("Testing: cert durability across CA restart\n")

    ca_dir = tempfile.mkdtemp(prefix="chaos-F02-")
    try:
        import pki_server as pki

        # Issue certs with CA instance 1.
        ca1 = pki.CertificateAuthority(ca_dir=ca_dir)
        audit1 = make_audit_log(ca_dir)
        issued: list[int] = []
        for i in range(ITERATIONS):
            try:
                cert = issue_one(ca1, audit1, cn=f"f02-pre-restart-{i}")
                issued.append(cert.serial_number)
            except Exception as e:
                result.check(f"issue_{i}", False, str(e))

        result.check(
            "all_issued",
            len(issued) == ITERATIONS,
            f"only {len(issued)}/{ITERATIONS} issued",
        )

        # Simulate process death + restart: close resources, open a new CA.
        del ca1, audit1

        ca2 = pki.CertificateAuthority(ca_dir=ca_dir)
        audit2 = make_audit_log(ca_dir)

        # Issue a few more certs from the "restarted" instance.
        post_issued: list[int] = []
        for j in range(10):
            cert = issue_one(ca2, audit2, cn=f"f02-post-restart-{j}")
            post_issued.append(cert.serial_number)

        del ca2, audit2

        # Check invariants.
        pki_db = Path(ca_dir) / "certificates.db"
        audit_db = Path(ca_dir) / "audit.db"

        ok1, msg1 = audit_log_complete.check(pki_db, audit_db)
        result.check("audit_log_complete_after_restart", ok1, msg1)

        ok2, msg2 = no_duplicate_serials.check(pki_db)
        result.check("no_duplicate_serials", ok2, msg2)

        # Verify that pre-restart serials are all still in the DB.
        import sqlite3
        conn = sqlite3.connect(f"file:{pki_db}?mode=ro", uri=True)
        present_serials = {r[0] for r in conn.execute("SELECT serial FROM certificates")}
        conn.close()
        missing = set(issued) - present_serials
        result.check(
            "pre_restart_certs_durable",
            len(missing) == 0,
            f"{len(missing)} pre-restart cert(s) missing after restart",
        )

        # Verify no serial overlap between pre- and post-restart issuance.
        overlap = set(issued) & set(post_issued)
        result.check(
            "no_serial_reuse_across_restart",
            len(overlap) == 0,
            f"Serial(s) reused across restart: {overlap}",
        )

        return result.summary()
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
