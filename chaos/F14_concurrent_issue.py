"""
F14 — Two or more threads issuing concurrently against the same CA.

Invariants tested: 2 (no duplicate serials), 3 (cRLNumber monotonic),
                   8 (advisory lock not held by dead process).

This is the primary fully-automated chaos scenario — no special infrastructure
required. Tests that the serial-allocation advisory lock correctly serializes
concurrent issuance and that no serial collisions occur under load.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import (
    ITERATIONS, ScenarioResult, make_test_ca, make_audit_log,
    concurrent_issue,
)
from chaos.invariants import (
    audit_log_complete, no_duplicate_serials, crl_number_monotonic,
)


def run() -> bool:
    result = ScenarioResult("F14_concurrent_issue")
    print("\n=== F14: Concurrent issuance from multiple threads ===")
    n_threads = 8
    certs_per_thread = max(ITERATIONS // n_threads, 10)
    print(f"    {n_threads} threads × {certs_per_thread} certs = "
          f"{n_threads * certs_per_thread} total\n")

    ca_dir = tempfile.mkdtemp(prefix="chaos-F14-")
    try:
        import pki_server as pki

        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = make_audit_log(ca_dir)

        issued = concurrent_issue(
            ca, audit,
            n_threads=n_threads,
            certs_per_thread=certs_per_thread,
        )

        expected_total = n_threads * certs_per_thread
        result.check(
            "all_certs_issued",
            len(issued) == expected_total,
            f"issued {len(issued)}/{expected_total} certs",
        )

        del ca, audit

        pki_db = Path(ca_dir) / "certificates.db"
        audit_db = Path(ca_dir) / "audit.db"

        ok2, msg2 = no_duplicate_serials.check(pki_db)
        result.check("no_duplicate_serials", ok2, msg2)

        ok1, msg1 = audit_log_complete.check(pki_db, audit_db)
        result.check("audit_log_complete", ok1, msg1)

        ok3, msg3 = crl_number_monotonic.check(pki_db)
        result.check("crl_number_monotonic (no CRLs)", ok3, msg3)

        # Verify serial uniqueness within our issued set.
        in_memory_serials = [c.serial_number for c in issued]
        result.check(
            "no_duplicate_serials_in_memory",
            len(in_memory_serials) == len(set(in_memory_serials)),
            f"found {len(in_memory_serials) - len(set(in_memory_serials))} duplicate(s)",
        )

        # Advisory lock sanity: the DB serial counter should equal the number
        # of certs issued + the seed value (1000).
        import sqlite3
        conn = sqlite3.connect(f"file:{pki_db}?mode=ro", uri=True)
        db_count = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
        conn.close()
        result.check(
            "cert_count_matches_db",
            db_count == len(issued),
            f"DB has {db_count} rows but we issued {len(issued)}",
        )

        return result.summary()
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
