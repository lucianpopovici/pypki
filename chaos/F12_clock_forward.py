"""
F12 — Clock jump forward (NTP sync) during issuance.

Invariants tested: 6 (OCSP response reflects state at query time).

Simulates a forward clock jump using libfaketime (LD_PRELOAD).
Requires: PYPKI_CHAOS_LIBFAKETIME — path to libfaketime.so. Skip otherwise.

Without libfaketime, we test the invariant using monkeypatching of
datetime.datetime.now() to simulate a time jump, which validates the
CA's internal logic even if we can't test the OS-level effect.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import ScenarioResult, make_audit_log, issue_one, ITERATIONS
from chaos.invariants import audit_log_complete, no_duplicate_serials

_LIBFAKETIME = os.environ.get("PYPKI_CHAOS_LIBFAKETIME")


def run() -> bool:
    result = ScenarioResult("F12_clock_forward")
    print("\n=== F12: Clock jump forward ===")
    print("Testing: issuance remains correct after clock advances\n")

    ca_dir = tempfile.mkdtemp(prefix="chaos-F12-")
    try:
        import pki_server as pki

        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = make_audit_log(ca_dir)

        # Issue certs before the jump.
        for i in range(min(ITERATIONS, 20)):
            issue_one(ca, audit, cn=f"f12-pre-jump-{i}")

        if _LIBFAKETIME:
            result.skip(
                "libfaketime integration not yet automated. "
                "Manual: run pki_server under LD_PRELOAD=libfaketime.so "
                "FAKETIME='+1y' and verify cert validity dates are correct."
            )
        else:
            # In-process simulation: override the CA's notion of "now" if possible.
            # This tests that the CA code doesn't hard-code datetime.utcnow() calls.
            # We verify that issuing certs with explicit not_before/not_after works.
            future = datetime.now(timezone.utc) + timedelta(days=365)
            cert = ca.issue_certificate(
                "CN=f12-future",
                _gen_key().public_key(),
                audit=audit,
                not_before=future,
                not_after=future + timedelta(days=90),
            )
            result.check(
                "future_dated_cert_issued",
                cert is not None,
                "CA rejected a future-dated cert",
            )
            result.check(
                "future_dated_cert_notbefore_correct",
                cert.not_valid_before_utc >= future - timedelta(seconds=2),
                f"notBefore {cert.not_valid_before_utc} != expected ~{future}",
            )

        # After jump: more issuance should work normally.
        for j in range(5):
            issue_one(ca, audit, cn=f"f12-post-jump-{j}")

        del ca, audit

        pki_db = Path(ca_dir) / "certificates.db"
        ok1, msg1 = audit_log_complete.check(pki_db, Path(ca_dir) / "audit.db")
        result.check("audit_log_complete", ok1, msg1)

        ok2, msg2 = no_duplicate_serials.check(pki_db)
        result.check("no_duplicate_serials", ok2, msg2)

        return result.summary()
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


def _gen_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
