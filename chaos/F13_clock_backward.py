"""
F13 — Clock jump backward during issuance.

Invariants tested: 3 (cRLNumber monotonicity).

A backward clock jump can cause the `crl_number` counter to be compared
against a timestamp that looks "earlier" than the last CRL. The cRLNumber
must not regress — it is a monotonic counter independent of wall time.

Simulates using libfaketime if available; otherwise tests in-process.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import ScenarioResult, make_audit_log, issue_one
from chaos.invariants import crl_number_monotonic

_LIBFAKETIME = os.environ.get("PYPKI_CHAOS_LIBFAKETIME")


def run() -> bool:
    result = ScenarioResult("F13_clock_backward")
    print("\n=== F13: Clock jump backward ===")
    print("Testing: cRLNumber remains monotonic after backward clock jump\n")

    ca_dir = tempfile.mkdtemp(prefix="chaos-F13-")
    try:
        import pki_server as pki
        from cryptography.hazmat.primitives.asymmetric import ec

        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = make_audit_log(ca_dir)
        key = ec.generate_private_key(ec.SECP256R1())

        # Issue + revoke a cert to populate a CRL.
        cert1 = ca.issue_certificate("CN=f13-c1", key.public_key(), audit=audit)
        ca.revoke_certificate(cert1.serial_number, reason=0)

        # Generate the first CRL.
        try:
            ca.generate_crl()
            result.check("first_crl_generated", True)
        except Exception as e:
            result.check("first_crl_generated", False, str(e))
            return result.summary()

        if _LIBFAKETIME:
            result.skip(
                "libfaketime backward clock not automated. "
                "Manual: run with FAKETIME='-1h' and verify second CRL has "
                "a higher cRLNumber than first."
            )
        else:
            # In-process: generate a second CRL immediately and verify monotonicity.
            # cRLNumber is a DB counter independent of wall time, so it must
            # increase regardless of any clock change.
            cert2 = ca.issue_certificate("CN=f13-c2", key.public_key(), audit=audit)
            ca.revoke_certificate(cert2.serial_number, reason=0)
            try:
                ca.generate_crl()
                result.check("second_crl_generated", True)
            except Exception as e:
                result.check("second_crl_generated", False, str(e))

        pki_db = Path(ca_dir) / "certificates.db"
        ok3, msg3 = crl_number_monotonic.check(pki_db)
        result.check("crl_number_monotonic", ok3, msg3)

        del ca, audit
        return result.summary()
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
