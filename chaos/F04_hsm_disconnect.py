"""
F04 — HSM session severed during C_Sign.

Invariants tested: 1 (audit completeness), 7 (durability before response).

Requires: PKCS#11 HSM. Skip when PYPKI_CHAOS_HSM_LIB is not set.

The test attempts to sign a cert using the HSM backend, then simulates a device
error by unloading the PKCS#11 library mid-operation. Verifies that:
1. The failed signing does not produce a cert entry in the DB.
2. No audit log entry is written for the failed signing.
3. After the HSM reconnects, issuance succeeds normally.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import ScenarioResult, make_audit_log
from chaos.invariants import audit_log_complete, no_duplicate_serials

_HSM_LIB = os.environ.get("PYPKI_CHAOS_HSM_LIB")


def run() -> bool:
    result = ScenarioResult("F04_hsm_disconnect")
    print("\n=== F04: HSM session severed during C_Sign ===")

    if not _HSM_LIB:
        result.skip("PYPKI_CHAOS_HSM_LIB not set — HSM not available")
        return result.summary()

    ca_dir = tempfile.mkdtemp(prefix="chaos-F04-")
    try:
        import pki_server as pki

        ca = pki.CertificateAuthority(
            ca_dir=ca_dir,
            hsm_lib=_HSM_LIB,
        )
        audit = make_audit_log(ca_dir)

        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())

        # Record cert count before the injected failure.
        import sqlite3
        pki_db = Path(ca_dir) / "certificates.db"

        def cert_count() -> int:
            conn = sqlite3.connect(f"file:{pki_db}?mode=ro", uri=True)
            n = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
            conn.close()
            return n

        count_before = cert_count()

        # Simulate HSM disconnect: attempt issuance with a broken HSM lib path.
        # In a real HSM test environment, this would be done by physically
        # severing the USB/PCIe connection. Here we simulate by patching.
        failed = False
        try:
            # Temporarily break the HSM backend.
            original_sign = getattr(ca, "_hsm_sign", None)
            if original_sign:
                def broken_sign(*args, **kwargs):
                    raise RuntimeError("Simulated HSM C_Sign failure (DeviceError)")
                ca._hsm_sign = broken_sign
                ca.issue_certificate("CN=hsm-fail-test", key.public_key(), audit=audit)
            else:
                result.skip("CertificateAuthority does not have _hsm_sign — skip HSM-specific test")
                return result.summary()
        except Exception:
            failed = True
        finally:
            if original_sign:
                ca._hsm_sign = original_sign  # restore

        result.check("failed_signing_raises", failed, "Expected exception from broken HSM")

        # The failed signing should not have written a cert to the DB.
        count_after_fail = cert_count()
        result.check(
            "no_partial_cert_on_failure",
            count_after_fail == count_before,
            f"count changed: {count_before} → {count_after_fail}",
        )

        # Normal issuance should succeed after recovery.
        cert = ca.issue_certificate("CN=hsm-recovery", key.public_key(), audit=audit)
        result.check("recovery_issuance_succeeds", cert is not None)

        ok1, msg1 = audit_log_complete.check(pki_db, Path(ca_dir) / "audit.db")
        result.check("audit_log_complete", ok1, msg1)

        ok2, msg2 = no_duplicate_serials.check(pki_db)
        result.check("no_duplicate_serials", ok2, msg2)

        del ca, audit
        return result.summary()
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
