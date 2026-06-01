"""
F05 — Disk full during CRL write.

Invariants tested: 3 (cRLNumber monotonicity).

Requires: PYPKI_CHAOS_TMPFS — path to a small tmpfs mount point. Skip otherwise.

The test fills the tmpfs to capacity while a CRL generation is in progress,
then verifies that cRLNumber remains monotonic after the failure.
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

_TMPFS = os.environ.get("PYPKI_CHAOS_TMPFS")


def run() -> bool:
    result = ScenarioResult("F05_crl_disk_full")
    print("\n=== F05: Disk full during CRL write ===")

    if not _TMPFS:
        result.skip("PYPKI_CHAOS_TMPFS not set — tmpfs not available")
        return result.summary()

    ca_dir = tempfile.mkdtemp(prefix="chaos-F05-", dir=_TMPFS)
    filler_path = Path(_TMPFS) / "filler"
    try:
        import pki_server as pki

        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = make_audit_log(ca_dir)

        # Issue and revoke a cert so the CRL is non-empty.
        key_obj = _gen_key()
        cert = ca.issue_certificate("CN=crl-victim", key_obj.public_key(), audit=audit)
        ca.revoke_certificate(cert.serial_number, reason=0, audit=audit)

        # Generate a first CRL (should succeed).
        try:
            ca.generate_crl(audit=audit)
        except Exception as e:
            result.check("first_crl_ok", False, str(e))
            return result.summary()
        result.check("first_crl_ok", True)

        # Fill the tmpfs to near-capacity.
        _fill_disk(_TMPFS, filler_path)

        # Attempt CRL generation under disk-full condition.
        crl_fail_ok = False
        try:
            ca.generate_crl(audit=audit)
        except (OSError, IOError, Exception):
            crl_fail_ok = True

        result.check(
            "crl_fails_gracefully_when_disk_full",
            crl_fail_ok,
            "Expected CRL generation to fail with disk-full error",
        )

        # Free the disk.
        filler_path.unlink(missing_ok=True)

        # CRL generation should succeed again.
        try:
            ca.generate_crl(audit=audit)
            result.check("crl_recovers_after_disk_freed", True)
        except Exception as e:
            result.check("crl_recovers_after_disk_freed", False, str(e))

        # Invariant: cRLNumber must still be monotonic.
        pki_db = Path(ca_dir) / "certificates.db"
        ok3, msg3 = crl_number_monotonic.check(pki_db)
        result.check("crl_number_monotonic", ok3, msg3)

        del ca, audit
        return result.summary()
    finally:
        filler_path.unlink(missing_ok=True)
        shutil.rmtree(ca_dir, ignore_errors=True)


def _gen_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


def _fill_disk(path: str, filler: Path) -> None:
    """Write to filler until OSError (disk full)."""
    try:
        with filler.open("wb") as f:
            while True:
                f.write(b"\x00" * 4096)
    except OSError:
        pass


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
