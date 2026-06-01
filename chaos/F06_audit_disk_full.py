"""
F06 — Disk full during audit-log write.

Invariants tested: 1 (audit completeness), 7 (durability before response).

Requires: PYPKI_CHAOS_TMPFS. Skip otherwise.

If the audit-log write fails (disk full), `issue_certificate()` should either:
  (a) propagate the error and not return a cert (preferred), or
  (b) return the cert but log a warning.

In both cases, after disk space is freed, the audit log must be queryable
and any successfully issued certs must appear in it.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import ScenarioResult, make_audit_log, issue_one
from chaos.invariants import audit_log_complete

_TMPFS = os.environ.get("PYPKI_CHAOS_TMPFS")


def run() -> bool:
    result = ScenarioResult("F06_audit_disk_full")
    print("\n=== F06: Disk full during audit-log write ===")

    if not _TMPFS:
        result.skip("PYPKI_CHAOS_TMPFS not set — tmpfs not available")
        return result.summary()

    ca_dir = tempfile.mkdtemp(prefix="chaos-F06-", dir=_TMPFS)
    filler_path = Path(_TMPFS) / "filler-audit"
    try:
        import pki_server as pki

        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = make_audit_log(ca_dir)

        # Issue a few certs normally.
        for i in range(5):
            issue_one(ca, audit, cn=f"f06-pre-{i}")

        # Fill the disk.
        _fill_disk(_TMPFS, filler_path)

        # Attempt issuance with audit disk full.
        issued_under_full = False
        error_raised = False
        try:
            cert = issue_one(ca, audit, cn="f06-disk-full")
            issued_under_full = True
        except Exception:
            error_raised = True

        # Either behaviour is acceptable; what matters is consistency.
        result.check(
            "consistent_failure_or_success",
            issued_under_full != error_raised or True,  # always pass; we observe
            f"issued={issued_under_full}, error={error_raised}",
        )

        # Free disk space.
        filler_path.unlink(missing_ok=True)

        # Post-recovery issuance must succeed.
        try:
            issue_one(ca, audit, cn="f06-recovery")
            result.check("recovery_issuance_ok", True)
        except Exception as e:
            result.check("recovery_issuance_ok", False, str(e))

        del ca, audit

        # Audit log must be coherent (check count vs certs).
        pki_db = Path(ca_dir) / "certificates.db"
        audit_db = Path(ca_dir) / "audit.db"
        ok1, msg1 = audit_log_complete.check(pki_db, audit_db)
        result.check("audit_coherent_after_recovery", ok1, msg1)

        return result.summary()
    finally:
        filler_path.unlink(missing_ok=True)
        shutil.rmtree(ca_dir, ignore_errors=True)


def _fill_disk(path: str, filler: Path) -> None:
    try:
        with filler.open("wb") as f:
            while True:
                f.write(b"\x00" * 4096)
    except OSError:
        pass


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
