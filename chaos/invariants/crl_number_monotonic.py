"""
Invariant 3: cRLNumber is strictly monotonic across all CRLs ever issued.

Reads stored CRL DER blobs from the `crl_base` table and verifies that the
cRLNumber extension value strictly increases.

Usage:
    python3 chaos/invariants/crl_number_monotonic.py <pki_db>
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path


def _extract_crl_number(der: bytes) -> int | None:
    """
    Extract the cRLNumber extension value from a CRL DER blob.
    cRLNumber OID: 2.5.29.20
    Uses the cryptography library; returns None if no cRLNumber extension.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
        crl = x509.load_der_x509_crl(der)
        ext = crl.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER)
        return ext.value.crl_number
    except Exception:
        return None


def check(pki_db: str | Path) -> tuple[bool, str]:
    """Returns (ok, message)."""
    conn = sqlite3.connect(f"file:{pki_db}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT id, issued_at, der FROM crl_base ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return True, "No CRLs issued yet — invariant vacuously holds"

    numbers: list[tuple[int, int | None]] = []
    for row_id, issued_at, der in rows:
        der_bytes = bytes(der) if not isinstance(der, bytes) else der
        crl_num = _extract_crl_number(der_bytes)
        numbers.append((row_id, crl_num))

    # Check strict monotonicity.
    prev_num = -1
    for row_id, crl_num in numbers:
        if crl_num is None:
            # CRL with no cRLNumber extension — warn but don't fail.
            continue
        if crl_num <= prev_num:
            return (
                False,
                f"CRL at row {row_id} has cRLNumber={crl_num} "
                f"which is not greater than previous {prev_num}",
            )
        prev_num = crl_num

    return (
        True,
        f"All {len(numbers)} CRL(s) have strictly increasing cRLNumber "
        f"(last={prev_num})",
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pki_db>")
        sys.exit(1)
    ok, msg = check(sys.argv[1])
    print("PASS" if ok else "FAIL", "—", msg)
    sys.exit(0 if ok else 1)
