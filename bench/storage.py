"""
bench/storage.py — Storage growth measurement.

Measures:
  - Bytes per issued cert in the `certificates` table
  - Bytes per audit log row
  - Projected disk growth at various issuance rates

Usage:
    python3 bench/storage.py [--n 1000]
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bench._harness import BenchResult, hw_info, gen_key, write_result


def measure_storage(n: int) -> list[BenchResult]:
    import pki_server as pki

    ca_dir = tempfile.mkdtemp(prefix="bench-storage-")
    try:
        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = pki.AuditLog(Path(ca_dir))

        pki_db_path = Path(ca_dir) / "pypki.db"
        audit_db_path = Path(ca_dir) / "audit.db"

        def db_size(path: Path) -> int:
            return os.path.getsize(path) if path.exists() else 0

        size_before_pki = db_size(pki_db_path)
        size_before_audit = db_size(audit_db_path)

        key_pub = gen_key().public_key()
        for i in range(n):
            ca.issue_certificate(f"CN=storage-{i}", key_pub, audit=audit)

        # Force WAL checkpoint so sizes are accurate.
        for db_path in (pki_db_path, audit_db_path):
            if db_path.exists():
                conn = sqlite3.connect(str(db_path))
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.close()

        size_after_pki = db_size(pki_db_path)
        size_after_audit = db_size(audit_db_path)

        bytes_per_cert = (size_after_pki - size_before_pki) / max(n, 1)
        bytes_per_audit = (size_after_audit - size_before_audit) / max(n, 1)

        results = []

        r1 = BenchResult("storage/bytes_per_cert", unit="byte")
        r1.add_note("bytes_per_cert", f"{bytes_per_cert:.0f}")
        r1.add_note("db_size_after_N_certs", f"{size_after_pki / 1024:.1f} KB")
        r1.add_note("n_certs", str(n))
        # Projections
        for rate in (10, 100, 1000):
            per_day = rate * 86400 * bytes_per_cert / 1e6
            r1.add_note(f"projected_MB_per_day_at_{rate}_certs_per_sec",
                        f"{per_day:.1f}")
        r1.print_summary()
        results.append(r1)

        r2 = BenchResult("storage/bytes_per_audit_row", unit="byte")
        r2.add_note("bytes_per_audit_row", f"{bytes_per_audit:.0f}")
        r2.add_note("audit_db_size", f"{size_after_audit / 1024:.1f} KB")
        r2.print_summary()
        results.append(r2)

        del ca, audit
        return results
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Storage growth benchmark")
    parser.add_argument("--n", type=int, default=1000, help="Certs to issue")
    args = parser.parse_args(argv)

    print("=== Storage growth measurement ===")
    hw = hw_info()
    results = measure_storage(args.n)
    ts = hw["timestamp"].replace(":", "-").replace("+", "")[:19]
    write_result(f"storage-{ts}.md", results, hw)
    print("\n=== Done ===")


if __name__ == "__main__":
    main()
