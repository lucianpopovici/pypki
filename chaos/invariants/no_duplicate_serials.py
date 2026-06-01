"""
Invariant 2: No two certificates share a serial number.

RFC 5280 §4.1.2.2: serial numbers MUST be unique per issuer.

Usage:
    python3 chaos/invariants/no_duplicate_serials.py <pki_db>
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path


def check(pki_db: str | Path) -> tuple[bool, str]:
    """Returns (ok, message)."""
    conn = sqlite3.connect(f"file:{pki_db}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT serial, COUNT(*) AS cnt FROM certificates "
            "GROUP BY serial HAVING cnt > 1"
        ).fetchall()

        total = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]

        if not rows:
            return True, f"No duplicate serials in {total} cert(s)"

        dupes = [(r[0], r[1]) for r in rows]
        return False, f"Duplicate serials: {dupes[:10]}"
    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pki_db>")
        sys.exit(1)
    ok, msg = check(sys.argv[1])
    print("PASS" if ok else "FAIL", "—", msg)
    sys.exit(0 if ok else 1)
