"""
Invariant 4: A revoked certificate stays revoked, with the same revoked_at
timestamp and reason code, after a restart or DB failover.

Takes a snapshot of all revoked certs before a failure, then verifies the
snapshot matches the DB state after recovery.

Usage:
    python3 chaos/invariants/revocation_persists.py <pki_db> [<snapshot_json>]

Without a snapshot, prints the current revocation state as JSON (for
comparison after restart).
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path


def snapshot(pki_db: str | Path) -> list[dict]:
    """Return the current revocation state as a list of dicts."""
    conn = sqlite3.connect(f"file:{pki_db}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT serial, revoked, revoked_at, reason "
            "FROM certificates WHERE revoked = 1 ORDER BY serial"
        ).fetchall()
        return [
            {"serial": r[0], "revoked": r[1], "revoked_at": r[2], "reason": r[3]}
            for r in rows
        ]
    finally:
        conn.close()


def check(pki_db: str | Path, expected: list[dict]) -> tuple[bool, str]:
    """
    Verify that every entry in `expected` still matches the DB.
    Returns (ok, message).
    """
    conn = sqlite3.connect(f"file:{pki_db}?mode=ro", uri=True)
    try:
        actual_map: dict[int, dict] = {}
        for r in conn.execute(
            "SELECT serial, revoked, revoked_at, reason FROM certificates WHERE revoked = 1"
        ).fetchall():
            actual_map[r[0]] = {"serial": r[0], "revoked": r[1], "revoked_at": r[2], "reason": r[3]}
    finally:
        conn.close()

    failures: list[str] = []
    for exp in expected:
        serial = exp["serial"]
        if serial not in actual_map:
            failures.append(f"serial {serial} no longer revoked")
            continue
        act = actual_map[serial]
        if act["revoked_at"] != exp["revoked_at"]:
            failures.append(
                f"serial {serial}: revoked_at changed "
                f"({exp['revoked_at']} → {act['revoked_at']})"
            )
        if act["reason"] != exp["reason"]:
            failures.append(
                f"serial {serial}: reason changed "
                f"({exp['reason']} → {act['reason']})"
            )

    if failures:
        return False, "; ".join(failures[:5])
    return True, f"All {len(expected)} revoked cert(s) persisted correctly"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pki_db> [<snapshot_json>]")
        sys.exit(1)

    db = sys.argv[1]

    if len(sys.argv) == 2:
        # Print snapshot for comparison.
        data = snapshot(db)
        print(json.dumps(data, indent=2))
        sys.exit(0)

    expected = json.loads(Path(sys.argv[2]).read_text())
    ok, msg = check(db, expected)
    print("PASS" if ok else "FAIL", "—", msg)
    sys.exit(0 if ok else 1)
