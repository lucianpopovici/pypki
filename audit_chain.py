"""audit_chain.py — Hash-chained tamper-evident audit log.

Each audit row commits to its predecessor via SHA-256:

    this_hash = SHA-256(prev_hash_hex || canonical_row_bytes(ts, event, detail, ip))

Length-prefixed field encoding prevents the concatenation-ambiguity attack
("AB" || "C" ≠ "A" || "BC" when fields carry their byte-lengths).

Insertion serializes through advisory_lock("audit-chain") so two concurrent
writers can't both read the same prev_hash and produce a fork.

Public API
----------
    append(event, detail, ip, database)          Insert one chained row
    backfill_chain(database) -> int              Hash legacy rows in-place
    verify_chain(database, start_id, end_id)     Check integrity, return report
    export_chain(database, since, start_id, end_id) -> dict   Export segment
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
from typing import Optional

logger = logging.getLogger("pypki.audit_chain")

_ZERO_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Break:
    id: int
    kind: str  # "prev_hash_mismatch" | "this_hash_mismatch"
    expected: str
    found: str


@dataclasses.dataclass(frozen=True)
class VerificationReport:
    rows_checked: int
    breaks: list[Break]
    final_hash: str

    @property
    def ok(self) -> bool:
        return len(self.breaks) == 0


# ---------------------------------------------------------------------------
# Canonical serialization
# ---------------------------------------------------------------------------

def canonical_row_bytes(ts: str, event: str, detail: str, ip: str) -> bytes:
    """Deterministic, length-prefixed serialization of one audit row's fields.

    Field order: ts, event, detail, ip — matches the audit table column order.
    Each field is encoded as 8-byte big-endian length followed by UTF-8 bytes.
    NULL values are treated as empty string so the encoding is always defined.
    """
    parts: list[bytes] = [
        ts.encode(),
        event.encode(),
        (detail or "").encode(),
        (ip or "").encode(),
    ]
    return b"".join(len(p).to_bytes(8, "big") + p for p in parts)


# ---------------------------------------------------------------------------
# Append (the write path)
# ---------------------------------------------------------------------------

def append(event: str, detail: str, ip: str, database) -> None:
    """Insert one audit row with SHA-256 hash chaining.

    Acquires advisory_lock("audit-chain") to prevent split-chain races when
    multiple threads or processes write concurrently.
    """
    import datetime
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    with database.advisory_lock("audit-chain"):
        prev = database.fetchone(
            "SELECT this_hash FROM audit ORDER BY id DESC LIMIT 1"
        )
        prev_hash = prev["this_hash"] if (prev and prev["this_hash"]) else _ZERO_HASH

        row_bytes = canonical_row_bytes(ts, event, detail or "", ip or "")
        this_hash = hashlib.sha256(prev_hash.encode() + row_bytes).hexdigest()

        database.execute(
            "INSERT INTO audit(ts, event, detail, ip, prev_hash, this_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, event, detail, ip, prev_hash, this_hash),
        )


# ---------------------------------------------------------------------------
# Backfill (run once at startup after the 002_audit_chain migration)
# ---------------------------------------------------------------------------

def backfill_chain(database) -> int:
    """Compute and store hashes for pre-chain rows whose this_hash is NULL.

    Called by AuditLog.__init__() immediately after migrations are applied.
    Idempotent: rows already hashed are skipped; returns 0 if nothing to do.

    Backfill runs inside advisory_lock("audit-chain") so it doesn't race
    with an in-progress append from another thread.
    """
    with database.advisory_lock("audit-chain"):
        # Anchor: last row that already has a hash (partial prior backfill).
        tail = database.fetchone(
            "SELECT this_hash FROM audit WHERE this_hash IS NOT NULL "
            "ORDER BY id DESC LIMIT 1"
        )
        rows = database.fetchall(
            "SELECT id, ts, event, detail, ip FROM audit "
            "WHERE this_hash IS NULL ORDER BY id ASC"
        )
        if not rows:
            return 0

        prev_hash = tail["this_hash"] if tail else _ZERO_HASH

        for row in rows:
            row_bytes = canonical_row_bytes(
                row["ts"], row["event"],
                row["detail"] or "", row["ip"] or "",
            )
            this_hash = hashlib.sha256(prev_hash.encode() + row_bytes).hexdigest()
            database.execute(
                "UPDATE audit SET prev_hash = ?, this_hash = ? WHERE id = ?",
                (prev_hash, this_hash, row["id"]),
            )
            prev_hash = this_hash

    logger.info("audit_chain: backfilled %d row(s)", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_chain(
    database,
    start_id: int = 1,
    end_id: Optional[int] = None,
) -> VerificationReport:
    """Walk rows in insertion order and verify hash integrity.

    start_id=1, end_id=None → verify the entire chain.
    Subset verification resolves the anchor (row start_id-1) from the DB.

    A Break means one of:
      - the row was tampered with (content or hash field changed),
      - a row was deleted (the chain gap makes every successor fail), or
      - a concurrency bug inserted two rows with the same prev_hash.
    """
    rows = database.fetchall(
        "SELECT id, ts, event, detail, ip, prev_hash, this_hash "
        "FROM audit WHERE id >= ? AND (? IS NULL OR id <= ?) ORDER BY id ASC",
        (start_id, end_id, end_id),
    )

    if start_id == 1:
        expected_prev = _ZERO_HASH
    else:
        anchor = database.fetchone(
            "SELECT this_hash FROM audit WHERE id = ?", (start_id - 1,)
        )
        expected_prev = (
            anchor["this_hash"] if (anchor and anchor["this_hash"]) else _ZERO_HASH
        )

    breaks: list[Break] = []

    for row in rows:
        row_bytes = canonical_row_bytes(
            row["ts"], row["event"],
            row["detail"] or "", row["ip"] or "",
        )
        computed = hashlib.sha256(expected_prev.encode() + row_bytes).hexdigest()

        stored_prev = row["prev_hash"] or _ZERO_HASH
        stored_this = row["this_hash"] or ""

        if stored_prev != expected_prev:
            breaks.append(Break(
                id=row["id"], kind="prev_hash_mismatch",
                expected=expected_prev, found=stored_prev,
            ))
        if stored_this != computed:
            breaks.append(Break(
                id=row["id"], kind="this_hash_mismatch",
                expected=computed, found=stored_this,
            ))

        # Advance using the stored hash so downstream breaks are reported
        # individually rather than cascading from a single bad row.
        expected_prev = stored_this if stored_this else computed

    return VerificationReport(
        rows_checked=len(rows),
        breaks=breaks,
        final_hash=expected_prev,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_chain(
    database,
    since: Optional[str] = None,
    start_id: int = 1,
    end_id: Optional[int] = None,
) -> dict:
    """Export a chain segment as a JSON-serializable dict.

    ``since`` (ISO-8601 string) selects rows with ts >= since.
    ``start_id`` / ``end_id`` are an alternative numeric range.
    Both forms include the final_hash of the last included row so an
    operator can publish the hash to an external anchor (git, S3, etc.).
    """
    if since is not None:
        rows = database.fetchall(
            "SELECT id, ts, event, detail, ip, prev_hash, this_hash "
            "FROM audit WHERE ts >= ? ORDER BY id ASC",
            (since,),
        )
    else:
        rows = database.fetchall(
            "SELECT id, ts, event, detail, ip, prev_hash, this_hash "
            "FROM audit WHERE id >= ? AND (? IS NULL OR id <= ?) ORDER BY id ASC",
            (start_id, end_id, end_id),
        )

    final_hash = rows[-1]["this_hash"] if rows else _ZERO_HASH
    final_id = rows[-1]["id"] if rows else None
    return {
        "rows": [dict(r) for r in rows],
        "final_id": final_id,
        "final_hash": final_hash,
    }
