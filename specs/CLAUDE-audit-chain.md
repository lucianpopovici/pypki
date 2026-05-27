# CLAUDE-audit-chain.md — Hash-Chained Tamper-Evident Audit Log

Companion to `CLAUDE.md`. Follow all conventions there. Small, focused
change: ~200 LoC, no new deps, makes the existing `audit_log` table
tamper-evident by chaining each entry's hash to the previous one. Real
compliance value (WebTrust, SOC2, ISO 27001) for very little code.

---

## What this is

Today, `audit_log` records every issuance, revocation, config change,
and admin action. A determined attacker with DB write access can edit
or delete rows without leaving a trace. Hash-chaining each row makes
that detectable: editing row N invalidates the hash of every row N+1,
N+2, etc., and the verification CLI surfaces the break point.

This is tamper-*evident*, not tamper-*proof*. An attacker who has write
access can still corrupt the chain; we just guarantee the auditor will
notice. To go from evident to proof, the chain root must be published
to an external place (Git, CT-style log, etc.) — covered as a follow-up
in the open questions.

---

## Construction

Each row gets two new columns:

- `prev_hash` (TEXT, hex SHA-256): the `this_hash` of the previous row
  in insertion order (NULL or all-zero for the first row).
- `this_hash` (TEXT, hex SHA-256): `SHA-256(prev_hash || canonical_serialize(row))`.

Canonical serialization is deterministic: a fixed field order, JSON
with sorted keys for the `details_json` blob, ISO-8601 for any
date-like values. The serialization function lives in `audit_chain.py`
and is the single source of truth for "what bytes does row N hash."

Insertion always runs inside `advisory_lock("audit-chain")` so two
concurrent issuances can't both think they're appending after row N
and end up with two rows claiming `prev_hash = hash(N)`.

---

## Schema

```sql
-- db_migrations/pki/00X_audit_chain.sql
ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN this_hash TEXT;

CREATE INDEX idx_audit_log_this_hash ON audit_log(this_hash);

-- Migration: backfill existing rows. Order by id ASC, compute the chain
-- once at deploy time. Existing rows are immutable from this point;
-- the migration logs a single audit entry marking the seal point.
```

Backfill SQL lives in `db_migrations/pki/00X_audit_chain_backfill.py`
(Python-only migration since the hash computation is non-trivial in
SQL). Same migration runner pattern as the existing data migration
tooling described in `CLAUDE.md`'s migrations section.

Postgres: `ALTER TABLE ADD COLUMN` is online; backfill in batches of
10k to avoid long locks.

---

## Append path

```python
# audit_chain.py
def append(event_type: str, subject: str | None, serial: str | None,
           requester_ip: str | None, details: dict, db: Database) -> int:
    with db.advisory_lock("audit-chain"):
        prev = db.fetchone(
            "SELECT this_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        )
        prev_hash = prev["this_hash"] if prev else "0" * 64
        timestamp = int(time.time())
        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))

        row_bytes = canonical_row_bytes(
            timestamp, event_type, subject, serial, requester_ip, details_json
        )
        this_hash = hashlib.sha256(prev_hash.encode() + row_bytes).hexdigest()

        row_id = db.execute(
            """INSERT INTO audit_log
               (timestamp, event_type, subject, serial, requester_ip,
                details_json, prev_hash, this_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            (timestamp, event_type, subject, serial, requester_ip,
             details_json, prev_hash, this_hash)
        )["id"]

        return row_id

def canonical_row_bytes(timestamp, event_type, subject, serial,
                        requester_ip, details_json) -> bytes:
    # Fixed field order, length-prefixed each field to avoid ambiguity.
    parts = [
        str(timestamp).encode(),
        event_type.encode(),
        (subject or "").encode(),
        (serial or "").encode(),
        (requester_ip or "").encode(),
        details_json.encode(),
    ]
    return b"".join(len(p).to_bytes(8, "big") + p for p in parts)
```

Length-prefixing each field prevents the classic "A|BC vs AB|C produce
the same concat" attack. Mandatory.

The existing `AuditLog` class in `pki_server.py` becomes a thin wrapper
around `audit_chain.append`.

---

## Verification

```python
# audit_chain.py (cont.)
def verify_chain(db: Database, start_id: int = 1, end_id: int | None = None
                 ) -> VerificationReport:
    rows = db.fetchall(
        "SELECT * FROM audit_log WHERE id >= ? "
        "AND (? IS NULL OR id <= ?) ORDER BY id ASC",
        (start_id, end_id, end_id)
    )
    expected_prev = "0" * 64 if start_id == 1 else _expected_prev_for(start_id, db)
    breaks = []

    for row in rows:
        row_bytes = canonical_row_bytes(
            row["timestamp"], row["event_type"], row["subject"], row["serial"],
            row["requester_ip"], row["details_json"]
        )
        computed = hashlib.sha256(expected_prev.encode() + row_bytes).hexdigest()

        if row["prev_hash"] != expected_prev:
            breaks.append(Break(id=row["id"], kind="prev_hash_mismatch",
                                expected=expected_prev, found=row["prev_hash"]))
        if row["this_hash"] != computed:
            breaks.append(Break(id=row["id"], kind="this_hash_mismatch",
                                expected=computed, found=row["this_hash"]))

        expected_prev = row["this_hash"]

    return VerificationReport(rows_checked=len(rows), breaks=breaks,
                              final_hash=expected_prev)
```

A break means either (a) the row was tampered with, (b) a row was
deleted, or (c) two rows were inserted with the same `prev_hash` due to
a concurrency bug. All three are bad and surface the same way.

---

## CLI

```
pypki_admin.py audit-verify [--from-id N] [--to-id M] [--json]
```

Exit code 0 = chain intact; 2 = breaks detected. Print:

```
Verified rows 1..148273 in 4.3s
Chain intact.
Final hash: 7f3a...d4
```

Or on break:

```
Verified rows 1..148273 in 4.3s
CHAIN BROKEN at row 8821:
  prev_hash mismatch: expected 9c2a...41, found 5d11...8e
3 subsequent rows are unverifiable from this point.
```

`audit-export --since <iso>` exports the chain segment plus the final
hash so an operator can publish it to an external store (Git commit,
external log) for tamper-proofness.

`audit-seal` writes the current final hash to a configured external
location (file, S3, webhook URL). Operators wire this into cron for
periodic external anchoring.

---

## Implementation

### Files touched

| File                | Change                                                |
| ------------------- | ----------------------------------------------------- |
| `audit_chain.py`    | New module: append, verify, canonical serialization   |
| `pki_server.py`     | `AuditLog` calls `audit_chain.append`                 |
| `db_migrations/pki/00X_audit_chain.sql` | Schema additions          |
| `db_migrations/pki/00X_audit_chain_backfill.py` | Backfill script   |
| `db_migrations/acme/`, `db_migrations/scep/` | Apply same change to those audit tables (if separate) |
| `pypki_admin.py`    | `audit-verify`, `audit-export`, `audit-seal`          |
| `test_pki_server.py` | `TestAuditChainAppend`, `TestAuditChainVerify`, `TestAuditChainConcurrency` |
| `README.md`         | Audit section update                                  |
| `CHANGELOG.md`      | `### Added`, `### Security`                           |
| `docs/AUDIT.md`     | Verification runbook, seal-to-external setup          |

### Backwards compatibility

Rows written before the migration get `prev_hash = NULL` and `this_hash`
computed during backfill. The migration logs one special `chain_sealed`
event marking the cutover; verification from id 1 succeeds because the
backfill produced a self-consistent chain over the historical data.

A more rigorous deployment would refuse to seal historical data and
instead start the chain fresh at the migration. Document both options;
default to backfill because it lets operators prove the chain post-hoc
without losing history.

---

## CLI flags

```
--audit-chain-enabled true                  # default true once shipped
--audit-seal-target file:/var/lib/pypki/audit-seal.json
--audit-seal-target https://anchor.example.com/seal
--audit-seal-interval 3600                  # seconds between auto-seals
```

External seal payload (JSON):

```json
{
  "final_id": 148273,
  "final_hash": "7f3a...d4",
  "sealed_at": "2026-05-25T14:00:00Z",
  "sealed_by": "pypki-audit-seal/cron",
  "signature": "base64url(ECDSA-P256(sha256(payload_without_signature)))"
}
```

The seal is signed with the CA's dedicated audit-seal key (`ca/audit-seal/`
— generated at first seal). Operators publish the seal to a git repo,
S3 bucket, or external log; auditors fetch the latest seal and run
`audit-verify --to-id <final_id>` to confirm the chain matches.

---

## Tests

```
class TestAuditChainAppend(unittest.TestCase):
    def test_first_row_has_zero_prev_hash(self): ...
    def test_subsequent_rows_chain_correctly(self): ...
    def test_canonical_serialization_is_deterministic(self): ...
    def test_canonical_serialization_handles_null_fields(self): ...
    def test_canonical_serialization_handles_unicode(self): ...
    def test_details_json_sorted_keys(self): ...
    def test_length_prefix_prevents_concat_ambiguity(self): ...

class TestAuditChainVerify(unittest.TestCase):
    def test_intact_chain_passes(self): ...
    def test_modified_row_detected(self): ...
    def test_deleted_row_detected(self): ...
    def test_inserted_row_with_forged_hash_detected(self): ...
    def test_verify_subset_with_from_to(self): ...
    def test_first_break_reported_plus_downstream_count(self): ...

class TestAuditChainConcurrency(unittest.TestCase):
    def test_concurrent_appends_serialize(self): ...
    def test_advisory_lock_prevents_split_chain(self): ...
    def test_10k_concurrent_appends_chain_intact(self): ...

class TestAuditChainSeal(unittest.TestCase):
    def test_seal_payload_signed_correctly(self): ...
    def test_seal_to_file_target(self): ...
    def test_seal_to_https_target(self): ...
    def test_seal_failure_logged_and_retried(self): ...
    def test_external_verifier_can_check_seal_signature(self): ...

class TestAuditChainMigration(unittest.TestCase):
    def test_backfill_produces_intact_chain(self): ...
    def test_backfill_is_idempotent(self): ...
    def test_chain_sealed_event_recorded_at_cutover(self): ...
```

---

## Per-change checklist

- [ ] `audit_chain.py` — new module
- [ ] `pki_server.py` — `AuditLog` shim
- [ ] `db_migrations/pki/00X_audit_chain.sql` — schema
- [ ] `db_migrations/pki/00X_audit_chain_backfill.py` — backfill
- [ ] `pypki_admin.py` — `audit-verify`, `audit-export`, `audit-seal`
- [ ] `test_pki_server.py` — five new test classes
- [ ] `README.md` — audit-trail section update
- [ ] `CHANGELOG.md` — `### Added`, `### Security`
- [ ] `docs/AUDIT.md` — verification + external-anchoring runbook
- [ ] `pypki-flows.html` — audit chain illustration

Run `./run_tests.sh`. The 10k concurrent append test catches the most
likely real-world break (the advisory lock); don't skip it.

---

## Open questions

1. **Periodic re-verification cost**: `audit-verify` over a year of
   busy CA operations is ~10M rows. SHA-256 in Python does ~150 MB/s;
   each canonical row is ~200 bytes, so ~30 seconds per 10M rows.
   Fine for cron; not fine inline per request. Keep verification as
   an offline operation.

2. **Merkle tree vs linear chain**: a Merkle tree supports efficient
   proofs of inclusion for a subset of rows. A linear chain forces
   verifying everything from the last seal forward. For PyPKI's
   audit log volume the linear chain is fine; Merkle is overkill.
   Document the choice in `docs/AUDIT.md`.

3. **Public CT-style log**: the natural extension is to make the
   audit log itself a transparency log a la RFC 6962, append-only
   and publicly readable. Out of scope here. The seal mechanism is
   the bridge: a deployment that publishes seals to a git repo gets
   90% of the value with 5% of the effort.

4. **External time anchoring**: a tamper-proof timestamp on each seal
   (RFC 3161 against an external TSA, or a blockchain anchor) closes
   the "rewrite history and reseal" attack. PyPKI already has a TSA
   (`tsa_server.py`); use a *different* TSA for seal anchoring to
   avoid the operator being able to forge both. Document in
   `docs/AUDIT.md`; don't ship in v1.

5. **Multi-DB-backend chain**: when PyPKI uses separate Postgres
   instances for PKI / ACME / SCEP audit logs, each chain is
   independent. Acceptable — operators run `audit-verify --db acme`
   etc. Don't try to interleave chains across backends; the
   coordination cost outweighs the benefit.
