# CLAUDE-backup-restore.md — Backup, Restore, and Disaster Recovery

Companion to `CLAUDE.md`. Follow all conventions there. Adds scheduled
encrypted backups, scripted restore, Shamir's Secret Sharing for the
offline root, and runbooks for the three real disaster scenarios.
Mostly new code (~1500 LoC) plus operational documentation.

---

## What this is

PyPKI today has no first-class backup story. Operators do file-level
copies of the SQLite DB and CA key files and hope nothing went wrong.
That's adequate for homelab; it's insufficient for any deployment where
losing the CA key means re-bootstrapping trust across the fleet.

This spec covers four threads:

1. **Encrypted, scheduled, integrity-verified backups** of DB + keys + config.
2. **Scripted, idempotent restore** that operators can drill in CI.
3. **Shamir's Secret Sharing for the offline root key**, replacing the
   single-passphrase model.
4. **Runbooks for three disaster scenarios**: leaf compromise,
   DB compromise, CA-key compromise.

---

## Backup format

A backup is a single tarball (`pypki-backup-<ts>.tar.zst` if zstd is
available, `.tar.gz` otherwise) with a fixed layout:

```
manifest.json                  # versioning, file hashes, signing identity
db/                            # one file per logical DB (pki, acme, scep, est)
  pki.sql.zst                  # SQL dump, deterministic ordering
  acme.sql.zst
  scep.sql.zst
keys/                          # CA private keys (already passphrase-encrypted
                               #   per existing key storage), plus a per-backup
                               #   wrapping layer
  root-2026.pem.age            # age-encrypted to the backup recipient
  intermediate-internal.pem.age
config/
  config.yaml                  # PyPKI runtime config
  policy.yaml                  # if policy engine enabled
audit-seal.json                # latest audit-chain seal at backup time
signature                      # detached signature over manifest.json
```

`manifest.json`:

```json
{
  "format_version": 1,
  "created_at": "2026-05-25T03:00:00Z",
  "created_by": "pypki-backup/cron",
  "instance_id": "pki.example.com",
  "files": {
    "db/pki.sql.zst": {"sha256": "...", "size": 12345678},
    ...
  },
  "audit_seal": {"final_id": 148273, "final_hash": "..."},
  "key_recipient_fingerprints": ["sha256:abc...", "sha256:def..."],
  "next_backup_estimated": "2026-05-26T03:00:00Z"
}
```

The signature is over the canonical-JSON-encoded manifest; any change
to any file changes a hash in `manifest.json` which changes the
signature.

---

## Encryption design

Two layers, deliberately separable:

**Layer 1 — bulk encryption** of the whole tarball:

- Symmetric key from a passphrase via `scrypt` (N=2^17, r=8, p=1) — same
  parameters as the rest of the codebase, RFC 7914.
- AES-256-GCM with random nonce.
- Or a public-key recipient via age-style X25519 KEM (operator preference).

**Layer 2 — per-key wrapping** of CA keys before they go into the tarball:

- Each CA private key is age-encrypted to one or more recipients
  configured at backup time (`--backup-key-recipient age1xyz...`).
- Multiple recipients = m-of-1 (any one can decrypt). For m-of-n,
  Shamir splits the symmetric key (next section).

This separation lets you give "DB-only" backups to one team (analysts,
auditors) and "full" backups including keys to a different team
(security officers). Routine restore drills use DB-only; key recovery
is a separate ceremony.

---

## Shamir's Secret Sharing for the offline root

The offline root is the highest-stakes key in any PKI. Today it's
protected by a single passphrase held by one human — single point of
failure on both sides (lost passphrase = lost CA; compromised
passphrase = compromised CA).

Replace with m-of-n Shamir splitting over GF(256):

- Operator chooses `m, n` at root generation (`pypki_admin.py
  ca-init --root --shamir 3-of-5`).
- The 32-byte symmetric key wrapping the root private key gets split
  into 5 shares; any 3 reconstitute the key.
- Each share is printed in a QR-code + paper-mnemonic format
  (BIP-39-style 24-word) for hand-distribution to share-holders.
- Shares never touch disk on the issuing machine; the operator hands
  out QR codes during the ceremony and zeroizes the originals.
- Recovery: any 3 share-holders bring their cards to a clean machine
  running `pypki_admin.py ca-recover --shamir`; the tool reconstructs
  the key in memory, uses it for one operation, and zeroizes.

Implementation: ~150 LoC of GF(256) Lagrange interpolation in
`shamir.py`. Pure stdlib, no deps. Test vectors from NIST.

Mnemonic encoding: SLIP-0039 if a high-quality stdlib-only implementation
fits; otherwise a simple BIP-39-style with the standard English wordlist
shipped in the repo. SLIP-0039 is purpose-built for Shamir shares and
includes checksums; the engineering effort to implement it correctly is
non-trivial. Decide based on whether a clean implementation lands in
budget.

---

## Backup schedule and targets

Targets configured via `--backup-target` URI:

- `file:///var/lib/pypki/backups/`
- `s3://bucket-name/prefix/` (uses `auth_aws.py` from cloud-KMS work)
- `gs://bucket-name/prefix/`
- `https://example.com/backups/` (operator-provided endpoint accepting PUT)

Multiple targets allowed (each backup uploaded to all). Failure on any
one logs an error but doesn't fail the others — partial backups are
better than no backup.

Retention via `--backup-retention <count>` and/or `--backup-retention-days
<days>`. Old backups deleted by `pypki-backup` during the next cycle;
remote targets need explicit lifecycle policies on the operator's
storage (PyPKI doesn't manage cloud retention).

Schedule via cron / systemd timer — PyPKI provides the executable, the
operator handles scheduling. Example systemd timer in `docs/BACKUP.md`.

---

## Restore

`pypki_admin.py restore --from <tarball> --to <dir> [--db-only] [--keys-only] [--dry-run]`

Steps:

1. Verify manifest signature against configured trust store.
2. Verify every file's hash against the manifest.
3. Decrypt outer layer (passphrase or age key).
4. Optionally decrypt key layer (separate recipients).
5. Stage to `--to <dir>`; never overwrite a running PyPKI's live
   directory. Operator points the new PyPKI at the staged dir.

`--dry-run` does (1)–(2) and reports without writing anything.
Drill-ability is the whole point: operators run this in CI against
a recent backup nightly.

Selective restore for the "leaf compromise" scenario: restore only
specific tables (e.g. `certificates` and `revocations`) without
clobbering `audit_log` continuity. Implemented as a `--tables
<list>` flag with explicit allowlist of safe-to-replace tables.

---

## Disaster runbooks

### Scenario 1: leaf compromise (one or many)

Trigger: someone exfiltrates a leaf cert's private key, or a class of
leaves needs reissuance (e.g. CA/Browser Forum incident).

Response (no backup needed; documented for completeness):

1. Identify affected certs by SQL query against `certificates`.
2. Mass-revoke via `pypki_admin.py revoke-batch --serial-file
   <list> --reason key_compromise`.
3. Shorten ARI windows for affected certs: `pypki_admin.py
   ari-bulk-shorten --filter <sql>` (from CLAUDE-ari.md).
4. Audit-log automatically records the batch.
5. CRL and OCSP responder refresh on next cycle (or trigger manually).

Mean time to remediation: minutes, given a populated ARI table and
fleet running ARI-capable clients.

### Scenario 2: DB compromise / corruption

Trigger: SQLite file corruption, accidental DROP TABLE, schema
migration failure, ransomware.

Response:

1. Stop PyPKI: `systemctl stop pypki`.
2. Restore latest backup to staging dir: `pypki_admin.py restore
   --from <latest> --to /var/lib/pypki-staging`.
3. Verify audit chain: `pypki_admin.py audit-verify` against the
   restored DB; confirm the final hash matches the audit-seal in the
   backup manifest.
4. Promote staging to live (atomic mv of directories).
5. Start PyPKI: `systemctl start pypki`.
6. Reconcile: any certs issued between last backup and the incident
   are gone. Audit log records the gap. Decide per profile whether
   to actively reissue (TLS server certs that clients depend on)
   or wait for renewal (short-lived certs).

Mean time to remediation: ~30 minutes with rehearsed runbook.

### Scenario 3: CA-key compromise

Trigger: signs of HSM/KMS access by unauthorized identity, exfiltrated
encrypted key file, share-holder compromise.

Response (the worst day; document thoroughly):

1. Halt issuance: `pypki_admin.py emergency-stop --reason
   ca_key_compromise`.
2. Generate replacement intermediate from the offline root (Shamir
   recovery ceremony if applicable).
3. Cross-sign the replacement with the compromised intermediate so
   relying parties don't see a discontinuity — or, if the compromise
   is severe enough, skip cross-signing and accept the trust break.
4. Issue replacement leaves under the new intermediate. ACME clients
   re-enroll on next polling cycle; non-ACME endpoints need manual
   re-enrollment.
5. Revoke the compromised intermediate and put its serial in the
   root's CRL.
6. CT logs: file an incident report if this CA chains to a publicly
   trusted root.

Mean time to remediation: hours to days. The Shamir ceremony itself
is the long pole.

`docs/DR.md` carries the full runbook with operator commands, decision
trees, and post-incident reviews.

---

## Implementation

### Files touched

| File             | Change                                                  |
| ---------------- | ------------------------------------------------------- |
| `backup.py`      | New module: snapshot, encrypt, package, upload           |
| `restore.py`     | New module: verify, decrypt, stage                      |
| `shamir.py`      | New module: GF(256) SSS                                 |
| `mnemonic.py`    | New module: BIP-39-style encoding (or SLIP-0039)        |
| `ceremony.py`    | Extended for Shamir flow                                |
| `pypki_admin.py` | `backup-now`, `restore`, `restore --dry-run`,           |
|                  | `ca-init --shamir m-of-n`, `ca-recover --shamir`,       |
|                  | `emergency-stop`, `revoke-batch`                        |
| `pki_server.py`  | Emergency-stop state, audit events                      |
| `db_migrations/pki/00X_dr.sql` | Backup registry, restore log         |
| `test_pki_server.py` | `TestBackup`, `TestRestore`, `TestShamir`, `TestDR` |
| `README.md`      | Backup + DR section                                     |
| `CHANGELOG.md`   | `### Added`, `### Security`                             |
| `docs/BACKUP.md` | Setup, schedule, targets                                |
| `docs/DR.md`     | Three disaster runbooks                                 |
| `docs/CEREMONY.md` | Shamir ceremony script                                |

### Schema

```sql
-- db_migrations/pki/00X_dr.sql
CREATE TABLE backups (
    id              {{auto_pk}},
    created_at      INTEGER NOT NULL,
    manifest_hash   TEXT NOT NULL,
    target_uri      TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    upload_duration_ms INTEGER NOT NULL,
    upload_status   TEXT NOT NULL,           -- 'success' | 'partial' | 'failed'
    audit_final_id  INTEGER NOT NULL,
    audit_final_hash TEXT NOT NULL
);

CREATE TABLE restore_events (
    id              {{auto_pk}},
    started_at      INTEGER NOT NULL,
    completed_at    INTEGER,
    manifest_hash   TEXT NOT NULL,
    dry_run         INTEGER NOT NULL,
    initiator       TEXT NOT NULL,
    selective_tables TEXT,                   -- JSON array if partial
    outcome         TEXT                     -- 'ok' | 'failed' | 'aborted'
);

CREATE TABLE emergency_state (
    state           TEXT PRIMARY KEY,        -- one row, always 'global'
    halted          INTEGER NOT NULL DEFAULT 0,
    halt_reason     TEXT,
    halted_at       INTEGER,
    halted_by       TEXT
);
INSERT INTO emergency_state (state, halted) VALUES ('global', 0);
```

---

## CLI flags

```
--backup-enabled true
--backup-target file:///var/lib/pypki/backups/
--backup-target s3://my-bucket/pypki/
--backup-passphrase-file /etc/pypki/backup.passphrase
--backup-key-recipient age1xyz...                # one or more
--backup-retention-count 30
--backup-retention-days 90
--backup-compression zstd|gzip|none

--shamir-shares 5
--shamir-threshold 3
```

---

## Tests

```
class TestBackup(unittest.TestCase):
    def test_tarball_layout_matches_spec(self): ...
    def test_manifest_hashes_every_file(self): ...
    def test_signature_over_manifest_verifies(self): ...
    def test_passphrase_encryption_round_trip(self): ...
    def test_age_recipient_encryption_round_trip(self): ...
    def test_multiple_recipients_any_can_decrypt(self): ...
    def test_multiple_targets_partial_failure_is_logged(self): ...
    def test_retention_deletes_oldest_first(self): ...

class TestRestore(unittest.TestCase):
    def test_dry_run_makes_no_changes(self): ...
    def test_tampered_file_detected_via_hash(self): ...
    def test_tampered_manifest_detected_via_signature(self): ...
    def test_db_only_restore_skips_keys(self): ...
    def test_keys_only_restore_skips_db(self): ...
    def test_selective_table_restore_preserves_audit_log(self): ...
    def test_audit_chain_intact_after_restore(self): ...
    def test_restore_records_event(self): ...

class TestShamir(unittest.TestCase):
    def test_split_and_reconstruct_round_trip(self): ...
    def test_threshold_minus_one_shares_insufficient(self): ...
    def test_any_threshold_subset_reconstructs(self): ...
    def test_nist_test_vectors(self): ...
    def test_mnemonic_round_trip(self): ...
    def test_share_corruption_detected(self): ...

class TestDR(unittest.TestCase):
    def test_emergency_stop_blocks_new_issuance(self): ...
    def test_emergency_stop_does_not_block_revocation(self): ...
    def test_revoke_batch_handles_10k_certs(self): ...
    def test_full_restore_drill_end_to_end(self): ...      # integration
```

The end-to-end restore drill is non-negotiable in CI. It exercises the
full path: take a backup, wipe state, restore, verify audit chain,
issue a fresh cert, confirm it chains to the restored CA. If this test
isn't green, the project has no backup story.

---

## Per-change checklist

- [ ] `backup.py`, `restore.py`, `shamir.py`, `mnemonic.py` — new modules
- [ ] `ceremony.py` — Shamir extension
- [ ] `pypki_admin.py` — new subcommands
- [ ] `pki_server.py` — emergency-stop gate, audit events
- [ ] `db_migrations/pki/00X_dr.sql` — schema
- [ ] `test_pki_server.py` — four new test classes
- [ ] `README.md` — Backup + DR section
- [ ] `CHANGELOG.md` — `### Added`, `### Security`
- [ ] `docs/BACKUP.md`, `docs/DR.md`, `docs/CEREMONY.md` — runbooks
- [ ] `pypki-flows.html` — backup/restore/Shamir flows
- [ ] `.github/workflows/restore-drill.yml` — nightly CI restore test

Run `./run_tests.sh`. The restore drill workflow runs nightly on a
clean container.

---

## Open questions

1. **age vs custom encryption**: `age` (the format and tool) is the
   sensible default for key encryption to recipients. Implementing the
   age format in pure stdlib is ~400 LoC. Alternative: ship our own
   format. Recommend implementing age — it's a stable, audited format
   and operators may already have age keys.

2. **zstd availability**: Python 3.14+ has `compression.zstd` in
   stdlib; earlier versions need the `zstandard` pip package. Detect at
   import time and fall back to gzip. Document the size difference
   (~3× smaller with zstd on SQL dumps).

3. **Hot-DB consistency**: SQLite backups during writes need `VACUUM
   INTO` or `.dump` to get a consistent snapshot. Postgres uses
   `pg_dump --serializable-deferrable`. Both supported; the backup
   tool picks based on `--db-backend`.

4. **Cloud-KMS-backed roots and Shamir**: if the root key is in cloud
   KMS, Shamir doesn't apply (KMS controls the key). Document that
   `--shamir` and `--ca-key-backend aws-kms` are mutually exclusive
   for the same CA, and offer the matrix: offline file-backed root +
   Shamir + online cloud-KMS intermediates is the recommended pattern.

5. **Backup verification cadence**: configurable, default daily. A
   verified backup is one that passed dry-run restore + audit-chain
   verification. Surface `pypki_backup_last_verified_at` metric so
   ops dashboards can alert on stale verification.
