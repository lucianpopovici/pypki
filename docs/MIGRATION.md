# PyPKI Migration Guide

> Last reviewed: 2026-06-01 (commit 453e7ba)

This document covers data and configuration migrations for PyPKI deployments. It will grow as features ship; today it covers:

1. [SQLite → PostgreSQL backend migration](#1-sqlite--postgresql-backend-migration)
2. [Upgrading to a new PyPKI version](#2-upgrading-to-a-new-pypki-version)

Future sections will cover CA cert renewal, sub-CA rollover, and offline-root-online-subca migration when those tools ship.

---

## 1. SQLite → PostgreSQL backend migration

You'll want this when your single-node SQLite deployment outgrows itself: multiple PyPKI nodes for HA, regulated environments that require Postgres for audit, or operational reasons (existing Postgres infrastructure, point-in-time recovery, etc.).

PyPKI is designed to make this an afternoon's work, not a multi-week project. The schema decisions in `db.py` and the migration runner in `migrations.py` were made specifically so that the data is portable as-is.

### Status

**Status:** ✅ Tooling shipped (`pypki_admin.py migrate-data` and `pypki_admin.py verify-migration`).

The full specification is in [CLAUDE.md](../CLAUDE.md) under "SQLite → Postgres data migration." The implementation lives in `migration.py` (the migration core) and `pypki_admin.py` (the operator CLI), with end-to-end tests in `test_migration.py`.

### What's covered

The shipped tool handles all four of PyPKI's logical databases (`pki`, `audit`, `acme`, `scep`):

- **All canonical tables copied** with `INSERT ... ON CONFLICT (pk) DO UPDATE` semantics so re-runs are idempotent and seeded singletons (`serial_counter` id=1, `crl_number` id=1) are correctly overwritten with source values rather than producing PK conflicts.
- **Ephemeral tables skipped** — `acme.nonces` is regenerated within seconds and carrying it across is meaningless.
- **`schema_migrations` not copied** — the destination has its own.
- **Auto-PK sequence resync** for `audit.audit` and `pki.crl_base` after migration so the next `INSERT` on Postgres doesn't collide with a migrated row's id.
- **Schema version gate** — refuses to run if source and destination are at different migration versions, with a clear error pointing at `pypki migrate`.
- **Verification step** — checks row counts, byte-identical random samples, schema version match, and Postgres sequence safety. Exit code 3 = drift detected, do not cut over.

### Runbook

```bash
# 1. Stand up Postgres, empty DB
$ createdb pypki_pki && createdb pypki_audit && createdb pypki_acme && createdb pypki_scep

# 2. Apply schema to each destination DB
$ for ns in pki audit acme scep; do
    python pki_server.py --db-url "postgresql:///pypki_$ns" --migrate-only
  done

# 3. Verify schema versions match (source = SQLite at ./ca, dst = Postgres)
$ python pypki_admin.py verify-migration \
    --from-ca-dir ./ca \
    --to-db-url-tmpl 'postgresql:///pypki_{namespace}' \
    --sample 10
# (may report row-count mismatches — that's expected at this point;
# the schema-version check is what we care about pre-cutover)

# 4. STOP PyPKI — downtime begins
$ systemctl stop pypki

# 5. Run the data migration
$ python pypki_admin.py migrate-data \
    --from-ca-dir ./ca \
    --to-db-url-tmpl 'postgresql:///pypki_{namespace}' \
    --yes

# 6. Verify the result. Exit code 0 = safe to cut over.
$ python pypki_admin.py verify-migration \
    --from-ca-dir ./ca \
    --to-db-url-tmpl 'postgresql:///pypki_{namespace}'

# 7. Restart PyPKI with the new --db-url. Downtime ends.
$ systemctl edit pypki   # change --db-url
$ systemctl start pypki

# 8. Archive the SQLite DB read-only for a week before deletion.
$ chmod -R 0444 ./ca/*.db
```

Expected duration of step 5 scales with row count: seconds for <10k rows, ~3 minutes for 1M rows, ~30 minutes for 10M rows. Audit log dominates volume in mature deployments.

### Why downtime is required

PyPKI does not support dual-write or lazy migration. Reasons:

- Serial number allocation is monotonic and persisted in the source-of-truth DB. A dual-write window would risk double-allocation if either side wrote and then crashed.
- CRL number is similarly monotonic. A lost CRL number bump means relying parties see CRL number "go backward" and reject the new CRL.
- ACME nonces and CMP transaction IDs are short-lived; migrating them mid-flight is meaningless.

The tradeoff (a few minutes of downtime instead of complex dual-write code) is the right call for PyPKI's deployment scale. Operators with strict no-downtime requirements should either:
- Schedule the migration during a planned maintenance window, OR
- Run two PyPKI deployments side-by-side under a load balancer, migrate one, switch traffic, then migrate the second

### Rollback

If verify-migration fails or post-cutover you discover an issue, rollback to SQLite is possible **only if no new writes have hit Postgres since the cutover.** Stop the service, change `--db-url` back to SQLite, restart. Any writes that did go to Postgres are lost on rollback.

This is why step 8 (archive the SQLite DB read-only) matters. For at least a week after migration, treat the SQLite copy as the rollback path.

---

## 2. Upgrading to a new PyPKI version

PyPKI is under active development. Read the CHANGELOG before every upgrade.

### Standard procedure

```bash
# 1. Backup
sudo systemctl stop pypki
sudo tar czf /backup/pypki-pre-upgrade-$(date +%Y%m%d).tar.gz /var/lib/pypki/

# 2. Read CHANGELOG for the version you're upgrading TO. Pay attention
#    to entries under "### Security" and "### Breaking" — these may
#    require operator action.
$EDITOR /opt/pypki/CHANGELOG.md

# 3. Replace the source. (Adjust paths to your install layout.)
sudo cp -r /opt/pypki /opt/pypki.old.$(date +%Y%m%d)
sudo cp -r path/to/new/pypki-main/* /opt/pypki/

# 4. Re-install Python deps (in case requirements.txt changed)
sudo python3 -m pip install -r /opt/pypki/requirements.txt --upgrade

# 5. Run the test suite against your DB to catch upgrade-time issues.
#    This applies pending migrations as a side effect of test setup.
sudo -u pypki python3 -m pytest /opt/pypki/test_db.py /opt/pypki/test_migrations.py -v

# 6. Start the service. The migration runner will apply any pending
#    schema migrations on first start (idempotent if already applied).
sudo systemctl start pypki
sudo systemctl status pypki

# 7. Smoke test
curl https://pki.home.arpa/healthz
curl https://pki.home.arpa/ca.crt | openssl x509 -noout -subject

# 8. Watch logs for errors over the next ~10 minutes.
sudo journalctl -fu pypki
```

### What can go wrong

**Schema migration fails on startup**

Most likely: a previous deployment manually ALTERed a table. Open `journalctl -u pypki`, look for the migration error, fix the conflict by hand (drop the manually-added column, etc.), then restart. The migration runner is idempotent — once it applies, future starts are unaffected.

**Existing certs become unreadable / unparseable**

This should never happen. If it does, restore from backup and file an issue with the exact certificate that failed.

**Audit log entries from before the upgrade no longer appear in the Web UI**

The audit log schema has not changed across PyPKI versions; entries should remain visible. If they don't, check that the AuditLog DB still exists at `<ca_dir>/audit.db` and is readable by the pypki user.

**The CA private key fails to decrypt**

The CA passphrase format has not changed. If you genuinely cannot decrypt:
- Check that `PYPKI_CA_PASSPHRASE` is set in the service environment (not just your shell)
- Verify the passphrase against the SAME PyPKI version: `python3 -c 'from cryptography.hazmat.primitives.serialization import load_pem_private_key; load_pem_private_key(open("/var/lib/pypki/ca/ca.key","rb").read(), b"YOUR_PASSPHRASE")'`
- If still failing, restore from backup

### Downgrade

PyPKI does not support downgrade. Once a schema migration has applied, the older code may not understand the schema. If a release ships a regression, the path is: report it, wait for a fix, restore from backup if necessary.

---

## 3. CA private key compromise migration (emergency procedure)

This is **not** a normal migration; it's an emergency response. Documented here for completeness.

If you suspect or confirm that the CA private key has been compromised, see [THREAT_MODEL.md §3.3](THREAT_MODEL.md#33-ca-private-key-compromise) for the full procedure. Brief summary:

1. Take the CA offline IMMEDIATELY
2. Notify subscribers and relying parties out-of-band
3. Stand up a new CA with a new key pair (different `<ca_dir>`)
4. Distribute the new CA cert to relying parties
5. Re-issue subscriber certs from the new CA
6. Publish a final advisory CRL from the old CA revoking everything

This is a process gap in PyPKI today — there is no automated tooling to handle it. Operators MUST have a written runbook prepared in advance. **Do not attempt to invent the procedure during the incident.**

---

## References

- [CPS.md](CPS.md) — Certification Practice Statement
- [THREAT_MODEL.md](THREAT_MODEL.md) — adversary model and per-component compromise scenarios
- [COMPATIBILITY.md](COMPATIBILITY.md) — version compatibility matrix
- [CLAUDE.md](../CLAUDE.md) (developer doc) — full specification of migration tooling
