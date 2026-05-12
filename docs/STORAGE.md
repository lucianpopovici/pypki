# PyPKI Storage Backends

This document covers PyPKI's storage layer: the supported backends, when
to pick which, how to deploy each, and how to switch between them when
your needs change. The design contract is **optionality**: stay on
SQLite for as long as it suits, switch to Postgres in an afternoon when
it doesn't, and never have to rebuild your CA.

---

## Table of Contents

1. [The Three Deployment Shapes](#1-the-three-deployment-shapes)
2. [How PyPKI Stores State](#2-how-pypki-stores-state)
3. [Shape A — SQLite (Homelab, Single Node)](#3-shape-a--sqlite-homelab-single-node)
4. [Shape B — Single-Node Postgres](#4-shape-b--single-node-postgres)
5. [Shape C — HA Postgres (Multi-Node)](#5-shape-c--ha-postgres-multi-node)
6. [Switching Backends — SQLite → Postgres Runbook](#6-switching-backends--sqlite--postgres-runbook)
7. [Switching Backends — Postgres → SQLite](#7-switching-backends--postgres--sqlite)
8. [Backup and Recovery](#8-backup-and-recovery)
9. [Operational Notes](#9-operational-notes)

---

## 1. The Three Deployment Shapes

PyPKI fits cleanly into three storage shapes. Pick the smallest one that meets your durability and availability needs — there is no advantage to running heavier infrastructure than you need.

| Shape | Storage | Issuance rate | Failure tolerance | Backup model |
|---|---|---|---|---|
| **A. Homelab** | SQLite | Up to a few per second | Single-host failure = downtime | File copy + Litestream replication |
| **B. Single-node Postgres** | One Postgres server | Hundreds per second | Single-host failure = downtime | `pg_dump` / WAL archiving |
| **C. HA Postgres** | Postgres primary + replicas | Thousands per second | Survives primary loss | Streaming replication + WAL archive |

Picking up: **Shape A** is the right answer for almost every homelab and most small-business deployments. **Shape B** is the right answer when you outgrow SQLite's single-writer model — typically when you start running multiple PyPKI processes for HTTP throughput, not for cert volume. **Shape C** is the right answer when CA downtime materially hurts (regulated environments, internal services that gate ingress, ACME pipelines that block deploys).

---

## 2. How PyPKI Stores State

PyPKI keeps state in **four logical databases**, all stored under `<ca_dir>` (default `./ca`):

| File | Owner | Contents |
|---|---|---|
| `certificates.db` | `CertificateAuthority`, `IPsecHandler` | All issued certs, the serial counter, base CRLs, the CRL number counter, archived keys, IPsec pending requests |
| `audit.db` | `AuditLog` | Append-only audit trail (issuance, revocation, admin actions) |
| `acme.db` | `ACMEServer` | ACME accounts, orders, authorizations, challenges, RFC 8555 nonces |
| `scep.db` | `SCEPHandler` | SCEP transaction state |

Each logical database is independently configurable. By default they all live in the same `<ca_dir>` directory as separate SQLite files. Switching only the audit log to a shared Postgres instance (for example) is a one-flag operation.

**Why four files instead of one?** Two reasons. First, the four bodies of state are mostly independent — the cert DB is read by issuance, the audit DB is append-only, the ACME DB rotates short-lived rows. Second, it makes per-namespace backend choice cheap. You can audit-log to a centralized Postgres while keeping cert state on local SQLite, with no schema or code changes.

---

## 3. Shape A — SQLite (Homelab, Single Node)

This is the default. Nothing to install. Suitable for any deployment where **all of these are acceptable**:

- A single PyPKI process is enough for your throughput
- You can tolerate the CA being down during host outages
- Your backup strategy can rely on file-level snapshots

### Setup

```bash
# Just start it — SQLite files are created on first run.
pypki --ca-dir /var/lib/pypki/ca \
      --tls-cert-self-signed \
      --cmp-prefix /cmp \
      --acme-prefix /acme \
      --ocsp-prefix /ocsp
```

After first start, the directory contains:

```
/var/lib/pypki/ca/
├── ca.key                  # CA private key (passphrase-protected by default)
├── ca.crt                  # CA certificate
├── certificates.db         # Cert state, CRL, key archive, IPsec
├── audit.db                # Audit log
├── acme.db                 # ACME state
└── scep.db                 # SCEP state
```

### What Makes SQLite Work for This

- **WAL mode** (write-ahead logging) is enabled at startup. Readers don't block writers.
- **Foreign keys ON** and **synchronous = FULL** ensure durability against host crashes.
- **5-second busy timeout** lets concurrent threads queue politely on the writer lock instead of erroring out.
- **`BEGIN IMMEDIATE`** is used for the serial-number race window so two concurrent issuances cannot allocate the same serial.

### Why You Might Outgrow It

You'll know it's time to move when:

- You start needing **multiple PyPKI processes** behind a load balancer for HTTP throughput. SQLite has one writer at a time. With one PyPKI process this is invisible; with three, your tail latency for issuance starts climbing.
- You need **multi-host availability**. SQLite cannot be safely shared across hosts via NFS or similar. If host A dies, host B cannot pick up the cert state without manual intervention.
- Your **audit log retention requirements** make local files awkward (e.g., regulator wants centralized SIEM-friendly storage).

### Backup Strategy for Shape A

**Daily file-level backups** are the simplest workable strategy. Stop the PyPKI process briefly, copy `<ca_dir>` somewhere durable, restart. The SQLite WAL files are normally checkpointed at shutdown, so a clean copy is consistent.

For zero-downtime backups, use **Litestream** (https://litestream.io). It streams SQLite WAL frames to S3-compatible storage continuously and supports point-in-time recovery to any second within the retention window. Tested and recommended:

```toml
# /etc/litestream.yml
dbs:
  - path: /var/lib/pypki/ca/certificates.db
    replicas:
      - url: s3://pypki-backup/certs
  - path: /var/lib/pypki/ca/audit.db
    replicas:
      - url: s3://pypki-backup/audit
  - path: /var/lib/pypki/ca/acme.db
    replicas:
      - url: s3://pypki-backup/acme
  - path: /var/lib/pypki/ca/scep.db
    replicas:
      - url: s3://pypki-backup/scep
```

Restore from Litestream is `litestream restore -o <new_path> s3://...`. The CA private key (`ca.key`) is not in any database — back it up separately, e.g., to encrypted object storage with a different access policy than the DB backup.

---

## 4. Shape B — Single-Node Postgres

You run **one Postgres server** and point PyPKI at it via a `--db-url`-style flag per namespace. Use this when:

- You need multiple PyPKI processes for HTTP concurrency
- You want centralized backups under your existing Postgres operations
- You don't need HA, but you do need standardized DBA tooling

### Setup

```bash
# Provision the Postgres database
sudo -u postgres createdb pypki
sudo -u postgres psql -c "CREATE USER pypki WITH ENCRYPTED PASSWORD 'changeme';"
sudo -u postgres psql -c "GRANT ALL ON DATABASE pypki TO pypki;"

# Apply schema (the runner is idempotent; safe to re-run)
pypki migrate --pki-db-url postgresql://pypki:changeme@localhost/pypki
pypki migrate --audit-db-url postgresql://pypki:changeme@localhost/pypki
pypki migrate --acme-db-url postgresql://pypki:changeme@localhost/pypki
pypki migrate --scep-db-url postgresql://pypki:changeme@localhost/pypki

# Start PyPKI pointed at Postgres
pypki --ca-dir /var/lib/pypki/ca \
      --pki-db-url   postgresql://pypki:changeme@localhost/pypki \
      --audit-db-url postgresql://pypki:changeme@localhost/pypki \
      --acme-db-url  postgresql://pypki:changeme@localhost/pypki \
      --scep-db-url  postgresql://pypki:changeme@localhost/pypki \
      ...
```

> **Note on namespace flags.** As of the current PyPKI version, only `--audit-db-url` is fully wired through to the runtime. The other namespace URL flags (`--pki-db-url`, `--acme-db-url`, `--scep-db-url`) are part of the Tier 5.2 DAL refactor and ship progressively as each component is wired to the DAL. Until then, those namespaces remain on SQLite at `<ca_dir>/<ns>.db`. See `CLAUDE.md` §5.2 for the wiring schedule.

### Concurrency

PyPKI's serial-number allocation uses `pg_advisory_xact_lock` keyed on a stable BLAKE2b hash of `"serial-allocation"`. Multiple PyPKI processes can safely share the same Postgres database — the lock guarantees no two issuances ever pick the same serial. This is the same correctness guarantee the SQLite shape gets from `BEGIN IMMEDIATE`, just expressed differently.

The connection pool defaults are 2 minimum / 20 maximum per PyPKI process. At three PyPKI processes that's up to 60 Postgres connections. If your Postgres `max_connections` is the default 100, you have headroom; if you run more PyPKI processes or other applications on the same Postgres, raise `max_connections` accordingly.

### Backup Strategy for Shape B

Standard Postgres tooling. The CA cert is in the database; the CA private key is not. Back up both.

```bash
# Daily logical backup
pg_dump --format=custom --file=/backup/pypki-$(date +%Y%m%d).dump pypki

# Continuous WAL archiving for point-in-time recovery
# postgresql.conf:
#   archive_mode = on
#   archive_command = 'rsync %p backup-server:/wal/%f'
```

Restore is `pg_restore --create --dbname=postgres /backup/pypki-YYYYMMDD.dump`. After restore, run `pypki migrate ...` against the restored database to confirm schema integrity (it's a no-op if the dump was clean).

---

## 5. Shape C — HA Postgres (Multi-Node)

Two or more PyPKI processes on different hosts, all pointed at a Postgres cluster (primary + at least one synchronous replica). PyPKI itself is stateless except for a small in-memory cache of OCSP responses; **all durable state is in Postgres**.

This is the right shape when:

- CA downtime materially hurts. Examples: cert-manager-driven ingress that won't reissue without the CA up, ACME-driven infra that blocks deploys, regulated environments with availability SLAs.
- You already operate Postgres in HA and want PyPKI to ride along.

### Topology

```
                  ┌──────────────────────┐
                  │   Load balancer      │
                  │   (HAProxy/nginx)    │
                  └─────────┬────────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
        ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐
        │  PyPKI 1  │ │  PyPKI 2  │ │  PyPKI 3  │  Each pointed at the Postgres
        │           │ │           │ │           │  primary via --*-db-url.
        └─────┬─────┘ └─────┬─────┘ └─────┬─────┘  All three share the same
              │             │             │        ca.key, mounted read-only.
              └─────────────┼─────────────┘
                            │
                  ┌─────────▼─────────┐
                  │  Postgres primary │
                  │  + sync replicas  │
                  └───────────────────┘
```

**Critical:** All PyPKI processes must use **the same CA private key**. Every issuance is signed by `ca.key`. Mount it read-only from a shared secret store (Vault, Kubernetes secret, encrypted EFS, etc.); do not let multiple processes hold their own copies that could drift.

**OCSP signer keys** (separate from the CA key — see `docs/CPS.md` §6.1.4) are also shared across all PyPKI processes for the same reason.

### Cert Issuance Correctness Under Concurrent PyPKI Processes

The serial-number race is the only place where two concurrent issuances on different PyPKI processes could collide. PyPKI uses `pg_advisory_xact_lock(stable_hash("serial-allocation"))` so the second of two concurrent attempts blocks until the first commits. The lock is released automatically when the transaction ends. There is **no possibility of duplicate serial numbers** across the cluster.

The CRL number counter is protected the same way (`pg_advisory_xact_lock(stable_hash("crl-number-allocation"))`).

The audit log has no such requirement — it's append-only and ordering across processes is not semantically meaningful.

### Backup Strategy for Shape C

Treat PyPKI as a stateless application of your Postgres cluster. The cluster's existing backup, WAL archiving, and DR procedures cover it. Test restores periodically. Document the CA private key recovery path separately — the database backup does not contain the private key.

---

## 6. Switching Backends — SQLite → Postgres Runbook

This is the optionality contract: an existing PyPKI deployment running on SQLite can move to Postgres in **roughly an hour of downtime**, without rebuilding any certs.

### Pre-flight (no downtime)

1. **Stand up Postgres**, empty database.
   ```bash
   sudo -u postgres createdb pypki
   sudo -u postgres psql -c "CREATE USER pypki WITH ENCRYPTED PASSWORD '...';"
   sudo -u postgres psql -c "GRANT ALL ON DATABASE pypki TO pypki;"
   ```

2. **Apply the schema** to the empty Postgres database. The migration runner is idempotent.
   ```bash
   pypki migrate --db-url postgresql://pypki:...@localhost/pypki
   ```

3. **Verify schema versions match.** Both databases must be at the same migration version before data migration.
   ```bash
   pypki schema-version --db-url sqlite:///./ca/certificates.db
   pypki schema-version --db-url postgresql://pypki:...@localhost/pypki
   ```
   If versions differ, run `pypki migrate ...` against whichever is behind. The `migrate-data` tool refuses to run with version mismatch.

### Cutover (downtime starts here)

4. **Stop the PyPKI process.**
   ```bash
   systemctl stop pypki
   ```

5. **Copy the data.** This is the only step whose duration scales with deployment size.
   ```bash
   pypki migrate-data \
       --from sqlite:///./ca/certificates.db \
       --to   postgresql://pypki:...@localhost/pypki
   ```

   Expected duration:

   | Total rows | Step 5 duration |
   |---|---|
   | < 10k | seconds |
   | 10k — 100k | tens of seconds |
   | 100k — 1M | 1-3 minutes |
   | 1M — 10M | 10-30 minutes |

   Audit log dominates volume in mature deployments. If your audit log is huge (10M+ rows) and downtime is precious, you can pass `--audit-log-cutoff <unix_ts>` to bring over only recent audit rows and archive the older rows separately.

6. **Verify the migration**.
   ```bash
   pypki verify-migration \
       --src sqlite:///./ca/certificates.db \
       --dst postgresql://pypki:...@localhost/pypki
   ```

   This runs four checks:
   - Row counts per table match exactly
   - A random sample of rows is byte-identical between source and destination
   - Singletons in the meta table (`last_serial`, `crl_number`, `schema_version`) match exactly — drift here causes silent issuance bugs
   - Auto-increment sequences are positioned past `MAX(id)` so the next INSERT does not collide

   On any failure: **abort, restart with the old `--db-url`**, investigate. Do not ship a partial migration.

### Restart on the new backend (downtime ends)

7. **Update the systemd unit** to point at Postgres.
   ```bash
   systemctl edit pypki   # change --ca-dir and --db-url args
   systemctl start pypki
   ```

   At this moment all CMP, ACME, EST, SCEP, OCSP, and REST endpoints come back online against the new backend. The CA cert is unchanged, the CA private key is unchanged, all issued certs are still valid, all CRLs still verify. **Clients see zero disruption beyond the restart window.**

### Post-cutover

8. **Keep the SQLite database read-only for at least a week.**
   ```bash
   chmod 0400 ./ca/certificates.db ./ca/audit.db ./ca/acme.db ./ca/scep.db
   mv ./ca/*.db ./ca/pre-postgres-$(date +%Y%m%d)/
   ```

   The rollback window is the time between step 7 (restart) and discovering a problem. Cutting any new write to Postgres means losing it on rollback; the operator decides whether to accept that loss or reconcile manually. After a week of green operation on Postgres, delete the archived SQLite files.

### Rollback

If something goes wrong post-migration and the SQLite files still exist:

```bash
systemctl stop pypki
systemctl edit pypki    # revert --db-url to sqlite://...
systemctl start pypki
```

This works **only if no new writes have hit Postgres since cutover that you cannot afford to lose**. Audit-log writes that happened in the rollback window will be lost; certs issued in that window will work (the cert itself is signed and lives outside the database) but won't appear in the SQLite cert table, breaking revocation lookup. For a clean rollback, plan it within the first few minutes after cutover, before issuance traffic resumes.

---

## 7. Switching Backends — Postgres → SQLite

Less common, but supported. Use the same `migrate-data` tool with reversed `--from` / `--to`:

```bash
systemctl stop pypki
pypki migrate-data \
    --from postgresql://pypki:...@localhost/pypki \
    --to   sqlite:///./ca/certificates.db
pypki verify-migration \
    --src postgresql://pypki:...@localhost/pypki \
    --dst sqlite:///./ca/certificates.db
systemctl edit pypki    # update --db-url to sqlite path
systemctl start pypki
```

Caveat: if your Postgres deployment had multiple PyPKI processes writing concurrently, going back to SQLite means accepting the single-writer constraint. Plan for a load reduction or process consolidation before the cutover.

---

## 8. Backup and Recovery

| What | Where | Backup model | Restore |
|---|---|---|---|
| **CA private key** | `<ca_dir>/ca.key` | Encrypted, off-host, separate access policy from DB backups | Copy back, type the passphrase |
| **CA certificate** | `<ca_dir>/ca.crt` AND inside `certificates.db` | Trivially regenerable from the key, but back it up anyway for fast recovery | Copy back |
| **Cert state** | `certificates.db` (SQLite) or Postgres `certificates`, `serial_counter`, `crl_base`, `crl_number`, `key_archive` tables | File copy / Litestream / pg_dump | Standard restore |
| **Audit log** | `audit.db` or Postgres `audit` table | File copy / Litestream / pg_dump | Append-only — restore creates new rows correctly |
| **ACME state** | `acme.db` or Postgres `acme_*` tables | File copy / Litestream / pg_dump | Restore. Live ACME orders may need to retry; this is normal |
| **SCEP state** | `scep.db` or Postgres `scep_transactions` | Same | Restore; pending transactions retry |
| **OCSP signing key** | `<ca_dir>/ocsp_signer.key` | Encrypted, off-host | Copy back |

The CA private key is the only piece of state whose loss is unrecoverable. **If `ca.key` is gone, the only path forward is to stand up a new CA**: every issued certificate becomes unrevokable garbage, and every relying party must be repointed at the new CA's root. Treat `ca.key` backup as a different operational concern than database backup — different access policies, different storage, periodic test-restores.

---

## 9. Operational Notes

### Schema migrations

PyPKI ships SQL migration files under `db_migrations/<namespace>/NNN_<description>.sql`. Each PyPKI startup applies any not-yet-applied migrations to its target database. The runner is idempotent and transactional — failed migrations roll back cleanly.

The `schema_migrations` bookkeeping table records what's been applied. Inspect it with:

```sql
SELECT version, name, applied_at
FROM schema_migrations
ORDER BY version;
```

### When `pypki migrate` should be run

- Always after upgrading PyPKI binaries (in case the new version ships new migrations).
- Once during initial deployment of Shape B or Shape C.
- Once before `migrate-data` in the SQLite → Postgres switchover.
- Never automatically at runtime if you don't want it to — the runtime code calls it on each startup, but CI/CD pipelines that prefer explicit migration steps can pass `--no-auto-migrate` (when supported) and run `pypki migrate` as a separate phase.

### Read-only verification

A useful operational pattern: a long-running `pypki verify-migration` job that checks SQLite (the durable archive copy) against Postgres (the live system) periodically, flagging drift. Especially useful in the rollback-window week after a switchover. Drift between the two means **either the rollback archive is stale (expected) or the production data has been corrupted (alarm)**.

---

## See also

- `docs/CPS.md` §6.5 — operational requirements (key generation, archive)
- `docs/THREAT_MODEL.md` §1 — what's in the TCB and what isn't
- `docs/DEPLOYMENT/homelab-single-node.md` — concrete Shape A walkthrough
- `CLAUDE.md` §5.2 — the engineering spec for the DAL refactor and migration tool
