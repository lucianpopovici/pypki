# CLAUDE-db-bootstrap.md — Database Bootstrap Automation

Companion to `CLAUDE.md`. Follow all conventions there. Closes the
gap between "Postgres exists" and "PyPKI can use Postgres safely."
A single idempotent command that creates the DB, role, grants,
extensions, and connection-pool config — and a parallel path that
does the SQLite equivalent (much simpler).

---

## What this is

SQLite bootstrap is one line: create the file, set WAL mode, run
migrations. Done.

Postgres has more surface area. New operators stumble on:

- Should the role be a superuser? (No.)
- What grants does PyPKI actually need? (Specific to the schema; not "all".)
- Which extensions, if any?
- TLS to Postgres — required, preferred, off?
- Connection pooling — PgBouncer, pgcat, or in-process?
- Tuning knobs (`shared_buffers`, `wal_level`, `synchronous_commit`)
- Backup integration for the DB itself (separate from PyPKI's backup?)

This spec answers all of those concretely, ships a single command
that gets them right, and makes the right answers reproducible.

---

## The command

```
pypki_admin.py db-init \
  --backend postgres \
  --dsn postgres://admin@db.example.com:5432/postgres \
  --target-db pypki \
  --target-role pypki \
  --target-role-password-source file:///etc/pypki/secrets/db.password \
  --tls require \
  --extensions citext \
  --apply-tuning recommended
```

- `--dsn` is the *bootstrap* DSN with admin privileges. Used to
  create the database and role. PyPKI does **not** retain these
  credentials.
- `--target-db`, `--target-role` are what PyPKI itself will use.
- `--target-role-password-source` is where the *new* role's password
  will be read from (created if absent) and where PyPKI's runtime
  config will look for it.
- `--apply-tuning recommended` applies a vetted set of parameters to
  the new database. `--apply-tuning none` skips them; `--apply-tuning
  print-only` shows what would change without applying.

The command is fully idempotent: running it on an already-bootstrapped
database verifies the state matches and exits 0. Detects and refuses
to silently downgrade (e.g. existing TLS=on, requested TLS=off).

---

## What it creates

### Postgres path

```sql
-- Idempotent. Each step checks existence before creating.

-- 1. Role with minimal privileges
CREATE ROLE pypki WITH
  LOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION
  NOBYPASSRLS
  CONNECTION LIMIT 100
  PASSWORD '<from password source>';

-- 2. Database owned by the role (clean ownership model)
CREATE DATABASE pypki
  WITH OWNER = pypki
  ENCODING = 'UTF8'
  LC_COLLATE = 'C.UTF-8'
  LC_CTYPE = 'C.UTF-8'
  TEMPLATE = template0;

-- 3. Extensions (in the new database, executed as superuser)
\c pypki
CREATE EXTENSION IF NOT EXISTS citext;
-- pgcrypto NOT installed: PyPKI does its own crypto in Python,
-- and pgcrypto's presence has been a CVE vector historically.

-- 4. Grants (revoke broad, grant narrow)
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO pypki;
GRANT CREATE ON SCHEMA public TO pypki;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO pypki;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO pypki;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO pypki;

-- 5. Per-table fine-grained grants once migrations run
--    (db-init invokes migrations.py after this point)
```

The role has only what it needs:

- `LOGIN`: yes, it's an app role.
- `NOSUPERUSER`: a compromised PyPKI cannot read other databases.
- `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`: defense in depth.
- `NOBYPASSRLS`: leaves the door open for row-level security if
  multi-tenancy adopts it.
- `CONNECTION LIMIT 100`: cap blast radius of connection exhaustion.

No `pg_hba.conf` editing — that's the operator's responsibility and
will vary by Postgres deployment style (cloud-managed, on-prem,
container). Document the recommended entries in `docs/POSTGRES.md`.

### SQLite path

```python
def init_sqlite(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA journal_mode = WAL")          # concurrent reads
        conn.execute("PRAGMA synchronous = NORMAL")        # WAL durability sufficient
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA mmap_size = 268435456")       # 256 MB
        conn.execute("PRAGMA cache_size = -65536")         # 64 MB
        conn.execute("PRAGMA busy_timeout = 30000")        # 30s
    os.chmod(path, 0o600)
    os.chmod(path.parent, 0o700)
    # Migrations run after this; same code path as Postgres
```

Permissions matter: a world-readable SQLite file is a leak of
everything PyPKI stores. The command enforces 0600 on the file and
0700 on its parent.

---

## TLS to Postgres

`--tls require` (default) sets `sslmode=require` in the runtime DSN.
PyPKI refuses to connect over plaintext.

Stronger options:

- `--tls verify-ca --tls-ca /etc/pypki/db-ca.crt`
- `--tls verify-full --tls-ca /etc/pypki/db-ca.crt`
- `--tls mtls --tls-ca ... --tls-cert ... --tls-key ...` — mutual TLS,
  where PyPKI's DB client cert is itself issued by PyPKI (or by an
  external CA, depending on operator topology).

`verify-full` is the right default for cloud-managed Postgres (AWS
RDS, Cloud SQL, Azure Database) where the cloud provider supplies a
CA bundle. The init wizard fetches the provider's bundle automatically
when it detects a managed Postgres DSN.

---

## Connection pooling

PyPKI's process model is multi-threaded request handling on one
process per node. Each request needs a DB connection during its
lifetime. Pool sizing:

```
pool_size = (peak_concurrent_requests × avg_db_calls_per_request)
            / target_dbcall_concurrency
```

Default `--pool-min 4 --pool-max 32` works for issuance rates up to a
few hundred per second. Beyond that, externalize pooling.

### PgBouncer integration

PgBouncer goes between PyPKI and Postgres. Document the recipe:

```ini
# /etc/pgbouncer/pgbouncer.ini
[databases]
pypki = host=db.example.com port=5432 dbname=pypki

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = 6432
pool_mode = transaction          # CRITICAL — see below
max_client_conn = 1000
default_pool_size = 32
reserve_pool_size = 8
server_tls_sslmode = require
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
```

`pool_mode = transaction` is the right choice for PyPKI's workload
but it constrains what PyPKI is allowed to do:

- No `SET LOCAL` outside a transaction.
- No `LISTEN/NOTIFY`.
- No prepared statements (or use the explicit-name workaround).
- No advisory locks held across transactions.

The DAL already uses advisory locks for serial allocation. With
PgBouncer in transaction mode, advisory locks must be acquired and
released within the same transaction (which is already the case in
`db.py:advisory_lock()` — verify before declaring PgBouncer-safe).

`db-init` emits a sample PgBouncer config if `--with-pgbouncer-sample`
is passed.

---

## Tuning

`--apply-tuning recommended` writes parameters appropriate for a
PKI workload (write-heavy at issuance peaks, predictable rather than
massive, durability-critical):

```sql
ALTER SYSTEM SET wal_level = 'replica';
ALTER SYSTEM SET synchronous_commit = 'on';
ALTER SYSTEM SET full_page_writes = 'on';
ALTER SYSTEM SET checkpoint_timeout = '15min';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET max_wal_size = '2GB';
ALTER SYSTEM SET min_wal_size = '256MB';
ALTER SYSTEM SET shared_buffers = '25% of RAM';
ALTER SYSTEM SET effective_cache_size = '50% of RAM';
ALTER SYSTEM SET work_mem = '16MB';
ALTER SYSTEM SET maintenance_work_mem = '256MB';
ALTER SYSTEM SET random_page_cost = 1.1;          -- SSD assumption
ALTER SYSTEM SET log_min_duration_statement = '1000';
ALTER SYSTEM SET log_lock_waits = on;
SELECT pg_reload_conf();
```

The "25% of RAM" entries are computed from `meminfo` at run time.
On managed Postgres these `ALTER SYSTEM` statements are often
disabled — the command detects that, skips, and prints the
recommended values for the operator to set via the provider's UI.

`--apply-tuning print-only` always works regardless of permissions
and is the recommended path on cloud-managed databases.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `db_bootstrap.py` | New module: SQLite + Postgres bootstrap, idempotency checks  |
| `pg_tuning.py`    | New module: tuning recommendations, applies ALTER SYSTEM     |
| `pgbouncer.py`    | New module: sample config emission, connectivity verification |
| `pypki_admin.py`  | `db-init` subcommand                                         |
| `db.py`           | Verify advisory locks are transaction-scoped (PgBouncer compat) |
| `test_pypki_init.py` | `TestSQLiteBootstrap`, `TestPostgresBootstrap`,            |
|                   | `TestPostgresTuning`, `TestPgBouncerCompat`                  |
| `README.md`       | Quick-start mentions `db-init`                               |
| `CHANGELOG.md`    | `### Added`                                                  |
| `docs/POSTGRES.md`| Full operator guide                                          |
| `examples/postgres/` | Sample `pg_hba.conf` entries, PgBouncer config, RDS / Cloud SQL / Azure DB tuning matrices |

### Idempotency design

Every step is a check-then-act under a transaction:

```python
def ensure_role(conn, role: str, password_hash: str):
    exists = conn.fetchone(
        "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)
    )
    if not exists:
        conn.execute(f"CREATE ROLE {q(role)} LOGIN PASSWORD %s ...", (password_hash,))
    else:
        # Verify attributes match expectations
        attrs = conn.fetchone(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolconnlimit "
            "FROM pg_roles WHERE rolname = %s", (role,)
        )
        _assert_attrs_match_or_explain(attrs)
```

The "or explain" path is the operator-friendly bit: if existing
state diverges, print exactly what differs and how to fix it. No
silent "fix" of unexpected state — that's how you accidentally break
a working deployment.

---

## CLI flags

```
pypki_admin.py db-init
  --backend sqlite|postgres
  --dsn <bootstrap-dsn>                      # postgres only
  --target-db <name>                         # postgres only
  --target-role <name>                       # postgres only
  --target-role-password-source <uri>        # file://, env://, vault://
  --tls require|verify-ca|verify-full|mtls   # postgres only
  --tls-ca <path>
  --tls-cert <path>
  --tls-key <path>
  --extensions citext,...                    # postgres only
  --apply-tuning recommended|none|print-only # postgres only
  --pool-min 4
  --pool-max 32
  --with-pgbouncer-sample
  --output-config /etc/pypki/db.yaml         # writes the runtime DSN config
  --dry-run
```

`--dry-run` prints every SQL statement and filesystem action that
would happen, without running anything. Required for change-control
environments.

---

## Tests

```
class TestSQLiteBootstrap(unittest.TestCase):
    def test_creates_file_with_0600_permissions(self): ...
    def test_creates_parent_dir_with_0700(self): ...
    def test_wal_mode_enabled(self): ...
    def test_foreign_keys_enabled(self): ...
    def test_idempotent_second_run_no_op(self): ...

class TestPostgresBootstrap(unittest.TestCase):
    # Against ephemeral Postgres in CI (docker-compose or testcontainers)
    def test_creates_role_with_minimal_privileges(self): ...
    def test_role_not_superuser(self): ...
    def test_role_cannot_create_db(self): ...
    def test_creates_database_owned_by_role(self): ...
    def test_revokes_public_then_grants_role(self): ...
    def test_idempotent_second_run_no_op(self): ...
    def test_refuses_to_downgrade_tls(self): ...
    def test_attribute_mismatch_explained_clearly(self): ...
    def test_unicode_role_name_handled(self): ...

class TestPostgresTuning(unittest.TestCase):
    def test_recommended_writes_expected_alter_system(self): ...
    def test_print_only_makes_no_changes(self): ...
    def test_managed_postgres_alter_system_failure_handled(self): ...
    def test_ram_percentages_resolved_from_meminfo(self): ...

class TestPgBouncerCompat(unittest.TestCase):
    def test_advisory_lock_acquired_and_released_in_same_tx(self): ...
    def test_no_listen_notify(self): ...
    def test_no_unscoped_set_local(self): ...
    def test_sample_config_parses(self): ...
```

Postgres tests run against a real Postgres in CI via a service
container. SQLite tests are pure in-process.

---

## Per-change checklist

- [ ] `db_bootstrap.py`, `pg_tuning.py`, `pgbouncer.py` — new modules
- [ ] `pypki_admin.py` — `db-init` subcommand
- [ ] `db.py` — confirm PgBouncer-transaction-mode-safe (advisory locks etc.)
- [ ] `test_pypki_init.py` — four test classes
- [ ] `.github/workflows/test.yml` — Postgres service container in CI
- [ ] `README.md` — quick-start update
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `docs/POSTGRES.md` — full guide: pg_hba, TLS, tuning, PgBouncer,
      RDS/Cloud SQL/Azure DB recipes
- [ ] `examples/postgres/` — sample configs
- [ ] `pypki-flows.html` — DB bootstrap flow

Run `./run_tests.sh` with `PYPKI_TEST_POSTGRES_DSN` set in CI.

---

## Open questions

1. **Row-level security for multi-tenancy**: a Postgres-native
   alternative to the DAL-level query rewriting in
   `CLAUDE-multitenancy.md`. Pros: defense in depth at the DB. Cons:
   Postgres-only, slower, complicates testing. Recommend DAL-level
   as primary, add RLS as `--with-rls` opt-in for paranoid deployments.

2. **Schema-per-tenant vs single-schema-with-tenant-id**: separate
   schemas give cleaner isolation and per-tenant `pg_dump`. Single
   schema is simpler. Stick with single-schema-plus-tenant_id (the
   multitenancy spec's approach); document the rationale.

3. **Backups for the DB itself**: PyPKI's backup system
   (`CLAUDE-backup-restore.md`) dumps the logical schema via
   `pg_dump --serializable-deferrable`. This is sufficient for
   restore, but operators may also want filesystem-level Postgres
   backups (WAL archiving + base backup) for point-in-time recovery
   between PyPKI's snapshot intervals. Document the layered approach.

4. **Read replicas**: PyPKI's read-heavy endpoints (OCSP, CRL,
   ACME directory, certificate lookup) could go to replicas;
   writes always go to primary. Out of scope here; sketch in
   `docs/POSTGRES.md` as a future direction.

5. **Cluster bootstrap**: in HA deployments, multiple PyPKI nodes
   share one DB. `db-init` runs once, on the first node. The other
   nodes need a `db-verify` command that confirms the existing DB
   matches their expected schema/version without trying to re-init.
   Add `pypki_admin.py db-verify` alongside `db-init`.
