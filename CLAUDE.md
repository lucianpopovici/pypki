# CLAUDE.md — PyPKI Development Guide

This file gives Claude (and any engineer picking up the work) the context and
conventions needed to extend PyPKI. All planned RFC work through Tier 5 is
now shipped; see the active roadmap for what remains open.

---

## Project conventions (read first)

Follow these across every change:

- **No new pip dependencies** unless absolutely required. PyPKI leans hard on
  `cryptography` + stdlib. ASN.1 primitives are hand-rolled in
  `scep_server.py` (`_seq`, `_set`, `_oid`, `_integer`, `_octet_string`,
  `_ctx`, `_encode_length`, `_decode_tlv`); reuse them.
- **Datetimes**: always `datetime.now(timezone.utc)`, never naive `utcnow()`.
- **Serials**: use `x509.random_serial_number()` for new issuance paths.
- **Audit log**: every issuance, revocation, config change, and admin action
  must be recorded via the existing audit logger in `pki_server.py`.
- **Rate limiting**: new public endpoints go through the existing token-bucket
  limiter.
- **Tests**: `test_pki_server.py` uses `unittest.TestCase` with one class per
  RFC / feature area (e.g., `TestRFC5280CRL`, `TestRFC9608NoRevAvail`). Follow
  that pattern: `TestRFC<nnnn><shortname>`.
- **README**: every RFC we claim to implement gets a row in the Protocol
  compliance table and, where user-visible, a feature section and/or CLI flag
  documented.
- **CHANGELOG**: add entries under `## [Unreleased]` grouped by
  `### Added` / `### Fixed` / `### Changed` / `### Security` /
  `### Documentation`.
- **CLI flags** stay additive and namespaced (e.g., `--tsa-port`, `--ct-log-url`).
  Secrets go through existing auth/config patterns, never positional args.
- **Profiles**: new key/EKU combinations belong in the `CertProfile` catalog in
  `pki_server.py` near line 606. Current profiles: `tls_server`, `tls_client`,
  `code_signing`, `email`, `email_signing`, `email_encryption_rsa`,
  `email_encryption_ec`, `ocsp_signing`, `tsa_signing`, `sub_ca`,
  `short_lived`, `default`, `ml_dsa_signing`.
- **No browser storage / no external network calls from servers** — PyPKI is
  offline-capable; any new outbound call must be optional and toggleable.
- **DB schema**: columns in `certificates` are exactly `serial`, `subject`,
  `not_before`, `not_after`, `der`, `revoked`, `revoked_at`, `reason`,
  `profile`. No `cn`, `status`, `requester_ip`, or `created_at` columns.
  Dates stored as ISO-8601 strings. See `db_migrations/pki/001_initial.sql`.

---

## Shipped feature inventory

### RFC compliance (Tiers 1–4)

| Feature | RFC | Key files | CLI flags / endpoints |
|---------|-----|-----------|----------------------|
| CRL `cRLNumber` + AKI extensions | RFC 6818 / 5280 | `pki_server.py` | — |
| OCSP nonce 1–32 byte enforcement | RFC 8954 | `ocsp_server.py` | `--ocsp-require-nonce` |
| RSASSA-PSS CA signing | RFC 4055 | `pki_server.py` | `--sig-algorithm rsa-pss` |
| Strict PEM bundle validation | RFC 7468 | `pki_server.py` | — |
| CMP response signature protection | RFC 4210 | `cmp_server.py` | — |
| CRMF POPO verification | RFC 4211 | `cmp_server.py` | — |
| PKCS#8 key output everywhere | RFC 5958 | all server modules | — |
| Sub-CA path_length + NameConstraints | — | `pki_server.py`, `web_ui.py` | `POST /api/issue-sub-ca` |
| EST CSR SAN passthrough + profile routing | RFC 7030 | `est_server.py` | label paths |
| Time-Stamp Authority | RFC 3161 + 5816 | `tsa_server.py` | `--tsa-prefix`, `--tsa-policy-oid` |
| ACME IP identifier | RFC 8738 | `acme_server.py` | `--acme-allow-private-ip` |
| Ed25519 / Ed448 CA keys | RFC 8410 | `pki_server.py` | `--ca-key-type ed25519\|ed448` |
| ECDSA CA keys (P-256/384/521) | RFC 5480 + 5758 | `pki_server.py` | `--ca-key-type ec-p256\|p384\|p521` |
| PKCS#12 hardening | RFC 7292 | `pki_server.py` | `--p12-allow-unencrypted` |
| CT pre-cert flow + SCT verification | RFC 6962 | `pki_server.py` | `--ct-log-url`, `--ct-require-n` |
| AES-GCM AuthEnvelopedData in SCEP | RFC 5083 + 5084 | `scep_server.py` | — |
| CMP algorithm advertisement | RFC 9481 | `cmp_server.py` | — |
| CMP pvno echo | RFC 9482 | `cmp_server.py` | — |
| CMS `contentType` attribute always present | RFC 8933 | `scep_server.py`, `tsa_server.py` | — |
| EST `serverkeygen` + profile-aware `csrattrs` | RFC 8295 | `est_server.py` | label paths |
| No Revocation Available extension | RFC 9608 | `pki_server.py` | — |
| CPS framework (docs + wiring) | RFC 3647 | `pki_server.py`, `docs/CPS.md` | `--cps-uri`, `--cps-policy-oid` |
| ACME STAR short-term auto-renewal | RFC 8739 | `acme_server.py` | `--acme-star-enabled` |
| S/MIME v4 (sign / encrypt / key agree) | RFC 8551 | `smime_server.py` | `--smime-prefix` |
| ML-DSA (FIPS 204) X.509 issuance | FIPS 204 | `pki_server.py` | `--ca-key-type ml-dsa-44/65/87`, `POST /api/paired-issue` |
| Related Certificates extension | RFC 9763 | `pki_server.py`, `web_ui.py` | `POST /api/paired-issue` |

### Operational maturity (Tier 5)

| Feature | Key files |
|---------|-----------|
| PKCS#11 / HSM support | `hsm_backend.py`, `pki_server.py` |
| Postgres dual-backend + versioned migrations | `db.py`, `migrations.py`, `pypki_admin.py` |
| Offline root + key ceremony tooling | `ceremony.py`, `pypki_admin.py` |
| RA approval workflow (REST, CMP, EST, web UI) | `pki_server.py`, `acme_server.py`, `cmp_server.py`, `web_ui.py` |
| ACME EAB + per-account rate limiting | `acme_server.py` |
| Cross-signing | `pki_server.py`, `web_ui.py` |
| OCSP pre-generated static responses | `ocsp_server.py`, `pypki_admin.py` |
| SCEP one-time challenge passwords | `scep_server.py`, `web_ui.py` |
| Lifecycle webhooks | `hooks.py`, `pki_server.py` |
| Structured JSON logging + request IDs | `pki_server.py`, `dispatcher_server.py` |
| Prometheus histograms + gauges | `pki_server.py`, `ocsp_server.py`, `acme_server.py` |
| Documentation (CPS, threat model, deployment guides) | `docs/` |

---

## Active roadmap

### PQC — what remains

- **ML-DSA (FIPS 204) ✅ shipped** — `issue_ml_dsa_certificate()`,
  `issue_paired_certs()`, `POST /api/paired-issue`. Hand-rolls TBSCertificate
  DER because `cryptography` 48.0.0 `CertificateBuilder` does not yet accept
  ML-DSA public keys. Revisit once library support lands.
- **RFC 9763 ✅ shipped** — `RelatedCertificate` extension (OID
  `1.3.6.1.5.5.7.1.36`), one-directional SHA-512 hash link from ML-DSA cert
  to classical cert to avoid circular dependency.
- **Composite signatures** (`draft-ietf-lamps-pq-composite-sigs`) — classical
  + PQC in a single signature structure; cleaner migration than RFC 9763
  pairing for some deployments. Wait for RFC status before implementing.

### Protocol extras — deferred

- **RFC 9148** — EST over CoAP: only worth it for IoT; adds `aiocoap`
  dependency. Defer unless a concrete user need appears.

---

## Skip list (low ROI — do not implement without explicit user need)

- RFC 5055 — SCVP (effectively dead)
- RFC 6402 — CMC (CMP covers the same ground)
- RFC 3709 — logotype (vanity)
- RFC 5544 / 6019 / 6283 — niche timestamp formats
- RFC 5755 — Attribute Certificates (OAuth, SAML, and Kerberos PAC ate this space)

---

## Per-change checklist

Every RFC addition MUST update:

- [ ] Source module(s)
- [ ] `test_pki_server.py` (or dedicated test file if a new module)
- [ ] `README.md` Protocol compliance table
- [ ] `README.md` feature/CLI documentation if user-visible
- [ ] `CHANGELOG.md` under `## [Unreleased]`
- [ ] `pypki-flows.html` if it introduces a new protocol flow

Run `./run_tests.sh` before presenting any change.

---

## Database design — SQLite + Postgres

This section is the canonical reference for the DAL (`db.py`). The decisions
here govern schema shape, migration files, and connection management across
the whole codebase. Goal: **two backends, one codebase, one schema**.

### Hard requirements (non-negotiable)

1. **Atomic serial-number allocation.** RFC 5280 §4.1.2.2 requires uniqueness.
   Use `advisory_lock("serial-allocation")` — `BEGIN IMMEDIATE` on SQLite,
   `pg_advisory_xact_lock` on Postgres.
2. **Durable commits.** SQLite WAL with `synchronous=FULL`; Postgres default
   `synchronous_commit=on`. Never advise turning these off.
3. **Single writer or proper transactions.** Two CA instances must not
   duplicate serials.
4. **Backup + point-in-time recovery.** Losing the audit log loses the ability
   to answer "did we issue this cert?"

### Architecture — thin DAL, no ORM

```
db.py
├── class Database(ABC)
│   ├── execute(sql, params)
│   ├── fetchone(sql, params)
│   ├── fetchall(sql, params)
│   ├── transaction()           # context manager
│   ├── advisory_lock(name)     # context manager — for serial/CRL allocation
│   └── now()                   # current unix-seconds; centralized for tests
│
├── class SQLiteDB(Database)
│   └── sqlite3 stdlib, WAL mode, BEGIN IMMEDIATE for advisory_lock
│
└── class PostgresDB(Database)
    └── psycopg 3, ConnectionPool, pg_advisory_xact_lock for advisory_lock
```

`--db-url` selects the backend:

| URL prefix | Backend |
|------------|---------|
| `sqlite:///path/to/db.sqlite` | SQLiteDB |
| `postgresql://user:pass@host/db` | PostgresDB |
| `postgres://...` | PostgresDB |

### SQL portability — key decisions

1. **Parameter style**: write all SQL with `?`; `PostgresDB.execute` translates
   to `%s` at execution time.
2. **RETURNING**: require SQLite ≥ 3.35 (March 2021); no fallback complexity.
3. **Upsert**: `INSERT ... ON CONFLICT (col) DO UPDATE SET ...` — identical
   syntax on both.
4. **Time / dates**: store unix-seconds as `INTEGER` everywhere. Convert to/from
   `datetime` at the application boundary. Never `TIMESTAMP WITH TIME ZONE`.
5. **JSON**: store as plain `TEXT`; `json.dumps`/`json.loads` at the boundary.
   Never use `JSONB` or JSON1 engine-specific types.
6. **Auto-increment**: SQLite `INTEGER PRIMARY KEY AUTOINCREMENT` vs Postgres
   `BIGSERIAL`. Hide behind a DDL helper using `{{auto_pk}}` token in shared
   migration files.

### The serial-number race

```python
# SQLite — BEGIN IMMEDIATE acquires the write lock
@contextmanager
def advisory_lock(self, name: str):
    self.conn.execute("BEGIN IMMEDIATE")
    try: yield
    except: self.conn.rollback(); raise
    else:   self.conn.commit()

# Postgres — pg_advisory_xact_lock auto-released on tx end
@contextmanager
def advisory_lock(self, name: str):
    lock_id = stable_int_hash(name)
    with self.conn.transaction():
        self.conn.execute("SELECT pg_advisory_xact_lock(%s)", (lock_id,))
        yield
```

### Schema — core tables

```sql
CREATE TABLE certificates (
    id              {{auto_pk}},
    serial          TEXT NOT NULL UNIQUE,   -- decimal string; 20-byte RFC 5280 serials
    subject         TEXT NOT NULL,
    not_before      TEXT NOT NULL,          -- ISO-8601 string
    not_after       TEXT NOT NULL,          -- ISO-8601 string
    der             BLOB NOT NULL,          -- DER cert as source of truth
    revoked         INTEGER NOT NULL DEFAULT 0,
    revoked_at      TEXT,
    reason          INTEGER,                -- RFC 5280 §5.3.1 numeric code
    profile         TEXT NOT NULL
);
CREATE INDEX idx_certs_not_after ON certificates(not_after);
CREATE INDEX idx_certs_subject   ON certificates(subject);

CREATE TABLE audit_log (
    id              {{auto_pk}},
    timestamp       INTEGER NOT NULL,       -- unix seconds
    event_type      TEXT NOT NULL,
    subject         TEXT,
    serial          TEXT,
    requester_ip    TEXT,
    details_json    TEXT
);
CREATE INDEX idx_audit_ts     ON audit_log(timestamp);
CREATE INDEX idx_audit_serial ON audit_log(serial);
```

> Note: `certificates` schema above reflects the actual shipped schema in
> `db_migrations/pki/001_initial.sql`. The design-phase schema in earlier
> drafts of this document used different column names (`serial_hex`, `cn`,
> `subject_dn`, etc.) — those were superseded. Always read the migration files
> as the authoritative schema.

**Key choices:**
- `serial TEXT` — accommodates full 20-byte RFC 5280 serials as decimal strings.
- `der BLOB` — DER cert is the source of truth; other columns are projections.
- **Soft delete only.** Never hard-delete cert rows; set `revoked=1`. Hard-delete
  only ephemeral state (ACME nonces, CMP replay nonces) on a TTL basis.
- **ISO-8601 strings** for `not_before`/`not_after` (the shipped schema uses
  text, not unix-seconds, for date columns in the certificates table).

### Connection management

**SQLite**: thread-local connections via `threading.local()`. Do not share
a connection across threads.

**Postgres**: connection pool via `psycopg_pool.ConnectionPool`
(`min_size=2, max_size=20`). Every handler acquires from pool, returns on
completion via context manager.

**Critical**: do NOT hold a connection across an RSA signing operation (10–50ms
for RSA-2048). Sign first, then take a connection to write the result.

### Connection-string parsing

```python
def make_db(url: str) -> Database:
    if url.startswith("sqlite://"):
        path = url.removeprefix("sqlite:///")
        return SQLiteDB(path)
    if url.startswith(("postgresql://", "postgres://")):
        return PostgresDB(url)
    raise ValueError(f"Unsupported DB URL scheme: {url!r}")
```

Postgres options ride inside the URL: `?sslmode=require`,
`?target_session_attrs=read-only`, etc.

### Deployment shapes

**Homelab — SQLite (default)**
```bash
python pypki.py --ca-dir ./ca           # default sqlite:///./pki.db
```
Add Litestream for continuous replication to S3 (no code changes).

**Small business — single-node Postgres**
```bash
python pypki.py --ca-dir ./ca \
  --pki-db-url  postgresql://pypki:pass@localhost/pypki_pki \
  --acme-db-url postgresql://pypki:pass@localhost/pypki_acme \
  --scep-db-url postgresql://pypki:pass@localhost/pypki_scep
```

**HA cluster — multi-node Postgres**
```bash
python pypki.py --ca-dir ./ca \
  --pki-db-url 'postgresql://pypki:pass@pgbouncer.internal/pypki?sslmode=require'
```
Serial + CRL number allocation is serialized via advisory locks — race-free
at any scale. OCSP responders can safely use a read replica.

### Migrations

Migration files live in `db_migrations/pki/` (numbered SQL files). The runner
in `migrations.py` reads the `schema_migrations` table, applies pending files
in order, rolls back on failure. Idempotent — safe to run on every startup.

`pypki_admin.py` provides `migrate-data` and `verify-migration` subcommands
for SQLite → Postgres data migration. See `docs/MIGRATION.md` for the operator
runbook.

### Version requirements

- **SQLite ≥ 3.35** (March 2021) — for `RETURNING` and improved upsert.
- **Postgres ≥ 13** (September 2020) — advisory locks, online index creation.
- **psycopg 3.x** — `pip install 'psycopg[binary]'`. psycopg2 is not supported.
