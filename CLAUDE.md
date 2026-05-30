# CLAUDE.md — PyPKI Canonical Design Document

This file is the contract between PyPKI maintainers (including future
Claude instances) and the codebase. Sidecar specs (`CLAUDE-<slug>.md`)
carry per-feature design; this file carries the cross-cutting rules,
patterns, and state that apply to every change.

**If you are a Claude instance reading this for the first time in a
session, read sections 1–4 in full before touching code.** Sections
5–8 are reference material; consult on demand.

---

## 1. Load-bearing rules

Hard rules. Violating any of these breaks something important.

### 1.1 Source-verify before claiming

Never assert "X is not implemented," "X works like Y," or "X is
missing" without `view`-ing the file and quoting the actual code.
Soft-recall is wrong often enough that *every* such assertion needs
verification. Past mistakes — all caught by the user, all avoidable —
include claiming revocation reason codes weren't implemented, claiming
Web UI cert search didn't exist, claiming OpenTelemetry tracing wasn't
present, claiming the expiry monitor wasn't shipped. All were wrong.
All were stated with false confidence.

The protocol:

1. State what you're about to claim.
2. Identify the file(s) that would prove or disprove it.
3. `view` them.
4. Quote the line that settles the question.
5. Then make the claim.

If step 4 doesn't produce a quote, the answer is "I don't know yet;
let me grep further" — not a guess.

### 1.2 Stop-and-confirm triggers

Before any of the following, stop and confirm with the user. These
are operations where being wrong is expensive:

- **Key material**: anything touching CA private keys, HSM/KMS
  references, Shamir shares, key backend selection, key rotation,
  or key export logic.
- **Wire-format code**: handlers in `cmp_server.py`, `scep_server.py`,
  `acme_server.py`, `est_server.py`, `ocsp_server.py`, `tsa_server.py`,
  `smime_server.py`. Wire-bit changes affect external clients.
- **Audit-chain canonical serialization**: any change to
  `canonical_row_bytes()` (once `CLAUDE-audit-chain.md` ships) or its
  predecessor `AuditLog` row format. Changing the bytes invalidates
  every chain hash.
- **DAL query rewriter**: changes to `db.py:TenantScopedConnection`,
  `_inject_tenant_filter()`, or the `TENANT_SCOPED_TABLES` allowlist.
  Bugs here are cross-tenant data leaks.
- **Advisory lock keys**: the *string values* passed to
  `advisory_lock()`. Different keys across processes don't serialize.
  Changing one without coordinating with running peers is a silent
  correctness break.
- **Schema migrations that aren't pure-additive**: column renames,
  drops, type changes, NOT NULL additions without defaults. These
  break rolling upgrades.
- **CertProfile defaults that affect existing certs**: validity_days,
  allowed_algorithms, EKU lists. Changing a default re-issues affect
  the security posture of every cert in that profile.
- **Cryptographic primitives**: introducing a new algorithm, changing
  signature parameters, modifying ASN.1 encoding, altering OID tables.

When in doubt, ask. The cost of one clarifying message is much lower
than the cost of one wire-format regression.

### 1.3 No new pip dependencies without explicit approval

PyPKI is stdlib-first by design. The only runtime deps are
`cryptography` and `psycopg3`. New deps require:

1. Explicit user approval after a stated alternative ("we could
   implement X in N LoC using stdlib").
2. A documented reason in `CHANGELOG.md`.
3. The dep being optional (lazy import + clear error) if it serves a
   single backend.

Examples of dependencies you might think are needed and aren't:
`boto3` (use SigV4 + `urllib.request`), `python-systemd` (use a 40-LoC
`sd_notify` shim), `python-saml` (implement the SP we need), `requests`
(stdlib `urllib.request` is fine), `pyyaml` (JSON is acceptable for
config; or write a flat-YAML parser).

### 1.4 Audit-log every state change

No exceptions. Issuance, revocation, sub-CA creation, config reload,
TLS rotation, policy reload, backup, restore, upgrade, tenant
creation, admin role grant — all must call into the audit log via
`AuditLog.append(...)`. Reads don't need to be audited (too noisy);
writes always do.

Audit-log details payloads must never contain secrets (passphrases,
private keys, OIDC client secrets, HMAC keys). Truncate, hash, or
omit. If you're tempted to put a secret in the audit log "just for
debugging," log a content hash instead.

### 1.5 Source paths are not file paths

All source files live at `/mnt/user-data/outputs/` in Claude's
working environment. This directory maps to the actual repository
in the user's filesystem. Reads via `view` are non-destructive;
writes via `create_file` / `str_replace` modify the canonical
source. Don't create files in `/tmp` or `/home/claude` and expect
them to persist — they don't survive between sessions.

When proposing a multi-file change, do all the writes inside one
session and call `present_files` at the end so the user can see
the deltas in their UI.

---

## 2. Source-verification protocol

When a question of fact comes up about the code:

1. **State the question precisely.** "Does PyPKI implement RFC 5280
   §5.3.1 revocation reason codes?" not "is revocation supported?"

2. **List candidate files.** For the revocation example: `pki_server.py`
   (issuance/revocation surface), `ocsp_server.py` (response generation),
   any CRL builder.

3. **`view` each candidate.** Default to viewing the whole file unless
   it's massive; for very large files, search-then-view with a range.

4. **Quote.** When stating the finding, quote the relevant line(s)
   with `path:lineno`. Example: "`pki_server.py:842` enumerates
   `RevocationReason.key_compromise`, `superseded`, etc., mapping to
   RFC 5280 §5.3.1 codes 1, 4, ...".

5. **Note absence honestly.** If the search came back empty, say so:
   "I searched X, Y, Z and found no reference to <feature>; it
   appears unimplemented" — not "X is not implemented."

The protocol is mandatory before any factual claim. It is also the
mechanism for resolving disagreements: if the user says "X exists,"
the resolution is `grep` + `view` + quote, not back-and-forth assertion.

---

## 3. Code conventions

### 3.1 Language and style

- **Python 3.12+**. Use modern syntax: `match` statements when
  pattern-matching makes structure clearer, `:=` walrus where it
  eliminates a redundant variable, PEP 604 `X | Y` union types, PEP
  695 type aliases where appropriate.
- **`datetime.now(timezone.utc)`** everywhere. `datetime.utcnow()` is
  deprecated in 3.12+ and gives naive datetimes — a footgun for cert
  validity arithmetic.
- **`pathlib.Path`** for new code paths. String paths only where an
  external API (subprocess, sqlite3 connection string) requires them.
- **`dataclass(frozen=True)`** for value types. Reduces accidental
  mutation; required for things passed to hash-chain serialization.
- **Type hints on every public function and method.** Internal
  helpers can elide, but anything reachable from another module or
  another file must annotate.
- **No `Any` without justification.** A comment explaining why is
  required when `Any` appears in a signature. `object` is usually
  what's wanted.
- **No `from x import *`.** Explicit imports only.
- **No module-level mutable state.** Configuration is passed in;
  singletons are constructed in `pki_server.py:main()` and threaded
  through.

### 3.2 Database access

- **`?` placeholders, always.** Even in Postgres-only DAL code. The
  DAL rewrites to `%s` for psycopg3 internally. Hand-writing
  Postgres-style placeholders breaks SQLite tests.
- **ISO-8601 strings** for any timestamp column. The DAL converts
  on the way in and out for the appropriate backend.
- **Token substitution** for cross-backend SQL: `{{auto_pk}}` for
  autoincrementing primary keys, `{{blob}}` for binary BLOB columns.
- **`advisory_lock("<key>")`** for cross-process serialization.
  Lock keys are short stable strings (`"serial-allocation"`,
  `"audit-chain"`, `"codesign-merkle"`). See section 5.4 for the
  load-bearing list.
- **Transactions are explicit.** `with db.transaction() as tx:` or
  the equivalent. No autocommit-with-implicit-rollback.
- **No new `sqlite3.connect()` calls.** The DAL migration is in
  progress (section 7); add new code through `db.py`, not bare
  sqlite3.

### 3.3 ASN.1 and wire formats

PyPKI hand-rolls DER encoding for two reasons:

1. **Algorithms `cryptography` doesn't support yet** (ML-DSA,
   SLH-DSA, composite signatures).
2. **Bit-exact output for interop** with finicky external clients
   (some SCEP / CMP implementations are sensitive to encoding choices
   the library makes differently between versions).

Use the helpers in `scep_server.py`: `_seq`, `_set`, `_oid`,
`_integer`, `_octet_string`, `_ctx`, `_encode_length`,
`_decode_tlv`, `_bit_string` (add when needed). Don't reinvent.

When adding a new algorithm, the rule of thumb: if `cryptography`
ships it and `CertificateBuilder` accepts the key type, use the
library. If not, hand-roll TBSCertificate DER directly. Document
the decision in the change's commit message.

### 3.4 Errors and logging

- **No catch-and-swallow** in issuance paths. An exception
  generating a cert should propagate to the caller, get audit-logged
  at the boundary, and produce a 500 with a request ID.
- **No `print()` in library code.** Use `logging`. `pki_server.py`
  configures the root logger; modules import `log =
  logging.getLogger(__name__)` and use that.
- **Request IDs.** Every inbound request gets a UUID logged in every
  audit entry and surfaced in error responses. Operators correlate
  via the ID.

### 3.5 Threading and I/O

- **Thread-safety is a property, not a hope.** Any class shared
  across requests must say so in its docstring and document the
  thread-safety story.
- **No new sync I/O in the OCSP hot path.** OCSP responses are
  served per-request; sync HTTP / KMS / DB calls in that path tank
  latency. Pre-compute and cache where the response shape allows.
- **No `time.sleep()` in tests.** Use a test clock (the existing
  `test_pki_server.py` has helpers; reuse them). Sleeps make tests
  flaky and slow.

---

## 4. What NOT to do

A non-exhaustive but battle-tested list. Each entry is here because
breaking it caused a real problem.

- **Do not introduce an ORM.** SQLAlchemy, Tortoise, Peewee — none of
  them. The hand-rolled DAL with explicit SQL is a feature.
- **Do not catch `Exception` to hide errors.** Catch the specific
  exception you can handle; let the rest propagate.
- **Do not `sleep()` in tests.** Use the test clock.
- **Do not put secrets in audit log details.** Hash, truncate, or
  omit.
- **Do not write schema migrations that are non-reversible without
  documenting why.** Reversibility is the default; irreversibility
  is the exception that must be justified.
- **Do not change advisory lock keys without a coordinated cutover.**
  Two processes using different keys for the "same" lock don't
  serialize. See section 5.4.
- **Do not bypass `AuditLog.append()`.** The audit chain (when it
  ships) depends on a single funnel. Direct INSERTs into `audit_log`
  break the chain.
- **Do not add `sqlite3.connect()`.** Go through `db.py`.
- **Do not reproduce the cert's DER outside the issuance path.** Load
  via `x509.load_der_x509_certificate` from the stored bytes; don't
  rebuild from fields.
- **Do not write to `/mnt/user-data/uploads/`.** That directory is
  read-only for user-provided files. Outputs go to
  `/mnt/user-data/outputs/`.
- **Do not skip `present_files` after creating outputs.** Without it,
  the user can't see the new files.
- **Do not fragment tests across files.** All tests go in
  `test_pki_server.py`. Per-feature test classes (`TestRFC9773ARI`,
  `TestCompositeMLDSA`, etc.) are how you organize.
- **Do not introduce real-implementation interop tests as optional.**
  Every protocol feature ships with a subprocess test against the
  real client (`certbot`, `ssh-keygen -L`, `wg-quick`, etc.). Failure
  to add one blocks merge.
- **Do not generate certs with `notBefore == notAfter`.** Some
  validators choke; some don't. Minimum validity is 60 seconds.
- **Do not assume the user's environment.** Don't run `apt`, `pip`,
  `systemctl`, etc., implicitly. Propose; let the user execute.
- **Do not edit files in `/mnt/user-data/uploads/`** even if asked.
  Read-only mount; copy to `/home/claude` or `/mnt/user-data/outputs/`
  first.

---

## 5. Architectural map

Concrete landmarks. Update on every meaningful refactor; stale
landmarks here are a bug.

### 5.1 Module index

| Module                  | Role                                                          |
| ----------------------- | ------------------------------------------------------------- |
| `pki_server.py`         | Main HTTP server, CertProfile catalog, issuance, lifecycle     |
| `db.py`                 | DAL: connection management, query helpers, advisory locks      |
| `migrations.py`         | Schema migration runner (SQLite + Postgres)                    |
| `db_migrations/`        | SQL migration files, per logical DB                            |
| `acme_server.py`        | RFC 8555 ACME server                                           |
| `scep_server.py`        | SCEP server; also home to ASN.1 encoding helpers               |
| `est_server.py`         | RFC 7030 EST server                                            |
| `cmp_server.py`         | CMPv2/v3 server                                                |
| `ocsp_server.py`        | OCSP responder (pre-computed + on-demand)                      |
| `tsa_server.py`         | RFC 3161 timestamp authority                                   |
| `smime_server.py`       | S/MIME signing for `email_signing` profile                     |
| `dispatcher_server.py`  | Front-door dispatcher; routes by URL prefix                    |
| `hsm_backend.py`        | PKCS#11 key backend (cloud-KMS extension planned)              |
| `ceremony.py`           | Offline root key ceremony tooling                              |
| `hooks.py`              | Webhook lifecycle hooks                                        |
| `pypki_admin.py`        | Admin CLI: revocation, migration, backup, etc.                 |
| `web_ui.py`             | HTML admin UI                                                  |
| `test_pki_server.py`    | All tests; per-feature test classes                            |
| `ssh_ca.py`             | SSH certificate builder, KRL generation, key classification    |
| `ssh_wire.py`           | SSH binary wire-format primitives (RFC 4251 §5)                |
| `onion.py`              | Tor v3 address decode + ACME onion-csr-01 CSR validation       |
| `slh_dsa.py`            | SLH-DSA (FIPS 205) key gen, SPKI/PKCS#8 DER, sign/verify      |
| `notify.py`             | Stdlib sd_notify shim; `WatchdogThread` for `WatchdogSec=`     |
| `tls_manager.py`        | Hot-swap `ssl.SSLContext` under lock; TLS renewal logic         |
| `db_bootstrap.py`       | SQLite WAL init, Postgres role/schema bootstrap, idempotent     |
| `pg_tuning.py`          | RAM-based Postgres parameter recommendations + `ALTER SYSTEM`   |
| `pgbouncer.py`          | PgBouncer sample config emit + connectivity verify              |
| `preflight.py`          | Check registry, parallel runner, human/JSON/Prometheus output   |
| `checks/`               | Eight check modules: secrets, runtime, tls, hardening, backup,  |
|                         | issuance, audit, backends                                       |
| `upgrade.py`            | 11-state upgrade state machine; transactional migrations        |
| `wizard.py`             | Interactive enterprise wizard; stdlib-only YAML writer          |
| `pypki_init.py`         | First-run bootstrap CLI (`--homelab` / `--enterprise`)          |
| `bootstrap/`            | Sub-package: ca_setup, tls_setup, db_setup, systemd_setup,     |
|                         | firewall_setup                                                  |
| `packaging/`            | systemd units, nftables/ufw/firewalld, AppArmor, sysctl,       |
|                         | ulimits, cron, topology reference docs                          |

Additional modules are added per sidecar spec (`policy.py`,
`audit_chain.py`, etc.). Each spec lists the module it introduces.

### 5.2 Key code locations

These line numbers drift; if the line you find isn't what's described,
`grep` for the named symbol.

| Symbol                              | Location                              |
| ----------------------------------- | ------------------------------------- |
| `CertProfile` catalog               | `pki_server.py:~606`                  |
| `issue_certificate()`               | `pki_server.py`                       |
| `issue_sub_ca()`                    | `pki_server.py`                       |
| `issue_ml_dsa_certificate()`        | `pki_server.py`                       |
| `AuditLog` (the funnel)             | `pki_server.py`                       |
| `advisory_lock()`                   | `db.py`                               |
| `_seq`, `_set`, `_oid`, `_integer`  | `scep_server.py`                      |
| `_encode_length`, `_decode_tlv`     | `scep_server.py`                      |
| `Row` class (dict + int indexing)   | `db.py`                               |
| `migration runner`                  | `migrations.py`                       |

### 5.3 Database structure

Four logical DBs, each with its own migrations directory:

- `db_migrations/pki/` — main: certificates, CA keys, audit, profiles
- `db_migrations/acme/` — ACME accounts, orders, authorizations
- `db_migrations/scep/` — SCEP enrollments, transactions
- `db_migrations/est/` — EST enrollments

Logical DBs map to separate SQLite files in single-instance
deployments and to separate schemas (or the same schema with
prefixes — operator's choice) in Postgres.

### 5.4 Load-bearing patterns

Patterns whose change is a coordinated cutover, not a single-PR fix.
If you need to modify one, plan the migration first.

| Pattern                                                   | Why load-bearing                                  |
| --------------------------------------------------------- | ------------------------------------------------- |
| `?` placeholders + `{{auto_pk}}` / `{{blob}}` substitution | Every migration; backends rely on the rewriter   |
| `AuditLog.append()` as the single audit funnel             | Audit chain integrity                            |
| `advisory_lock("serial-allocation")` string key            | Serial allocation across processes                |
| `advisory_lock("audit-chain")` string key                  | Hash chain append serialization                   |
| `Row` class supporting `row["name"]` and `row[0]`          | Mixed-use across codebase; breaking it hits hard  |
| Thread-local SQLite connections                            | sqlite3's thread-affinity rules                   |
| CertProfile is immutable at runtime                        | Issuance assumes profiles don't shift mid-request |
| Cert serial space (20-byte random)                         | RFC 5280 compliance; collision math               |
| SSH cert serial (uint64 monotonic, separate counter)        | SSH spec requires uint64                          |
| ASN.1 helper signatures (`_seq(*items)`)                  | Called from many sites                            |

**Do not change any of these without a sidecar PR documenting the
cutover plan.**

---

## 6. Test discipline

- **All tests in `test_pki_server.py`.** Per-feature test classes.
  Don't create `test_<feature>.py`; consolidation is intentional.
- **Test class naming**: `TestRFC<nnnn><shortname>` for protocol
  features (e.g. `TestRFC9773ARI`), `Test<FeatureName>` otherwise
  (e.g. `TestPortalIsolation`).
- **Every protocol spec ships with a real-implementation interop
  test.** Subprocess against `certbot`, `ssh-keygen`, `openssl`,
  `wg`, etc. These are non-negotiable for protocol changes.
- **Postgres tests skip cleanly** when `PYPKI_TEST_POSTGRES_DSN`
  isn't set. The main suite stays hermetic.
- **No `time.sleep()`**. Use the test clock helpers.
- **Coverage isn't the metric**; behavior-against-spec is. A test
  that exercises a line but doesn't assert the right behavior is
  worse than no test (false confidence).

Run via `./run_tests.sh`. CI runs the same script plus the workflows
described in sidecar specs (systemd-security, topology-smoke,
upgrade-matrix, openapi-drift).

---

## 7. DAL migration (complete)

The DAL replaces direct `sqlite3.connect()` calls with `db.py`
abstractions over two backends (SQLite, Postgres). Migration is complete.

All application modules (`scep_server.py`, `acme_server.py`, `est_server.py`,
`cmp_server.py`, `ocsp_server.py`, `ceremony.py`, `pki_server.py`) go through
`make_db()` and the `Database` interface.

The only intentional `sqlite3.connect()` calls remaining are:
- `db.py` — the implementation itself
- `db_bootstrap.py` — bootstrap-time PRAGMA setup that runs before the DAL
  is initialized (`init_sqlite`, `verify_sqlite`)

`grep -n "sqlite3.connect" *.py` now returns only these two files.

---

## 8. Normative references

What PyPKI claims to implement. Verify the spec version on every
release.

| Reference                                | Topic                       | Status |
| ---------------------------------------- | --------------------------- | ------ |
| RFC 5280                                 | X.509 certificate profile   | core   |
| RFC 6960                                 | OCSP                        | core   |
| RFC 5019                                 | Lightweight OCSP profile    | core   |
| RFC 3161 + RFC 5816                      | Time Stamp Protocol         | core   |
| RFC 8555                                 | ACME                        | core   |
| RFC 8737                                 | ACME tls-alpn-01            | core   |
| RFC 8738                                 | ACME for IP identifiers     | core   |
| RFC 8739                                 | ACME STAR (short-term auto-renewal) | core |
| RFC 7030                                 | EST                         | core   |
| RFC 4210 + RFC 4211 + RFC 9480           | CMPv2 / CMPv3               | core   |
| RFC 9481                                 | CMP algorithm requirements  | core   |
| draft-nourse-scep + de-facto SCEP        | SCEP                        | core   |
| RFC 8551                                 | S/MIME 4.0                  | core   |
| RFC 5958                                 | Asymmetric Key Packages     | core (PKCS#8 wrapper) |
| FIPS 204                                 | ML-DSA                      | shipped |
| RFC 9763                                 | Paired hybrid certificates  | shipped |
| draft-ietf-lamps-pq-composite-sigs (-18) | Composite signatures        | spec'd, gated |
| FIPS 205                                 | SLH-DSA                     | shipped, gated (--enable-slh-dsa) |
| draft-ietf-lamps-x509-slhdsa-09          | SLH-DSA in X.509            | shipped, gated (--enable-slh-dsa) |
| RFC 9773                                 | ACME Renewal Information    | shipped |
| RFC 9799                                 | ACME for .onion             | shipped, gated (--acme-onion-enabled) |
| OpenSSH PROTOCOL.certkeys                | SSH certificates + KRL      | shipped, gated (--ssh-ca-enabled) |

"core" = implemented and tested. "shipped" = implemented but
algorithm space still settling. "spec'd" = sidecar `CLAUDE-*.md`
exists; not yet implemented. "gated" = code may exist behind a
`--enable-X` flag; default off.

Update this table on every release. Re-verify the spec versions
at https://datatracker.ietf.org annually; sidecar specs note the
draft revision they target.

---

## 9. Sidecar specs

Per-feature design documents live next to this file as
`CLAUDE-<slug>.md`. When implementing a feature, the sidecar is
authoritative for that feature; this file is cross-cutting context.

Current sidecars:

**Protocol additions**

- `CLAUDE-ari.md` — RFC 9773 ACME Renewal Information
- `CLAUDE-composite-mldsa.md` — Composite ML-DSA in X.509
- `CLAUDE-slh-dsa.md` — SLH-DSA (FIPS 205) in X.509
- `CLAUDE-acme-onion.md` — RFC 9799 ACME for .onion

**Platform features**

- `CLAUDE-ssh-ca.md` — SSH certificate authority
- `CLAUDE-sso.md` — OIDC and SAML SSO for admin
- `CLAUDE-portal.md` — Self-service end-user portal
- `CLAUDE-policy-engine.md` — Policy-as-code for issuance
- `CLAUDE-audit-chain.md` — Tamper-evident hash-chained audit log (**shipped**)
- `CLAUDE-terraform-provider.md` — Terraform provider

**Differentiated capabilities**

- `CLAUDE-cloud-kms.md` — AWS / GCP / Azure KMS backends
- `CLAUDE-backup-restore.md` — Backup, restore, Shamir-shared root
- `CLAUDE-multitenancy.md` — Tenant isolation
- `CLAUDE-code-signing-portal.md` — Code signing with build attestations
- `CLAUDE-crypto-agility-dashboard.md` — PQ migration tracker
- `CLAUDE-embedded-enrollment.md` — WireGuard + Matter device identities

**Deployment and operations**

- `CLAUDE-bootstrap-cli.md` — First-run `pypki init`
- `CLAUDE-systemd-hardening.md` — systemd unit with hardening
- `CLAUDE-db-bootstrap.md` — Database bootstrap automation
- `CLAUDE-tls-bootstrap.md` — TLS self-bootstrap
- `CLAUDE-deployment-topologies.md` — Four reference topologies
- `CLAUDE-os-hardening-firewall.md` — Host hardening + firewall
- `CLAUDE-upgrade-tooling.md` — In-place upgrade with auto-rollback
- `CLAUDE-preflight-check.md` — Diagnostic preflight CLI

When adding a feature, create a new sidecar following the same
structure: What this is / Wire surface (if applicable) / Implementation
/ CLI flags / Tests / Per-change checklist / Open questions.

---

## 10. Glossary

- **DAL** — Database Abstraction Layer (`db.py` + `migrations.py`).
- **Sidecar spec** — A `CLAUDE-<slug>.md` file documenting one feature.
- **The data migration tool** — `pypki_admin.py migrate-data` /
  `verify-migration`. Moves rows from SQLite to Postgres.
- **Tier 5** — Operator-maturity features (HSM, RA workflow, offline
  ceremony, etc.). Successor to tiers 1–4 of RFC compliance.
- **Stop-and-confirm** — The interaction pattern from section 1.2.
- **Source-verify** — The protocol from section 2.
- **Load-bearing pattern** — A code pattern whose change is a
  coordinated cutover. Listed in section 5.4.
- **CertProfile** — A named bundle of issuance rules
  (`tls_server`, `code_signing`, `ssh_user`, etc.). Catalog in
  `pki_server.py`.
- **Cert serial** — A 20-byte random integer for X.509 certs;
  uint64 monotonic for SSH certs. Different spaces, different
  allocators, both serialized via `advisory_lock()`.
- **Pre-issuance hook** / **lifecycle hook** — Callable point in
  `hooks.py` invoked at known moments in cert lifecycle.

---

## 11. Known issues and historical lessons

Bugs caught in past sessions. Each is here so a future Claude reads
them once and doesn't recreate them.

| Bug                                                       | Cause                                  | Lesson |
| --------------------------------------------------------- | -------------------------------------- | ------ |
| Sub-CA key export used PKCS#1 instead of PKCS#8           | Misreading RFC 5958                    | RFC 5958 wraps the key; always use OneAsymmetricKey for export |
| `path_length` silently ignored in `issue_sub_ca()`        | Field accepted, never threaded through | Trace every parameter from API to cert; write a test |
| Name constraints not exposed via REST API                 | API surface incomplete                 | When adding a cert field internally, add the API surface in the same PR |
| EST `_handle_simpleenroll` silently dropped all SANs      | CSR parsing extracted Subject, skipped extensions | When porting CSR fields, audit *all* extensions, not just SAN |
| Soft claims about implementation state                    | Trusting memory over source            | Source-verify (section 1.1 and section 2) |

Mermaid rendering pitfall: `startOnLoad: false` + expose all sections
before `mermaid.run()` + restore visibility is the correct pattern for
tab-based diagram pages. If you see Mermaid diagrams in tabs not
rendering, this is the fix.

---

## 12. Current state

Update at the end of each significant session. Append to section 13
(session log) rather than rewriting this section unless the prior
state is no longer accurate.

**DAL migration**: complete. All application modules go through `make_db()`.
Only `db.py` (implementation) and `db_bootstrap.py` (pre-DAL PRAGMA setup)
retain `sqlite3.connect()`.

**Security baseline**: CA key passphrase encryption, admin API
authentication, HTML escaping (XSS), CSRF protection, SQLite
connection leak fixes shipped. Serial number race condition
identified; mitigation is `advisory_lock("serial-allocation")` which
is in place for `AuditLog` and pending for `CertificateAuthority`.

**PQC posture**: ML-DSA shipped, RFC 9763 shipped, SLH-DSA shipped
(leaf certs gated behind `--enable-slh-dsa`; requires `pip install slh-dsa`).
Composite ML-DSA spec'd but not implemented. Crypto-agility dashboard
spec'd but not implemented.

**Infrastructure**: Docker Compose with PyPKI + nginx; PAM auth with
brute-force lockout; configurable `base_path` for Web UI. Helm chart
and per-cloud Terraform spec'd but not implemented.

**SSH CA**: shipped. `ssh_ca.py`, `ssh_wire.py` implement Ed25519/ECDSA/RSA
user and host cert issuance, KRL generation, and `ssh-keygen -L`/`-Q`
interop. Enabled via `--ssh-ca-enabled`. ML-DSA CA keys rejected. Web UI
at `/ssh`. Admin CLI: `ssh-revoke`, `ssh-list`, `ssh-krl-export`.

**ACME for .onion**: shipped, gated. `onion.py` implements Tor v3
address decode and `onion-csr-01` challenge validation per RFC 9799.
Enabled via `--acme-onion-enabled`. `onion_eligible` CertProfile added.

**Deployment infrastructure**: All 8 deployment sidecar specs implemented.
`notify.py` (sd_notify shim), `tls_manager.py` (hot-swap TLS), `db_bootstrap.py`
(SQLite WAL + Postgres bootstrap), `pg_tuning.py`, `pgbouncer.py`, `preflight.py`
(parallel check runner, 3 output formats), `checks/` (8 check modules), `upgrade.py`
(11-state machine, transactional migrations), `wizard.py` (enterprise wizard),
`pypki_init.py` (first-run CLI), `bootstrap/` package, `packaging/` (systemd units,
nftables/ufw/firewalld, AppArmor, sysctl, cron, topology reference docs).
`pypki_admin.py` extended with: `db-init`, `tls-rotate/status/replace`,
`hardening-status/apply/validate`, `preflight`, `upgrade/upgrade-check/status/rollback`.

**Test suite**: `test_pki_server.py`, 930+ tests, 2 Postgres
tests correctly skipping without env var.

**Observability**: Prometheus metrics + Grafana dashboard JSON
shipped; alerting rules defined; OpenTelemetry tracing present.

---

## 13. Session log

Each significant session appends a 5-line entry. Format:

```
### YYYY-MM-DD — <one-line summary>
- Decided: <what was decided>
- Done: <what was implemented>
- Pending: <what's still open>
- Deferred: <what was explicitly punted and why>
- Landmarks changed: <files / functions / line numbers that moved>
```

Past entries (reconstructed from memory; future sessions append):

### 2026-04 — DAL bootstrap
- Decided: hand-rolled DAL over two backends; no ORM
- Done: `db.py`, `migrations.py`, four `001_initial.sql`, `Row` class,
  thread-local SQLite, advisory_lock primitive, SQLite→Postgres
  migrate-data tool
- Pending: ~14 `sqlite3.connect()` sites to convert
- Deferred: ORM evaluation (philosophical no)
- Landmarks changed: `db.py` (new), `migrations.py` (new),
  `pki_server.py:AuditLog` (DAL-backed)

### 2026-05 — Roadmap completion + spec drafting
- Decided: existing roadmap is shipped; future work routes through
  sidecar specs
- Done: 24 `CLAUDE-<slug>.md` sidecars drafted across four batches:
  protocol additions (ARI, composite ML-DSA, SLH-DSA, ACME-onion),
  platform features (SSH CA, SSO, portal, policy engine, audit chain,
  Terraform provider), differentiated capabilities (cloud KMS,
  backup-restore, multi-tenancy, code-signing portal, agility
  dashboard, embedded enrollment), deployment (bootstrap CLI, systemd
  hardening, db bootstrap, TLS bootstrap, topologies, OS hardening,
  upgrade tooling, preflight)
- Pending: implementation of any sidecar
- Deferred: SAML phase 2 of SSO until OIDC ships and a user asks
- Landmarks changed: none; sidecars are new files alongside CLAUDE.md

### 2026-05-30 — RFC 9799 ACME for .onion + SSH CA implementation
- Decided: unsigned KRLs (OpenSSH generates unsigned KRLs; sig format is
  version-specific); audit via `audit.record()` parameter pattern (not a
  classmethod), matching existing `issue_certificate()` convention
- Done: `onion.py` (Tor v3 decode, onion-csr-01 validation); `ssh_wire.py`
  (RFC 4251 §5 primitives); `ssh_ca.py` (cert builder, KRL, profile catalog);
  `db_migrations/acme/003_onion.sql`; `db_migrations/pki/004_ssh.sql`;
  `onion_eligible` CertProfile; SSH CA methods on `CertificateAuthority`;
  CLI flags `--acme-onion-*` and `--ssh-ca-*`; Web UI `/ssh` routes;
  admin CLI `ssh-revoke` / `ssh-list` / `ssh-krl-export`; 47 new tests
  (6 test classes) covering wire format, interop, and profile enforcement
- Pending: portal, SSO, composite ML-DSA implementation
- Deferred: KRL signing (format is unclear across OpenSSH versions)
- Landmarks changed: `onion.py` (new), `ssh_wire.py` (new), `ssh_ca.py`
  (new), `acme_server.py` (onion-csr-01 support), `pki_server.py` (SSH CA
  methods + onion_eligible profile), `web_ui.py` (/ssh routes),
  `pypki_admin.py` (ssh-* subcommands)

### 2026-05-30 — SLH-DSA (FIPS 205) X.509 leaf certificate issuance
- Decided: use `slhdsa` pip package (not a hand-rolled FIPS 205 impl); leaf
  certs only — the CA retains a classical key because `cryptography` lib has
  no SLH-DSA support; slhdsa package schema API is broken for DER export so
  SPKI/PKCS#8 encoding is hand-rolled in `slh_dsa.py`
- Done: `slh_dsa.py` (new — SLH_DSA_OIDS, SLHDSAPrivateKey/PublicKey, generate,
  load_pem/der_private_key, hand-rolled SPKI + PKCS#8 DER); `pki_server.py`
  (HAS_SLHDSA gate, _sig_alg_der_for_key + _sign_data + _hash_for_key extended,
  12 SLH-DSA entries in _CA_KEY_FACTORIES, `slh_dsa_signing` CertProfile,
  `issue_slh_dsa_certificate()`, `--enable-slh-dsa` flag); `web_ui.py`
  (`POST /api/slh-dsa-issue`); 31 tests in TestSLHDSAX509 + TestSLHDSAInterop
- Pending: portal, SSO, composite ML-DSA
- Deferred: SLH-DSA CA keys (requires cryptography library support to load
  SLH-DSA CA certs; deferred until upstream ships)
- Landmarks changed: `slh_dsa.py` (new), `pki_server.py` (HAS_SLHDSA +
  `issue_slh_dsa_certificate` + slh_dsa_signing profile), `web_ui.py`
  (`_api_slh_dsa_issue`)

### 2026-05-30 — All 8 deployment sidecar specs implemented
- Decided: all deployment tests go in `test_pki_server.py` (not `test_pypki_init.py`
  as sidecars suggested); stdlib-only YAML writer in `wizard.py` (no pyyaml dep);
  `pypki_self_tls` CertProfile for hot-rotated server TLS (ECDSA P-256/P-384, 90 d)
- Done: `notify.py` (sd_notify shim + `WatchdogThread`); `tls_manager.py` (atomic
  `ssl.SSLContext` hot-swap); `db_bootstrap.py` (SQLite WAL + Postgres idempotent
  bootstrap); `pg_tuning.py` (RAM-based params + managed-Postgres graceful fallback);
  `pgbouncer.py` (sample config emit); `preflight.py` (parallel runner, 3 output
  formats, `@register_check` registry); `checks/` (8 modules: secrets, runtime, tls,
  hardening, backup, issuance, audit, backends); `upgrade.py` (11-state machine,
  transactional migrations with per-migration savepoints, canary issuance health
  window); `wizard.py` (8-question enterprise wizard, `?` help, resume); `pypki_init.py`
  (homelab 6-step + enterprise wizard + `--from-answers` replay); `bootstrap/` package
  (ca_setup, tls_setup, db_setup, systemd_setup, firewall_setup); `packaging/`
  (systemd units + hardening, nftables/ufw/firewalld templates, AppArmor profile,
  sysctl+ulimits, cron, topology docs); `pypki_admin.py` extended with 12 new
  subcommands; `pki_server.py` sd_notify + CLI flags; 65 new tests (15 test classes)
- Pending: portal, SSO, composite ML-DSA, ARI implementation
- Deferred: CI workflow YAML files (`.github/workflows/systemd-security.yml` etc.) —
  structure is clear, not worth generating without a real CI target
- Landmarks changed: `notify.py`, `tls_manager.py`, `db_bootstrap.py`, `pg_tuning.py`,
  `pgbouncer.py`, `preflight.py`, `checks/`, `upgrade.py`, `wizard.py`, `pypki_init.py`,
  `bootstrap/`, `packaging/` (all new); `pki_server.py` (pypki_self_tls profile +
  sd_notify + CLI flags); `pypki_admin.py` (12 new subcommands)

---

## 14. How to update this file

- **Rules sections (1–4)** change rarely. When they do, the change
  needs explicit justification in the commit message.
- **Map section (5)** should be updated whenever a file is added,
  removed, renamed, or substantially refactored. Stale landmarks
  here are a bug; treat updating them as part of the refactor PR.
- **Test discipline (6)** changes only when the project's testing
  approach shifts.
- **DAL migration (7)** updates as conversion sites complete. Each
  conversion PR ticks one item.
- **References (8)** updates per release.
- **Sidecars (9)** updates when a new sidecar is added or removed.
- **Glossary (10)** grows as terminology accumulates. Prune when
  terms become universally understood within the project.
- **Known issues (11)** is append-only. Add bugs as they're found,
  even after they're fixed — the lesson outlives the bug.
- **Current state (12)** and **session log (13)** update every
  significant session.

Do not let this file grow past ~2000 lines. If it does, content
belongs in a sidecar or has gone stale. Prune ruthlessly.
