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

Never assert "X is not implemented," "X works like Y," or "X is missing" without
reading the file and quoting the actual line. Soft-recall has been wrong repeatedly:
revocation reason codes, Web UI cert search, OTel tracing, expiry monitor — all
claimed absent, all present. Follow the five-step protocol in §2.

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
  `canonical_row_bytes()` or the `AuditLog` row format. Changing the
  bytes invalidates every chain hash.
- **DAL query rewriter**: changes to `tenant.py:TenantScopedConnection`,
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
omit.

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
   with `path:lineno`.

5. **Note absence honestly.** If the search came back empty, say so:
   "I searched X, Y, Z and found no reference to <feature>; it
   appears unimplemented" — not "X is not implemented."

The protocol is mandatory before any factual claim.

---

## 3. Code conventions

### 3.1 Language and style

- **Python 3.12+**. Use modern syntax: `match` statements, `:=` walrus,
  PEP 604 `X | Y` union types, PEP 695 type aliases where appropriate.
- **`datetime.now(timezone.utc)`** everywhere. `datetime.utcnow()` is
  deprecated in 3.12+ and gives naive datetimes.
- **`pathlib.Path`** for new code paths. String paths only where an
  external API requires them.
- **`dataclass(frozen=True)`** for value types. Required for things
  passed to hash-chain serialization.
- **Type hints on every public function and method.**
- **No `Any` without justification.**
- **No `from x import *`.** Explicit imports only.
- **No module-level mutable state.** Singletons are constructed in
  `pki_server.py:main()` and threaded through.

### 3.2 Database access

- **`?` placeholders, always.** The DAL rewrites to `%s` for psycopg3
  internally.
- **ISO-8601 strings** for any timestamp column.
- **Token substitution**: `{{auto_pk}}` for autoincrement PKs, `{{blob}}`
  for binary BLOB columns.
- **`advisory_lock("<key>")`** for cross-process serialization.
  Lock keys: `"serial-allocation"`, `"audit-chain"`, `"codesign-merkle"`.
  See §5.4 for the full load-bearing list.
- **Transactions are explicit.** `with db.transaction():` — no autocommit.
- **No new `sqlite3.connect()` calls.** All code goes through `db.py`.
- **`TenantScopedConnection`** for any query against tenant-scoped tables
  in multi-tenant code paths.

### 3.3 ASN.1 and wire formats

PyPKI hand-rolls DER encoding for two reasons:

1. **Algorithms `cryptography` doesn't support yet** (ML-DSA, SLH-DSA,
   composite signatures).
2. **Bit-exact output for interop** with finicky SCEP/CMP clients.

Use the helpers in `scep_server.py`: `_seq`, `_set`, `_oid`, `_integer`,
`_octet_string`, `_ctx`, `_encode_length`, `_decode_tlv`, `_bit_string`.

### 3.4 Errors and logging

- **No catch-and-swallow** in issuance paths.
- **No `print()` in library code.** Use `log = logging.getLogger(__name__)`.
- **Request IDs.** Every inbound request gets a UUID logged in every
  audit entry and surfaced in error responses.

### 3.5 Threading and I/O

- **Thread-safety is a property, not a hope.** Document it in docstrings.
- **No new sync I/O in the OCSP hot path.** Pre-compute and cache.
- **No `time.sleep()` in tests.** Use the test clock helpers.

---

## 4. What NOT to do

- **Do not introduce an ORM.** The hand-rolled DAL with explicit SQL is a feature.
- **Do not catch `Exception` to hide errors.** Catch specific exceptions.
- **Do not change advisory lock keys without a coordinated cutover.**
- **Do not bypass `AuditLog.append()`.** Direct INSERTs into `audit_log` break the chain.
- **Do not reproduce the cert's DER outside the issuance path.** Load
  via `x509.load_der_x509_certificate` from stored bytes.
- **Do not fragment tests across files.** All tests go in `test_pki_server.py`.
- **Do not introduce real-implementation interop tests as optional.**
  Every protocol feature ships with a subprocess test against the real client.
- **Do not generate certs with `notBefore == notAfter`.** Minimum validity is 60 seconds.
- **Do not assume the user's environment.** Propose; let the user execute.

---

## 5. Architectural map

Concrete landmarks. Update on every meaningful refactor; stale
landmarks here are a bug.

### 5.1 Module index

| Module                  | Role                                                               |
| ----------------------- | ------------------------------------------------------------------ |
| `pki_server.py`         | Main HTTP server, CertProfile catalog, issuance, lifecycle         |
| `db.py`                 | DAL: connection management, query helpers, advisory locks          |
| `migrations.py`         | Schema migration runner (SQLite + Postgres)                        |
| `db_migrations/`        | SQL migration files (pki: 001–014, acme, scep, est)                |
| `acme_server.py`        | RFC 8555 ACME server                                               |
| `scep_server.py`        | SCEP server; ASN.1 encoding helpers                                |
| `est_server.py`         | RFC 7030 EST server                                                |
| `cmp_server.py`         | CMPv2/v3 server                                                    |
| `ocsp_server.py`        | OCSP responder (pre-computed + on-demand)                          |
| `tsa_server.py`         | RFC 3161 timestamp authority                                       |
| `smime_server.py`       | S/MIME signing for email profiles                                  |
| `dispatcher_server.py`  | Front-door dispatcher; routes by URL prefix                        |
| `hsm_backend.py`        | PKCS#11 key backend                                                |
| `key_backend.py`        | KeyBackend protocol + KMSRSAPrivateKey/KMSECPrivateKey shims       |
| `kms_aws.py`            | AWS KMS signing backend (SigV4)                                    |
| `kms_gcp.py`            | GCP Cloud KMS signing backend (OAuth2)                             |
| `kms_azure.py`          | Azure Key Vault signing backend (AAD)                              |
| `auth_aws.py`           | AWS SigV4 + IMDSv2 auth helper                                     |
| `auth_gcp.py`           | GCP metadata server + service-account JWT auth                     |
| `auth_azure.py`         | Azure IMDS + client-credential auth                                |
| `ceremony.py`           | Offline root key ceremony tooling                                  |
| `hooks.py`              | Webhook lifecycle hooks                                            |
| `pypki_admin.py`        | Admin CLI (40+ subcommands)                                        |
| `web_ui.py`             | HTML admin UI + REST API                                           |
| `portal.py`             | Self-service portal (scoped cert view, renewal, revocation)        |
| `tenant.py`             | Multi-tenancy: TenantScopedConnection, TenantManager, quotas       |
| `oidc.py`               | OIDC/JWS primitives: discovery, JWKS, verify_id_token, PKCE        |
| `auth.py`               | OIDCConfig, JWKSCache, DbSessionStore, role mapping, flow cookie   |
| `codesign.py`           | Code-signing portal orchestrator                                   |
| `intoto.py`             | DSSE envelope parse/sign/verify; SLSA Provenance v1 decoder        |
| `merkle_log.py`         | RFC 6962 append-only Merkle tree with inclusion proofs             |
| `openapi.py`            | OpenAPI spec loader, drift checker                                 |
| `wireguard_ca.py`       | WireGuard peer identity registry and config distribution           |
| `matter.py`             | Matter DAC/PAI/PAA X.509 builder (vendor/product OIDs)             |
| `agility.py`            | Crypto-agility dashboard: classifier, aggregator, forecaster       |
| `composite.py`          | Composite ML-DSA X.509                                             |
| `ssh_ca.py`             | SSH cert builder, KRL generation                                   |
| `ssh_wire.py`           | SSH binary wire-format primitives (RFC 4251 §5)                    |
| `onion.py`              | Tor v3 address decode + ACME onion-csr-01 validation               |
| `slh_dsa.py`            | SLH-DSA (FIPS 205) key gen, SPKI/PKCS#8 DER                        |
| `policy.py`             | Policy-as-code engine: load, evaluate, hot-reload JSON policies    |
| `audit_chain.py`        | Tamper-evident hash-chained audit log                              |
| `backup.py`             | BackupEngine: AES-256-GCM + scrypt, Ed25519 manifest               |
| `restore.py`            | RestoreEngine: verify, decrypt, stage; selective table restore     |
| `shamir.py`             | GF(256) Shamir SSS                                                 |
| `mnemonic.py`           | BIP-39-style byte→word encoding + CRC-16                           |
| `notify.py`             | stdlib sd_notify shim; WatchdogThread                              |
| `tls_manager.py`        | Hot-swap ssl.SSLContext under lock                                  |
| `db_bootstrap.py`       | SQLite WAL init, Postgres role/schema bootstrap                    |
| `pg_tuning.py`          | RAM-based Postgres parameter recommendations                       |
| `pgbouncer.py`          | PgBouncer sample config emit + connectivity verify                 |
| `preflight.py`          | Check registry, parallel runner, human/JSON/Prometheus output      |
| `checks/`               | Eight check modules: secrets, runtime, tls, hardening, backup, …  |
| `upgrade.py`            | 11-state upgrade state machine; transactional migrations           |
| `wizard.py`             | Interactive enterprise wizard                                      |
| `pypki_init.py`         | First-run bootstrap CLI (`--homelab` / `--enterprise`)             |
| `bootstrap/`            | Sub-package: ca_setup, tls_setup, db_setup, systemd_setup, …      |
| `packaging/`            | systemd units, nftables/ufw/firewalld, AppArmor, sysctl, cron      |
| `tools/pypki-wg-sync/`  | WireGuard pull-mode sync agent (stdlib only, no deps)              |
| `test_pki_server.py`    | All tests; per-feature test classes                                |

### 5.2 Key code locations

Line numbers drift; `grep` for the named symbol if the line is off.

| Symbol                              | Location                              |
| ----------------------------------- | ------------------------------------- |
| `CertProfile` catalog               | `pki_server.py` (~1580)               |
| `issue_certificate()`               | `pki_server.py`                       |
| `issue_ml_dsa_certificate()`        | `pki_server.py`                       |
| `AuditLog` (the funnel)             | `pki_server.py`                       |
| `advisory_lock()`                   | `db.py`                               |
| `TenantScopedConnection`            | `tenant.py`                           |
| `TENANT_SCOPED_TABLES`              | `tenant.py`                           |
| `_inject_tenant_filter()`           | `tenant.py`                           |
| `_seq`, `_set`, `_oid`, `_integer`  | `scep_server.py`                      |
| `Row` class (dict + int indexing)   | `db.py`                               |
| `migration runner`                  | `migrations.py`                       |
| `CodeSignService`                   | `codesign.py`                         |
| `AWSKMSBackend`/`GCPKMSBackend`/…  | `kms_aws.py`, `kms_gcp.py`, `kms_azure.py` |

### 5.3 Database structure

Migrations live under `db_migrations/<namespace>/`:

- `db_migrations/pki/` — 001–014: certificates, CA keys, SSH, policy,
  DR, agility, SSO, portal, WireGuard, Matter, KMS, tenant, codesign
- `db_migrations/acme/` — ACME accounts, orders, authorizations
- `db_migrations/scep/` — SCEP enrollments, transactions
- `db_migrations/est/` — EST enrollments

### 5.4 Load-bearing patterns

Patterns whose change is a coordinated cutover, not a single-PR fix.

| Pattern                                                   | Why load-bearing                                  |
| --------------------------------------------------------- | ------------------------------------------------- |
| `?` placeholders + `{{auto_pk}}` / `{{blob}}` substitution | Every migration; backends rely on the rewriter   |
| `AuditLog.append()` as the single audit funnel             | Audit chain integrity                            |
| `advisory_lock("serial-allocation")` string key            | Serial allocation across processes                |
| `advisory_lock("audit-chain")` string key                  | Hash chain append serialization                   |
| `advisory_lock("codesign-merkle")` string key              | Merkle tree leaf append serialization             |
| `TENANT_SCOPED_TABLES` allowlist in `tenant.py`            | Cross-tenant data isolation; bugs = data leaks   |
| `Row` class supporting `row["name"]` and `row[0]`          | Mixed-use across codebase                        |
| Thread-local SQLite connections                            | sqlite3's thread-affinity rules                   |
| CertProfile is immutable at runtime                        | Issuance assumes profiles don't shift mid-request |
| Cert serial space (20-byte random)                         | RFC 5280 compliance; collision math               |
| SSH cert serial (uint64 monotonic, separate counter)        | SSH spec requires uint64                          |
| ASN.1 helper signatures (`_seq(*items)`)                  | Called from many sites                            |

**Do not change any of these without a sidecar PR documenting the cutover plan.**

---

## 6. Test discipline

- **All tests in `test_pki_server.py`.** Per-feature test classes.
- **Test class naming**: `TestRFC<nnnn><shortname>` for protocol features,
  `Test<FeatureName>` otherwise.
- **Every protocol spec ships with a real-implementation interop test.**
  Subprocess against `certbot`, `ssh-keygen`, `openssl`, `wg`, etc.
- **Postgres tests skip cleanly** when `PYPKI_TEST_POSTGRES_DSN` isn't set.
- **No `time.sleep()`.** Use the test clock helpers.
- **Coverage isn't the metric; behavior-against-spec is.**

Run via `./run_tests.sh`.

---

## 7. Normative references

What PyPKI claims to implement.

| Reference                                | Topic                                             | Status  |
| ---------------------------------------- | ------------------------------------------------- | ------- |
| RFC 5280                                 | X.509 certificate profile                         | core    |
| RFC 6960                                 | OCSP                                              | core    |
| RFC 5019                                 | Lightweight OCSP profile                          | core    |
| RFC 3161 + RFC 5816                      | Time Stamp Protocol                               | core    |
| RFC 8555                                 | ACME                                              | core    |
| RFC 8737                                 | ACME tls-alpn-01                                  | core    |
| RFC 8738                                 | ACME for IP identifiers                           | core    |
| RFC 8739                                 | ACME STAR (short-term auto-renewal)               | core    |
| RFC 7030                                 | EST                                               | core    |
| RFC 4210 + RFC 4211 + RFC 9480           | CMPv2 / CMPv3                                     | core    |
| RFC 9481                                 | CMP algorithm requirements                        | core    |
| draft-nourse-scep + de-facto SCEP        | SCEP                                              | core    |
| RFC 8551                                 | S/MIME 4.0                                        | core    |
| RFC 5958                                 | Asymmetric Key Packages (PKCS#8 wrapper)          | core    |
| FIPS 204                                 | ML-DSA                                            | shipped |
| RFC 9763                                 | Paired hybrid certificates                        | shipped |
| FIPS 205                                 | SLH-DSA, gated (`--enable-slh-dsa`)               | shipped |
| draft-ietf-lamps-pq-composite-sigs (-18) | Composite signatures, gated                       | shipped |
| RFC 9773                                 | ACME Renewal Information                          | shipped |
| RFC 9799                                 | ACME for .onion, gated (`--acme-onion-enabled`)   | shipped |
| OpenSSH PROTOCOL.certkeys                | SSH certificates + KRL, gated (`--ssh-ca-enabled`)| shipped |
| RFC 9336                                 | X.509 EKU for Document Signing                    | shipped |
| RFC 4158 (Informational)                 | Certification Path Building (AIA caIssuers)       | shipped |
| RFC 7636                                 | PKCE (Authorization Code + PKCE flow)             | shipped |
| RFC 6962 §2.1                            | Merkle hash tree (code-signing transparency log)  | shipped |
| CSA Matter Core Spec §6.2.2              | Matter DAC/PAI/PAA device attestation certs       | shipped |
| DSSE spec                                | Dead Simple Signing Envelope (code-signing)       | shipped |

"core" = implemented and tested. "shipped" = implemented, may have
algorithm-space caveats noted. "gated" = behind a `--enable-X` flag.

---

## 8. Sidecar specs

All sidecars have shipped. They live in `specs/CLAUDE-<slug>.md`.

**Protocol additions** — all shipped

- `specs/CLAUDE-ari.md` — RFC 9773 ACME Renewal Information
- `specs/CLAUDE-composite-mldsa.md` — Composite ML-DSA in X.509
- `specs/CLAUDE-slh-dsa.md` — SLH-DSA (FIPS 205) in X.509
- `specs/CLAUDE-acme-onion.md` — RFC 9799 ACME for .onion
- `specs/CLAUDE-document-signing.md` — RFC 9336 document-signing EKU profile
- `specs/CLAUDE-rfc4158.md` — RFC 4158 path-building (AIA caIssuers)

**Platform features** — all shipped

- `specs/CLAUDE-ssh-ca.md` — SSH certificate authority
- `specs/CLAUDE-sso.md` — OIDC SSO (phase 1 OIDC; SAML is phase 2, deferred)
- `specs/CLAUDE-portal.md` — Self-service end-user portal
- `specs/CLAUDE-policy-engine.md` — Policy-as-code for issuance
- `specs/CLAUDE-audit-chain.md` — Tamper-evident hash-chained audit log
- `specs/CLAUDE-terraform-provider.md` — Terraform provider contract (OpenAPI, /api/v1/)

**Differentiated capabilities** — all shipped

- `specs/CLAUDE-cloud-kms.md` — AWS / GCP / Azure KMS backends
- `specs/CLAUDE-backup-restore.md` — Backup, restore, Shamir-shared root
- `specs/CLAUDE-multitenancy.md` — Tenant isolation
- `specs/CLAUDE-code-signing-portal.md` — Code signing with Merkle log + in-toto
- `specs/CLAUDE-crypto-agility-dashboard.md` — PQ migration tracker
- `specs/CLAUDE-embedded-enrollment.md` — WireGuard + Matter device identities

**Deployment and operations** — all shipped

- `specs/CLAUDE-bootstrap-cli.md` — First-run `pypki init`
- `specs/CLAUDE-systemd-hardening.md` — systemd unit with hardening
- `specs/CLAUDE-db-bootstrap.md` — Database bootstrap automation
- `specs/CLAUDE-tls-bootstrap.md` — TLS self-bootstrap
- `specs/CLAUDE-deployment-topologies.md` — Four reference topologies
- `specs/CLAUDE-os-hardening-firewall.md` — Host hardening + firewall
- `specs/CLAUDE-upgrade-tooling.md` — In-place upgrade with auto-rollback
- `specs/CLAUDE-preflight-check.md` — Diagnostic preflight CLI

When adding a future feature, create `CLAUDE-<slug>.md` at root,
move to `specs/` once shipped. Follow the structure: What this is /
Wire surface / Implementation / CLI flags / Tests / Checklist / Open questions.

---

## 9. Glossary

- **DAL** — Database Abstraction Layer (`db.py` + `migrations.py`).
- **Sidecar spec** — A `CLAUDE-<slug>.md` file (root = pending, `specs/` = shipped).
- **Stop-and-confirm** — The interaction pattern from §1.2.
- **Source-verify** — The protocol from §2.
- **Load-bearing pattern** — A code pattern whose change requires a coordinated
  cutover. Listed in §5.4.
- **CertProfile** — A named bundle of issuance rules. Catalog in `pki_server.py`.
- **TenantScopedConnection** — DAL wrapper that auto-injects `AND tenant_id = ?`
  into queries against `TENANT_SCOPED_TABLES`. The primary isolation layer.
- **Cert serial** — A 20-byte random integer for X.509 certs; uint64 monotonic
  for SSH certs. Different spaces, different allocators.
- **Ephemeral cert** — `code_signing_ephemeral` profile: 10-minute validity,
  URI SAN = OIDC identity, noRevAvail. Used by the code-signing portal.

---

## 10. Known issues and historical lessons

| Bug                                                       | Cause                                  | Lesson |
| --------------------------------------------------------- | -------------------------------------- | ------ |
| Sub-CA key export used PKCS#1 instead of PKCS#8           | Misreading RFC 5958                    | Always use OneAsymmetricKey for key export |
| `path_length` silently ignored in `issue_sub_ca()`        | Field accepted, never threaded through | Trace every parameter from API to cert; write a test |
| Name constraints not exposed via REST API                 | API surface incomplete                 | When adding a cert field, add the API surface in the same PR |
| EST `_handle_simpleenroll` silently dropped all SANs      | CSR parsing extracted Subject, skipped extensions | Audit *all* extensions when porting CSR fields |
| Soft claims about implementation state                    | Trusting memory over source            | Source-verify (§1.1 and §2) |
| Merkle inclusion proof wrong for non-power-of-2 trees     | Missing RFC 6962 `last_node` tracking  | Use RFC 6962's `fn = n-1` + while-loop reduction for verify |

---

## 11. Current state

**DAL**: complete. All modules go through `make_db()`. Only `db.py`
(implementation) and `db_bootstrap.py` (pre-DAL PRAGMA) retain `sqlite3.connect()`.

**Test suite**: `test_pki_server.py`, **1222 tests**, 2 Postgres-gated
tests skip without `PYPKI_TEST_POSTGRES_DSN`.

**All sidecars shipped.** No pending `CLAUDE-*.md` files at root.

**PQC**: ML-DSA shipped, SLH-DSA shipped (leaf certs, gated), Composite ML-DSA
shipped (gated), RFC 9763 paired certs shipped. Crypto-agility dashboard + Grafana
at `dashboards/pypki-agility.json`.

**SSO**: OIDC phase 1 shipped (`oidc.py`, `auth.py`, `db_migrations/pki/008_sso.sql`).
DB-backed sessions, Bearer token API access, role mapping. SAML is phase 2, deferred.

**Portal**: Self-service portal (`portal.py`, `db_migrations/pki/009_portal.sql`).
`cert_owners` table, `TenantScopedConnection`-aware, profile-level gates.

**Cloud KMS**: AWS KMS, GCP Cloud KMS, Azure Key Vault (`kms_aws.py`,
`kms_gcp.py`, `kms_azure.py`, `auth_aws.py`, `auth_gcp.py`, `auth_azure.py`,
`key_backend.py`). No pip deps; `--ca-key-backend aws-kms|gcp-kms|azure-kv`.

**Multi-tenancy**: `tenant.py` implements `TenantScopedConnection` (parameterized
`AND tenant_id = ?` injection), `TenantManager` (CRUD, DNS routing, quotas),
`TENANT_SCOPED_TABLES` allowlist. `db_migrations/pki/013_tenant.sql` adds tenant
tables + `tenant_id` columns to all user-data tables.

**WireGuard PKI**: `wireguard_ca.py` (Curve25519 registry, config distribution),
`tools/pypki-wg-sync/sync.py` (pull-mode agent). `db_migrations/pki/010_wireguard.sql`.

**Matter certs**: `matter.py` (DAC/PAI/PAA with vendor/product OIDs, ECDSA P-256
enforced, bulk NDJSON streaming). `db_migrations/pki/011_matter.sql`.

**Terraform contract**: `openapi.py`, `docs/openapi.json` (50+ endpoints, OpenAPI 3.0.3),
`/api/v1/` versioned prefix, `GET /api/health`, `GET /api/version`,
`GET /api/certs/<serial>` JSON, `POST /api/issue`.

**Code-signing portal**: `codesign.py` + `intoto.py` + `merkle_log.py`
(RFC 6962 Merkle tree with RFC-correct `last_node` inclusion proof verification).
`db_migrations/pki/014_codesign.sql`. `code_signing_ephemeral` CertProfile.
`codesign.*` policy predicates. `--codesign-enabled` / `--codesign-issuers-file`.

**Policy engine**: `policy.py`. 14 match predicates (including `codesign.*`),
4 decision types, hot-reload via SIGHUP. `codesign_meta` field on `IssuanceRequest`.

**Backup/DR**: AES-256-GCM + scrypt, Ed25519-signed manifests, Shamir M-of-N.
Emergency halt gate in `issue_certificate()`.

**Deployment infrastructure**: All 8 deployment sidecars done. `preflight.py`,
`upgrade.py`, `wizard.py`, `pypki_init.py`, `bootstrap/`, `packaging/` all shipped.

**Observability**: Prometheus metrics + Grafana dashboards, OTel tracing, audit chain.

---

## 12. Session log

Compressed history through 2026-06-01: DAL, all protocols, PQC, SSH CA,
ACME for .onion, deployment infra (8 sidecars), policy engine, backup/DR,
Tier 6 hardening (chaos, conformance, bench), Tier 8 docs (HOWTO guides),
crypto-agility dashboard — all completed and committed.

### 2026-06-02 — All remaining sidecars implemented + README trimmed

- Decided: All 9 pending sidecars implemented in this session. For multi-tenancy, `TenantScopedConnection` lives in `tenant.py` (not `db.py`) to minimize core DAL changes. For Merkle proofs, RFC 6962 §2.1 `last_node` tracking (`fn = n-1`) is required for correctness with non-power-of-2 trees. Cloud KMS uses stdlib urllib + hand-rolled SigV4/OAuth2/AAD auth (no boto3/google-cloud/azure). OIDC SSO reused `oidc.py` primitives. Code-signing ephemeral key is discarded after single use (Python GC, not secure erase — acceptable given 10-min window). SAML deferred as phase 2 SSO. OpenAPI spec is hand-written JSON, not auto-generated.
- Done: `oidc.py`, `auth.py` (SSO); `portal.py` (self-service portal); `wireguard_ca.py`, `matter.py` (embedded enrollment); `openapi.py`, `docs/openapi.json` (Terraform contract); `key_backend.py`, `kms_aws.py`, `kms_gcp.py`, `kms_azure.py`, `auth_aws.py`, `auth_gcp.py`, `auth_azure.py` (cloud KMS); `tenant.py` (multi-tenancy); `codesign.py`, `intoto.py`, `merkle_log.py` (code-signing portal); 195 new tests across 13 test classes; all 9 sidecars moved to `specs/`; README trimmed from 2362 → 180 lines; CHANGELOG updated; 9 commits pushed.
- Pending: `docs/PERFORMANCE.md` real numbers; BetterTLS integration; ML-DSA IETF test vectors; SAML phase 2 (when a user asks).
- Deferred: SIA `caRepository` on sub-CA certs; EST csrattrs hint for document_signing; public Sigstore anchoring for code-signing (per spec open question 1); per-tenant Merkle trees.
- Landmarks changed: `tenant.py` (new), `oidc.py` (new), `auth.py` (new), `portal.py` (new), `wireguard_ca.py` (new), `matter.py` (new), `key_backend.py`+`kms_*.py`+`auth_*.py` (new), `codesign.py`+`intoto.py`+`merkle_log.py` (new), `openapi.py` (new), `pki_server.py` (many new profiles + CLI flags), `web_ui.py` (codesign/WG/Matter/OpenAPI routes, /api/v1/ alias, _api_health/version/openapi/issue), `pypki_admin.py` (25+ new subcommands), `policy.py` (`codesign.*` predicate, `codesign_meta` field), `db_migrations/pki/008–014` (new), `README.md` (2362 → 180 lines)

### 2026-06-05 — Module-signing trust model experiment

- Decided: kernel source walk + QEMU experiment to determine whether Linux module
  signatures can be verified per-CA (root enrolled once) or require per-leaf enrollment.
  Hypothesis: dropping `CMS_NOCERTS` from `sign-file` embeds the signer cert in the
  PKCS#7, allowing `pkcs7_validate_trust_one` to chain leaf→root via AKI.
- Done: Strand 1 source analysis (`linux-6.19.10` tree): `sign-file.c` flag expression
  confirmed; `pkcs7_verify.c:pkcs7_find_key` (anchor `sinfo->signer = x509`) and
  `pkcs7_trust.c:pkcs7_validate_trust_one` traced in full; `signing.c:mod_verify_sig`
  keyring path confirmed (`VERIFY_USE_SECONDARY_KEYRING`). Strand 2: AKI present on
  all `code_signing` leaves via `pki_server.py:2486`. Strand 3: QEMU experiment on
  6.19.10-300.fc44 — E0 (stock `sign-file`, `CMS_NOCERTS`) exit=1 "unavailable key";
  E1 (patched, cert embedded, leaf absent from all keyrings) exit=0 "hello: loaded".
- Verdict: **per-CA module trust IS achievable** on 6.19.10 by dropping `CMS_NOCERTS`.
  Per-leaf remains required for IMA (established). Both modes documented with security
  tradeoff in `MODSIG_TRUST_FINDINGS.md`.
- Landmarks changed: `MODSIG_TRUST_MODEL.md` (spec, new), `MODSIG_TRUST_FINDINGS.md` (findings, new).

### 2026-06-05 — Module-signing enrollment tooling

- Done: `modsig_enroll.py` (`ModsigSigner` embed_cert=True/False, `ModsigEnroller` ca/leaf recipes with keyctl/mok/dracut artifacts, `IMAEnroller` for `.ima` keyring, `install_recipe()`). `pypki_admin` subcommands: `modsig-sign`, `modsig-enroll`, `ima-sign`, `ima-enroll`. `harness/enroll_modsig.sh` (`TRUST_MODE`, `ENROLL_METHOD`). `harness/modsig_roundtrip.sh` updated: `--trust-mode ca|leaf`, Gate B5 (per-CA insmod with embedded cert, leaf absent), verdict count trust-mode-aware. `TestModsigEnrollment` (11 tests). Sidecar `specs/CLAUDE-modsig-enrollment.md`.
- Decided: `openssl cms -sign` without `-nocerts` is the signing path for ca mode (no patch to kernel sign-file required for the Python tooling path). IMA always per-leaf (IMA sig v2 embeds SKID directly). Dracut hooks embed cert as base64 in shell script so they survive initramfs rebuilds.
- Landmarks changed: `modsig_enroll.py` (new), `pypki_admin.py` (4 subcommands), `harness/enroll_modsig.sh` (new), `harness/modsig_roundtrip.sh` (B5 gate), `specs/CLAUDE-modsig-enrollment.md` (new).

---

## 13. How to update this file

- **Rules (1–4)**: change rarely; justify in commit message.
- **Map (5)**: update on every file add/rename/refactor. Stale landmarks are a bug.
- **References (7)**: update per release.
- **Sidecars (8)**: update when a sidecar is added or ships.
- **Known issues (10)**: append-only — the lesson outlives the bug.
- **Current state (11)** and **session log (12)**: update every significant session.

Do not let this file grow past ~2000 lines. Prune ruthlessly.
