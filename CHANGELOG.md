# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **RFC 3647 — Certificate Policy / CPS framework** (`docs/CPS.md`).
  CPS document follows the full RFC 3647 §6 nine-section outline,
  calibrated for self-hosted PyPKI deployments (homelab + small enterprise).
  `--cps-uri URL` and `--cps-policy-oid OID` CLI flags (already wired in
  `pki_server.py`) embed a CPS URI qualifier and policy OID in the
  `CertificatePolicies` extension of every issued certificate. Section 1.3
  updated to reflect the shipped RA approval workflow. Compliance table row
  and README "Deployment-wide CPS URI" subsection added.

- **§5.4 — Registration Authority / approval workflow** (`pki_server.py`,
  `acme_server.py`, `cmp_server.py`, `est_server.py`,
  `db_migrations/pki/003_pending_requests.sql`).
  New `RAPolicy` class evaluates auto-approval rules: `mode="all"` (approve
  everything), `mode="none"` (always require manual review), `mode="profile_list"`
  (per-profile list + `fnmatch` SAN patterns). New `RAWorkflow` class manages
  the `pending_requests` table — `submit()` either auto-issues or stores a pending
  row, `approve()` calls `issue_certificate()` and finalises the request,
  `deny()` records a reason. ACME finalization routes through RA when enabled:
  orders that require approval move to `processing` state (RFC 8555 §7.4) and
  carry an `ra_request_id` linking them to the pending row; `GET /acme/order/<id>`
  transitions the order to `valid`/`invalid` when the RA decision arrives. REST
  API returns HTTP 202 with `{"status": "pending", "request_id": "..."}` for
  pending requests. Approve/deny/list REST endpoints at `/api/ra/approve/<id>`,
  `/api/ra/deny/<id>`, `/api/ra/pending`, `/api/ra/recent`, `/api/ra/request/<id>`.
  CLI flags: `--ra-auto-approve`, `--ra-require-approval`,
  `--ra-auto-approve-profiles PROFILE [...]`, `--ra-policy-file PATH`.
  22 tests in `TestRAWorkflow`.

- **§5.4 — CMP PKIStatus=3 (waiting) + pollReq/pollRep RA integration**
  (`cmp_server.py`). When RA requires manual approval, `ir`/`cr` responses
  carry `PKIStatus=3` (waiting) per RFC 4210 §5.2.8. Clients poll via
  `pollReq` (body type 25); server responds with `pollRep` (body type 26,
  `checkAfter=60s`) while the request is pending, or `ip`/`cp` with
  `status=0` once approved. State is tracked in an in-memory
  `_ra_pending` dict keyed by `transactionID`. 4 tests in `TestRAWorkflow`.

- **§5.4 — EST HTTP 202 + Retry-After RA integration** (`est_server.py`).
  When RA requires manual approval, `simpleenroll` returns `HTTP 202` with
  `Retry-After: 60` per RFC 7030 §4.2.3. A re-submitted CSR (detected by
  SHA-256 fingerprint of the CSR DER stored as `protocol_ref`) returns the
  issued certificate once approved, or 403 if denied. 3 tests in
  `TestRAWorkflow`.

- **Sub-CA PKCS#12 bundle export** (`cmp_server.py`, `web_ui.py`). `POST
  /api/sub-ca` (and `/api/issue-sub-ca`) now accept `"export_format":
  "pkcs12"` and an optional `"p12_password"` field. When requested, the
  response contains a base64-encoded PKCS#12 bundle (key + certificate +
  issuer chain) under the `"p12_b64"` key instead of separate `cert_pem`/
  `key_pem` fields. 2 tests in `TestHTTPAPI`.

- **§5.4 — RA approver dashboard** (`web_ui.py`). New "RA Queue" page at
  `/ra-queue` lists all pending certificate requests with one-click Approve
  and Deny buttons (Deny prompts for an optional reason). Recent decisions
  (last 20) are shown in a separate table. `POST /api/ra/approve/<id>` and
  `POST /api/ra/deny/<id>` REST endpoints backed by `RAWorkflow.approve()`
  and `RAWorkflow.deny()`. When RA is not enabled the page shows a helpful
  configuration hint instead of a broken table. 11 tests in
  `TestRAWebUIDashboard`.

### Fixed

- **CMP `_parse_pki_header` `transactionID` extraction** (`cmp_server.py`).
  The header parser was assigning optional fields by sequential position
  rather than by ASN.1 context tag number. As a result `transactionID`
  (context tag [4]) was never extracted when preceding optional fields
  (`senderKID`, `recipKID`) were absent — the transaction ID always fell
  back to `os.urandom(16)`, breaking RA-pending state tracking,
  `certConf` correlation, and any stateful CMP exchange. Fixed by
  tag-based field identification using a mapping of context-tag byte
  to field name.

- **§5.11 — Prometheus histogram metrics** (`pki_server.py`,
  `ocsp_server.py`, `acme_server.py`). New `_Histogram` class and three
  module-level instances: `pypki_issuance_duration_seconds` (labels:
  `profile`, `protocol`), `pypki_ocsp_duration_seconds`, and
  `pypki_acme_order_duration_seconds` (label: `challenge_type`). Timing
  is recorded via `time.perf_counter()` at the signing call in
  `issue_certificate()`, at `OCSPResponseBuilder.build()`, and at ACME
  finalization. `CertificateAuthority.metrics_prometheus()` now appends
  histogram exposition lines (Prometheus text format: `_bucket`, `_sum`,
  `_count` per label set). New `protocol` parameter on `issue_certificate()`
  (default `""`) lets callers label observations by enrollment protocol
  (`"acme"`, `"cmp"`, `"est"`, `"scep"`, `"ipsec"`, `""`). No new
  pip dependencies. 14 tests in `TestMetricsDepth`.

- **§5.1 — PKCS#11 / HSM backend** (`hsm_backend.py`, `pki_server.py`).
  New `HSMConfig` dataclass and `load_hsm_signing_key(cfg)` function open a
  PKCS#11 session, locate a key by label, and return an `HSMRSAPrivateKey`
  or `HSMECPrivateKey` that subclasses the `cryptography` library ABCs so
  `CertificateBuilder.sign()` and all existing signing paths work unchanged.
  Raw PKCS#11 ECDSA output (r||s) is converted to DER inside the wrapper;
  RSA PKCS#1 v1.5 and PSS are supported via mechanism mapping. The CA key
  is never written to disk when `--hsm-module` is set. Key generation on the
  token (`EXTRACTABLE=False`) via `--hsm-init-if-missing`. CLI flags:
  `--hsm-module PATH`, `--hsm-slot N`, `--hsm-pin-env VAR` (default
  `PYPKI_HSM_PIN`), `--hsm-key-label LABEL` (default `pypki-ca`),
  `--hsm-init-if-missing`. Optional dependency: `pip install python-pkcs11`;
  import is deferred and only triggered when `--hsm-module` is supplied.
  16 unit tests in `TestHSMBackend` (mock HSM, RSA/EC signing, ABC
  isinstance checks, CertificateBuilder integration); 1 integration test
  gated on `PYPKI_TEST_HSM_MODULE` env var.

- **§5.2 — Dual-backend storage: SQLite (default) + PostgreSQL** (`db.py`,
  `migrations.py`, `pki_server.py`, `acme_server.py`, `scep_server.py`,
  `ocsp_server.py`, `ipsec_server.py`). New `Database` ABC with `SQLiteDB`
  and `PostgresDB` implementations; `make_db(url)` factory selects the
  backend from a URL (`sqlite:///…` or `postgresql://…`). All
  `sqlite3.connect()` call sites across all server modules replaced with
  the DAL. Serial and CRL number allocation race-free via
  `advisory_lock("serial-allocation")` / `advisory_lock("crl-allocation")`
  on both backends (SQLite `BEGIN IMMEDIATE`, Postgres `pg_advisory_xact_lock`).
  New CLI flags `--pki-db-url`, `--acme-db-url`, `--scep-db-url` (default:
  `sqlite:///…` matching the current `ca_dir` layout). `SCEPDatabase` and
  `ACMEDatabase` accept either a path string (backwards-compat) or a
  `Database` object. `ApprovalQueue` (IPsec) migrated to DAL.
  PostgreSQL requires `pip install 'psycopg[binary]'`; SQLite ≥ 3.35 required.
  7 tests in `TestDatabaseBackend` (basic CRUD, transaction rollback, advisory
  lock serialization, 50-thread serial concurrency test, CLI flag audit).

- **§5.10 — Structured logging + request IDs** (`pki_server.py`,
  `dispatcher_server.py`). `JsonFormatter` emits one JSON object per log
  line; `RequestIdFilter` injects a 16-char hex `req_id` (set per HTTP
  request in `dispatcher_server._dispatch` via `contextvars.ContextVar`) so
  all log records from a single request share the same ID. New
  `configure_logging(level, format)` helper replaces the old `basicConfig`
  call. New `--log-format json|text` CLI flag (default `text` for
  back-compat). 11 tests in `TestStructuredLogging`.

- **§5.9 — Lifecycle hooks / webhooks** (`hooks.py`, `pki_server.py`). New
  `WebhookDispatcher` class delivers JSON POST notifications to one or more
  URLs on `cert.issued`, `cert.revoked`, `cert.expiring`, `subca.issued`,
  and `cross.signed` events. Delivery is asynchronous (background thread +
  queue); up to 5 retry attempts with exponential back-off (capped at 300 s);
  final failure is audit-logged. `X-PyPKI-Signature: sha256=<hex>` header
  signs every delivery via HMAC-SHA256 so receivers can verify authenticity.
  `verify_signature(body, secret, header)` helper for receiver-side
  verification. Dispatcher enabled by new CLI flags `--webhook-url URL`
  (repeatable), `--webhook-secret SECRET`, `--webhook-events EVENT,...`
  (default: all). `CertificateAuthority._webhook` attribute wired into
  `issue_certificate`, `revoke_certificate`, `cross_sign`, and the expiry
  monitor. 15 tests in `TestLifecycleHooks`.

- **§5.3 — Offline root + key ceremony tooling** (`ceremony.py`,
  `pypki_admin.py`). Three new `pypki_admin` subcommands:
  - `export-root` — packages the CA key, cert, and counters into an
    AES-256-GCM encrypted tar.gz bundle (PBKDF2-SHA256, 600k iterations).
    Optional Shamir M-of-N passphrase splitting in GF(256) (`--threshold M
    --shares N`); shares are base64-encoded for distribution.
  - `sign-csr` — decrypts the bundle (or reconstructs the passphrase from
    M shares via `--share`) and issues a sub-CA certificate from the offline
    root. Supports `--validity-days`, `--path-length`, `--permitted-dns`,
    `--excluded-dns`. No DB writes, no network access required.
  - `import-cert` — appends a ceremony-signed cert into the online CA's
    `ca-chain.pem`; idempotent (second import of the same cert is a no-op).
  13 tests in `TestCeremony` covering encryption round-trips, 2-of-3 and
  3-of-5 Shamir reconstruction, bundle I/O, `sign-csr` issuing a valid
  NameConstraints sub-CA cert, and import idempotency.

### Security

- **RFC 4210 §5.1.3 — CMPv2/v3 response signature protection.** Every
  CMPv2 and CMPv3 response now carries a `[0] PKIProtection` BIT STRING
  signed by the CA over the `ProtectedPart` (header ‖ body), along with
  the full `[1] extraCerts` chain. Algorithm: `sha256WithRSAEncryption`,
  matching the existing `protectionAlg` hint. Closes the gap that caused
  strict clients (EJBCA, strongSwan pki, RFC 9482 Lightweight CMP Profile
  validators) to reject our otherwise-valid replies. New helper
  `CMPv2Handler._protected_response` auto-supplies the signer key, signer
  cert, and parent chain; all 12 response callsites in `CMPv2Handler` and
  `CMPv3Handler` migrated. The legacy unprotected path is preserved (no
  kwargs → no protection) for back-compat with tests and bootstrap.
- **RFC 4211 §4 — CRMF proof-of-possession verification.** Server now
  verifies the `POPOSigningKey` signature on every CRMF `CertReqMsg`
  before issuance, defeating the attack where a malicious requester
  submits a CRMF claiming someone else's public key. New helpers
  `CMPv2ASN1.parse_crmf` and `CMPv2ASN1.verify_popo` support RFC 4211
  §4.1 case 2 (POPO signed over the `CertRequest` DER). Algorithms
  verified: RSA-PKCS1v15 with SHA-256/384/512, ECDSA with SHA-256/384/512,
  Ed25519. The algorithm OID is extracted from the CRMF itself, not the
  certTemplate, and cross-checked against the public-key type to prevent
  algorithm-substitution attacks. `raVerified` and `POPOSigningKeyInput`
  variants are explicitly rejected. On failure or missing POPO with
  client-supplied SPKI, the response is a `PKIStatusInfo` rejection with
  `failInfo` bit 9 (`badPOP`) per RFC 4210 §3.1.4 and the event is
  audit-logged as `popo_failed` / `popo_missing`.

### Changed

- **RFC 5958 — Remaining PKCS#8 cleanup** (`pki_server.py`). Three
  remaining `PrivateFormat.TraditionalOpenSSL` sites converted to
  `PrivateFormat.PKCS8`: TLS server key written to disk at startup
  (line ~2396), mTLS client key returned from the internal
  `issue_client_cert()` helper (line ~2483), and the throwaway CT
  pre-cert signing key written to a temp file (line ~2633). No server
  module now uses PKCS#1 or SEC1 legacy key format.

### Fixed

- **RFC 6818 / RFC 5280 §5.2.1, §5.2.3 — CRL mandatory extensions.**
  All three CRL builders (`generate_crl`, `generate_crl_der`,
  `generate_delta_crl`) now emit the previously-missing `cRLNumber` and
  `authorityKeyIdentifier` extensions. CRL numbers are allocated
  atomically via a new `crl_number` counter table seeded by migration
  `db_migrations/pki/002_crl_number.sql`; allocation uses
  `BEGIN IMMEDIATE` for cross-process safety, monotonically increasing
  across all three builders, persisting across CA restarts. Delta CRLs
  retain their existing `DeltaCRLIndicator` (critical) and now carry all
  three extensions; the delta number is always greater than the base per
  RFC 5280 §5.2.4. The CRL signature still verifies against the CA
  public key.
- **Pre-existing crash in `generate_crl_der` when revoked certs are
  present.** The builder used `datetime.fromtimestamp()` against an
  ISO-8601 TEXT column (`revoked_at`), which would crash any call against
  a DB containing revoked certs. Fixed by switching to
  `datetime.fromisoformat()`, mirroring the working call in
  `generate_crl()`. Surfaced by the new RFC 6818 CRL tests.

### Added

- **RFC 8933 — CMS `contentType` attribute always present in `signedAttrs`.**
  Confirmed via audit that `CMSBuilder.signed_data` (SCEP) and
  `TSAResponseBuilder.build` (TSA) always include the `id-contentType`
  (`1.2.840.113549.1.9.3`) signed attribute whenever `signedAttrs` are
  present, satisfying the RFC 8933 MUST. Added `TestRFC8933CMSContentType` in
  `test_scep_server.py` (7 tests) verifying contentType presence across
  success/failure/pending SCEP responses, value is `OID_DATA`, signedAttrs
  is never absent, and the PKCS#1v15 signature over signedAttrs verifies;
  plus one test in `TestRFC3161TSA` verifying TSA SignedData carries
  `id-contentType = OID_TST_INFO` in its signedAttrs.

- **RFC 7292 — PKCS#12 unencrypted-export rejection.** `export_pkcs12` now
  rejects passwordless export by default, raising `ValueError` with a message
  that points operators to `--p12-allow-unencrypted`. The opt-out flag wires
  through `main()` → `ca._p12_allow_unencrypted`. Tests in
  `TestRFC7292PKCS12Hardening` (5 tests) verify the guard, the opt-out, and
  the error message.

- **RFC 6962 — CT CLI wiring and SCT ECDSA verification.** Three new CLI flags:
  `--ct-log-url URL` (repeatable), `--ct-log-pubkey PATH` (repeatable, aligned
  by index with log URLs), `--ct-require-n N` (minimum SCTs; 0 = best-effort).
  All three wire into `ca._ct_log_urls`, `ca._ct_log_pubkeys`, `ca._ct_require_n`
  in `main()`. New `CertificateAuthority.verify_sct_signature` static method
  verifies the `DigitallySigned` TLS structure from a CT log response: parses hash
  algorithm, signature algorithm, and signature bytes; reconstructs the
  `TreeLeafMessage` signed bytes (version, sig_type, timestamp, entry_type,
  signed_entry, extensions); verifies the ECDSA P-256 signature against the log's
  PEM public key. Wrong key, tampered bytes, or invalid pubkey return `False`
  without raising. `issue_certificate_with_ct` raises `RuntimeError` when fewer
  than `ct_require_n` SCTs are obtained. Tests in `TestRFC6962CTCLIWiring`
  (11 tests).

- **RFC 9481 + RFC 9482 — CMP algorithm advertisement and pvno echo.** The CMP
  `genm`/`genp` exchange now handles three RFC 9481 info-type OIDs:
  `id-it-signKeyPairTypes` returns RSA + ECDSA P-256/P-384/P-521 + Ed25519/Ed448
  as `SEQUENCE OF AlgorithmIdentifier`; `id-it-encKeyPairTypes` returns RSA;
  `id-it-preferredSymmAlg` returns AES-256-GCM. Also fixed a critical pre-existing
  bug in `parse_pki_message` (`data[0]` referenced before assignment, causing
  `UnboundLocalError` silently caught → `body_type=None` for all CMP messages).
  RFC 9482 §3.1 pvno echo: `_handle_cert_request` now propagates the client's
  `pvno` so `ir`/`cr` responses from a pvno=3 client carry pvno=3. Tests in
  `TestRFC9481CMPAlgorithms` (9 tests) and `TestRFC9482LightweightCMP` (7 tests).

- **ACME per-account certificate rate limiting.** New `--acme-per-account-cert-limit N`
  and `--acme-per-account-window-days N` CLI flags (default: 0 = unlimited, 7 days).
  When a limit is set, `_handle_finalize` counts certificates issued for the account
  in the rolling window via `ACMEDatabase.count_account_certs_since` (joins `certificates`
  + `orders` tables) and returns 429 `rateLimited` if the limit is reached. The limit
  is 0 (off) by default, preserving existing behavior. Tests in
  `TestACMEPerAccountRateLimit` (7 tests) verify DB counting, window isolation,
  multi-account isolation, handler propagation, and CLI defaults.

- **§5.7 — OCSP pre-generated static responses (RFC 5019 §6).** New
  `ocsp_server.generate_static_responses(ca, output_dir, validity_hours=24)`
  pre-builds one signed `.ocsp` file per certificate in the CA database. Files
  are written under `<output_dir>/<sha1-issuer-key>/<sha1-issuer-name>/<serial>.ocsp`
  (compatible with nginx `proxy_cache`, Apache `mod_ssl_ct`, and any static
  file serving infrastructure). Each file is a DER-encoded `OCSPResponse` with
  `thisUpdate=now` and `nextUpdate=now+validity_hours`; good/revoked/unknown status
  from the DB. Returns the count of files written. New `pypki_admin.py` subcommand
  `ocsp-prebuild --ca-dir DIR --output DIR --validity-hours N` calls the function
  from the command line. Tests in `TestOCSPStaticResponses` (7 tests) verify count,
  file creation, three-level path layout, integer serial filenames, valid DER
  OCSPResponse structure, revoked status encoding, and CLI subcommand execution.

- **§5.6 — Cross-signing.** New `CertificateAuthority.cross_sign(other_cert, validity_days)`
  issues a certificate with the same subject DN and public key as an existing certificate,
  signed by this CA. Enables CA algorithm migrations (RSA → ECC → ML-DSA) and dual-trust
  path deployments: clients trusting the old root continue using the old-signed copy;
  clients trusting the new root use the cross-signed copy. Extensions copied from source:
  BasicConstraints (critical, ca flag + path_length preserved), KeyUsage, SubjectAlternativeName.
  Generated fresh: SubjectKeyIdentifier, AuthorityKeyIdentifier (from this CA's key),
  AIA/CDP from this CA's configured URLs. Serial from `_next_serial()`, validity from
  `not_valid_before=now`. Cross-signed certs stored in DB with `profile='cross_signed'`
  and audit-logged with both source and destination SHA-256 fingerprints (first 16 hex
  chars). New `POST /api/cross-sign` web UI endpoint (admin auth required) accepts
  `{"certificate_pem": "...", "validity_days": N}` and returns `{"certificate_pem":
  "...", "serial": N}`. Tests in `TestCrossSign` (10 tests) verify subject/SPKI
  preservation, fresh serial, correct issuer and AKI, signature verification, DB storage,
  BasicConstraints for both CA and EE certs, and source immutability.

- **§5.8 — SCEP single-use OTP challenge passwords.** Replaces the static shared
  secret with per-enrollment one-time passwords. New `SCEPDatabase.add_otp(ttl_seconds)`
  mints a 32-character URL-safe base64 token (24 random bytes, stored in new
  `otp_tokens` table); `consume_otp(token)` atomically marks it used via
  `BEGIN IMMEDIATE` transaction; `purge_expired_otps()` cleans up stale rows.
  New `SCEPHandler.use_otp = True` class attribute activates the OTP path
  (checked first; falls back to static challenge if also set — mixed mode).
  New module-level `mint_otp(ca_dir, ttl_seconds)` helper allows the web UI
  and admin scripts to mint OTPs without a handler reference. New
  `POST /api/scep/otp` web UI endpoint (requires admin auth) calls `mint_otp`
  and returns `{"otp": token, "ttl_seconds": n}`. CLI: new `--scep-use-otp`
  flag enables OTP mode at startup. Tests in `TestSCEPOneTimePasswords` (13
  tests) cover minting, single-use enforcement, expiry, purge, module helper,
  handler wiring, proxy `scep_db` exposure, and mixed-mode compatibility.

- **RFC 8295 — EST server-generated keys endpoint.** `POST /.well-known/est/serverkeygen`
  returns a `multipart/mixed` response with two base64-encoded parts: an
  `application/pkcs7-mime; smime-type=certs-only` cert chain and an
  `application/pkcs8` PKCS#8 PrivateKeyInfo (RFC 5958 compliant — not legacy
  PKCS#1). An optional PKCS#10 CSR body is accepted for subject/SAN hints and
  profile-specific SAN validation. Tests in `TestRFC8295ESTExtensions` (11 tests)
  verify the multipart structure, PKCS#7 cert validity, PKCS#8 key format, and
  the binding guarantee that the cert's public key matches the returned private key.

- **RFC 5083 + RFC 5084 — AES-GCM AuthEnvelopedData in SCEP CMS.** Eliminates
  the CBC padding-oracle surface from SCEP-encrypted CSR payloads.

  *New `CMSBuilder.auth_enveloped_data(plaintext, recipient_cert)`*: builds a
  DER-encoded `ContentInfo { id-ct-authEnvelopedData, AuthEnvelopedData }` using
  AES-256-GCM. Key transport: RSA PKCS#1v15 (same as the existing
  `enveloped_data`). CEK: 32-byte random; GCM nonce: 12-byte random; auth tag:
  16-byte (maximum, stored in the `mac` field per RFC 5083 §2). `GCMParameters`
  includes `aes-ICVlen=16` (explicit, since default is 12 per RFC 5084 §3.1).

  *Extended `CMSParser.parse_enveloped_data(der, key)`*: now dispatches on the
  `ContentInfo` OID — `id-envelopedData` → existing AES-CBC / 3DES-CBC path;
  `id-ct-authEnvelopedData` → new GCM path (`_decrypt_auth_enveloped`). The
  calling signature is unchanged; SCEP `PKCSReq` handling automatically benefits
  from both paths.

  *New `_cms_content_type(der)`* module-level helper peeks at the `ContentType`
  OID of a `ContentInfo` without fully parsing it — used by `_handle_pki_request`
  to log whether incoming CSR payloads use CBC or GCM.

  *`GetCACaps` response* now includes `AES-GCM` in addition to `AES`; SCEP
  clients that read capabilities will offer GCM-encrypted CSRs.

  *16 new tests in `TestRFC5083AuthEnvelopedData`*: OID verification, builder
  round-trips (empty / short / 4 096-byte), GCMParameters nonce length (12 B)
  and ICVlen (16), wrong-key failure, tampered-ciphertext / tampered-mac-tag
  auth failures, CBC dispatch unchanged, GCM dispatch, GetCACaps token, and
  `_cms_content_type` helper.

- **RFC 3161 + RFC 5816 — Time-Stamp Authority (TSA) server.** New
  `tsa_server.py` implements a complete RFC 3161 TSA with RFC 5816
  `signingCertificateV2`.

  *Protocol*: POST `<prefix>` accepts `application/timestamp-query` DER,
  responds with `application/timestamp-reply`. `TimeStampReq` parser
  handles `version`, `messageImprint`, `nonce`, `certReq`, and `reqPolicy`.
  `TimeStampResp` contains a CMS `SignedData` (v3) wrapping a `TSTInfo`
  as `id-ct-TSTInfo` encapsulated content.

  *RFC 5816 compliance*: every `TimeStampToken` carries a
  `signingCertificateV2` signed attribute containing an `ESSCertIDv2`
  (SHA-256 hash of the TSA signing cert DER). Signed attributes are
  DER-canonical SET OF (lexicographically sorted).

  *Hash policy*: SHA-256, SHA-384, and SHA-512 accepted. SHA-1 and MD5
  rejected with `failInfo=badAlg` per current NIST SP 800-131A guidance.

  *TSA signing cert*: auto-provisioned from the CA on first start
  (`tsa.key` / `tsa.crt` in the CA directory). Per RFC 3161 §2.3: EKU
  `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8) is the **only** EKU and is
  marked **critical**; KU is `digitalSignature` only; valid for 365 days.

  *New CLI flags*: `--tsa-prefix PREFIX` (activates the TSA),
  `--tsa-policy-oid OID` (default: placeholder — assign a real PEN OID
  for production), `--tsa-accuracy-seconds N` (declared accuracy, default
  1), `--tsa-cert PATH` / `--tsa-key PATH` (use pre-provisioned TSA cert).

  *`CertProfile.PROFILES`*: new `tsa_signing` entry with `eku_critical=True`
  so `issue_certificate(..., profile="tsa_signing")` automatically emits
  the critical EKU.

  *Serial counter*: monotonic, file-backed `tsa_serial.txt` in the CA
  directory; thread-safe.

  *25 new tests* in `TestRFC3161TSA`: request parsing, granted response
  structure, TSTInfo field echoing (messageImprint, nonce, serialNumber),
  `signingCertificateV2` correctness, CMS signature verification and
  corruption detection, hash algorithm policy enforcement, serial
  monotonicity, and TSA cert RFC compliance.

- **Multi-algorithm CA — RFC 4055, RFC 5480 + RFC 5758, RFC 8410.** A
  single refactor lifts PyPKI from RSA-only signing to full support for
  RSASSA-PSS, ECDSA (P-256/384/521), and EdDSA (Ed25519/Ed448) at the CA
  level.

  *New module-level helpers in `pki_server.py`*: `_hash_for_key(key)`
  picks the right hash class per key type (SHA-256 for RSA, matched-curve
  SHA-2 for ECDSA per RFC 5758 §3.2, `None` for EdDSA). `_sign_builder(
  builder, key, *, rsa_pss=False)` and `_sign_data(key, data, *,
  rsa_pss=False)` dispatch to the correct `sign()` shape for each key
  type. `_generate_ca_key(key_type)` reads from `_CA_KEY_FACTORIES`, a
  catalog covering rsa-2048/3072/4096, ec-p256/p384/p521, ed25519, and
  ed448. `_eddsa_compatible_with_cms(key)` powers the SCEP guardrail.

  *`CertificateAuthority` constructor* accepts `ca_key_type` and
  `sig_algorithm`. `_load_or_create_ca` calls `_generate_ca_key`;
  `ca.key` is persisted as PKCS#8 `PrivateKeyInfo` (RFC 5958) so EC and
  EdDSA keys round-trip cleanly. Once `ca.key` exists on disk, the flag
  is ignored — switching algorithms requires a fresh CA dir.

  *All CA-key-signing call sites migrated.* `issue_certificate`, sub-CA
  issuance, `issue_client_cert`, three CRL builders (`generate_crl`,
  `generate_crl_der`, `generate_delta_crl`), name-constraints cert,
  CT-embedded cert, and the OCSP / IPsec signer-cert provisioners in
  `ocsp_server.py` and `ipsec_server.py` all go through `_sign_builder`
  with the CA's signature padding choice. Signature algorithm OIDs in
  issued certs and CRLs are now correct per RFC 5758 §3.2
  (`ecdsa-with-SHA256`/384/512) or RFC 8410 (`1.3.101.112` Ed25519,
  `1.3.101.113` Ed448).

  *New CLI flags in `pki_server.py`*: `--ca-key-type` (default
  `rsa-4096`) with choices `rsa-2048`, `rsa-3072`, `rsa-4096`,
  `ec-p256`, `ec-p384`, `ec-p521`, `ed25519`, `ed448`; and
  `--sig-algorithm` (default `rsa-pkcs1v15`) with choices
  `rsa-pkcs1v15`, `rsa-pss` for RSA CAs. ECDSA / EdDSA keys ignore
  `--sig-algorithm` (each has a single signature scheme).

  *SCEP guardrail.* SCEP is CMS-based (RFC 8894 §3 ⇒ RFC 5652) and
  requires a named digest algorithm in `SignerInfo`. The existing signer
  hardcodes RSA-PKCS1v15. `start_scep_server` now refuses to register
  the handler when the CA key is not RSA, with a clear actionable error
  pointing at `--ca-key-type rsa-...`. ECDSA support inside CMS is a
  separate work item.

  *Verified by `TestMultiAlgorithmCA` (19 tests)*: hash-for-key dispatch
  across RSA/ECC/EdDSA; key-factory catalog enumeration; per-curve
  signature OID assertions (P-256→ecdsa-with-SHA256, P-384→SHA384,
  P-521→SHA512); Ed25519 / Ed448 SPKI OIDs; PSS signature OID
  (`1.2.840.113549.1.1.10`); invalid sig-algorithm rejection; end-to-end
  leaf issuance through an EC-P256 CA producing the right signature OID
  on the leaf and preserving the RSA SPKI from the CSR; Ed25519 CA
  signature verification against the CA public key; EC CA CRL signed and
  verified; CA key persisted as PKCS#8 (not SEC1 / PKCS#1); SCEP
  guardrail refuses Ed25519 CA at startup with a clear error.

- **RFC 8738 — ACME IP identifier support.** ACME orders may now carry
  `{"type": "ip", "value": "<IPv4-or-IPv6>"}` identifiers per RFC 8738
  §3. The identifier value is parsed with `ipaddress.ip_address()`;
  private, loopback, link-local, multicast, reserved, and unspecified
  addresses are rejected with `rejectedIdentifier` unless the new
  `--acme-allow-private-ip` flag is set (off by default to mirror public-CA
  practice). Authorizations for `ip` identifiers offer only the `http-01`
  and `tls-alpn-01` challenge types — `dns-01` is omitted per RFC 8738 §4
  (there is no reverse-DNS variant). On finalize, the CSR's `iPAddress`
  SAN entries must cover the order's `ip` identifiers; the issued cert
  carries each as an `iPAddress` SAN (never `dNSName`). `http-01`
  validation correctly brackets IPv6 literals in the URL per RFC 3986
  §3.2.2. Verified by `TestRFC8738ACMEIPId` (16 tests): validator helper
  acceptance/rejection across DNS, public IPv4/IPv6, private IPv4,
  malformed values, and unknown types; per-identifier challenge
  selection in `create_order` (ip → no dns-01, dns → all three, mixed
  orders); `http-01` URL bracketing for IPv4 / IPv6 / hostname;
  `--acme-allow-private-ip` plumbing through `make_acme_handler` /
  `start_acme_server`; and end-to-end finalize producing `iPAddress`-only
  certs.

- **RFC 7468 — strict textual encoding parser for external PEM bundles.**
  New helper `_parse_pem_bundle(data, allowed_labels=None)` in
  `pki_server.py` tokenises a PEM bundle into `(label, der_bytes)` pairs,
  enforcing every framing rule in RFC 7468 §3: uppercase-only boundary
  markers (`-----BEGIN <LABEL>-----` / `-----END <LABEL>-----`), matching
  labels, only whitespace permitted outside encapsulation boundaries
  (no explanatory text between or after blocks), and a strict base64
  alphabet (`A–Za–z0–9+/` with at most two trailing `=`). Both canonical
  64-column wrapping and unwrapped base64 are accepted as long as the
  alphabet is valid. `_load_parent_chain` now ingests `ca-chain.pem`
  through the helper with `allowed_labels={"CERTIFICATE"}`, so any
  tampering with the chain file — lowercase markers, label substitution,
  trailing junk, or a stray `PRIVATE KEY` block — surfaces a clear
  `ValueError` instead of silently misparsing. The default allowlist for
  imports is `CERTIFICATE`, `X509 CRL`, `PKCS7`. Verified by
  `TestRFC7468PEM` (15 tests): canonical and unwrapped acceptance,
  multi-block concatenation, round-trip with `x509.load_der_x509_certificate`,
  lowercase / mismatch / trailing-data / invalid-base64 / empty-body /
  missing-END rejection, allowlist enforcement, and integration through
  `_load_parent_chain`.

- **RFC 8954 — OCSP nonce extension profile enforcement.** The OCSP
  request parser now enforces the RFC 8954 §2.1 nonce-length bounds
  (1 ≤ len ≤ 32 bytes) after unwrapping the inner OCTET STRING.
  Out-of-bounds nonces (including 0-byte) are flagged at parse time and
  the handler returns `malformedRequest` (status 1). Valid nonces are
  echoed verbatim per RFC 6960 §4.4.1. New CLI flag
  `--ocsp-require-nonce` enables strict mode: nonceless requests are
  rejected with `unauthorized` (status 6). Off by default to match the
  RFC 6960 default; useful against MITM replay of cached responses. Test
  coverage in `TestRFC8954OCSPNonce`: 1/8/16/32-byte boundary
  acceptance, 33/64/128-byte rejection, empty nonce rejection, strict
  mode behaviour both ways.

### Changed

- **RFC 5958 — CMP private-key output normalized to PKCS#8.** Replaced
  all five `PrivateFormat.TraditionalOpenSSL` callsites (four in
  `cmp_server.py` covering `ir` auto-generated key, PKCS#12 bundle path,
  API key return, and enrollment response private-key field; one in
  `web_ui.py` covering sub-CA export) with `PrivateFormat.PKCS8`.
  CMP responses now emit `PrivateKeyInfo` instead of legacy
  `RSAPrivateKey` / `ECPrivateKey`. No compatibility risk — every modern
  client (OpenSSL 1.1+, strongSwan, Java keytool, Windows certutil)
  reads PKCS#8 transparently, and the change is a prerequisite for ECC
  CA support. Verified by `TestRFC5958PKCS8`. Internal CA-key-on-disk
  writes (`pki_server.py`, `ocsp_server.py`, `ipsec_server.py`) still
  use `TraditionalOpenSSL` and are tracked for a follow-up cleanup
  pass — those files are read only by PyPKI itself, so the divergence
  is purely cosmetic.

### Documentation

#### RFC compliance analysis — RFC 9370, RFC 9180, RFC 9763

Assessed three additional RFCs for relevance to PyPKI:

**RFC 9370 — Multiple Key Exchanges in IKEv2** — Not applicable. This RFC
governs the IKEv2 VPN handshake protocol (multiple hybrid PQC+classical key
exchange rounds during SA setup). It is implemented by VPN gateways such as
strongSwan, Cisco IOS-XE, and Palo Alto PAN-OS — not by the PKI server that
issues their certificates. PyPKI's existing RFC 4945 / RFC 4806 / RFC 4809
coverage addresses all CA-side obligations for IKEv2 deployments. Added to
Protocol compliance table with N/A status and rationale.

**RFC 9180 — HPKE (Hybrid Public Key Encryption)** — Not applicable. HPKE is
an encryption scheme used in TLS Encrypted Client Hello (ECH), Oblivious HTTP
(OHTTP), and Messaging Layer Security (MLS). It has no intersection with X.509
certificate issuance or management. Added to Protocol compliance table with N/A
status and rationale.

**RFC 9763 — Related Certificates for Multiple Authentications** — Relevant;
planned. Defines a `relatedCertRequest` CSR attribute and a `RelatedCertificate`
X.509 extension (OID `1.3.6.1.5.5.7.1.36`) for linking a classical cert to its
PQC counterpart. Primary use case is dual-certificate TLS 1.3 authentication
during the classical → ML-DSA migration period. Implementation is deferred
until ML-DSA support is available (the two features are co-dependent). Added to
Protocol compliance table with 🗓️ Planned status and to the Roadmap section.

#### Roadmap updates

- ML-DSA prerequisites clarified: the `cryptography` pre-built wheel bundles
  its own OpenSSL; rebuilding from source (`--no-binary cryptography`) against
  system OpenSSL 3.3+ is required to expose the `mldsa` binding
- RFC 9763 roadmap entry added alongside ML-DSA, covering `issue_certificate_pair()`,
  `RelatedCertificate` extension embedding, CSR `relatedCertRequest` parsing,
  and `POST /api/certs/<serial>/related` endpoint

---

## [0.10.0] — 2026-03-01

### Added — Intermediate CA support + zero-downtime TLS certificate reload; 35 new tests (260 total, 35 test classes)

#### 1. Intermediate CA support (`pki_server.py`)

PyPKI can now operate as an **intermediate (subordinate) CA** — signed by an
external root CA — while still issuing leaf certificates, generating CRLs,
responding to OCSP requests, and serving all five certificate management
protocols (CMP, ACME, SCEP, EST, IPsec).

**Core infrastructure**

`CertificateAuthority.__init__` gains an optional `parent_chain_path: str`
parameter pointing to a PEM file containing one or more parent CA certificates
(immediate issuer first, root last).

`_load_parent_chain(path)` — validates that the first certificate in the file
actually signed the CA's own certificate (raises `ValueError` otherwise),
then validates chain continuity upward to the root.  The chain is stored in
`self._parent_chain` as a list of `x509.Certificate` objects.

Auto-discovery: if `parent_chain_path` is `None`, the server automatically
looks for `<ca_dir>/ca-chain.pem` and loads it silently if present.  Place the
chain file there and no CLI flag is needed.

New properties:
- `is_intermediate: bool` — `True` when at least one parent cert is loaded
- `ca_chain_ders: List[bytes]` — DER bytes `[own_cert, parent, …, root]`
- `ca_chain_pem: bytes` — concatenated PEM in the same order

New CLI flag:
- `--parent-cert PATH` — path to the parent chain PEM file

Startup banner: new **CA Mode** line shows `intermediate (N parent cert(s))`
or `root (self-signed)`.

**TLS chain presentation**

`provision_tls_server_cert()` appends parent chain PEM blocks to `server.crt`
so that `ssl.SSLContext.load_cert_chain()` sends the complete intermediate
chain to TLS clients.  Browsers and TLS stacks that don't already have the
intermediate in their trust cache will receive it during the handshake.

`build_tls_context()` and `build_ssl_context()` updated to load the full chain
for mTLS client verification.

**PKCS#12 export**

`export_pkcs12()` includes all parent certificates in the PKCS#12 CA bag so
that importing applications (browsers, OS key stores) can build the complete
path to the root.

**Protocol chain serving** — all five protocols now serve the full chain:

| Module | Change |
|---|---|
| `cmp_server.py` | `GET /ca/cert.pem`, `GET /.well-known/cmp`, `GetCACerts` genm, bootstrap bundle — all serve `ca_chain_pem` |
| `est_server.py` | `/cacerts`, `simpleenroll`, `simplereenroll`, `serverkeygen` — PKCS#7 bags include full chain via new `ESTCMSBuilder.certs_only_chain(chain_ders)` |
| `scep_server.py` | `GetCACert` — returns plain DER for root CAs; returns PKCS#7 p7c containing full chain for intermediate CAs (RFC 8894 §4.2) |
| `ipsec_server.py` | `GET /ipsec/ca-cert` serves `ca_chain_pem` |
| `web_ui.py` | `GET /ca/cert.pem` serves full chain; dashboard shows **CA Mode** and **Chain Depth** |

**Using PyPKI as a Let's Encrypt-chained intermediate**

Let's Encrypt does not operate a subordinate CA program for third parties.
This feature is designed for **private PKI hierarchies** — your own root signs
your intermediate, which runs this server.  For publicly-trusted leaf
certificates, combine with option 1 (Let's Encrypt TLS on the server endpoints
via `--tls-cert` / `--tls-key`; zero intersection between the two chains).

Test class: `TestIntermediateCA` (21 tests) — chain loading, validation
rejection, `ca_chain_ders`/`ca_chain_pem` properties, `is_intermediate` flag,
issued-cert issuer, PKCS#12 CA bag, `server.crt` chain content, auto-discovery
of `ca-chain.pem`.

---

#### 2. Zero-downtime TLS certificate reload (`cmp_server.py`, `est_server.py`, `ipsec_server.py`, `pki_server.py`)

All three TLS-capable servers (CMP, EST, IPsec) can now reload their TLS
certificate from disk **without restarting and without dropping in-flight
connections**.  This is the key integration point for Let's Encrypt: point
`--tls-cert` at certbot's `fullchain.pem` and the server picks up every
90-day renewal automatically.

**`TLSContextHolder`** (`cmp_server.py`)

Thread-safe, atomically-swappable wrapper around `ssl.SSLContext`.

- `get()` — returns the current context (lock-free, GIL-safe fast path)
- `swap(new_ctx)` — atomically replaces the context; all new connections
  immediately use the new certificate; in-flight TLS handshakes are
  unaffected
- `ssl_context` property shim — existing code that sets `srv.ssl_context`
  directly continues to work without modification

**`TlsCertWatcher`** (`cmp_server.py`)

Background daemon thread that polls a cert file's mtime every N seconds.

- When mtime advances (certbot wrote a new cert), calls `build_ctx()` to
  construct a fresh `SSLContext` and calls `holder.swap()`
- If the build fails (malformed cert, mismatched key), logs the error and
  **keeps the old context** — the server stays up and retries on the next
  poll cycle
- `reload_now()` — forces an immediate reload regardless of mtime; used
  by the API endpoint and by the `start()` / `stop()` lifecycle

**`TLSServer`** (`cmp_server.py`)

Refactored to read from `ctx_holder.get()` on every `get_request()` call
instead of holding a single context at startup.  The `ssl_context` attribute
shim preserves backward compatibility.

**EST and IPsec servers refactored to per-connection wrapping**

Both previously wrapped the listening socket once at startup
(`srv.socket = ctx.wrap_socket(...)`), making in-process reload impossible.
Both are now converted to the same per-connection pattern as `TLSServer`,
with their own `_TLSThreadedServer` inner class and a shared
`TLSContextHolder`.

**`POST /api/reload-tls`** (`cmp_server.py`)

New management endpoint — forces an immediate TLS certificate reload from
disk.  Returns `{"ok": true}` on success or HTTP 500 on failure.

Designed as a certbot deploy-hook target:

```
/etc/letsencrypt/renewal-hooks/deploy/pypki-reload.sh
---
#!/bin/sh
curl -sf -X POST https://pki.example.com:8080/api/reload-tls
```

**New CLI flag** (`pki_server.py`)

`--tls-reload-interval SECS` — seconds between cert-file mtime polls
(default: 60).  Set `0` to disable the automatic watcher and rely solely on
`POST /api/reload-tls`.

**Startup banner** — new **TLS Cert Reload** row shows the poll interval and
the API endpoint, or `n/a (no TLS)` for plain-HTTP mode.

**Graceful shutdown** — `KeyboardInterrupt` handler stops all watcher threads
before shutting down the HTTP servers.

**Let's Encrypt quick-start:**

```bash
# Obtain cert once
certbot certonly --standalone -d pki.example.com

# Start PyPKI — watcher picks up every renewal within 60 s
python pki_server.py \
  --tls \
  --tls-cert /etc/letsencrypt/live/pki.example.com/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/pki.example.com/privkey.pem \
  --tls-reload-interval 60
```

Test class: `TestTlsCertWatcher` (14 tests) — `TLSContextHolder` get/swap/
property/thread-safety, `TlsCertWatcher.reload_now()` success/swap/failure/
auto-poll/stop, CMP server ctx_holder attachment, `reload_tls()` callable,
returns-True on success, swaps context, plain-HTTP returns False.

---

### Changed

- `CertificateAuthority.__init__`: new `parent_chain_path` parameter
- `provision_tls_server_cert()`: appends parent chain blocks to `server.crt`
- `build_tls_context()` / `build_ssl_context()`: full chain for mTLS trust store
- `export_pkcs12()`: parent certs included in CA bag
- `start_cmp_server()`: new `tls_reload_interval` parameter; returns server with `reload_tls()` and `_tls_watcher`
- `start_est_server()`: new `tls_reload_interval` parameter; per-connection TLS wrapping
- `start_ipsec_server()`: per-connection TLS wrapping; reads `ca._tls_reload_interval`
- `CMPv2HTTPHandler.do_POST_api()`: new `POST /api/reload-tls` branch
- `CMPv2HTTPHandler` GET docs: `POST /api/reload-tls` listed
- Startup banner: `CA Mode` row, `TLS Cert Reload` row
- `main()` shutdown: stops TLS watchers before shutting down servers

### Fixed

- No bug fixes in this release; all changes are additive

---

## Releasing v0.10.0

```bash
git add pki_server.py cmp_server.py est_server.py ipsec_server.py \
        scep_server.py web_ui.py test_pki_server.py CHANGELOG.md README.md
git commit -m "v0.10.0: intermediate CA support + zero-downtime TLS cert reload

Intermediate CA:
- --parent-cert PATH / auto-discover ca-chain.pem
- _load_parent_chain(): validates issuer signature + chain continuity
- ca_chain_pem / ca_chain_ders / is_intermediate properties
- provision_tls_server_cert(): appends parent chain to server.crt
- export_pkcs12(): parent certs in PKCS#12 CA bag
- cmp_server: /ca/cert.pem, GetCACerts, well-known, bootstrap serve full chain
- est_server: /cacerts, simpleenroll, serverkeygen PKCS#7 include full chain
- scep_server: GetCACert returns p7c for intermediate CAs (RFC 8894 §4.2)
- ipsec_server: /ipsec/ca-cert serves ca_chain_pem
- web_ui: CA Mode + Chain Depth in dashboard, chain PEM endpoint
- TestIntermediateCA: 21 tests

Zero-downtime TLS reload:
- TLSContextHolder: atomic ssl.SSLContext swap, ssl_context shim
- TlsCertWatcher: mtime-polling daemon thread, keeps old ctx on failure
- TLSServer: per-connection wrapping from ctx_holder.get()
- EST, IPsec: converted from socket-wrap to per-connection TLS
- POST /api/reload-tls: certbot deploy-hook target
- --tls-reload-interval SECS (default 60; 0 = watcher disabled)
- TestTlsCertWatcher: 14 tests

260 tests total (35 test classes)"

git tag -a v0.10.0 -m "v0.10.0: intermediate CA + zero-downtime TLS reload, 260 tests"
git push && git push origin v0.10.0

gh release create v0.10.0 \
  --title "v0.10.0 — Intermediate CA + Zero-Downtime TLS Cert Reload" \
  --notes-file CHANGELOG.md
```

---

## [0.9.0] — 2026-02-26

### Added — 13 "nice-to-have" features; 63 new tests (241 total, 33 test classes)

#### 1. Key Archival / Key Escrow

`archive_private_key(serial, private_key_pem, password)` — encrypts a subscriber PEM
private key with AES-256-CBC and stores it in a dedicated `key_archive` SQLite table.

`recover_private_key(serial, password)` — decrypts and returns the PEM; wrong password
raises `ValueError`.

HTTP endpoints:
- `POST /api/certs/<serial>/archive` — `{"private_key_pem": "...", "password": "..."}`
- `POST /api/certs/<serial>/recover` — `{"password": "..."}`

Test class: `TestKeyArchival` (7 tests)

---

#### 2. Name Constraints Extension (RFC 5280 §4.2.1.10)

`issue_certificate_with_name_constraints(subject, public_key, permitted_dns, excluded_dns,
permitted_ip)` — issues a sub-CA certificate with a critical `NameConstraints` extension
(OID `2.5.29.30`).

Supports:
- `permitted_dns` / `excluded_dns` — list of DNS zone strings (e.g. `".corp.example.com"`)
- `permitted_ip` — list of CIDR strings (e.g. `"10.0.0.0/8"`)
- Extension is always **critical** per RFC 5280 §4.2.1.10

Test class: `TestNameConstraints` (7 tests)

---

#### 3. Certificate Expiry Monitoring

`expiring_certificates(days_ahead=30)` — returns a list of `{serial, subject, not_after,
days_left, profile}` dicts for certs expiring within `days_ahead` days.

`start_expiry_monitor(days_ahead, callback, interval_seconds=86400)` — starts a background
`threading.Thread` that calls `callback(cert_info)` for each expiring cert on schedule.

HTTP endpoint:
- `GET /api/expiring?days=<N>` — JSON array; default 30 days

Test classes: `TestExpiryMonitor` (6 tests), `TestCertFilterEndpoint` (8 tests)

---

#### 4. One-Shot Certificate Renewal

`renew_certificate(serial)` — fetches the original cert's subject, SAN, profile, and
public key from the database and calls `issue_certificate()` with a new serial and fresh
validity window.

HTTP endpoint:
- `POST /api/certs/<serial>/renew` — returns `{"serial": ..., "subject": ..., "not_after": ...}`

Old certificate is not automatically revoked.

Test class: `TestCertificateRenewal` (9 tests)

---

#### 5. Prometheus `/metrics` Endpoint

`get_metrics()` — returns a dict of counters from the database and in-memory state.

`metrics_prometheus()` — renders the dict as `text/plain` Prometheus exposition format with
`# HELP` and `# TYPE` lines.

HTTP endpoint:
- `GET /metrics` — `Content-Type: text/plain; version=0.0.4`

Counters exposed: `pypki_certs_issued_total`, `pypki_certs_revoked_total`,
`pypki_ocsp_fetches_total`, `pypki_rate_limit_hits_total`, `pypki_crl_updates_total`.

Test class: `TestPrometheusMetrics` (9 tests)

---

#### 6. TLS 1.3-Only Mode

`build_tls_context(tls13_only=True)` — sets `ssl.TLSVersion.TLSv1_3` as both `minimum_version`
and `maximum_version` on the returned `SSLContext`. TLS 1.2 connections are refused at the
handshake layer.

CLI flag:
- `--tls13-only` — applies to all TLS server sockets (CMPv2, ACME, EST, SCEP)

Default: off (TLS 1.2 + 1.3 both accepted).

Test class: `TestTLS13Only` (5 tests)

---

#### 7. OCSP Stapling Cache

`fetch_ocsp_staple(serial, ocsp_responder_url, ttl_seconds=3600)` — fetches an OCSP
response for the given serial from `ocsp_responder_url`, caches it in memory for
`ttl_seconds`, and returns the DER bytes. Returns `None` if the fetch fails or no OCSP
URL is configured.

`invalidate_ocsp_staple(serial)` — removes the cached staple immediately (call on
revocation).

Cache is stored as `_ocsp_staple_cache: Dict[int, Tuple[bytes, float]]` — a lazy attribute
on the `CertificateAuthority` instance.

Test class: `TestOCSPStapling` (6 tests)

---

#### 8. Certificate Transparency (CT Log Submission)

`submit_to_ct_log(cert_der, issuer_cert_der, log_url)` — POSTs the chain to
`<log_url>/ct/v1/add-chain` and returns the raw SCT bytes (DER). Network errors are
caught and logged; `None` is returned on failure.

`embed_scts(cert_der, scts)` — embeds a list of SCT byte strings into the
`SignedCertificateTimestampList` extension (OID `1.3.6.1.4.1.11129.2.4.2`) and returns
updated DER.

`issue_certificate_with_ct(subject, public_key, log_urls, **kwargs)` — issues a cert,
submits to each log URL, and embeds all received SCTs.

Pre-defined class-level constants:
- `CT_LOG_ARGON_2025 = "https://ct.googleapis.com/logs/us1/argon2025h2/"`
- `CT_LOG_XENON_2025 = "https://ct.googleapis.com/logs/us1/xenon2025h2/"`

Test class: `TestCertificateTransparency` (7 tests)

---

#### 9. ACME `dns-01` Production Hooks

`make_dns01_webhook_hook(hook_url, timeout=10)` — factory returning a callable that
POSTs `{"domain": ..., "token": ..., "key_auth": ...}` to `hook_url` to create/delete
DNS TXT records.

`make_dns01_rfc2136_hook(nameserver, zone, key_name, key_algorithm, key_secret)` — factory
returning a callable that builds RFC 2136 `nsupdate`-compatible DNS UPDATE packets using
`dnspython` (optional; raises `ImportError` with a clear message if absent).

Both hooks return `True` on success and `False`/raise on failure. Pass the callable to the
ACME server's `dns01_hook` parameter to enable real `dns-01` validation.

Test class: `TestDNS01Hooks` (5 tests)

---

#### 10. OpenTelemetry Tracing

`_setup_otel(service_name)` — initialises the OpenTelemetry tracer. If the
`opentelemetry` package is not installed, a no-op tracer (`_NoOpSpan`, `_NoOpTracer`)
is used transparently — no `ImportError`, no configuration required.

`_get_tracer()` — returns the configured tracer (real or no-op).

Instrumented call sites: `issue_certificate`, `revoke_certificate`, `generate_crl`,
and every HTTP request handler.

Span attributes: `cert.serial`, `cert.profile`, `cert.subject`, `http.status_code`,
`http.method`, `http.path`.

CLI: pass `OTEL_EXPORTER_OTLP_ENDPOINT` + `OTEL_SERVICE_NAME` env vars to activate.

Test class: `TestOpenTelemetryNoOp` (4 tests)

---

#### 11. `datetime.timezone.utc` migration (correctness fix)

All 14 remaining calls to `datetime.datetime.utcnow()` replaced with
`datetime.datetime.now(datetime.timezone.utc)`. The returned `datetime` is now
timezone-aware throughout, eliminating Python 3.12 `DeprecationWarning` messages and
ensuring correct UTC handling on systems with non-UTC local clocks.

Test class: `TestDatetimeTimezoneAwareness` (4 tests)

---

#### 12. Random CA root serial number (RFC 5280 §4.1.2.2)

The self-signed root CA certificate now uses `x509.random_serial_number()` for its
serial, matching the requirement in RFC 5280 §4.1.2.2 and CA/B Forum BR §7.1.

Test class: `TestRandomCASerial` (3 tests)

---

### Changed

- `CertificateAuthority.__init__`: calls `_init_key_archive_table()` on startup
- `do_GET` / `do_POST` in `CMPv2HTTPHandler`: dispatch added for `/metrics`,
  `/api/expiring`, `/api/certs/<serial>/renew`, `/api/certs/<serial>/archive`,
  `/api/certs/<serial>/recover`
- Startup banner updated to include Metrics URL
- Module docstring updated with all new feature descriptions

### Fixed

- `datetime.datetime.utcnow()` deprecated since Python 3.12 — replaced with
  `datetime.datetime.now(datetime.timezone.utc)` everywhere in both `pki_server.py`
  and `web_ui.py`

#### Web Dashboard (`web_ui.py`) — v0.9.0 update

`web_ui.py` was previously present in the working directory but had never been committed
to the repository. This release adds it to version control and updates it to match the
v0.9.0 feature set.

Changes from the v0.6.0 baseline:

- **Version badge** updated from `v0.6.0` to `v0.9.0`
- **New page — Expiring Certificates** (`/expiring`): lists all non-revoked certificates
  expiring within 30 days, sorted by days remaining; colour-coded rows (red ≤7d, amber ≤30d);
  per-row **Renew** button calls `POST /api/renew`
- **New page — Prometheus Metrics** (`/metrics-ui`): renders the full Prometheus text output
  from `ca.metrics_prometheus()` in a `<pre>` block; link to the raw `/api/metrics` scrape
  endpoint
- **`POST /api/renew`** — new REST endpoint; body `{"serial": N}`; calls
  `ca.renew_certificate(serial)`; returns `{"ok": true, "serial": <new>, "not_after": "..."}`
- **`GET /api/metrics`** — new REST endpoint; returns `ca.metrics_prometheus()` with
  content-type `text/plain; version=0.0.4` (Prometheus scrape-compatible)
- **Navigation bar**: two new links — `Expiring` and `Metrics` — inserted between
  `Certificates` and `Revocation`
- **API Docs page** updated with the two new endpoints
- **`datetime.utcnow()` → `datetime.now(timezone.utc)`** in `_dashboard()` and
  `_certs_page()` (Python 3.12 deprecation fix)
- `fromisoformat()` comparisons made timezone-aware throughout

---

## Releasing v0.9.0

```bash
git add pki_server.py test_pki_server.py web_ui.py CHANGELOG.md README.md
git commit -m "v0.9.0: 13 new features — key escrow, name constraints, expiry monitor,
  renewal, Prometheus /metrics, TLS 1.3-only, OCSP stapling cache, CT log submission,
  dns-01 RFC 2136 + webhook hooks, OpenTelemetry tracing, datetime/serial fixes.
  web_ui.py: add Expiring and Metrics pages, /api/renew, /api/metrics, Python 3.12 fixes.
  63 new tests (241 total, 33 test classes)"

git tag -a v0.9.0 -m "v0.9.0: 13 new features, 241 tests"
git push && git push origin v0.9.0

gh release create v0.9.0 \
  --title "v0.9.0 — Key escrow, CT, Prometheus, TLS 1.3-only & more" \
  --notes-file CHANGELOG.md
```

---

## [0.8.0] — 2026-02-25

### Added — RFC 9549/9598 IDNA, RFC 5280 §4.2.1.4 CertificatePolicies, 30 new tests

#### RFC 9549 / RFC 9598 — Internationalized Names (`pki_server.py`)

**Priority 2 from the v0.7.0 RFC compliance audit.**

New helper functions (module-level, importable):
- `_idna_encode_label(label)` — single DNS label U→A via Python's built-in IDNA codec;
  implicitly enforces `UseSTD3ASCIIRules` per RFC 6818 §5
- `_idna_encode_domain(domain)` — full FQDN, label-by-label, with `*` wildcard passthrough
- `_encode_smtp_utf8_mailbox(mailbox)` — DER UTF8String (tag `0x0C`) wrapping the UTF-8
  address; used as the `OtherName` value for `SmtpUTF8Mailbox`
- `_split_email(email)` — splits on `@`, raises `ValueError` on malformed input
- `_has_non_ascii(s)` — returns `True` if any code-point > U+007F

New OID constant:
- `OID_SMTP_UTF8_MAILBOX = x509.ObjectIdentifier("1.3.6.1.5.5.7.8.9")`

`issue_certificate()` — three new wiring points:

**`san_dns` — RFC 9549 §4.1: U-label → A-label**
- Every DNS SAN value passes through `_idna_encode_domain()` before being stored
- `münchen.de` → `xn--mnchen-3ya.de`; `sub.münchen.de` → `sub.xn--mnchen-3ya.de`
- Pure-ASCII domains pass through unchanged (no encoding overhead)
- Wildcard labels (`*`) preserved; only the non-wildcard labels are encoded
- `ValueError` from the IDNA codec is caught; a warning is logged and the value
  stored as-is (graceful degradation for edge-case inputs)

**`san_emails` — RFC 9549 §4.2 / RFC 9598: two-path routing**
- ASCII local-part + ASCII host → `rfc822Name` unchanged (`alice@example.com`)
- ASCII local-part + IDN host → `rfc822Name` with A-label host
  (`bob@münchen.de` → `bob@xn--mnchen-3ya.de`)
- Non-ASCII local-part → `SmtpUTF8Mailbox` `OtherName`
  (OID `1.3.6.1.5.5.7.8.9`, DER UTF8String value per RFC 9598 §3)
- Malformed addresses (no `@`) log a warning and are skipped

**`subject_str` / `DC=` — RFC 6818 §5 / RFC 9549 §4**
- `DC` added to `oid_map` → `NameOID.DOMAIN_COMPONENT`
- IDN `DC=` values (e.g. `DC=münchen`) automatically A-label encoded
- Pure-ASCII labels (e.g. `DC=example`, `DC=com`) pass through unchanged

#### RFC 5280 §4.2.1.4 / RFC 6818 §3 — CertificatePolicies (`pki_server.py`)

**Priority 3 from the v0.7.0 RFC compliance audit.**

New helper function:
- `_build_policy_information(oid, cps_uri=None, notice_text=None)`  
  Builds an `x509.PolicyInformation` with optional CPS URI qualifier (`id-qt-cps`)
  and/or `UserNotice` qualifier; `explicit_text` is always encoded as UTF8String
  per RFC 6818 §3

New OID constants:
- `OID_ANY_POLICY = x509.ObjectIdentifier("2.5.29.32.0")`
- `OID_POLICY_DV  = x509.ObjectIdentifier("2.23.140.1.2.1")` — CA/B Forum DV
- `OID_POLICY_OV  = x509.ObjectIdentifier("2.23.140.1.2.2")` — CA/B Forum OV
- `OID_POLICY_IV  = x509.ObjectIdentifier("2.23.140.1.2.3")` — CA/B Forum IV
- `OID_POLICY_EV  = x509.ObjectIdentifier("2.23.140.1.1")`   — CA/B Forum EV
- `OID_QT_CPS     = x509.ObjectIdentifier("1.3.6.1.5.5.7.2.1")` — id-qt-cps
- `OID_QT_UNOTICE = x509.ObjectIdentifier("1.3.6.1.5.5.7.2.2")` — id-qt-unotice

`issue_certificate()` — new `certificate_policies: Optional[List[dict]]` parameter:
- Each dict: `{"oid": "...", "cps_uri": "...", "notice_text": "..."}`
- `oid` is required; `cps_uri` and `notice_text` are optional
- Dict entries missing `oid` are silently skipped
- Empty list produces no extension
- Falls back to `CertProfile.get(profile).get("certificate_policies")` if the
  explicit parameter is `None`, so profiles can declare default policies
- Explicit parameter always overrides the profile default
- Extension is always non-critical (RFC 5280 §4.2.1.4 SHOULD)

#### Unit Test Suite expansion (`test_pki_server.py`)

30 new tests — total is now **178** across **20 test classes**.

`TestRFC9549IDNA` (13 tests):
- `test_ascii_dns_passes_through` — pure ASCII domain unchanged
- `test_u_label_dns_converted_to_a_label` — `münchen.de` → `xn--mnchen-3ya.de`
- `test_multi_label_idn_all_labels_encoded` — `sub.münchen.de` → `sub.xn--mnchen-3ya.de`
- `test_wildcard_label_preserved` — `*.example.com` stays unchanged
- `test_ascii_email_ascii_host_unchanged` — `alice@example.com` → `rfc822Name` as-is
- `test_ascii_local_idn_host_encoded` — `bob@münchen.de` → `bob@xn--mnchen-3ya.de` in `rfc822Name`
- `test_non_ascii_local_uses_smtp_utf8_mailbox` — `üser@münchen.de` → `SmtpUTF8Mailbox`; absent from `rfc822Name`
- `test_smtp_utf8_mailbox_oid_is_correct` — OID must be `1.3.6.1.5.5.7.8.9`
- `test_smtp_utf8_mailbox_value_is_utf8string` — first byte of value must be `0x0C`
- `test_smtp_utf8_mailbox_contains_original_address` — UTF-8 payload matches input
- `test_mixed_email_list_correct_routing` — mixed list routed correctly per address type
- `test_dc_attribute_accepted_in_subject` — `DC=` parsed to `DOMAIN_COMPONENT`
- `test_idn_dc_attribute_a_label_encoded` — `DC=münchen` stored as `DC=xn--mnchen-3ya`

`TestCertificatePolicies` (17 tests):
- `test_no_policies_by_default` — extension absent when not requested
- `test_single_policy_oid_added` — OID appears in extension
- `test_extension_is_non_critical` — `critical=False`
- `test_multiple_policies` — both OIDs present
- `test_cps_uri_qualifier_added` — CPS URI in policy qualifiers
- `test_policy_without_qualifiers_has_none` — `policy_qualifiers` is `None`
- `test_user_notice_added` — `UserNotice` in qualifiers
- `test_user_notice_explicit_text_utf8` — non-ASCII text survives DER round-trip
- `test_cps_uri_and_notice_together` — both qualifiers on same policy
- `test_cab_forum_dv_oid_constant` — `OID_POLICY_DV` == `2.23.140.1.2.1`
- `test_cab_forum_ov_oid_constant` — `OID_POLICY_OV` == `2.23.140.1.2.2`
- `test_cab_forum_ev_oid_constant` — `OID_POLICY_EV` == `2.23.140.1.1`
- `test_any_policy_oid_constant` — `OID_ANY_POLICY` == `2.5.29.32.0`
- `test_entry_missing_oid_skipped` — bad entry silently skipped
- `test_empty_policies_list_no_extension` — empty list → no extension
- `test_profile_level_policies_applied` — profile default applied
- `test_explicit_policies_override_profile_policies` — explicit overrides profile

### Changed

- `issue_certificate()` docstring substantially expanded: `certificate_policies`,
  `san_dns`, and `san_emails` parameter behaviour now fully documented
- Module docstring updated: RFC 9549/9598 and RFC 5280 §4.2.1.4 listed in features
- RFC compliance notes table in README updated: all ⚠️ rows promoted to ✅

### Fixed

- No bug fixes in this release; all changes are additive

---

## [0.7.0] — 2026-02-25

### Added — RFC 9608 (noRevAvail), Unit Test Suite, Module Rename

#### RFC 9608 — No Revocation Available Extension (`pki_server.py`, `acme_server.py`)

- New `OID_NO_REV_AVAIL = x509.ObjectIdentifier("2.5.29.56")` constant
- New `NO_REV_AVAIL_THRESHOLD_DAYS = 7` default threshold constant
- New `short_lived` certificate profile — adds `id-ce-noRevAvail`, suppresses CDP and AIA-OCSP per RFC 9608 §4
- `issue_certificate()` gains `no_rev_avail: Optional[bool]` parameter:
  - If `None` (default): inherited from the profile
  - If `True`: forces extension on; CDP and AIA-OCSP suppressed
  - Always forced `False` for CA certificates (RFC 9608 §4 MUST NOT)
- AIA OCSP extension now gated on `suppress_ocsp_aia` — suppressed automatically when `noRevAvail` is set
- CDP extension now gated on `suppress_cdp` — suppressed automatically when `noRevAvail` is set
- Extension encoding: OID `2.5.29.56`, `critical=False`, value = ASN.1 NULL (`05 00`)
- `acme_server.py`: `ACMEHandler` gains `cert_validity_days` (default 90) and `short_lived_threshold_days` (default 7) class attributes
- `acme_server.py`: `_handle_finalize()` auto-selects `short_lived` profile when `validity_days ≤ threshold`
- `acme_server.py`: `make_acme_handler()` and `start_acme_server()` accept `cert_validity_days` and `short_lived_threshold_days` parameters
- New CLI flags in `pki_server.py`:
  - `--acme-cert-days DAYS` — validity period for ACME-issued certificates (default: 90)
  - `--acme-short-lived-threshold DAYS` — noRevAvail auto-apply threshold (default: 7)

#### Unit + RFC Compliance Test Suite (`test_pki_server.py`)

- New file — 148 tests across 18 test classes, zero external dependencies (stdlib + `cryptography` only)
- RFC 5280 §4.1 — `TestRFC5280CertStructure` (9 tests): version v3, serial positivity/uniqueness/max-20-octets, SHA-256 signature, non-empty issuer, issuer matches CA subject, UTCTime/GeneralizedTime validity encoding, non-empty subject
- RFC 5280 §4.2 — `TestRFC5280Extensions` (9 tests): AKI present and matches CA SKI, SKI in all certs, KeyUsage critical, BasicConstraints critical + cA=False for end-entity, SAN DNS names, AIA OCSP URL, CDP URL
- RFC 5280 §5 — `TestRFC5280CRL` (11 tests): issuer, thisUpdate, nextUpdate ordering, SHA-256 signature, signature verification against CA key, revoked cert appears, good cert absent, delta CRL indicator present + critical, delta CRL incremental correctness
- RFC 9608 — `TestRFC9608NoRevAvail` (9 tests): extension present, non-critical, NULL value, CDP suppressed, AIA OCSP suppressed, absent from CA certs, explicit parameter, CA cert exemption enforced, standard cert unaffected
- `TestCertificateProfiles` (13 tests): all 8 profiles verified for EKU, KeyUsage bits, BasicConstraints, ocsp-nocheck, noRevAvail
- `TestSubCAIssuance` (7 tests): pathLenConstraint=0, 4096-bit key, issuer chain, cryptographic signature verification, keyCertSign/cRLSign usage, DB storage
- `TestPKCS12Export` (6 tests): export without error, cert present in bundle, CA chain present, no private key stored, unknown serial returns None, password-protected export
- `TestCSRValidation` (6 tests): valid CSR passes, missing CN, no SAN for tls_server profile, invalid FQDN, RSA key < 2048 bits, invalid signature
- `TestAuditLog` (7 tests): record/retrieve, newest-first ordering, limit enforcement, ISO 8601 timestamps, SQLite persistence across instances, issuance + revocation recording
- `TestRateLimiter` (6 tests): allows up to limit, blocks over, per-IP independence, status dict, unknown IP, thread safety under concurrent load
- `TestCertificateAuthority` (15 tests): all public methods, SAN IP/email, validity_days, PEM/DER properties, persistence across CA restart, full DN parsing
- `TestServerConfig` (6 tests): defaults, patch, unknown keys ignored, dict output, disk write, reload from disk
- `TestHTTPAPI` (16 tests): all endpoints live-tested over real HTTP — health, config, CA cert PEM/DER, list certs, full CRL, delta CRL, revoke (valid + nonexistent), sub-CA issuance, PEM/P12 download, rate-limit status, audit log, 404 fallback, HTTP 429 enforcement
- `TestOCSPParsing` (4 tests): module importable, OCSP server starts and responds, signing cert has id-pkix-ocsp-nocheck, signing cert has OCSPSigning EKU, signing cert is not a CA
- `TestCMPMessageStructure` (6 tests): CMPv2/v3 handler instantiation, garbage rejection returns valid error response, `build_pki_message` returns bytes, well-known URI constant, pvno constants
- `TestACMERFC9608Integration` (5 tests): profile selection logic below/above threshold, noRevAvail end-to-end, ACME module attributes, `start_acme_server` signature
- `TestESTModule` (3 tests): module importable, required operations present, `build_csrattrs` returns valid DER SEQUENCE
- `TestModuleStructure` (5 tests): all required classes/functions/constants exported, all 8 profiles present, noRevAvail OID value correct

#### Module Rename

- `pki_server.py` → **`pki_server.py`** — all internal cross-references, docstrings, CLI examples, and inter-module imports updated
- `cmpv2_client.py` updated to reference `pki_server.py`
- All other modules (`acme_server.py`, `est_server.py`, `scep_server.py`, `ocsp_server.py`, `web_ui.py`) updated

### Changed

- `CertProfile.PROFILES` now contains 8 entries — `short_lived` added alongside the existing 7
- `issue_certificate()` docstring updated to document `no_rev_avail` parameter and `short_lived` profile
- ACME `_handle_finalize()` now logs `profile=short_lived` or `profile=tls_server` per issued cert
- Startup banner updated: ACME line mentions RFC 9608 noRevAvail auto-apply

### Fixed

- No bug fixes in this release

---

## [0.6.0] — 2026-02-23

### Added — OCSP, Certificate Profiles, Sub-CA, PKCS#12, Delta CRL, CSR Validation, Rate Limiting, Audit Log, Web UI

#### OCSP Responder — RFC 6960 + RFC 5019 (`ocsp_server.py`)

- New standalone module with `start_ocsp_server()` integration hook
- **`POST /ocsp`** — RFC 6960 §A.1 HTTP POST binding; accepts DER-encoded OCSPRequest
- **`GET  /ocsp/<base64>`** — RFC 5019 §5 GET binding; CDN/proxy-cacheable with `Cache-Control: max-age`
- **`OCSPRequestParser`** — pure-Python DER parser extracting `CertID` (serial, issuer name hash, issuer key hash) and optional nonce from `requestExtensions`
- **`OCSPResponseBuilder`** — builds signed `BasicOCSPResponse` with:
  - SHA-256 CertID in every response
  - `good` [0] IMPLICIT NULL / `revoked` [1] RevokedInfo (with reason code) / `unknown` [2] IMPLICIT NULL
  - Nonce echo-back in `responseExtensions` (RFC 6960 §4.2.1)
  - Responder ID by SubjectKeyIdentifier ([2] byKey)
  - Signing cert included in `[0] certs` field
- **`provision_ocsp_signing_cert()`** — auto-issues a dedicated OCSP signing cert with:
  - EKU `OCSPSigning` (`1.3.6.1.5.5.7.3.9`)
  - `id-pkix-ocsp-nocheck` extension (`1.3.6.1.5.5.7.48.1.5`) so clients skip revocation checking on the OCSP cert itself
  - 30-day validity, auto-renewed on start if within 7 days of expiry
- **`OCSPResponseCache`** — TTL-based in-memory cache (default 300 s) keyed by serial; GET requests without nonce are cached; POST requests with nonce bypass cache
- Integrated into `pki_server.py` via `--ocsp-port` and `--ocsp-cache-seconds`

#### AIA + CDP Extensions in Issued Certificates (`pki_server.py`)

- `issue_certificate()` now accepts `ocsp_url` and `crl_url` parameters
- `CertificateAuthority.__init__()` accepts `--ocsp-url` and `--crl-url` CLI values stored as `_ocsp_url` / `_crl_url`
- Every issued certificate gets:
  - `authorityInfoAccess` (AIA) extension with OCSP access description if `ocsp_url` or `--ocsp-url` is set
  - `cRLDistributionPoints` (CDP) extension with full-name URI if `crl_url` or `--crl-url` is set
- New CLI flags `--ocsp-url URL` and `--crl-url URL`

#### Certificate Profiles (`pki_server.py`)

- New `CertProfile` class with seven built-in profiles:
  - `tls_server` — `serverAuth` EKU, `digitalSignature + keyEncipherment`, SAN recommended
  - `tls_client` — `clientAuth` EKU, `digitalSignature`
  - `code_signing` — `codeSigning` EKU, `digitalSignature + contentCommitment`
  - `email` — `emailProtection` EKU, `digitalSignature + keyEncipherment + contentCommitment`
  - `ocsp_signing` — `OCSPSigning` EKU, `nocheck` extension auto-added
  - `sub_ca` — `BasicConstraints cA=True`, `keyCertSign + cRLSign`
  - `default` — all key usages, no EKU restriction (previous behaviour)
- `issue_certificate()` `profile=` parameter controls which profile is applied
- Profile name stored in `certificates.db` (new `profile` column with migration guard)
- New `--default-profile` CLI flag for CMPv2 issuance (default: `default`)
- `san_emails` and `san_ips` parameters added to `issue_certificate()` alongside existing `san_dns`

#### Subordinate CA Issuance (`pki_server.py`)

- New `CertificateAuthority.issue_sub_ca(cn, validity_days, path_length)` method
  generates a 4096-bit RSA key pair and issues a CA certificate (BasicConstraints `cA=True`,
  path length 0, `sub_ca` profile)
- New `POST /api/sub-ca` HTTP endpoint — body `{"cn": "...", "validity_days": 1825}`;
  returns JSON with `cert_pem` and `key_pem`
- Accessible from web dashboard Sub-CA page

#### PKCS#12 / PFX Export (`pki_server.py`)

- New `CertificateAuthority.export_pkcs12(serial, password=None)` — uses
  `cryptography.hazmat.primitives.serialization.pkcs12`; bundles issued cert + CA chain;
  private key is never included (not stored server-side)
- New `GET /api/certs/<serial>/p12` HTTP endpoint — returns `application/x-pkcs12` with
  `Content-Disposition: attachment`
- New `GET /api/certs/<serial>/pem` HTTP endpoint — returns single cert PEM by serial

#### Delta CRL — RFC 5280 §5.2.4 (`pki_server.py`)

- New `CertificateAuthority.generate_delta_crl(base_crl_number)` method
- Only includes revocations since the last base CRL snapshot stored in new `crl_base` SQLite table
- Adds `deltaCRLIndicator` critical extension with the base CRL number
- Automatically records the current full CRL as the new base after generation
- New `GET /ca/delta-crl` HTTP endpoint; 6-hour `nextUpdate`

#### CSR Policy Validation (`pki_server.py`)

- New `CertificateAuthority.validate_csr(csr, profile)` method returns list of violation strings
- Checks: CSR signature validity, presence of CN, minimum RSA key size (2048 bits)
- Profile-specific: `tls_server` profile enforces FQDN-like CN and SAN extension presence
- Returns empty list if valid — callers can reject or log violations

#### Rate Limiting (`pki_server.py`)

- New `RateLimiter` class — token-bucket per IP address (sliding 60-second window)
- Applied at the top of `do_POST()` before CMP processing; returns HTTP `429 Too Many Requests`
  with `Retry-After: 60` header
- New `--rate-limit N` CLI flag (0 = disabled, default)
- New `GET /api/rate-limit` endpoint shows current request count for the caller's IP
- `RateLimiter` instance shared with Web UI

#### Structured Audit Log (`pki_server.py`)

- New `AuditLog` class backed by `ca/audit.db` SQLite database
- Schema: `id, ts (ISO-8601), event, detail, ip`
- Events recorded: `startup`, `shutdown`, `issue`, `issue_sub_ca`, `revoke`, `config_patch`
- New `--audit` (default on) / `--no-audit` CLI flags
- New `GET /api/audit` endpoint — returns last 200 events as JSON
- `AuditLog` instance passed to web UI and all issuance paths

#### Web Dashboard (`web_ui.py`)

- New standalone module; starts on `--web-port` (e.g. 8090); plain HTTP (no TLS needed — serve behind a reverse proxy in production)
- Pages:
  - **Dashboard** — stats grid (total/active/revoked/expired), CA info, active endpoints
  - **Certificates** — searchable/filterable table; per-cert PEM download, PKCS#12 download, one-click revoke button
  - **Revocation** — CRL/OCSP URL display, revoke-by-serial form with reason dropdown
  - **Sub-CA** — form to issue subordinate CA cert; result shown as JSON
  - **Config** — live config viewer + validity period editor (calls `PATCH /config`)
  - **Audit Log** — last 100 events in a table
  - **API Docs** — quick-reference endpoint table
- Pure HTML/CSS/JS — no external dependencies; single-file, no npm/webpack
- REST API used by dashboard JS: `GET /api/certs`, `POST /api/revoke`, `POST /api/config`,
  `POST /api/issue-sub-ca`, `GET /api/audit`
- Shared `CertificateAuthority`, `AuditLog`, and `RateLimiter` objects (no duplicate state)

#### Database migration (`pki_server.py`)

- `_init_db()` adds `profile TEXT DEFAULT 'default'` column to `certificates` table
  with `ALTER TABLE ... ADD COLUMN` inside a try/except (no-op on new DBs, migration on existing)
- New `crl_base` table for delta CRL base snapshots
- New `audit.db` database for structured audit events

---

## [0.5.0] — 2026-02-23

### Added — CMPv3 (RFC 9480) + EST (RFC 7030)

#### CMPv3 — RFC 9480 CMP Updates (`pki_server.py`)

- **`pvno` version negotiation** — new `CMPv3Handler` class (extends `CMPv2Handler`);
  reads `pvno` from the incoming PKIHeader and mirrors it back — clients sending
  `pvno=3` (cmp2021) receive `pvno=3` in all responses; CMPv2 clients are unaffected
- **`build_pki_message()` `pvno` parameter** — the DER builder now accepts an
  explicit `pvno` argument (default `2`) so every response path can propagate the
  negotiated version without breaking existing callers
- **New `genm` info types (RFC 9480 §4.3)**:
  - `id-it 17` `GetCACerts` — returns all CA certificates as a `CACertSeq` SEQUENCE
  - `id-it 18` `GetRootCACertUpdate` — returns `RootCaKeyUpdateContent` with
    `newWithNew` (current CA cert); `newWithOld`/`oldWithNew` omitted (no rollover)
  - `id-it 19` `GetCertReqTemplate` — returns `CertReqTemplateContent` with an RSA
    key-type hint and suggested extensions (SAN, EKU)
  - `id-it 21/22` `CRLStatusList` / `CRLUpdateRetrieve` — returns the current CRL
    built from the revocation database
  - Unknown OIDs fall back to the original CMPv2 `id-it-caProtEncCert` response
- **Extended polling — `pollReq` / `pollRep` (RFC 9480 §3.4)** — RFC 4210 only
  defined polling for `ir`/`cr`/`kur`; RFC 9480 extends it to `p10cr`, `certConf`,
  `rr`, `genm`, and `error` messages; implemented via an in-memory polling table
  (`_polling_table`) with `queue_for_polling()` API; `pollRep` includes
  `checkAfter` countdown so the client knows when to retry
- **Client `error` message handling** — RFC 9480 allows clients to send error
  messages; server now acknowledges with `pkiconf` instead of returning an
  unhandled-body-type error
- **Well-known URI paths (RFC 9480 / RFC 9811)**:
  - `POST /.well-known/cmp` — standard CMP-over-HTTP endpoint; body is plain
    PKIMessage DER (same as `POST /`)
  - `POST /.well-known/cmp/p/<label>` — named CA variant; label extracted and
    logged (future: multi-CA routing)
  - `GET  /.well-known/cmp` — returns CA certificate PEM (service discovery)
  - `GET  /.well-known/cmp/p/<label>` — same with optional `X-CMP-CA-Label` header
- **`CMPv3Handler` selected by default** — `main()` instantiates `CMPv3Handler`
  unless `--no-cmpv3` is passed; existing CMPv2 clients work transparently
- **New CLI flags**:
  - `--cmpv3` (default on) — enable CMPv3 handler
  - `--no-cmpv3` — force CMPv2-only behaviour
- **`OID_IT_*` constants** defined at module level for all RFC 9480 genm types
- **`CMP_WELL_KNOWN_PATH`** constant (`/.well-known/cmp`) used in both `do_GET`
  and `do_POST` routing

#### EST — RFC 7030 Enrollment over Secure Transport (`est_server.py`)

- New standalone module following the same pattern as `acme_server.py` and
  `scep_server.py` — shares `CertificateAuthority`, runs standalone or integrated
  via `--est-port`
- **Supported operations (all RFC 7030 MUST + OPTIONAL)**:
  - `GET  /.well-known/est/cacerts` — returns CA chain as base64-encoded PKCS#7
    certs-only SignedData (`application/pkcs7-mime; smime-type=certs-only`)
  - `POST /.well-known/est/simpleenroll` — accepts base64 DER PKCS#10 CSR,
    returns signed certificate chain as PKCS#7
  - `POST /.well-known/est/simplereenroll` — renewal; requires TLS client cert
    for authentication (RFC 7030 §4.2.2); subject from existing cert accepted
  - `GET  /.well-known/est/csrattrs` — returns `CsrAttrs` DER (RFC 7030 §4.5)
    hinting RSA key type + SAN + EKU clientAuth extensions
  - `POST /.well-known/est/serverkeygen` — server generates RSA-2048 key pair,
    issues cert, returns `multipart/mixed` with PKCS#7 cert and PKCS#8 private
    key (unencrypted; transport security provided by TLS)
  - All endpoints also accept `/.well-known/est/<label>/<op>` for named CA label
    routing (RFC 7030 §3.2.2)
- **Authentication — both methods active simultaneously**:
  - **HTTP Basic auth** — username:password checked against `ESTUserStore`;
    passwords stored as SHA-256 hex hashes; compared with `hashlib.compare_digest`
    to prevent timing attacks; `401 + WWW-Authenticate: Basic realm="EST"` on failure
  - **TLS client certificate** — `ssl.CERT_OPTIONAL`; certificate verified against
    CA by Authority Key Identifier (SKI match) or issuer name fallback; accepted
    cert object passed to handler for subject logging and reenroll validation
  - Either method satisfies `require_auth`; anonymous access allowed when
    `require_auth=False` (default for open internal CAs)
- **CSR decoding** — accepts base64 DER (RFC 7030 canonical), raw DER, or PEM
  (fallback) so real-world clients that deviate from the spec still work
- **EST HTTPS auto-TLS** — EST always runs over TLS (RFC 7030 §3); if no
  `--est-tls-cert`/`--est-tls-key` supplied, a server cert is auto-issued from
  the CA via `provision_tls_server_cert()`; `ssl.CERT_OPTIONAL` set so client
  cert auth works without breaking non-mTLS clients
- **`ESTCMSBuilder`** — pure-Python PKCS#7 certs-only SignedData builder (degenerate,
  no signers) used for `cacerts`, `simpleenroll`, and `simplereenroll` responses
- **`build_csrattrs()`** — builds RFC 7030 §4.5.2 `CsrAttrs` DER with
  `extensionRequest` attribute hinting SAN and EKU
- **`ESTUserStore`** — thread-safe in-memory user registry; `add_user()`,
  `authenticate()`, `has_users()`
- **Integration into `pki_server.py`**:
  - `est_server` imported at startup with `HAS_EST` guard
  - EST server started in background daemon thread alongside ACME, SCEP, CMPv3
  - New CLI argument group `EST options (RFC 7030)`:
    - `--est-port PORT`
    - `--est-user USER:PASS` (repeatable)
    - `--est-require-auth`
    - `--est-tls-cert PATH` / `--est-tls-key PATH`
  - Banner updated with `Listening (EST)` and `CMP Well-Known` rows
  - EST operations section added to banner
  - EST quick-start hint printed on startup
  - `est_srv.shutdown()` added to `KeyboardInterrupt` handler

---

## [0.4.0] — 2026-02-23

### Added — SCEP protocol (RFC 8894)

#### SCEP server (`scep_server.py`)

- New standalone module following the same pattern as `acme_server.py` —
  shares `CertificateAuthority` from `pki_server.py` and can run
  standalone or integrated via `--scep-port`
- SQLite-backed transaction log (`ca/scep.db`) recording all enrolment
  requests with status, subject, CSR PEM, issued cert PEM, requester IP,
  and timestamps
- **Supported operations:**
  - `GetCACaps` — advertises `AES`, `SHA-256`, `SHA-512`, `Renewal`,
    `POSTPKIOperation`
  - `GetCACert` — returns CA certificate as DER
    (`application/x-x509-ca-cert`)
  - `PKCSReq` — initial enrolment; decrypts CMS EnvelopedData, validates
    the PKCS#10 CSR signature, checks challenge password, issues certificate
  - `CertPoll` / `GetCertInitial` — poll for a pending certificate by
    `transactionID`
  - `GetCert` — retrieve an issued certificate by `IssuerAndSerialNumber`
  - `GetCRL` — return the current CRL built from the revocation database
  - `GetNextCACert` — CA rollover preview (returns current CA per RFC)
- **Pure-Python CMS engine** — no external ASN.1 library required:
  - `CMSParser.parse_signed_data()` — full CMS SignedData parser including
    signed attributes (`transactionID`, `senderNonce`, `recipientNonce`,
    `messageType`, `pkiStatus`, `failInfo`)
  - `CMSParser.parse_enveloped_data()` — RSA PKCS#1 v1.5 key unwrap +
    AES-256-CBC / AES-192-CBC / AES-128-CBC / 3DES-EDE-CBC content decrypt
  - `CMSBuilder.signed_data()` — builds RFC-compliant CMS SignedData
    responses signed with the CA key (SHA-256 + RSA)
  - `CMSBuilder.enveloped_data()` — RSA + AES-256-CBC envelope for
    encrypting CSR payloads (used in test clients)
  - `CMSBuilder._degenerate_certs()` — degenerate SignedData (certs-only,
    no signers) for `CertRep` certificate delivery
- **Challenge password authentication** — extracted from PKCS#10 CSR
  `challengePassword` attribute (OID `1.2.840.113549.1.9.7`); compared
  with constant-time `hmac_compare()` to prevent timing attacks
- **Renewal without challenge** — if the requester's existing certificate
  is included in the CMS envelope and its Authority Key Identifier matches
  the CA's Subject Key Identifier, the challenge requirement is waived
- URL routing accepts `/scep`, `/cgi-bin/pkiclient.exe`, and
  `/scep/pkiclient.exe` — the three paths used by different SCEP clients
  (Cisco IOS, Juniper, sscep, Windows NDES)

#### Integration into `pki_server.py`

- New CLI argument group `SCEP options (RFC 8894)`:
  - `--scep-port PORT` — start SCEP server on this port (e.g. 8889)
  - `--scep-challenge SECRET` — shared challenge password (empty = open
    enrolment, any CSR accepted)
- `scep_server` imported at startup with `HAS_SCEP` guard (graceful
  degradation if `scep_server.py` is not present)
- SCEP server started in background daemon thread alongside ACME and CMPv2
- Banner updated with `Listening (SCEP)` row and SCEP operations section
- SCEP quick-start hint printed on startup when `--scep-port` is set
- `scep_srv.shutdown()` added to `KeyboardInterrupt` handler

#### New methods on `CertificateAuthority`

- `get_certificate_by_serial(serial: int) -> Optional[str]` — query
  `certificates.db` for a PEM cert by serial number; used by SCEP `GetCert`
- `generate_crl_der() -> bytes` — build a proper DER-encoded CRL from the
  revocation database (replaces the stub that returned the CA cert); used by
  SCEP `GetCRL` and also available to CMPv2 and ACME consumers

---

## [0.3.0] — 2026-02-23

### Added — ACME certbot compatibility (11 RFC 8555 compliance fixes)

- **`new-account` 200 vs 201 status codes** — return `201 Created` for new
  accounts and `200 OK` for existing ones, as required by RFC 8555 §7.3
- **`onlyReturnExisting` flag** — clients that pass this flag (certbot uses it
  on reconnect) now receive `accountDoesNotExist` instead of a silent new
  account being created
- **`Link: <authz>;rel="up"` on challenge responses** — required header per
  RFC 8555 §7.5.1; certbot uses it to locate the authorization URL after
  triggering a challenge
- **`Location` header on finalize response** — RFC 8555 §7.4 requires this;
  certbot polls the order URL from this header to detect the `valid` transition
- **`Link: <directory>;rel="index"` on all error responses** — RFC 8555 §6.7
  requirement; allows clients to re-bootstrap after any error
- **`renewalInfo` stub in directory** — certbot ≥2.8 checks for this field
  (draft-ietf-acme-ari); added stub URL returning 404, which certbot treats
  as "not supported" and continues normally
- **`GET /acme/terms`** — certbot fetches the ToS URL from the directory and
  displays it to the user during registration; now returns a plaintext response
- **`GET /acme/renewal-info`** — returns a clean 404 JSON error instead of
  an unrouted 404, preventing certbot from logging parse errors
- **Unauthenticated `GET` for order, authz and cert resources** — certbot
  polls these endpoints with plain `GET` (not POST-as-GET) to track status
  changes; previously returned 404, causing certbot to stall
- **`Content-Length: 0` on revocation** — explicit empty body on `200 OK`
  revocation responses prevents client connection hang
- **`content_type` parameter on `_send_json`** — allows individual handlers
  to override the response Content-Type cleanly

### Fixed

- `create_or_find_account` now returns `(is_new: bool, account: dict)` so the
  HTTP status code can be set correctly per RFC 8555 §7.3
- Already-processed challenge responses now also include the `Link: rel="up"`
  header, not just newly-triggered ones

---

## [0.2.0] — 2026-02-23

### Added — ACME protocol (RFC 8555) + ALPN + key rollover

#### ACME server (`acme_server.py`)

- Full RFC 8555 ACME server implemented as a standalone module that shares
  the `CertificateAuthority` from `pki_server.py`
- SQLite-backed store for accounts, orders, authorizations, challenges and
  certificates (`ca/acme.db`)
- **Challenge types:**
  - `http-01` — real HTTP fetch to `/.well-known/acme-challenge/<token>`
  - `dns-01` — DNS TXT record lookup with optional auto-approve for internal CAs
  - `tls-alpn-01` — RFC 8737 challenge certificate with `id-pe-acmeIdentifier`
    extension, served over a dedicated SSLContext advertising `acme-tls/1`
- **Key rollover** — full RFC 8555 §7.3.5 implementation at
  `POST /acme/key-change`; double-JWS structure enforced (outer signed by old
  key, inner signed by new key); atomic database update
- **Account management** — JWK/KID flows, JWK thumbprint (RFC 7638) based
  account identity, contact storage
- **Order lifecycle** — `new-order → authz → challenge → finalize → cert`
  with background async validation thread per challenge
- **Certificate download** — `application/pem-certificate-chain` with full
  leaf + CA chain
- **Revocation** — `POST /acme/revoke-cert` authenticated by account key or
  certificate key
- Integrated into `pki_server.py` via `--acme-port`; can also run
  standalone

#### ALPN support (`pki_server.py`)

- `build_tls_context()` extended with `alpn_protocols` parameter (RFC 7301)
- Four named constants on `CertificateAuthority`:
  - `ALPN_HTTP1 = "http/1.1"`
  - `ALPN_H2    = "h2"`
  - `ALPN_CMP   = "cmpc"` (RFC 9483 — CMP over TLS)
  - `ALPN_ACME  = "acme-tls/1"` (RFC 8737)
- New CLI flags: `--alpn-h2`, `--alpn-cmp`, `--alpn-acme`, `--no-alpn-http`
- `build_acme_tls_alpn_context()` — generates a throwaway challenge
  certificate for `tls-alpn-01` with the correct `id-pe-acmeIdentifier`
  critical extension
- ALPN protocol list shown in server startup banner

#### Ansible CA import role (`ca_import/`)

- Multi-platform Ansible role for distributing the CA certificate to client
  machines
- **System trust store:** Debian/Ubuntu (`update-ca-certificates`), RHEL/Fedora
  (`update-ca-trust`), macOS (`security add-trusted-cert`)
- **Optional stores:** Java cacerts (`keytool`), Python certifi bundle, curl
  merged PEM bundle + `/etc/environment`, Mozilla NSS (`certutil`)
- Three CA cert source modes: fetch from PKI server URL, copy local file,
  inline PEM content (HashiCorp Vault compatible)
- Post-install Jinja2 verification script deployed and executed on each target
- Idempotent — safe to run repeatedly; `ca_import_remove: true` cleanly
  deregisters from all stores
- Inventory example with groups: `linux_servers`, `java_servers`,
  `python_servers`, `workstations`, `macos`, `ci_runners`

---

## [0.1.0] — 2026-02-23

### Added — Initial release

#### Certificate Authority

- Self-signed RSA-4096 root CA, auto-generated on first run
- SQLite certificate store (`ca/certificates.db`) with full issuance history
- Certificate revocation with reason codes
- CRL (Certificate Revocation List) generation and serving
- Hot-reloadable configuration via `ca/config.json` and `PATCH /config`

#### CMPv2 protocol (RFC 4210 / RFC 4211 / RFC 6712)

- Full ASN.1/DER parser and builder (no external ASN.1 library required for
  core operations; `pyasn1` used for advanced parsing)
- Supported message types: `ir`, `cr`, `kur`, `rr`, `certConf`, `genm/genp`,
  `p10cr`
- HTTP transport per RFC 6712 (`application/pkixcmp`)
- CRMF subject and public key extraction

#### TLS

- One-way TLS mode (`--tls`) — server certificate only
- Mutual TLS mode (`--mtls`) — client certificate required
- Auto-issued server TLS certificate with configurable SAN hostname
- Bring-your-own certificate (`--tls-cert` / `--tls-key`)
- Hardened cipher suites: ECDHE+AESGCM, CHACHA20; disabled RC4/DES/MD5
- TLS 1.2 minimum version
- `build_tls_context()` unified context builder for both TLS modes

#### Bootstrap endpoint

- `GET /bootstrap?cn=<name>` on a separate plain-HTTP port
- Issues a client certificate and returns PEM bundle (cert + key + CA)
- Intended for initial mTLS client onboarding on trusted networks

#### HTTP API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/` | CMPv2 endpoint |
| `GET`  | `/ca/cert.pem` | CA certificate (PEM) |
| `GET`  | `/ca/cert.der` | CA certificate (DER) |
| `GET`  | `/ca/crl` | Certificate Revocation List |
| `GET`  | `/api/certs` | All issued certificates (JSON) |
| `GET`  | `/api/whoami` | mTLS client identity |
| `GET`  | `/config` | Current configuration |
| `PATCH`| `/config` | Live configuration update |
| `GET`  | `/health` | Health check |

#### Live configuration

- `ServerConfig` class with thread-safe hot-reload from `ca/config.json`
- Priority chain: defaults ← config file ← CLI flags ← `PATCH /config`
- Configurable validity periods: end-entity, client cert, TLS server, CA
- CLI flags: `--end-entity-days`, `--client-cert-days`, `--tls-server-days`,
  `--ca-days`

#### Project

- MIT licence
- `README.md` with full CLI reference, API table, protocol compliance matrix,
  CA directory layout, and quick-start examples
- `SPDX-License-Identifier: MIT` headers on all source files

---

## Tag and release recommendations

```
v0.1.0   Initial release — CA + CMPv2 + mTLS
v0.2.0   ACME (RFC 8555) + ALPN + key rollover + Ansible CA import role
v0.3.0   certbot compatibility — 11 RFC 8555 compliance fixes
v0.4.0   SCEP protocol (RFC 8894) + CRL generation + GetCert by serial
v0.5.0   CMPv3 (RFC 9480) + EST (RFC 7030) + well-known CMP URI (RFC 9811)
v0.6.0   OCSP (RFC 6960) + profiles + sub-CA + PKCS#12 + delta CRL + audit + rate-limit + Web UI
```

```bash
# Tag and push the new release
git add ocsp_server.py web_ui.py pki_server.py CHANGELOG.md README.md
git commit -m "v0.6.0: OCSP + profiles + sub-CA + PKCS#12 + delta CRL + audit + Web UI

- ocsp_server.py: RFC 6960 + RFC 5019 OCSP responder with signing cert + cache
- AIA/CDP extensions embedded in all issued certificates
- CertProfile: 7 built-in profiles (tls_server, tls_client, code_signing, email, sub_ca, ...)
- CertificateAuthority.issue_sub_ca() + POST /api/sub-ca
- CertificateAuthority.export_pkcs12() + GET /api/certs/<serial>/p12
- generate_delta_crl() + GET /ca/delta-crl (RFC 5280 §5.2.4)
- validate_csr() naming + key-size policy enforcement
- RateLimiter: token-bucket per IP, --rate-limit N, HTTP 429
- AuditLog: SQLite ca/audit.db, GET /api/audit
- web_ui.py: HTML dashboard with cert inventory, revocation, sub-CA, config, audit"

git tag -a v0.6.0 -m "v0.6.0: OCSP + profiles + sub-CA + PKCS#12 + delta CRL + audit + Web UI"
git push && git push origin v0.6.0

# Create a GitHub Release
gh release create v0.6.0 \
  --title "v0.6.0 — OCSP, Profiles, Sub-CA, PKCS#12, Delta CRL, Audit Log, Web UI" \
  --notes-file CHANGELOG.md

git add scep_server.py est_server.py pki_server.py CHANGELOG.md README.md
git commit -m "v0.5.0: CMPv3 (RFC 9480) + EST (RFC 7030)

CMPv3:
- CMPv3Handler: pvno=3 auto-negotiation, well-known URI (RFC 9811)
- New genm types: GetCACerts, GetRootCACertUpdate, GetCertReqTemplate, CRLUpdate
- Extended polling for all message types (pollReq/pollRep)
- Client error message acknowledgement
- --cmpv3 / --no-cmpv3 CLI flags

EST:
- New est_server.py: cacerts, simpleenroll, simplereenroll, csrattrs, serverkeygen
- HTTP Basic auth + TLS client cert auth (both active simultaneously)
- Auto-TLS via CA auto-issue; ssl.CERT_OPTIONAL for mixed auth
- Integrated via --est-port / --est-user / --est-require-auth"

git tag -a v0.5.0 -m "v0.5.0: CMPv3 (RFC 9480) + EST (RFC 7030)"
git push && git push origin v0.5.0

# Create a GitHub Release
gh release create v0.5.0 \
  --title "v0.5.0 — CMPv3 + EST" \
  --notes-file CHANGELOG.md

# Or in the browser:
# https://github.com/lucianpopovici/network/releases/new
```

---

## Releasing v0.7.0

```bash
git add pki_server.py acme_server.py test_pki_server.py CHANGELOG.md README.md
git commit -m "v0.7.0: RFC 9608 noRevAvail + unit test suite + rename to pki_server.py

RFC 9608:
- id-ce-noRevAvail (OID 2.5.29.56) extension, non-critical, ASN.1 NULL value
- New short_lived certificate profile
- CDP and AIA-OCSP suppressed when noRevAvail is set (RFC 9608 §4)
- ACME auto-applies short_lived profile for certs with validity <= threshold
- --acme-cert-days and --acme-short-lived-threshold CLI flags

Testing:
- test_pki_server.py: 148 tests, 18 test classes
- RFC 5280 §4/§5, RFC 9608, all profiles, all HTTP API endpoints
- Zero external test dependencies (stdlib + cryptography)

Rename:
- pki_server.py renamed from pki_cmpv2_server.py
- All cross-module references updated"

git tag -a v0.7.0 -m "v0.7.0: RFC 9608 noRevAvail + unit tests + pki_server.py rename"
git push && git push origin v0.7.0

# Create a GitHub Release
gh release create v0.7.0 \
  --title "v0.7.0 — RFC 9608 noRevAvail + Unit Tests + Rename" \
  --notes-file CHANGELOG.md
```

---

## Releasing v0.8.0

```bash
git add pki_server.py test_pki_server.py CHANGELOG.md README.md
git commit -m "v0.8.0: IDNA (RFC 9549/9598) + CertificatePolicies (RFC 5280 §4.2.1.4)

IDNA (Priority 2):
- san_dns: U-label to A-label via built-in IDNA codec (RFC 9549 §4.1)
- san_emails: ASCII local+IDN host -> rfc822Name A-label; non-ASCII local -> SmtpUTF8Mailbox
- DC= in subject_str: domainComponent with IDNA encoding (RFC 6818 §5)
- New helpers: _idna_encode_domain, _encode_smtp_utf8_mailbox, OID_SMTP_UTF8_MAILBOX

CertificatePolicies (Priority 3):
- certificate_policies parameter on issue_certificate()
- CPS URI (id-qt-cps) and UserNotice (UTF8String, RFC 6818) qualifiers
- Profile-level default policies; explicit parameter overrides profile
- OID constants: OID_POLICY_DV/OV/IV/EV, OID_ANY_POLICY, OID_QT_CPS/UNOTICE

Tests: 30 new (178 total, 20 test classes)
- TestRFC9549IDNA: 13 tests covering all routing paths and edge cases
- TestCertificatePolicies: 17 tests covering OIDs, qualifiers, DER round-trip, profile defaults"

git tag -a v0.8.0 -m "v0.8.0: IDNA (RFC 9549/9598) + CertificatePolicies (RFC 5280 §4.2.1.4)"
git push && git push origin v0.8.0

gh release create v0.8.0 \
  --title "v0.8.0 — IDNA + CertificatePolicies" \
  --notes-file CHANGELOG.md
```
