# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

#### Admin API Authentication

All sensitive management endpoints (`/api/revoke`, `/api/sub-ca`, `/api/certs/<serial>/archive`,
`/api/certs/<serial>/recover`, `/api/certs/<serial>/renew`, `PATCH /config`) now support
token-based and mTLS CN-based authentication.

CLI flags:
- `--admin-api-key KEY` — require `X-Admin-Key` header on admin endpoints (also `PYPKI_ADMIN_API_KEY` env var)
- `--admin-allowed-cns CN1,CN2` — comma-separated mTLS client CN allowlist for admin operations
- `--bootstrap-token TOKEN` — shared secret required for `/bootstrap` endpoint (`X-Bootstrap-Token` header or `?token=` query param)

When no admin key or CN allowlist is configured, all endpoints remain open for backward compatibility.

#### CA Private Key Encryption

The root CA private key can now be encrypted at rest with a passphrase.

CLI flag:
- `--ca-key-passphrase PASS` — encrypts `ca.key` with `BestAvailableEncryption` (also `PYPKI_CA_KEY_PASSPHRASE` env var)

The key file permissions are set to `0600` on creation. If no passphrase is provided, a warning is logged.

#### Web Dashboard Security

- **Authentication** — web UI mutating endpoints (`/api/revoke`, `/api/renew`, `/api/config`,
  `/api/issue-sub-ca`) now enforce the same `--admin-api-key` / `--admin-allowed-cns` checks
  as the main PKI server
- **XSS prevention** — all user-sourced data (certificate subjects, audit log fields, config JSON,
  Prometheus metrics) is HTML-escaped before rendering via `html.escape()`
- **Security headers** — all responses include `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`
- **CSRF protection** — write endpoints check the `Origin` header to prevent cross-site request forgery
- **CN sanitization** — sub-CA common names are sanitized with the same regex filter as bootstrap
  (`[a-zA-Z0-9._\- ]`, max 64 chars)

#### Web Dashboard `PATCH /config` Support

The config editor on the web dashboard now works correctly. Added `do_PATCH` handler to
`WebUIHandler` to match the JavaScript `fetch()` call that sends `method: 'PATCH'`.

---

### Fixed

#### Critical — Runtime Crashes

- **`NameError` in CMP message parser** — `parse_pki_message()` referenced undefined variable
  `data` instead of `der_data` (line 586). All CMPv2/v3 message processing was broken.

- **`NameError` in web UI** — `do_GET_api_cert()` and `_api_issue_sub_ca()` referenced
  `Encoding` and `serialization` without importing them. PEM download, P12 download, and
  sub-CA issuance via the web dashboard all crashed with `NameError`.

- **`sqlite3.OperationalError` in `get_certificate_by_serial()`** — queried non-existent
  `cert_pem` column; the table stores `der`. Fixed to query `der` and convert to PEM.

- **`TypeError` in CRL generation** — `generate_crl_der()` called `fromtimestamp()` on ISO 8601
  date strings instead of `fromisoformat()`. Every CRL containing revoked certificates crashed.

#### High — Security

- **Unencrypted CA private key** — `ca.key` was written to disk with `NoEncryption()`. Now
  supports passphrase encryption via `--ca-key-passphrase` with `BestAvailableEncryption`.

- **No API authentication** — management endpoints (revoke, sub-CA, key recovery, config) had
  zero authentication. Added `--admin-api-key` and `--admin-allowed-cns` with `hmac.compare_digest`.

- **Web UI bypassed admin auth** — the web dashboard ran on a separate port and called CA methods
  directly, bypassing all admin authentication on the main server. Fixed by enforcing the same
  auth checks in `WebUIHandler`.

- **Sub-CA private key exposed without auth** — `/api/issue-sub-ca` returned a CA-grade private
  key in cleartext JSON to any caller. Now gated by admin authentication.

- **Stored XSS in web dashboard** — certificate subjects, audit log details, and other
  DB-sourced fields were interpolated into HTML without escaping. An attacker enrolling a
  certificate with `CN=<script>...` achieved persistent XSS on the dashboard.

- **Bootstrap endpoint unrestricted** — issued client certificates over plain HTTP to any
  caller with no rate limiting, no challenge, and no CN sanitization. Added rate limiting,
  optional `--bootstrap-token`, and CN regex filter (64-char limit).

- **Serial number race condition** — `_next_serial()` had a read-then-write race under
  concurrent requests. Fixed with `threading.Lock` + `BEGIN EXCLUSIVE` transaction.

#### High — Reliability

- **SQLite connection leaks** — 7 methods in `pki_server.py`, 19 in `acme_server.py`, and
  6 in `scep_server.py` lacked `try/finally` guards around `conn.close()`. Under load, leaked
  connections accumulated until the process hit the file descriptor limit. All sites now wrapped.

- **Tracing span closed prematurely** — `revoke_certificate()` closed the OpenTelemetry span
  before the DB work executed. Timing data was meaningless and exceptions were not captured.
  Moved DB work inside the `with` block.

- **Duplicate CRL generators** — `generate_crl()` (1-day validity) and `generate_crl_der()`
  (7-day validity, different date parsing) had divergent behavior. Consolidated
  `generate_crl_der()` to delegate to `generate_crl()`.

#### Medium

- **Fragile revocation serial extraction** — used a heuristic ("first INTEGER > 1000") to find
  the serial in CMP revocation requests. Replaced with proper CertTemplate `[1] serialNumber`
  field parsing per RFC 4210 §5.3.9.

- **Name constraints DB mismatch** — `issue_certificate_with_name_constraints()` stored one cert
  in the DB but returned a different re-signed cert with the same serial. Fixed to update the DB
  with the re-signed certificate.

- **Pending confirmations memory leak** — `_pending_confirmations` dict grew without bound for
  unconfirmed enrollments. Added timestamps and 5-minute TTL eviction.

- **`_init_db()` connection leak** — the database initialization method had no `try/finally`
  guard. Fixed.

- **`_init_key_archive_table()` called per-operation** — ran `CREATE TABLE IF NOT EXISTS` on
  every archive/recover call. Now called once during `_init_db()`.

- **Web UI config editor broken** — JavaScript sent `method: 'PATCH'` but `WebUIHandler` only
  had `do_POST`. Added `do_PATCH` handler.

- **Web UI silent JSON error** — malformed POST bodies were silently swallowed and set to `{}`.
  Now returns 400 Bad Request.

- **Web UI monkey-patch fragility** — `/api/certs/<serial>/<fmt>` routes were added via
  monkey-patching `do_GET` at module level. Moved into `do_GET` directly.

#### Low

- **Prometheus label escaping** — `profile.replace('"', '\"')` was a no-op in Python. Fixed
  to `replace('"', '\\"')`.

- **Redundant inline imports** — three `import copy` statements inside methods and one
  `import tempfile, os` removed; all already imported at module level.

- **Fragile `dir()` checks** — `if 'est_srv' not in dir()` replaced with proper `None`
  initialization (already present earlier in the code).

- **Duplicate handler factories** — `make_handler()` and `make_cmpv3_handler()` were identical
  copies. `make_cmpv3_handler()` now delegates to `make_handler()`.

- **Missing security headers** — web UI responses had no `X-Frame-Options`, `X-Content-Type-Options`,
  or `Cache-Control` headers. Added to prevent clickjacking and caching of sensitive pages.

- **No CSRF protection** — web UI POST endpoints had no Origin/Referer checks. Added Origin
  header validation on write requests.

- **API docs mismatch** — web UI API docs page listed `POST` for config update; actual method
  is `PATCH`. Fixed to show `PATCH`.

- **Version badge hardcoded** — web UI showed `v0.9.0` as a string literal. Replaced with
  `__version__` module variable.

---

### Changed

- `CertificateAuthority.__init__()` now accepts `ca_key_passphrase: Optional[bytes]` parameter
- `make_handler()` / `make_cmpv3_handler()` accept `admin_api_key`, `admin_allowed_cns`, `bootstrap_token` parameters
- `start_web_ui()` accepts `admin_api_key` and `admin_allowed_cns` parameters
- Web UI `_send_html()` parameter renamed from `html` to `html_content` to avoid shadowing the `html` module import

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
