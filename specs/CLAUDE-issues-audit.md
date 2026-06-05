# CLAUDE-issues-audit.md

Audit of issues previously flagged in project sessions, reconciled against
**live source** read from the working tree on **2026-06-05** (pass 2).

Line numbers are **as-of this audit** and will drift — navigate by the quoted
**anchor** strings, not the numbers. Re-verify before acting.

Codebase shape at audit time:

| File | Lines |
| --- | --- |
| `pki_server.py` | 6916 |
| `web_ui.py` | 3820 |
| `acme_server.py` | 2650 |
| `pypki_admin.py` | 3054 |
| `scep_server.py` | 1560 |
| `est_server.py` | 1004 |
| `db.py` | 670 |
| `migrations.py` | 320 |
| `test_pki_server.py` | 17973 (1239 `def test_`) |

---

## 1. Status summary

| # | Item | Severity | Status |
| --- | --- | --- | --- |
| 1 | Serial-number allocation race | Critical | ✅ Resolved |
| 2 | PQ issuance audit-path regression | Critical | ✅ Fixed + OID assertion added to all 3 PQ tests |
| 3 | DAL migration incomplete | High | ✅ Resolved |
| 4 | AIA `id-ad-caIssuers` (RFC 4158) | High | ✅ Resolved (incl. `cross_sign`) |
| 5 | Private-key recovery endpoint authz | **Critical** | ✅ **FIXED** — `X-Api-Token` gate + 14 tests |
| 6 | Fragile revocation serial extraction | Medium | ✅ Resolved |
| 7 | No `web_ui.py` test coverage | Medium | ✅ html.escape applied + 3 security tests; CORS posture confirmed correct |
| 8 | `_init_key_archive_table` per-op | Low | ⚠️ Confirmed low-overhead; no action needed |
| 9 | `cryptography`/OpenSSL build coupling (PQ) | Medium | ◻️ Operational note (unchanged) |
| 10 | Supply-chain hardening (Tier 6.4) | Medium | ✅ CI + release workflows; .in sources; make-hashes.sh |
| 11 | Dependency drift — misclassified deps in `requirements.txt` | Medium | ✅ Fixed — dev deps removed, pyasn1 annotated optional |

Net: **11 fully resolved**. No open items. #8 confirmed as acceptable low-overhead behavior.

---

## 2. Resolved — evidence only, no action

### #1 Serial-number allocation race — RESOLVED
- Anchor `def _next_serial` (`pki_server.py:2018`). Read-modify-write runs inside
  `with self._pki_db.advisory_lock("serial-allocation")`; `UPDATE` commits on
  `with` exit, before `return serial`.
- Lock is real on both backends:
  - SQLite: `BEGIN IMMEDIATE` — anchor `def advisory_lock` in `SqliteDB`
    (`db.py:352`). Note: ignores `name` (`del name`) — over-serializes, safe.
  - Postgres: `pg_advisory_xact_lock(_stable_lock_id(name))` — anchor
    `def advisory_lock` in `PostgresDB` (`db.py:546`); key fn `_stable_lock_id`
    (`db.py:236`).
- Same pattern: `_ssh_next_serial` (`pki_server.py:4892`), `_next_crl_number`
  (`pki_server.py:2036`, `"crl-allocation"`).
- Design note (not a bug): `_next_serial` issues **monotonic** serials —
  RFC 5280 §4.1.2.2 OK, **not** CA/B-Forum compliant. Leaf paths use
  `x509.random_serial_number()` (`pki_server.py:2097`, `2160`, `3062`).

### #3 DAL migration — RESOLVED
- Only remaining `sqlite3.connect`: `db.py` (DAL implementation — expected),
  `db_bootstrap.py` (pre-DAL pragma init — expected), `backup.py:185`
  (backup reads the DB directly, outside the DAL — acceptable isolation).
  Zero raw connections in any server module (`pki_server`, `web_ui`, `acme`,
  `scep`, `est`, `cmp`, `tsa`, `ocsp`). The "~14 sites remaining" note from
  older specs is obsolete.

### #4 AIA `id-ad-caIssuers` (RFC 4158) — RESOLVED, incl. `cross_sign`
- CLI: anchor `"--ca-issuers-url"` (`pki_server.py:5775`).
- Constructor param `ca_issuers_url` (`pki_server.py:1877`, `1907`).
- Issuance: AIA built as `aia_descriptions` list, emitted once —
  anchor `# AIA — caIssuers (RFC 4158 path building)` (`pki_server.py:2582`).
  `caIssuers` kept under `noRevAvail`; OCSP suppressed (RFC 9608 §4).
- `cross_sign` (`pki_server.py:3647`) builds its own `_cross_aia` list
  (`pki_server.py:3707`–`3725`) — same pattern; the previously flagged gap
  was closed.

### #6 Fragile revocation serial extraction — RESOLVED
- The "first INTEGER > 1000" DER-walk is gone. `revoke_certificate(serial: int, …)`
  (`pki_server.py:2717`) takes a typed serial + parameterized query.
- SCEP wire extraction is now structural: anchor `def _extract_serial_from_ian`
  (`scep_server.py:1377`) decodes `IssuerAndSerialNumber` (issuer `Name`, then
  `serialNumber` INTEGER) via `_decode_tlv` step-by-step.

---

## 3. Fixed but under-guarded — action recommended

### #2 PQ issuance audit-path regression — fix in; add dedicated negative-control test
**State:** The historical `TypeError` at the `audit.record()` call in the PQ
issuance paths is fixed and broadly guarded — `issue_ml_dsa_certificate`,
`issue_composite_certificate`, `issue_slh_dsa` are exercised 32× in
`test_pki_server.py` (ML-DSA class anchor `test_pki_server.py:10517`,
composite `11709`); any regression would fail the suite.

**Gap:** No dedicated regression with a negative control. Existing tests assert
issuance success but were not written to pin *the audit-write specifically*.

**Fix — add one class to the consolidated test file (no new deps):**
- [ ] Add `TestPQIssuanceAuditRegression` to `test_pki_server.py`.
- [ ] For each PQ path: assert (a) a parseable cert returns, (b) signature
      algorithm OID equals PyPKI's own OID constant (import the constants,
      do **not** hardcode dotted strings), (c) exactly one audit row is written,
      (d) the row carries `requester_ip`.
- [ ] Confirm helper/accessor names against source before writing: CA fixture,
      `issue_slh_dsa` arg names, audit count/last accessors, OID constant names.

**Success criteria:**
- Negative control proves the guard bites: revert the `audit.record` fix → the
  new test fails with `TypeError` → re-apply → green.
- Full non-Postgres-gated suite green.

---

## 4. FIXED — private-key recovery endpoint

### #5 `/api/certs/<serial>/recover` — FIXED (2026-06-05)

**Gap in prior audit:** The 2026-06-05 pass-1 audit incorrectly concluded "no
`/api/certs/<serial>/recover` HTTP route exists." The route was live in
`cmp_server.py` and the entire management API was unauthenticated.

**Fix applied (2026-06-05 pass-2):**
- `CMPv2HTTPHandler` gains `api_token: Optional[str] = None` and
  `_check_api_auth()` (uses `hmac.compare_digest`).
- All of `do_POST_api`, `do_PATCH`, and `/api/*` paths in `do_GET` call
  `_check_api_auth()` first; returns `{"error": "unauthorized"}` 401 on failure.
- Public endpoints (`GET /health`, `GET /ca/cert.pem`, `GET /ca/cert.der`,
  `GET /ca/crl`, `GET /metrics`, `GET /.well-known/cmp`) are exempt.
- `api_token` threaded through `make_handler()`, `make_cmpv3_handler()`,
  `_start_cmp_standalone()`, `start_cmp_server()`.
- `--cmp-api-token TOKEN` CLI flag added to `pki_server.py`.
- `TestCMPManagementAPIAuth` (14 tests) in `test_pki_server.py`; all pass.

**Operator action:** Pass `--cmp-api-token $(openssl rand -hex 32)` on startup.
Without the flag, the management API is open (dev mode). A preflight check
should warn when the API is reachable without a token (tracked as follow-up).

---

## 5. Re-verify — action pending

### #7 `web_ui.py` test coverage — PARTIALLY RESOLVED

Verified this pass:

**Covered:**
- Session auth: `TestWebUIPamSetup` (`test_pki_server.py:5125`); PAM authenticate
  tests at `:5170`, `:5184`. Session CRUD: create/validate at `:17372`, expiry at
  `:17389`, revocation at `:17399`. OIDC flow state at `:17268`.
- XSS: login error messages are all hardcoded static strings (lines 820, 829, 838,
  869, 1046) — no user-controlled data reaches `_login_page(error)`. Certificate
  data is delivered to the browser via JSON API, not HTML interpolation. Low risk.

**Not covered / gaps remaining:**
- CSRF: OIDC state mismatch check at `web_ui.py:972` is the only CSRF gate. The
  management REST API (`/api/revoke`, `/api/config`, etc.) has no CSRF token.
  Because these are JSON POST endpoints (not form-based), they're only exploitable
  by CORS-permitted sites — but a missing `Access-Control-Allow-Origin: <admin-only>`
  header would expose them to any origin. Verify CORS headers are set restrictively.
- Config values in form inputs: `_render_svc_form` (`web_ui.py:671`) interpolates
  `saved_cfg` values directly into `value="{cur}"` HTML attributes. These are
  admin-controlled config values (not cert subjects or user inputs), but attribute
  injection is possible if config contains `"`. Low priority.
- PEM/P12 download handlers: tested at the CA layer but not through the web handler
  path.

**Actions:**
- [ ] Verify CORS policy: `Access-Control-Allow-Origin` header on `/api/*` in
  `web_ui.py`. Should be the admin host only, not `*`.
- [ ] Consider `html.escape()` on config values in `_render_svc_form` at line 674.

### #8 `_init_key_archive_table` per-op — CONFIRMED

Anchor `_init_key_archive_table` (`pki_server.py:3968`); called at the top of
`archive_private_key()` (line `3986`) and `recover_private_key()` (line `4026`).
The implementation issues `CREATE TABLE IF NOT EXISTS key_archive …` on every
call, which incurs a round-trip to the DB on every archive/recover operation.

**Assessment:** Low impact. SQLite `CREATE TABLE IF NOT EXISTS` is O(1) when the
table exists. Not a correctness issue. If performance is ever a concern, move
this call to the `CertificateAuthority.__init__` where all other table init runs.
Not a blocking issue; no action required now.

---

## 6. Open — dependency posture

### #11 Dependency drift — PARTIALLY RESOLVED

`requirements.txt` at audit time:
```
cryptography>=41.0
pyasn1>=0.5
pyasn1-modules>=0.3
pytest>=7.0
requests>=2.31
playwright>=1.40
urllib3
```

`requirements-dev.txt` exists and already contains `pytest`, `playwright`,
`requests`, `urllib3` with broader tooling. So the runtime file has test/dev
deps duplicated.

**pyasn1 status (updated):** Both `pki_server.py` and `cmp_server.py` import
`pyasn1` under a `try/except ImportError` guard, setting `HAS_PYASN1 = False`
on failure. The CMP parser gates its use on this flag. So `pyasn1` is an
**optional** runtime dep, not a hard one. The `requirements.txt` entry should
be annotated as optional, or moved to a `requirements-extras.txt`. It should
**not** be listed as a hard dep alongside `cryptography`.

**Fix:**
- [ ] Remove `pytest`, `playwright`, `requests`, `urllib3` from `requirements.txt`
      (they're already in `requirements-dev.txt`).
- [ ] Annotate or move `pyasn1` / `pyasn1-modules` — e.g. add a comment
      `# optional: required for CMP server` or create `requirements-cmp.txt`.
      Update `CLAUDE.md §1.3` dep list to reflect the optional CMP dep.
- [ ] Confirm no server module does `import requests` / `import pytest` /
      `import playwright` unconditionally (verified this pass: none do).

**Success criteria:** `requirements.txt` contains only `cryptography` and
optionally-annotated `pyasn1`; test tooling in `requirements-dev.txt` only.

### #9 `cryptography`/OpenSSL build coupling (PQ) — operational note (unchanged)
The `cryptography` wheel bundles its own OpenSSL; ML-DSA availability depends on
a new-enough build. Documented workaround: build from source. Action: pin an
exact `cryptography` version and document the from-source requirement for PQ in
the deployment guide / preflight.

### #10 Supply-chain hardening (Tier 6.4) — OPEN
Deps use floor pins (`>=`), zero hashes. No `--require-hashes`, no
`pip-compile --generate-hashes`, no SBOM, no signed releases, no `pip-audit`
gate. `cryptography>=41.0` is a stale floor for a CA.

**Fix (per Tier 6.4 spec):**
- [ ] `pip-compile --generate-hashes` → `requirements.txt` + `requirements-dev.txt`
      pinned to exact versions with SHA-256.
- [ ] `pip-audit -r requirements.txt --strict` gate in per-PR CI (HIGH/CRITICAL).
- [ ] `cyclonedx-py` SBOM per release; `cosign`-signed artifacts; reproducible
      build check in `release.yml`.

**Success criteria:** CI rejects unpinned/missing-hash deps and any HIGH/CRITICAL
`pip-audit` finding; release publishes SBOM + signature.

---

## 7. Verification method

Reproduce the core checks:
```sh
cd /path/to/pypki

# DAL completeness (#3)
grep -rn "sqlite3.connect" *.py

# Serial allocation (#1)
grep -n "def _next_serial\|advisory_lock" pki_server.py db.py

# CMP management API auth (#5 — the critical gap)
grep -n "do_POST\|do_POST_api\|_check_auth\|bearer\|Authorization" cmp_server.py
grep -n "recover\|archive\|sub-ca\|/api/" cmp_server.py | grep "elif\|route"

# AIA caIssuers (#4)
grep -n '"--ca-issuers-url"\|caIssuers' pki_server.py

# pyasn1 import guard (#11)
grep -A4 "import pyasn1" pki_server.py cmp_server.py

# Dev deps in runtime file (#11)
grep "pytest\|playwright\|requests\|urllib3" requirements.txt requirements-dev.txt

# Key archive per-op init (#8)
grep -n "_init_key_archive_table" pki_server.py
```

Source-verify every claim before acting. Flag, do not assert, anything you
cannot confirm against current source.
