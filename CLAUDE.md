# CLAUDE.md — RFC Implementation Roadmap for PyPKI

This file gives Claude (and any engineer picking up the work) the context and
concrete steps needed to extend PyPKI's RFC coverage. It covers four tiers of
work, ordered by value. Each RFC section is self-contained: you can pick any
one up without reading the others.

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
  compliance table (line ~1641) and, where user-visible, a feature section
  and/or CLI flag documented.
- **CHANGELOG**: add entries under `## [Unreleased]` grouped by
  `### Added` / `### Fixed` / `### Changed` / `### Security` /
  `### Documentation`.
- **CLI flags** stay additive and namespaced (e.g., `--tsa-port`, `--ct-log-url`).
  Secrets go through existing auth/config patterns, never positional args.
- **Profiles**: new key/EKU combinations belong in the `CertProfile` catalog in
  `pki_server.py` near line 606.
- **No browser storage / no external network calls from servers** — PyPKI is
  offline-capable; any new outbound call must be optional and toggleable.

---

## Tier 1 — Fix existing gaps

These are quick wins. Do them first. Each one closes a known MUST violation
or a modern-client compatibility gap without adding new surface.

### RFC 6818 — Updates to RFC 5280 ✅ SHIPPED

**What was required.** Errata and clarifications to the cert/CRL profile.
Two MUST-violations existed in PyPKI's CRL builders:

1. CRL MUST contain the `cRLNumber` extension (§5.2.3)
2. CRL MUST contain the `authorityKeyIdentifier` extension (§5.2.1)

**What shipped**

- New migration `db_migrations/pki/002_crl_number.sql` adds a `crl_number`
  counter table (single-row keyed on id=1), seeded at 0.
- New helper `CertificateAuthority._next_crl_number()` allocates fresh
  numbers atomically using `BEGIN IMMEDIATE` for cross-process safety.
- All three CRL builders patched:
  - `generate_crl()` (l.1351) — adds both extensions
  - `generate_crl_der()` (l.1727) — adds both extensions
  - `generate_delta_crl()` (l.1826) — adds both extensions on top of the
    pre-existing `DeltaCRLIndicator` (which was already correct, kept as-is)
- Migration runner wired into `CertificateAuthority._init_db` so the
  `crl_number` table is created automatically on first start. Idempotent
  on subsequent starts.
- Pre-existing latent bug fixed: `generate_crl_der` (l.1844) used
  `datetime.fromtimestamp()` against an ISO-8601 TEXT column (`revoked_at`),
  which would have crashed any call against a DB containing revoked certs.
  Fix mirrors `generate_crl()`'s working `fromisoformat()` call. Surfaced
  by the new RFC 6818 tests.

**Tests added** (`TestRFC6818CRLExtensions` in `test_pki_server.py`):

- `test_generate_crl_includes_crl_number_extension` — non-critical, ≥1
- `test_generate_crl_includes_authority_key_identifier` — non-critical,
  matches `SHA-1(CA pubkey BIT STRING)`
- `test_generate_crl_der_includes_both_extensions`
- `test_crl_number_is_monotonically_increasing` across all three builders
- `test_crl_number_persists_across_ca_instances` — survives restart
- `test_delta_crl_includes_all_three_extensions` — cRLNumber, AKI,
  deltaCRLIndicator (critical)
- `test_delta_crl_number_greater_than_base` per RFC 5280 §5.2.4
- `test_crl_signature_still_verifies` — sanity check that the new
  extensions don't break signing

**Outstanding**

- README compliance table: change RFC 5280 row note to mention CRL
  extensions; add RFC 6818 row as `✅ Full`. Pending — markdown only,
  no code.
- CHANGELOG under `### Fixed`: "CRL now includes mandatory `cRLNumber`
  and `authorityKeyIdentifier` extensions (RFC 5280 §5.2.1, §5.2.3 /
  RFC 6818)." Pending — markdown only.
- CHANGELOG under `### Fixed`: "Pre-existing crash in `generate_crl_der`
  when revoked certs were present (used `fromtimestamp()` instead of
  `fromisoformat()`)." Pending — markdown only.

---

### RFC 8954 — OCSP Nonce Extension Update ✅ SHIPPED

**What was required.** The OCSP nonce value must be a DER-encoded OCTET
STRING of 1–32 bytes. Older clients sometimes sent raw bytes; 8954
profiles it strictly.

**What shipped**

- `ocsp_server.py` — `OCSPRequestParser.parse` enforces 1 ≤ len(nonce)
  ≤ 32 after unwrapping the inner OCTET STRING. Out-of-bounds nonces
  set a `nonce_length_violation` flag in the parsed dict.
- `ocsp_server.py` — `OCSPHandler._handle_request` checks the flag and
  returns `RESP_MALFORMED_REQUEST` (status 1) per RFC 8954 §2.1.
- New CLI flag `--ocsp-require-nonce` plumbed through `pki_server.py`
  argparse → `start_ocsp_server` → `OCSPHandler.require_nonce`. When
  set, nonceless requests are rejected with `RESP_UNAUTHORIZED`
  (status 6). Default off, matching RFC 6960 default.
- Echo behavior unchanged — valid nonces are reflected verbatim per
  RFC 6960 §4.4.1.

**Tests added** (`TestRFC8954OCSPNonce` in `test_pki_server.py`):

- 1, 8, 16, 32 byte nonces accepted (boundary coverage)
- 33, 64, 128 byte nonces flagged as violations
- Empty (0-byte) nonce flagged as violation
- Nonceless request accepted in default mode
- Oversize nonce returns malformed-request from handler
- Strict mode rejects nonceless request with unauthorized
- Strict mode accepts request that DOES carry a valid nonce

**Outstanding**

- README OCSP section bullet — pending markdown only.
- CHANGELOG `### Added`: "RFC 8954 nonce profile enforcement
  (1–32 byte bounds at parse time; `--ocsp-require-nonce` strict mode
  flag)." — pending markdown only.

---

### RFC 4055 — RSASSA-PSS and RSAES-OAEP ✅ SHIPPED (PSS for CA signing)

PSS is now an opt-in CA signing mode via `--sig-algorithm rsa-pss`. The
shipped surface covers RSASSA-PSS with MGF1+SHA-256 and salt length 32
(matches NIST SP 800-131A guidance). OAEP for key transport is not yet
wired and remains TODO if a CMS / SCEP path needs it.

— Original plan retained below for reference —

**What it requires.** Algorithm identifiers for PSS signatures and OAEP
encryption. Modern Authenticode and EU eIDAS expect PSS.

**Files to modify**

- `pki_server.py` → `CertificateAuthority.issue_certificate()` (line ~988)
- `cmp_server.py` → CA signature selection
- `scep_server.py` → `CMSBuilder` signature path (line ~485)

**Implementation**

- Add a CA-level config flag `sig_algorithm` with values
  `rsa-pkcs1v15` (default) or `rsa-pss`. Read from `pypki.json` or
  `--sig-algorithm` CLI flag.
- In `issue_certificate()`, when PSS is selected, sign via
  `.sign(ca_key, SHA256(), padding.PSS(mgf=MGF1(SHA256()),
  salt_length=SHA256().digest_size))` — note that the `cryptography` library
  needs the padding threaded through the builder; use `x509.CertificateBuilder`
  path with the library's native PSS support when available, or fall back to
  raw TBS bytes + PSS signature for older versions.
- Publish the PSS parameters in the certificate's `signatureAlgorithm` field
  (library handles this automatically when PSS is used).
- For CMS (SCEP): add PSS signer option in `CMSBuilder._build_signer_info`.
  OID: `1.2.840.113549.1.1.10` with `RSASSA-PSS-params` SEQUENCE.

**Tests** (new class `TestRFC4055PSS`)

- Issue a cert with `sig_algorithm=rsa-pss`; parse and verify `oid ==
  1.2.840.113549.1.1.10` and RSASSA-PSS-params decode correctly.
- Round-trip verification: `cert.public_key().verify(...)` with PSS padding.
- CMS SignedData with PSS signer parses in OpenSSL:
  `openssl cms -verify -in out.p7s -inform DER ...`.

**Docs**

- README: new subsection "Signature algorithm selection" in the CA features
  block. Compliance table: add RFC 4055 `✅ Full`.
- CHANGELOG `### Added`: RSASSA-PSS signature algorithm support.

---

### RFC 7468 — Textual Encoding of PKIX Structures (strict PEM) ✅ SHIPPED

**What was required.** PEM bundle ingestion must enforce uppercase-only
BEGIN/END markers, label-match, valid base64, and reject trailing or
inter-block text. Existing single-object loads via `cryptography` already
pass through library validation; the gap was multi-object bundles
(`ca-chain.pem`) where a hand-rolled regex extracted `CERTIFICATE` blocks
permissively.

**What shipped**

- `pki_server.py` — new module-level helper
  `_parse_pem_bundle(data, allowed_labels=None) -> list[tuple[str, bytes]]`
  parses by tokenising `-----BEGIN <LABEL>-----`/`-----END <LABEL>-----`
  pairs and decoding the base64 body. Enforces the full RFC 7468 §3
  framing contract: uppercase-only marker keywords *and* labels (a case-
  insensitive scan catches any non-canonical case), matching BEGIN/END
  labels, whitespace-only inter-block and post-last-block content, and
  the standard base64 alphabet (`A–Za–z0–9+/` with at most two trailing
  `=`). Both 64-column-wrapped and unwrapped base64 are accepted as long
  as the alphabet is valid.
- `pki_server.py` — `_load_parent_chain` now calls `_parse_pem_bundle`
  with `allowed_labels={"CERTIFICATE"}` instead of the prior
  `re.findall` regex. Errors bubble up wrapped in the existing
  `parent_chain_path '<file>': ...` context so operator output stays
  actionable. The chain validation chain (issuer→subject continuity,
  signature-over-ca.crt) is unchanged.
- `_RFC7468_DEFAULT_LABELS = {"CERTIFICATE", "X509 CRL", "PKCS7"}` is
  exposed at module level for future import callers (PKCS#7 bundles,
  CRL imports) so they all share the same allowlist.

**Tests added** (`TestRFC7468PEM`, 15 tests):

- Canonical 64-column PEM accepted; round-trips byte-exact with
  `x509.load_der_x509_certificate`
- Unwrapped (single-line) base64 accepted per RFC 7468 §3
- Multiple concatenated blocks parse in file order
- Lowercase `-----begin` / `-----end` rejected with "uppercase" error
- Trailing non-whitespace after the last END rejected
- Stray text between two valid blocks rejected
- BEGIN/END label mismatch rejected with "mismatch" error
- Invalid base64 alphabet (`@`) rejected with "base64" error
- Empty body rejected
- Missing END marker rejected
- Unknown label rejected when `allowed_labels` is set
- Default allowlist accepts `CERTIFICATE`, `X509 CRL`, `PKCS7`
- Integration test: `_load_parent_chain` surfaces the strict-parse
  ValueError on a tampered chain file

**Outstanding**

- README compliance table updated to `✅ Full` — done.
- CHANGELOG `### Added` entry — done.
- Wire the helper into other future PEM bundle ingestion paths (PKCS#7
  imports, CRL imports from disk) as those features land.

---

### RFC 4210 — CMPv2 response protection ✅ SHIPPED

**What was required.** §5.1.3: every `PKIMessage` SHOULD carry a
`protection` BIT STRING signed by the sender. PyPKI was parsing client
protection but not emitting any on responses — strict CMP clients
(EJBCA, some strongSwan pki builds, RFC 9482 Lightweight CMP Profile
validators) reject unprotected responses.

**What shipped**

- `cmp_server.py` — `CMPv2ASN1.build_pki_message` accepts new keyword
  arguments `signer_key`, `signer_cert`, `extra_certs`. When
  `signer_key` is supplied, the response is signed and the
  `[0] PKIProtection` BIT STRING + `[1] extraCerts SEQUENCE OF Certificate`
  fields are appended to the PKIMessage SEQUENCE.
- Signature is computed over `ProtectedPart ::= SEQUENCE { header, body }`
  (DER) per RFC 4210 §5.1.3.3. Algorithm: `sha256WithRSAEncryption`,
  matching the existing `protectionAlg` hint in the header. PSS / ECC
  algorithm coverage will follow when RFC 4055 / RFC 5480 land.
- New helper `CMPv2Handler._protected_response` wraps `build_pki_message`
  and auto-supplies `signer_key=self.ca.ca_key`, `signer_cert=self.ca.ca_cert`,
  and `extra_certs=self.ca._parent_chain`. All 12 caller sites in
  `CMPv2Handler` and `CMPv3Handler` migrated to use the helper. The
  legacy unprotected path is preserved (no kwargs → no protection) for
  back-compat with tests and bootstrap scenarios.

**Tests added** (`TestRFC4210Protection`, 6 tests):

- Legacy unprotected path still works (no signer_key → no [0]/[1] fields)
- Protected message has [0] protection field (tag 0xA0)
- Protected message has [1] extraCerts field (tag 0xA1)
- Protection signature verifies against ProtectedPart with CA pubkey
- Protection signature fails against corrupted body bytes
- ExtraCerts contains the signer cert DER

**Outstanding**

- README CMP section bullet — pending markdown only.
- CHANGELOG `### Security`: "CMPv2/v3 responses now carry signature
  protection and CA cert chain in extraCerts, closing RFC 4210 §5.1.3
  gap." — pending markdown only.

---

### RFC 4211 — CRMF proof-of-possession verification ✅ SHIPPED

**What was required.** §4: when a CRMF `CertReqMsg` is submitted with a
`POPOSigningKey`, the server MUST verify the signature to prove the
requester holds the private key matching the requested public key.
Without this check, a malicious requester can submit a CRMF claiming
someone else's public key.

**What shipped**

- `cmp_server.py` — new `CMPv2ASN1.parse_crmf(body_raw)` returns a
  richer dict including `subject`, `spki`, `certreq_der` (the bytes
  signed by POPO per §4.1 case 2), and `popo_raw` (the POPO TLV).
- `cmp_server.py` — new `CMPv2ASN1.verify_popo(certreq_der, spki, popo_raw)`
  returns `(ok: bool, reason: str)`. Supports RFC 4211 §4.1 **case 2
  only** (POPOSigningKey without POPOSigningKeyInput, signed bytes =
  certRequest DER). Rejects raVerified, keyEncipherment, keyAgreement
  alternatives — case 1/3 with POPOSigningKeyInput is also rejected
  with a clear error message.
- Algorithms verified: RSA-PKCS1v15 with SHA-256/384/512, ECDSA with
  SHA-256/384/512, Ed25519. Algorithm OID extracted from the CRMF
  itself, not the certTemplate, and cross-checked against the public
  key type to prevent algorithm-substitution attacks.
- `cmp_server.py:_handle_cert_request` now invokes `parse_crmf` +
  `verify_popo`. On failure or missing POPO with client-supplied SPKI:
  returns `PKIStatusInfo` rejection (status 2) with `failInfo` bit 9
  (`badPOP`) per RFC 4210 §3.1.4. Audit-logs both `popo_failed` and
  `popo_missing` events.
- Legacy `extract_subject_and_pubkey_from_crmf` kept as a back-compat
  wrapper returning `(subject, spki)` — no external callers exist in
  tree, but the wrapper means any third-party code keeps working.

**Tests added** (`TestRFC4211POPO`, 9 tests):

- `parse_crmf` returns the richer dict (certreq_der, popo_raw)
- Legacy extractor still works
- Valid RSA-SHA256 POPO accepted
- Valid ECDSA P-256 POPO accepted
- Valid Ed25519 POPO accepted
- POPO signed by a different key than certTemplate's SPKI → rejected
  (the classic attack vector)
- Corrupted signature bytes → rejected
- raVerified ([0] NULL) variant → rejected
- Empty inputs return False without crashing

**Outstanding**

- README CMP section bullet — pending markdown only.
- CHANGELOG `### Security`: "Enforce CRMF proof-of-possession per
  RFC 4211 §4; prevent cert issuance for third-party public keys."
  — pending markdown only.

---

### RFC 5958 — Asymmetric Key Package (PKCS#8) normalization

**What it requires.** §2: private keys delivered to clients should be
encoded as `OneAsymmetricKey` (PKCS#8 v2) or `PrivateKeyInfo` (PKCS#8 v1),
not legacy `RSAPrivateKey` (PKCS#1) or `ECPrivateKey` (SEC1).

**Source evidence.** EST (`est_server.py:520`) and IPsec
(`ipsec_server.py:876`) correctly use `PrivateFormat.PKCS8`. CMP had four
sites using `PrivateFormat.TraditionalOpenSSL` (PKCS#1 for RSA, SEC1 for EC);
the Web UI sub-CA endpoint was a fifth. **All five fixed.**

- ~~`cmp_server.py:585` — `ir` auto-generated key~~ **FIXED**
- ~~`cmp_server.py:1068` — PKCS#12 bundle construction path~~ **FIXED**
- ~~`cmp_server.py:1171` — API key return~~ **FIXED**
- ~~`cmp_server.py:1195` — enrollment response private key field~~ **FIXED**
- ~~`web_ui.py:1563` — sub-CA export~~ **FIXED**

**Additional sites discovered after the initial audit** (lower stakes —
mostly disk persistence of the CA's own keys, not client deliveries):

- `pki_server.py:885` — CA key persisted to disk on first boot
- `pki_server.py:1432` — internal key write
- `pki_server.py:1522` — internal key write
- `pki_server.py:1672` — internal key write
- `ipsec_server.py:2395` — IPsec response key
- `ipsec_server.py:2479` — IPsec response key
- `ocsp_server.py:472` — OCSP signer key persisted to disk

These should also migrate to PKCS#8 for consistency and ECC compatibility.
Functionally lower stakes since these files are read back only by PyPKI
itself (the format is internal), but the change is mechanical and the
risk is purely cosmetic. Track as a follow-up cleanup pass; not blocking.

**Files modified for the closed-out fix**

- `cmp_server.py` at the four line numbers above.

**Implementation**

- Replace `PrivateFormat.TraditionalOpenSSL` with `PrivateFormat.PKCS8` at
  every site. One-line changes. No compatibility risk — every modern tool
  (OpenSSL 1.1+, strongSwan, Java keytool, Windows certutil) reads PKCS#8
  transparently.
- Grep the rest of the codebase once to confirm no other site slipped
  through: `grep -rn "TraditionalOpenSSL" *.py` — only the four above should
  remain, and this edit removes them all.

**Tests**

- Existing CMP tests should still pass. Add one assertion in
  `TestCMPMessageStructure` (or a new `TestRFC5958PKCS8`): parse the returned
  private-key bytes with `serialization.load_der_private_key(pem)`; assert
  the first bytes decode as a PKCS#8 `PrivateKeyInfo` SEQUENCE (outer
  version INTEGER = 0, then AlgorithmIdentifier).

**Docs**

- CHANGELOG `### Changed`: "CMP private-key output normalized to PKCS#8
  (RFC 5958); removes TraditionalOpenSSL/PKCS#1 format from
  `ir`/`cr`/`kur` responses."
- Compliance table: RFC 5958 `✅ Full` (after the edit).

---

### Sub-CA issuance ergonomics (Kubernetes / cert-manager readiness)

**Context.** When PyPKI is used as a sub-CA provider for Kubernetes
(cert-manager `CA` ClusterIssuer), service mesh intermediates
(Istio/Linkerd), or any downstream consumer that holds the issued CA key,
three ergonomics gaps made the `/api/issue-sub-ca` path awkward. All three
are now fixed.

**What was wrong**

1. **Key output format.** `web_ui.py:1553` returned the sub-CA key as
   `PrivateFormat.TraditionalOpenSSL` (PKCS#1 for RSA, SEC1 for EC). Works
   with cert-manager and kubeadm but fails the RFC 5958 bar and breaks the
   moment an EC sub-CA is issued on tooling that expects PKCS#8. **Fixed**
   → `PrivateFormat.PKCS8`.

2. **Name constraints not exposed.** The REST endpoint called
   `issue_sub_ca()` unconditionally, bypassing
   `issue_certificate_with_name_constraints()`. A cluster holding an
   unconstrained sub-CA can mint certs for any name — serious blast-radius
   issue. **Fixed** → endpoint now accepts `permitted_dns`, `excluded_dns`,
   `permitted_emails`, `excluded_ips` and routes to the name-constrained
   path when any are present.

3. **`path_length` silently ignored.** `issue_sub_ca()` accepted a
   `path_length` parameter but never threaded it to `issue_certificate()`;
   the `sub_ca` profile hardcoded `path_length: 0`. Nested-CA scenarios
   (cluster-CA → mesh-intermediate → pod certs) were impossible via the
   high-level API. **Fixed** → `issue_certificate()` now accepts
   `path_length` as an explicit override, and both `issue_sub_ca` and
   `/api/issue-sub-ca` thread it through.

**Canonical Kubernetes bootstrap request**

```bash
curl -u admin:PASS -X POST https://pypki.local/api/issue-sub-ca \
  -H 'Content-Type: application/json' \
  -d '{
    "cn":               "k8s-cluster-ca",
    "validity_days":    1825,
    "path_length":      1,
    "permitted_dns":    ["cluster.local", "svc", "homelab.local"],
    "excluded_dns":     [],
    "permitted_emails": [],
    "excluded_ips":     []
  }'
```

`path_length=1` lets the cluster CA delegate one further tier (e.g., an
Istio/Linkerd intermediate). Use `path_length=0` if cert-manager will be the
sole consumer and no further CA is nested below.

**Remaining polish (not yet implemented)**

- **PKCS#12 bundle option.** Returning raw PEM over JSON is fine over mTLS
  on localhost, less so over any path involving logs, proxies, or shell
  history. Add `export_format: "pkcs12"` + `password` fields to
  `/api/issue-sub-ca`; reuse the existing
  `pkcs12.serialize_key_and_certificates` path. ~15 lines.
- **Sub-CA key encryption at rest for the response.** Optional
  `key_password` field that encrypts the returned PEM with PKCS#8 AES-256
  (the IPsec module already does this at `ipsec_server.py:876`).

**Deployment prerequisite (not a code change)**

Before bootstrapping any downstream consumer, start PyPKI with
`--ocsp-url` and `--crl-url` pointing at a cluster-reachable FQDN. The
sub-CA cert embeds these as AIA and CDP extensions
(`pki_server.py:1195-1220`); if the hostname isn't reachable from where
the chain gets validated, verification silently degrades.

**Tests**

- `TestSubCAIssuance` — add assertions:
  - Returned key PEM starts with `-----BEGIN PRIVATE KEY-----` (PKCS#8),
    not `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1).
  - When `path_length=1` is requested, the issued cert's `BasicConstraints`
    `path_length == 1`.
  - When `permitted_dns=["cluster.local"]` is requested, the issued cert
    carries a critical `NameConstraints` extension with exactly that
    permitted subtree.
- An integration test that issues a sub-CA, loads it as a local cert-manager
  mock issuer, and issues a workload cert from it — probably too heavy for
  the unit suite; keep as a manual checklist in the deployment runbook.

---

### EST CSR SAN pass-through + profile-aware csrattrs ✅ SHIPPED

**Context.** EST (`est_server.py`) had three related weaknesses around
Subject Alternative Name handling. All three are now fixed.

**1. CSR SANs were dropped on issuance — FIXED.**

`_handle_simpleenroll` used to call `ca.issue_certificate(subject_str=..., public_key=...)`
without extracting SANs from the CSR's `extensionRequest` attribute. A client
asking for `DNS:app.example.com` received a cert with **no SAN at all**.

The fix mirrors the `ipsec_server.py` pattern: extract `DNSName`,
`RFC822Name`, `IPAddress`, and `UniformResourceIdentifier` entries from the
CSR's SAN extension and pass them to `issue_certificate`. URI SANs (including
SPIFFE) are now plumbed through — see item 3.

**2. EST label routing to certificate profiles — ✅ SHIPPED** (commit `8fefbf5`)

`est_server.py` now has `EST_LABEL_PROFILE` mapping and `_handle_simpleenroll`,
`_handle_csrattrs`, and `_handle_serverkeygen` all accept and use `profile`.

```
/.well-known/est/simpleenroll              → profile="default"
/.well-known/est/tls-server/simpleenroll   → profile="tls_server"
/.well-known/est/tls-client/simpleenroll   → profile="tls_client"
/.well-known/est/ipsec/simpleenroll        → profile="ipsec_end"
/.well-known/est/code-signing/simpleenroll → profile="code_signing"
/.well-known/est/spiffe/simpleenroll       → profile="spiffe"
```

Unknown labels default to `"default"` (RFC 7030 doesn't mandate strict
label handling). `build_csrattrs(profile)` now returns profile-specific EKU
hints.

Tests added: `TestESTRouting` (label → profile routing, profile-aware
csrattrs EKU hints, unknown label fallback).

**3. Profile-specific `csrattrs` + server-side SAN format enforcement — ✅ SHIPPED** (commit `8fefbf5`)

`EST_CSR_ATTRS` dict in `est_server.py` enforces per-profile SAN constraints
at `simpleenroll`. New `_validate_csr_for_profile(csr, profile)` helper.

```python
EST_CSR_ATTRS = {
    "tls_server": {
        "san_required": True, "san_types": {"DNS", "IP"},
        "forbid_san": {"RFC822Name", "UniformResourceIdentifier", "OtherName"},
    },
    "tls_client": {
        "san_required": True, "san_types": {"DNS", "RFC822Name"},
    },
    "spiffe": {
        "san_required": True, "san_types": {"UniformResourceIdentifier"},
        "uri_scheme": "spiffe", "uri_authority": "cluster.local",
    },
    "ipsec_end": {
        "san_required": True, "san_types": {"DNS", "IP"},
    },
}
```

`pki_server.py` — `issue_certificate` now accepts `san_uris: Optional[list]`
so SPIFFE URI SANs land in the issued cert.

Tests added: `TestRFC7030ProfileCSRAttrs` — label csrattrs content, SPIFFE
URI acceptance/rejection, tls-server URI rejection, unknown label fallback.

**Why this matters for Kubernetes / SPIFFE.** EST is the right answer for
non-k8s devices (VPN clients, IoT nodes, Windows machines) that want
SPIFFE-style identities. PyPKI is now one of very few servers that does
profile-aware EST with SPIFFE enforcement.

---

## Tier 2 — High-value modern additions

### RFC 3161 + RFC 5816 — Time-Stamp Protocol ✅ SHIPPED

**What it requires.** A TSA accepts a `TimeStampReq` (hash + nonce + policy)
and returns a `TimeStampResp` containing a CMS SignedData wrapping a `TSTInfo`.
RFC 5816 upgrades the `ESSCertID` to `ESSCertIDv2` with SHA-256. **Always
implement both together.**

**What shipped** (commit `4e95674`)

- `tsa_server.py` (new file, ~430 lines): `TSARequestParser`, `TSAResponseBuilder`,
  `TSAHandler`, `TSASerialCounter`, `provision_tsa_signing_cert`,
  `start_tsa_server`. Full RFC 3161 DER encode/decode using hand-rolled ASN.1
  helpers from `scep_server.py`. Signed attributes sorted lexicographically
  (DER canonical SET OF) and re-tagged `[0] IMPLICIT` for `SignerInfo`.
- `pki_server.py`: `tsa_signing` CertProfile (EKU `id-kp-timeStamping` critical,
  KU `digitalSignature` only); TSA wired after OCSP in `main()`; CLI flags
  `--tsa-prefix`, `--tsa-policy-oid`, `--tsa-accuracy-seconds`, `--tsa-cert`,
  `--tsa-key`; TSA line in startup banner.
- RFC 5816 `signingCertificateV2`: SHA-256 of TSA cert DER in `ESSCertIDv2`
  SEQUENCE; `hashAlgorithm` omitted (DEFAULT sha256 per RFC 5816 §3).
- Policy: SHA-256/384/512 accepted; MD5/SHA-1 rejected with `badAlg`; wrong
  `version` rejected with `badRequest`; rate-limited and audit-logged.
- `TSA_DEFAULT_POLICY_OID = "1.3.6.1.4.1.99999.1"` (placeholder — replace
  with a real PEN OID in production).

**Tests added** (`TestRFC3161TSA` in `test_pki_server.py`, 25 tests):

- Parse, grant (status/OID/imprint/nonce/serial), certReq, RFC 5816
  `signingCertificateV2` present + hash matches, CMS signature verify +
  corrupt, hash policy (SHA-256/384/512 ✅; MD5 ❌), serial monotonicity.
- TSA cert RFC compliance: EKU `id-kp-timeStamping` critical, only EKU.
- `TestModuleStructure::test_cert_profile_has_all_profiles` updated to include
  `tsa_signing`.

**CLI flags**

```
--tsa-prefix PATH            URL prefix for TSA endpoint (default /tsa)
--tsa-policy-oid OID         Policy OID (default 1.3.6.1.4.1.99999.1)
--tsa-accuracy-seconds N     Declared accuracy (default 1)
--tsa-cert PATH              Pre-provisioned TSA cert (otherwise auto-issued)
--tsa-key PATH               Pre-provisioned TSA key
```

**Docs**: README compliance table updated (✅ Full). CHANGELOG `### Added`.

— Original plan retained below for reference —

**Files created/modified**

- `tsa_server.py` — mirror the shape of `ocsp_server.py`: its own
  `HTTPServer` with a handler class, a builder class, and integration hooks
  back into `CertificateAuthority`.
- `pki_server.py` — dedicated TSA signing cert auto-issued from the CA.

---

### RFC 8738 — ACME IP Identifier ✅ SHIPPED

**What was required.** Accept `{"type": "ip", "value": "<IPv4/IPv6>"}`
identifiers in ACME orders, omit `dns-01` for them, validate via
`http-01` / `tls-alpn-01` against the literal IP, and emit `iPAddress`
SAN entries on the issued certificate.

**What shipped**

- `acme_server.py` — new module-level `_validate_acme_identifier(ident,
  *, allow_private_ip)` helper parses ip values via
  `ipaddress.ip_address()` and gates private/loopback/link-local/
  multicast/reserved/unspecified addresses behind the new flag. Returns
  `(ok, error_detail)` for clean ACME problem-detail mapping
  (`unsupportedIdentifier` vs `rejectedIdentifier`).
- `acme_server.py` — `_ACME_CHALLENGE_TYPES_BY_IDENTIFIER` constant maps
  identifier type to challenge set. `ACMEDatabase.create_order` reads
  the per-identifier challenge tuple instead of always creating all
  three — RFC 8738 §4 compliance.
- `acme_server.py` — `_handle_new_order` calls the validator for every
  identifier; rejected identifiers produce 400 with the correct ACME
  problem type.
- `acme_server.py` — `_handle_finalize` computes `order_ips` set from
  `ip`-type identifiers, extracts `IPAddress` SANs from the CSR, asserts
  `csr_ips >= order_ips`, and threads `san_ips=...` into
  `issue_certificate` so the leaf carries `iPAddress` SANs (not
  `dNSName`). Primary subject CN falls back to the first IP literal for
  ip-only orders.
- `acme_server.py` — `ChallengeValidator.validate_http01` brackets IPv6
  literals in the URL per RFC 3986 §3.2.2; IPv4 and DNS hostnames are
  left untouched.
- `acme_server.py` — `make_acme_handler` and `start_acme_server` gained
  an `allow_private_ip: bool = False` parameter.
- `pki_server.py` — new `--acme-allow-private-ip` CLI flag (default off);
  threaded into `start_acme_server`.

**Tests added** (`TestRFC8738ACMEIPId`, 16 tests):

- Validator: dns accepted; public IPv4 (`8.8.8.8`) and public IPv6
  (`2606:4700:4700::1111`) accepted; private IPv4 rejected (10/8,
  192.168/16, 127/8, 169.254/16) with `private` in the detail; private
  IPv4 accepted when flag is on; malformed IP rejected; unknown
  identifier type rejected.
- Database: `create_order` for `ip` produces only `http-01` +
  `tls-alpn-01` challenges; for `dns` all three; mixed-identifier orders
  produce the correct set per authorization independently.
- `validate_http01`: IPv6 → `http://[v6]/...`; IPv4 → no brackets;
  hostname → no brackets (mocking `urllib.request.urlopen` to capture
  the URL).
- CLI plumbing: `start_acme_server` accepts `allow_private_ip` with
  default `False`; `make_acme_handler` propagates it to the class
  attribute.
- End-to-end finalize: an ip-only issuance produces a cert with
  exactly one `iPAddress` SAN and zero `dNSName` SANs.

**Outstanding**

- README compliance table — done (✅ Full).
- README ACME section bullet — done.
- CHANGELOG `### Added` — done.

---

### RFC 8410 — Ed25519 and Ed448 in X.509 ✅ SHIPPED

CA bootstrap supports `--ca-key-type ed25519` and `ed448`. Issued certs
and CRLs carry the correct EdDSA signature OID (`1.3.101.112` /
`1.3.101.113`). `_sign_builder` returns `builder.sign(key, None)` for
EdDSA. SCEP rejects EdDSA CAs at startup because CMS `SignerInfo`
requires a named digest algorithm (RFC 5652) — operator gets a clear
error pointing at `--ca-key-type rsa-...`.

— Original plan retained below for reference —

**What it requires.** Algorithm identifiers and subjectPublicKeyInfo encoding
for Ed25519/Ed448. Fast, small, no parameters.

**Files to modify**

- `pki_server.py` → `CertificateAuthority.__init__` (CA key generation),
  `issue_certificate()` (EE key generation), `CertProfile` (signature_alg
  per profile).
- `cmp_server.py`, `scep_server.py`, `est_server.py`, `acme_server.py`,
  `ipsec_server.py` → CSR signature verification paths already use
  `csr.is_signature_valid` which handles EdDSA via `cryptography` — verify.

**Implementation**

- Add `--ca-key-type` CLI flag: `rsa-2048` (default), `rsa-3072`, `rsa-4096`,
  `ec-p256`, `ec-p384`, `ed25519`, `ed448`.
- Key generation: `ed25519.Ed25519PrivateKey.generate()`.
- Signing: no hash algorithm passed to `builder.sign(ed_key, None)`. Watch for
  the several existing call sites that hardcode `SHA256()` — refactor into a
  helper `_sign_for_key(key, builder)` that picks the right padding/hash.
- Verify `ipsec_server.py:775` path already handles `None` hash (it has a
  comment about Ed25519); extend tests.
- SCEP does not support Ed25519 (CMS signer hash must be defined). Document
  that SCEP and RSA-PSS CA keys cannot combine with Ed25519 EE keys for the
  SCEP path; other protocols are fine.

**Tests** (new class `TestRFC8410EdDSA`)

- Generate Ed25519 CA, issue an RSA EE cert and an Ed25519 EE cert.
- Parse issued cert: `public_key()` is `Ed25519PublicKey`; signature OID is
  `1.3.101.112`.
- Verify CSR signature for an Ed25519 CSR.
- Cross-protocol: CMP `ir` with Ed25519 CA → pass; SCEP with Ed25519 CA →
  clear error, not a crash.

**Docs**

- README: add to Quick Start an Ed25519 example.
- Compliance table: RFC 8410 `✅ Full` (CA, CMP, EST, ACME, IPsec) /
  `⚠️ N/A for SCEP` with rationale.

---

### RFC 5480 + RFC 5758 — ECDSA and EC keys in PKIX ✅ SHIPPED (CA-side)

Full multi-curve coverage at the CA level: `--ca-key-type ec-p256`,
`ec-p384`, `ec-p521`. Matched-curve hash per RFC 5758 §3.2; signature
OIDs `1.2.840.10045.4.3.2/3/4` (ecdsa-with-SHA-256/384/512) appear in
issued certs and CRLs. SPKI is `id-ecPublicKey` (`1.2.840.10045.2.1`)
with the named-curve OID parameter.

Client / CSR-driven EC keys already worked through the library; this
ships the CA-side counterpart so the *CA itself* can be ECC.

— Original plan retained below for reference —

**What it requires.** RFC 5480 defines SPKI encoding, named curves
(P-256/384/521), and algorithm identifiers for ECC. RFC 5758 defines the
SHA-2 + ECDSA signature algorithm OIDs (e.g., `ecdsa-with-SHA256` =
`1.2.840.10045.4.3.2`).

**Source evidence.** Every CA-side key generation is hardcoded to RSA:
`pki_server.py:820` (CA), `1290`, `1386`, `1429`, `1599`, `1740` (EE/signing
subordinates). Every `builder.sign()` call uses `SHA256()` with RSA.
`acme_server.py:84` imports `EllipticCurvePublicKey` for account keys only.
**No EC certificate can currently be issued or signed by the CA.**

**Implementation strategy.** Do this work alongside or just after RFC 8410.
Both tasks converge on the same refactor: a single helper that picks the
correct `sign()` arguments for any key type.

**Files to modify**

- `pki_server.py` → every `rsa.generate_private_key` call site; every
  `.sign(self.ca_key, SHA256())` site (grep: `\.sign(.*SHA256`).
- `cmp_server.py` → three RSA generation sites (l.1290, 1386, 1429).
- `pki_server.py` → `CertProfile` — add per-profile allowed key types.

**Implementation**

- Add a single helper:
  ```python
  def _sign_builder(builder, key):
      if isinstance(key, rsa.RSAPrivateKey):
          return builder.sign(key, SHA256())
      if isinstance(key, ec.EllipticCurvePrivateKey):
          curve_to_hash = {
              ec.SECP256R1: SHA256, ec.SECP384R1: SHA384,
              ec.SECP521R1: SHA512,
          }
          h = next((H for C, H in curve_to_hash.items()
                    if isinstance(key.curve, C)), SHA256)
          return builder.sign(key, h())
      if isinstance(key, (ed25519.Ed25519PrivateKey,
                          ed448.Ed448PrivateKey)):
          return builder.sign(key, None)
      raise TypeError(f"Unsupported key type: {type(key).__name__}")
  ```
- Add CLI flag `--ee-key-type` to control EE key generation
  (`rsa-2048`/`rsa-3072`/`ec-p256`/`ec-p384`/`ed25519`), separate from the
  CA key type added under RFC 8410.
- Allow CSR-driven key type (when a client submits a CSR with an EC key,
  issue an EC cert — no change needed beyond removing the "RSA only"
  assumption in the policy checks at pki_server.py:1886).
- `CertProfile` per-profile allowed algorithms: `tls_server` and
  `tls_client` accept all; `code_signing` accepts RSA + ECDSA (Authenticode
  compat).
- Ensure `signatureAlgorithm` in issued cert uses the right OID per
  RFC 5758:
  - `1.2.840.10045.4.3.2` ecdsa-with-SHA256
  - `1.2.840.10045.4.3.3` ecdsa-with-SHA384
  - `1.2.840.10045.4.3.4` ecdsa-with-SHA512
  `cryptography` library sets these correctly when `.sign(ec_key, SHA256())`
  is used — verify in tests rather than hand-encoding.
- SPKI per RFC 5480: `AlgorithmIdentifier` = `id-ecPublicKey` (`1.2.840.
  10045.2.1`) + named curve OID parameter. Library handles this.

**Tests** (new class `TestRFC5480RFC5758ECC`)

- Generate P-256 CA → issue EE cert → parse: signature OID =
  `1.2.840.10045.4.3.2`, SPKI alg OID = `1.2.840.10045.2.1`, parameter =
  `1.2.840.10045.3.1.7` (secp256r1).
- P-384 CA + P-384 EE → signature OID = `1.2.840.10045.4.3.3`.
- P-256 CA + RSA EE → verify CA signs cert with ECDSA-SHA256 but EE's public
  key is RSA.
- CRL: P-256-signed CRL parses and verifies.
- OCSP: response signed by P-256 OCSP signer cert verifies.

**Docs**

- README Quick Start: add an EC example:
  `python pypki.py --ca-key-type ec-p256 --ee-key-type ec-p256`.
- Compliance table: RFC 5480 `✅ Full`, RFC 5758 `✅ Full`.
- CHANGELOG `### Added`: "ECC certificates (P-256/384/521) per RFC 5480 +
  RFC 5758; CA, intermediate, EE, OCSP signer, and CRL signing all
  support ECDSA."

---

### RFC 7292 — PKCS#12 hardening ✅ SHIPPED (partial)

**What it requires.** PKCS#12 export already works
(`pki_server.py:1757`). RFC 7292 (v1.1) fixes encoding ambiguities. Modern
guidance (NIST SP 800-132) demands a strong KDF iteration count.

**What shipped** (commit `8fefbf5`)

- `pki_server.py` — `export_pkcs12` now sets `friendly_name` to the cert
  subject CN (falling back to `"cert-<serial>"`), improving UX in Windows
  and macOS certificate import dialogs. `BestAvailableEncryption(password)`
  was already in place, giving AES-256 + HMAC-SHA256 with ≥600k PBKDF2
  iterations via the `cryptography` library.

**Outstanding**

- `--p12-allow-unencrypted` flag and rejection of passwordless export —
  not yet implemented. Currently unencrypted export is accepted silently.

**Tests**: `TestPKCS12Export` extended to verify `friendlyName` round-trip.

**Files to modify** (remaining)

- `pki_server.py` → `CertificateAuthority.export_pkcs12()` — reject
  password-less export unless `--p12-allow-unencrypted` is set.

**Docs**

- README: PKCS#12 section already exists — add note about default encryption
  strength and RFC 7292 alignment.

---

### RFC 6962 / RFC 9162 — Certificate Transparency (hardening)

**Current state.** Already implemented as opt-in at `pki_server.py:2459-2620`:
`OID_SCT_LIST` constant, `submit_to_ct_log()` against RFC 6962 §4.1
`add-chain`, `embed_scts()` builds the TLS-encoded SCT extension, and
`issue_with_ct()` wraps issuance. Defaults to Google Argon/Xenon 2025 logs
as sample URLs.

**What shipped** (commit `8fefbf5`)

- **Pre-certificate flow ✅** (RFC 6962 §3.1).
  - `pki_server.py` — `issue_certificate` accepts `ct_poison: bool = False`;
    when `True`, adds `OID_CT_POISON` (`1.3.6.1.4.1.11129.2.4.3`) as a
    critical `UnrecognizedExtension` (NULL encoded as `\x05\x00`).
  - New `submit_pre_cert_to_ct_log(pre_cert, endpoint)` submits to the log's
    `add-pre-chain` endpoint.
  - `issue_with_ct` refactored: (1) issue with `ct_poison=True` using the
    requested serial, (2) submit pre-cert to each log URL, (3) re-issue with
    `ct_poison=False` and same serial + SCTs embedded, (4) overwrite DB row
    via `INSERT OR REPLACE`.
- Tests added (`TestCertificateTransparencyPreCert`): pre-cert has poison
  extension + critical; final cert has poison removed + SCT list; serial
  preserved across both certs; `INSERT OR REPLACE` handles the DB overwrite.

**Outstanding — still TODO**

- **CLI wiring**: `--ct-log-url URL` (repeatable), `--ct-log-pubkey PATH`,
  `--ct-require-n N`. Today CT is only reachable programmatically via
  `ca.issue_with_ct(ct_log_urls=[...])`.
- **SCT signature verification** on received SCTs against log public keys
  before embedding — not yet checked.
- **Minimum-SCT-count enforcement** (Chrome wants ≥2 from qualified logs).

**Files to modify** (remaining)

- `pki_server.py` CLI parsing → add `--ct-log-url URL` (repeatable),
  `--ct-log-pubkey PATH` (repeatable, aligned by index), `--ct-require-n N`.
- `pki_server.py` → SCT verification helper that parses the TLS signature
  and verifies with the log's public key.

**Tests** (remaining)

- In-process mock CT log that signs SCTs with a known key; verify signature
  check passes on correct key, fails on wrong key.
- `--ct-require-n 2` with only 1 log reachable → issuance aborts.

**Docs**

- README: document `--ct-log-url` and recommended opt-in for publicly-trusted
  CAs only.
- Compliance table: keep RFC 6962 at `✅ Opt-in`, annotate "pre-cert flow ✅"
  in notes.
- CHANGELOG `### Changed`: CLI wiring + SCT verification (remaining).

---

### RFC 5083 + RFC 5084 — AuthEnvelopedData + AES-GCM in CMS ✅ SHIPPED

**What it requires.** AES-GCM content encryption in CMS, eliminating CBC
padding-oracle surface in SCEP.

**What shipped** (commit `fe4c22f`)

- `scep_server.py` — `CMSParser.parse_enveloped_data` refactored as a
  dispatcher: `_cms_content_type()` reads the outer `contentType` OID and
  routes to `_decrypt_enveloped()` (existing CBC path) or
  `_decrypt_auth_enveloped()` (new GCM path). Both paths remain active.
- `CMSBuilder.auth_enveloped_data(plaintext, recipient_cert)`: AES-256-GCM
  with 12-byte random nonce and 16-byte auth tag. CEK is 32 random bytes.
  `GCMParameters ::= SEQUENCE { nonce OCTET STRING, ICVlen INTEGER }` — ICVlen
  explicitly encoded as 16 (not DEFAULT 12). Auth tag split from
  `AESGCM.encrypt()` output into the `mac` field of `AuthEnvelopedData`.
- New OID constants: `OID_AES_256_GCM`, `OID_AUTH_ENVELOPED_DATA`
  (`1.2.840.113549.1.9.16.1.23`). SCEP request handler detects incoming
  `AuthEnvelopedData` and echoes `enc_scheme = "gcm"` in the response.
- `GetCACaps` updated: advertises `AES-GCM` capability.

**Tests added** (`TestRFC5083AuthEnvelopedData` in `test_scep_server.py`, 16 tests):

- OID constants correct; round-trips (empty / short / 4096-byte payloads);
  GCMParameters nonce=12B, ICVlen=16; security failures (wrong key, tampered
  ciphertext, tampered mac); dispatcher routing; `GetCACaps` includes AES-GCM;
  `_cms_content_type` helper.

**Docs**: README SCEP section updated. Compliance table: RFC 5083, RFC 5084 `✅ Full`.
CHANGELOG `### Added`.

---

## Tier 3 — PQC roadmap

PQC work depends on stable library support. `cryptography` tracks these; check
`cryptography.hazmat.primitives.asymmetric` before starting.

### RFC 9763 — Related Certificates (already on roadmap)

**What it requires.** `relatedCertRequest` CSR attribute (OID
`1.3.6.1.5.5.7.1.36`) and `RelatedCertificate` X.509 extension referencing a
paired cert via issuer + serial + hash.

**Implementation sketch**

- Add helper `x509_related_cert_ext(issuer_der, serial, cert_hash)` →
  `Extension`. No native `cryptography` support yet; build via `UnrecognizedExtension`.
- CSR attribute parsing: already possible through the `attributes`
  property of a CSR; add recognition for OID `1.3.6.1.5.5.7.1.36`.
- Workflow: issue classical cert → issue ML-DSA cert → each cert carries
  `RelatedCertificate` pointing at the other. Requires an
  "atomic pair issuance" API (`POST /api/paired-issue`).

**Dependency.** ML-DSA must be implemented first (see next).

---

### ML-DSA in X.509 (FIPS 204 / draft-ietf-lamps-dilithium-certificates)

**What it requires.** Algorithm identifiers and SPKI encoding for
ML-DSA-44/65/87 signatures.

**Implementation strategy**

- Abstract signature operations behind `_sign_for_key` (see RFC 8410 work).
- When `cryptography` adds `mldsa` primitives, wire them in as a new key type.
- Until then, **do not implement via `liboqs`** (adds C dep, build complexity).
  Document on the roadmap and revisit each release.

---

### Composite signatures (draft-ietf-lamps-pq-composite-sigs)

Wait for RFC status. Composite = classical + PQC in a single signature
structure. The cleaner migration path for some deployments than RFC 9763
pairing. Track the draft; implement once stable.

---

## Tier 4 — Protocol-specific extras

Grouped by area. Each is smaller than Tier 2 but still useful.

### RFC 9481 — Algorithm Requirements for CMP

- Audit current CMP algorithm usage vs 9481's MUST/SHOULD list.
- Explicitly advertise supported algs in CMP `genp` response (OID
  `1.3.6.1.5.5.7.4.1` — signKeyPairTypes).
- Add a test class `TestRFC9481CMPAlgorithms` that parses a `genp` response
  and asserts each listed alg is genuinely supported.

### RFC 9482 — Lightweight CMP Profile

- Already partial (RFC 9483 badge in README). 9482 is the client profile that
  embedded stacks target; 9483 is an older informational title for the same
  ground — double-check which applies.
- Verify compliance with 9482 §3 (request structure) and §5 (response
  handling). Most should already pass.
- Add a `TestRFC9482LightweightCMP` class with the 9482 Appendix B test
  vectors.

### RFC 8933 — CMS content-type attribute protection ✅ SHIPPED

**What it requires.** When `signedAttrs` are present in a `SignerInfo`, the
`contentType` attribute MUST be included.

**What shipped** (this session)

- Audit confirmed: `CMSBuilder.signed_data` (SCEP, `scep_server.py:605`) and
  `TSAResponseBuilder.build` (TSA, `tsa_server.py:375`) both unconditionally
  include `id-contentType` as the first signed attribute.
- `TestRFC8933CMSContentType` in `test_scep_server.py` (7 tests): contentType
  present in success/failure/pending responses; value is `OID_DATA`; signedAttrs
  never absent; signed_attrs bytes are deterministic; PKCS#1v15 signature over
  signedAttrs verifies against CA public key.
- `TestRFC3161TSA::test_rfc8933_content_type_present_in_tsa_signed_attrs` in
  `test_pki_server.py`: TSA signedAttrs contains `id-contentType = OID_TST_INFO`.
- README compliance table: RFC 8933 `✅ Full`.
- CHANGELOG `### Added`.

### RFC 8295 — EST extensions

- `server-generated-keys` endpoint: `/.well-known/est/serverkeygen`.
  Returns PKCS#8 private key + issued cert in a multipart response.
- `csrattrs` v2 with explicit OIDs for required extensions.
- Files: `est_server.py`. New endpoint handler; extend CMS multipart
  builder.
- Test class: `TestRFC8295ESTExtensions`.

### RFC 9148 — EST over CoAP (EST-coaps)

- Only worth it if IoT is a target audience. CoAP requires DTLS; adds a
  significant dependency surface (`aiocoap` or hand-rolled).
- **Recommend deferring** unless a concrete user need appears.

### RFC 8739 — ACME STAR (Short-Term Auto-Renewed)

- Implement `star-profile` order type: short-lived certs (hours/days)
  auto-renewed by the ACME server on the client's behalf.
- Useful for IoT fleets and ephemeral dev environments.
- Files: `acme_server.py` new order flow; background renewer.
- CLI: `--acme-star-enabled`, `--acme-star-max-lifetime`.

### RFC 8398 + RFC 8399 — Internationalized email + i18n 5280 updates

- Accept `otherName` SANs with `id-on-SmtpUTF8Mailbox` (OID
  `1.3.6.1.5.5.7.8.9`) in CSRs and issued certs.
- Update subject DN validation to accept UTF-8 in
  `id-at-organizationName` etc. (already handled by `cryptography`).
- Test: issue a cert for a Cyrillic mailbox SAN; parse and verify round-trip.

### RFC 8551 — S/MIME v4

- Only relevant if the `email` cert profile grows into a real S/MIME
  workflow. Adds CMS EnvelopedData recipient profiles, key-wrap algorithms
  (`id-aes256-wrap`), and AuthEnvelopedData usage guidance (overlaps RFC 5083).
- Defer until a user needs it.

### RFC 9608 — "No Revocation Available"

- Already on earlier audit list. Tests exist as `TestRFC9608NoRevAvail` and
  `TestACMERFC9608Integration`. **Verify the extension is actually emitted
  when the profile says so** — the test class is present, check if it's a
  pass.

### RFC 5755 — Attribute Certificates

- Skip unless a concrete use case lands. Attribute Certs are for
  authorization data bound to an identity, not identity itself. Very niche
  in modern deployments (Kerberos PAC, OAuth, and SAML ate this space).

### RFC 3647 — Certificate Policy / CPS framework (document, not code)

**Current state.** The code side works: `_build_policy_information`
(pki_server.py:354-385) emits a `CertificatePolicies` extension with
`id-qt-cps` URI and `UserNotice` qualifiers per RFC 5280 §4.2.1.4 / RFC
6818 §3. What's missing is a **published CPS document** the URI can point
at. Without that doc, the `cps_uri` field is a dangling reference.

**Deliverable.** A `docs/CPS.md` (or `docs/CP-CPS.md`) following the
RFC 3647 §6 outline. The RFC prescribes nine numbered top-level sections;
PyPKI needs them all even for a homelab CA, mostly so anyone auditing a
cert can see what promises the CA is making.

Required outline:

1. Introduction (overview, document name + identification, participants,
   cert usage, policy administration)
2. Publication and Repository Responsibilities
3. Identification and Authentication (naming, initial identity validation,
   re-key, revocation request)
4. Certificate Life-Cycle Operational Requirements (application, issuance,
   acceptance, key pair and cert usage, renewal, re-key, modification,
   revocation/suspension, status services, end-of-subscription, key escrow)
5. Facility, Management, and Operational Controls (physical, procedural,
   personnel, audit logging, records archival, key changeover, compromise
   and disaster recovery, termination)
6. Technical Security Controls (key pair generation + installation,
   private key protection, other aspects, activation data, computer
   security, life cycle, network, time-stamping)
7. Certificate, CRL, and OCSP Profiles
8. Compliance Audit and Other Assessments
9. Other Business and Legal Matters

**How to draft it for PyPKI.**

- Start with a template derived from an established homelab/internal CA CPS
  (e.g., the CAB Forum BR CPS outline stripped down; do not copy verbatim
  from any specific org's document).
- For each section, PyPKI has a technical answer already — extract it from
  the README and the code comments. For example, §6.1.1 (key pair
  generation) maps to "CA key generated via `rsa.generate_private_key` with
  4096-bit modulus at CA init" (pki_server.py:820). §7.1 (cert profiles)
  maps to the `CertProfile` catalog.
- Assign a policy OID. Use a private enterprise OID arc; a placeholder like
  `1.3.6.1.4.1.<your-PEN>.1.1` is fine. If the user doesn't own a PEN,
  document that the OID is for internal use only.
- Once drafted, reference it from issued certs: wire a new
  `--cps-uri URL` CLI flag that's passed into `issue_certificate()` and
  appears as the `id-qt-cps` qualifier.

**Tests**

- No unit tests — this is a markdown document. Add a CI check that the
  document file exists and contains each RFC 3647 §6 top-level section
  header.

**Docs**

- README: add a "Policy documents" section linking to `docs/CPS.md`.
- Compliance table: RFC 3647 `✅ Framework-compliant` once the document
  lands. Until then `⚙️ Extension only (no CPS doc)`.
- CHANGELOG `### Added`: "Certificate Practice Statement (RFC 3647 §6
  outline) published at docs/CPS.md; `--cps-uri` wires the URI into the
  `CertificatePolicies` extension of issued certs."

**Note.** This is the one item on this list that Claude can draft end-to-end
without touching code. Ask for a `CPS.md` starter document when ready; a
reasonable first pass is 15-20 pages covering all nine sections at a
homelab-appropriate level of formality.

---

## Tier 5 — Operational maturity

These are the cross-cutting features that move PyPKI from "homelab tool"
to "credible small-business or regulated-environment tool." They are not
RFC items — they are deployment-shape capabilities. Several have partial
implementations already; this section names the gap precisely so the work
isn't accidentally duplicated.

Recommended overall ordering: **CPS document** (markdown, no code) →
**threat model + deployment guides** (markdown) → **PKCS#11** (single
biggest security improvement) → **Postgres backend** (single biggest
operational improvement) → everything else as needs surface.

### 5.1 PKCS#11 / HSM support — biggest single security improvement

**Why.** Today the CA private key sits on disk encrypted with a passphrase.
For anything beyond homelab — a small business, a compliance-bound
deployment, a customer demo — the root key needs to live in hardware. The
industry-standard interface is PKCS#11; supported by SoftHSM (testing),
YubiHSM 2 (~$650, real hardware), Nitrokey HSM, AWS CloudHSM, GCP Cloud
HSM, and any vendor HSM via a vendor-supplied PKCS#11 module.

**Files to create**

- `hsm_backend.py` — abstraction layer with two implementations:
  `FileBackend` (current behaviour) and `PKCS11Backend`. Methods:
  `sign(data, mechanism)`, `decrypt(ciphertext, mechanism)`,
  `public_key()`, `key_type()`.

**Files to modify**

- `pki_server.py` — `CertificateAuthority` constructor takes a backend
  rather than a key path; every `self.ca_key.sign(...)` becomes
  `self.backend.sign(...)`. Same for `decrypt` (key archival).
- `cmp_server.py`, `scep_server.py`, `est_server.py` — anywhere a CA key
  is dereferenced.

**Implementation**

- Use `python-pkcs11` (pip install python-pkcs11). Optional dependency:
  if not installed and HSM not requested, no-op.
- CLI flags:
  ```
  --hsm-module /usr/lib/softhsm/libsofthsm2.so
  --hsm-slot 0
  --hsm-pin-env PYPKI_HSM_PIN     # PIN read from env var, never argv
  --hsm-key-label pypki-ca
  ```
- Initialization flow: if the labeled key exists on the token, use it; if
  not and `--hsm-init-if-missing` is set, generate it on the token. Never
  export the private key from the token.
- Mechanism mapping (RSA): `CKM_RSA_PKCS` for PKCS#1 v1.5,
  `CKM_RSA_PKCS_PSS` for PSS, `CKM_RSA_PKCS_OAEP` for OAEP. EC:
  `CKM_ECDSA_SHA256` etc.
- `cryptography`'s X.509 builders accept any object with a `.sign()` method
  via the Python signature protocol — write a thin `HSMSigningKey` wrapper
  that quacks like `RSAPrivateKey`/`EllipticCurvePrivateKey` and delegates
  to the token. The library then builds and signs certs unchanged.

**Tests**

- CI uses SoftHSM2 (apt install softhsm2). Add a `tests/hsm/` setup
  fixture that initializes a slot, generates a key, and runs the existing
  cert issuance suite against it.
- Verify: cert built with HSM signs identically (modulo signature randomness)
  to one built with a file-backed key of the same public modulus.
- Verify the private key never leaves the token: assert
  `backend.private_key_extractable() == False`.

**Docs**

- README new section "Hardware-Backed Keys (PKCS#11)". SoftHSM walkthrough
  for testing; YubiHSM 2 walkthrough for production. Mention compatible
  modules (Nitrokey HSM, AWS CloudHSM via cloudhsm-pkcs11, GCP Cloud HSM
  via libkmsp11).
- Threat model addendum: HSM-backed deployments. What does PIN compromise
  buy an attacker (sign-with-key, but no key extraction). What does box
  compromise buy (online signing only).
- CHANGELOG `### Added`: PKCS#11 / HSM backend support.

---

### 5.2 Postgres backend + HA — biggest single operational improvement

**Why.** SQLite + flock works for one node. There is no replication, no
read replicas, no graceful failover. For real deployments — stateless OCSP
responder pulling from a hot standby, active/passive CRL signers,
load-balanced ACME — Postgres is the standard answer.

**Current state.** Every `sqlite3.connect(...)` call (15+ sites in
`pki_server.py`) is direct, not abstracted. There is no DAL, no migration
runner, no schema version metadata other than `ALTER TABLE … ADD COLUMN`
inline migrations.

**Files to create**

- `db.py` — minimal abstraction. Two implementations: `SQLiteDB` (current
  behaviour) and `PostgresDB`. Common interface: `execute(sql, params)`,
  `executemany`, `fetchone`, `fetchall`, `transaction()` context manager.
- `db_migrations/` — versioned schema files: `001_initial.sql`,
  `002_audit_indices.sql`, etc. Migration runner reads `schema_version`
  table.

**Implementation**

- Use `psycopg[binary]` (3.x, pip install psycopg[binary]). Optional dep.
- CLI:
  ```
  --db-url sqlite:///path/to/pki.db                  (default)
  --db-url postgres://user:pass@host/db?sslmode=require
  ```
- SQL portability: avoid SQLite-isms. The current schema uses `INTEGER
  PRIMARY KEY` (auto-increment); switch to `BIGSERIAL` on Postgres,
  `INTEGER PRIMARY KEY AUTOINCREMENT` on SQLite. Hide behind the DAL.
- Connection pooling: `psycopg_pool.ConnectionPool` with min=2/max=20.
  Audit each handler that holds a connection; release on path completion.
- Read replicas: optional `--db-readonly-url` for OCSP responder. Routing
  policy: all writes → primary, OCSP/CRL reads → replica, everything else
  → primary.
- Transaction isolation: serializable for issuance (prevents serial
  number race), read-committed for OCSP. Today the codebase has a known
  serial-number race that flock + WAL mode hides; Postgres needs the
  isolation flag to be explicit.

**HA topology**

- Active/active OCSP: stateless responder, points at replica, runs behind
  any L4 LB.
- Active/passive CRL signer: only one node should generate CRLs to avoid
  cRLNumber duplication. Use Postgres advisory lock
  (`pg_try_advisory_lock(crl_signer_lock_id)`).
- ACME: stateless given Postgres backend (orders, authorizations,
  challenges all in DB).

**Tests**

- Run the full suite against `postgres://...` via CI. `testcontainers-python`
  spins up Postgres for the run.
- Concurrency test: 50 simultaneous issuance calls; assert all serial
  numbers unique.
- Failover test: kill primary mid-issuance; assert clean error not
  corruption.

**Docs**

- README "Storage backends" section. Recommended deployment topologies.
- Migration runbook: SQLite → Postgres dump-and-restore.

---

### 5.3 Offline root + key ceremony tooling

**Why.** Real PKIs run an offline root that signs intermediates once a
year (or longer). Today PyPKI assumes the root is always online. Sub-CA
issuance works (sub_ca ergonomics work in §1) but the root can't be cleanly
taken offline.

**Files to create**

- `ceremony.py` — CLI subcommand:
  ```
  pypki ceremony export-root  --out root-bundle.tar.gz
  pypki ceremony sign-csr     --in subca.csr --bundle root-bundle.tar.gz \
                              --out subca.crt --validity-days 1825 \
                              --path-length 0 --permitted-dns ...
  pypki ceremony import-cert  --in subca.crt
  ```
- `docs/ceremony.md` — runbook for an offline-root ceremony, including
  M-of-N split of the root passphrase via Shamir secret sharing.

**Implementation**

- `export-root` packages: encrypted root key, root cert, CRL number
  counter, last-issued serial counter, audit log tail. Bundle is encrypted
  with a fresh passphrase the operator types in.
- `sign-csr` runs in airgap mode: no DB writes, no network, only file I/O
  on the bundle and the CSR/cert files.
- `import-cert` brings the signed sub-CA back online: writes it into the
  intermediate CA's chain, sets up CDP/AIA URLs, starts serving CRL/OCSP.
- M-of-N: optional `--threshold 3 --shares 5` flag. Use a known SSS
  library or implement GF(256) Shamir directly (~80 lines, well-trodden).

**Tests**

- Round-trip: export → sign → import; verify the sub-CA's chain validates
  to the original root.
- M-of-N: split into 5 shares, reconstruct from any 3; assert any 2 fail.

**Docs**

- `docs/ceremony.md` with a step-by-step script (literally a script —
  what to type, what to verify, who signs the witness sheet).
- Threat model: what an offline root protects against (online compromise,
  long-lived signing key exposure) and does not (in-ceremony coercion,
  hardware tampering before generation).

---

### 5.4 RA / approval workflow

**Why.** Currently any authenticated client can request any cert in any
profile. Real deployments separate the RA (validates identity, approves
requests) from the CA (signs). Concretely: a "pending approval" state on
issuance requests, an approver role, and per-requester or per-profile
auto-approval rules.

**Files to modify**

- `pki_server.py` — new `pending_requests` table (csr DER, requester,
  profile, requested SANs, status, approver, decided_at).
- All enrollment paths (`acme_server.py` finalize, `cmp_server.py` ir/cr,
  `est_server.py` simpleenroll, `scep_server.py`, `ipsec_server.py`,
  REST `/api/certs`) — instead of issuing immediately, write a pending row
  and return `pending` status. ACME has a native `processing` order state
  for this; CMP has `waiting`; EST returns 202 with a `Retry-After`.
- `web_ui.py` — approver dashboard, `POST /api/approve/<id>` and
  `POST /api/deny/<id>`.
- New role `approver` in the existing auth model.

**Auto-approval policy (`policy.yaml` or equivalent)**

```
profiles:
  tls_server:
    auto_approve_when:
      - requester_role: service
      - san_dns_matches: ["*.cluster.local", "*.svc"]
  code_signing:
    auto_approve: false   # always manual review
```

**Tests**

- Manual-approval profile: submit ACME order, assert `processing` state,
  approve via API, assert order moves to `valid`.
- Auto-approval profile with matching SAN: instant `valid`.
- Auto-approval profile with non-matching SAN: falls back to manual.

**Docs**

- README new section "Registration Authority workflow". When to use it
  (regulated deployments) and when to skip it (homelab — set everything to
  auto-approve, get the audit trail anyway).

---

### 5.5 ACME EAB + per-account rate limiting ✅ SHIPPED (EAB core)

**Why.** RFC 8555 §7.3.4 — External Account Binding gates ACME account
creation behind a pre-shared MAC key issued by the CA admin. Without it,
anyone reachable to the ACME endpoint can request any cert that passes
challenges, which on a private CA is most of them.

**What shipped** (commit `8fefbf5`)

- `acme_server.py` — directory response sets `externalAccountRequired: true`
  when `require_eab=True`. New `_verify_external_account_binding(eab, jwk)`
  method validates the HS256 JWS per RFC 8555 §7.3.4: parses the flattened
  JWS, looks up the MAC key by `kid`, verifies the HS256 HMAC, and asserts
  the payload matches the account's JWK. Returns `(ok, error, kid)`.
- New `eab_keys` SQLite table (`kid`, `mac_key_b64`, `created_at`,
  `revoked_at`). `ACMEDatabase.add_eab_key` / `get_eab_key` helpers.
  Accounts table gains `eab_kid` column.
- Optional EAB: if client provides `externalAccountBinding` even when not
  required, it is verified anyway (defense in depth).
- CLI flags: `--acme-require-eab` (default off), `--acme-eab-file PATH`
  (JSON file mapping kid → mac_key_b64 for pre-provisioned keys).
- Tests added: `TestACMEEAB` — account creation without EAB when required →
  rejected; valid EAB → accepted; wrong HMAC → unauthorized; optional EAB
  verification.

**Outstanding**

- `web_ui.py` admin UI to mint EAB credentials in-browser — not yet
  implemented. Currently keys must be pre-provisioned via `--acme-eab-file`.
- Per-account rate limiting (separate from per-IP) — not yet implemented.

**Docs**

- README ACME section: EAB walkthrough. cert-manager has native EAB
  support in its `ACMEIssuer.externalAccountBinding` spec — show that in
  the example.

---

### 5.6 Cross-signing

**Why.** Two CAs sign each other's intermediates so trust paths can shift
without re-deploying root trust to every endpoint. Important for migrations
between key types (RSA → ECC → ML-DSA): you can issue an
ML-DSA-signed intermediate with the same name and key as your existing
intermediate, sign it with both old and new roots, and have clients
discover whichever path they trust.

**Files to modify**

- `pki_server.py` — new method `cross_sign(other_cert: x509.Certificate,
  validity_days)` that issues a certificate over the *same subject + same
  public key* as `other_cert`, signed by self.
- `web_ui.py` — `POST /api/cross-sign` endpoint accepting a PEM upload.

**Implementation**

- Subject and SPKI copied verbatim from input cert. Validity, AIA, CDP,
  CRL number from this CA. Serial number freshly generated. Extensions
  reviewed: keep BasicConstraints (cA=true, path_length); copy
  KeyUsage; do not copy ExtendedKeyUsage if it's an EE cert (cross-signing
  EE certs is unusual but supported).
- Audit-log carefully: cross-signing is a high-trust action, log the
  source cert's fingerprint and the resulting cert's fingerprint.

**Tests**

- Cross-sign an intermediate from another CA test fixture; verify the
  resulting cert has the same SPKI as input but a different signature.
- Verify the cross-signed cert chains to *this* CA's root.
- Verify the original cert still chains to *its* root (we didn't mutate
  anything).

---

### 5.7 OCSP stapling helpers + pre-generated responses

**Why.** Generating OCSP responses on every request requires the OCSP
signer to be online, reachable, and fast. Pre-generated responses (signed
periodically, served from a static CDN or reverse proxy) eliminate that
runtime dependency. RFC 5019 explicitly contemplates this for high-volume
deployments.

**Files to modify**

- `ocsp_server.py` — new `generate_static_responses(output_dir)` method
  that writes one signed `.ocsp` file per active cert serial under
  `output_dir/<sha1-of-issuer-key>/<sha1-of-issuer-name>/<serial>.ocsp`
  (the path layout nginx and Apache `mod_ssl_ct`-style serving expects).
- New CLI subcommand: `pypki ocsp prebuild --output /var/www/ocsp
  --validity 24h`.

**Implementation**

- Each pre-generated response has `thisUpdate=now`, `nextUpdate=now+24h`.
- A cron / systemd timer regenerates daily; nginx serves the resulting tree
  with appropriate caching headers.
- Stapling helper: optional sidecar that fetches its own staple periodically
  and exposes it for OpenSSL `SSL_CTX_set_tlsext_status_arg`. Out of
  scope for PyPKI proper; call out as a deployment recipe in docs.

**Tests**

- Regenerate full tree; assert one file per non-revoked, non-expired cert.
- Assert files validate against the issuer cert.

---

### 5.8 SCEP one-time challenge passwords

**Why.** Static SCEP challenge (one shared secret for all enrollments,
`scep_server.py:758`) is unsafe in any setting where an enrolling device
could be compromised before, during, or after enrollment. Microsoft NDES
solved this 20 years ago with one-time passwords minted by an admin per
enrollment.

**Files to modify**

- `scep_server.py` — accept either `--scep-challenge SECRET` (current
  behaviour) or `--scep-otp-store` (a small SQLite table or in-memory
  store of `otp → expiry`). On successful PKCSReq, mark the OTP consumed.
- `web_ui.py` — admin endpoint `POST /api/scep/otp` mints a fresh OTP,
  returns it once.

**Implementation**

- OTP format: 32-char URL-safe base64 (24 random bytes). Single-use, TTL
  configurable (default 24h).
- Concurrency: the consume operation is a transaction (`UPDATE ... WHERE
  consumed=0 RETURNING ...`). On Postgres, use the row-level lock; on
  SQLite, use the existing flock.
- Backwards-compat: if `--scep-challenge` is set, accept it OR an OTP.
  Document the precedence.

**Tests**

- Mint OTP; first enrollment succeeds; second enrollment with same OTP
  rejected.
- Expired OTP rejected.
- Mixed mode: legacy static challenge AND OTPs both work.

---

### 5.9 Lifecycle hooks (webhooks on event)

**Why.** The audit log captures issuance, revocation, expiry-warning
events but nothing reacts to them. A webhook mechanism unlocks Slack
notifications, IPAM updates, inventory pushes, monitoring integration,
and ad-hoc automation without touching PyPKI code.

**Files to create**

- `hooks.py` — event bus. Events: `cert.issued`, `cert.revoked`,
  `cert.expiring` (fired by the existing expiry monitor), `subca.issued`,
  `key.archived`, `key.recovered`. Delivery: HTTP POST with a JSON body,
  optional HMAC-SHA256 signature header for verification.

**Files to modify**

- Every event source: emit through the bus rather than logging only.
- `pki_server.py` CLI: `--webhook-url URL` (repeatable),
  `--webhook-secret SECRET`, `--webhook-events cert.issued,cert.revoked`.
- Web UI: webhook config page.

**Implementation**

- Async-style with a small queue + worker thread. Failures retry with
  exponential backoff up to 5 attempts; final failure is audit-logged.
- Body schema is stable and documented; first field is `event_version: 1`.
- HMAC: `X-PyPKI-Signature: sha256=<hex>` over the request body.

**Tests**

- Issue a cert; assert exactly one POST to the configured URL with the
  expected body and a valid HMAC.
- Webhook target down for the first 3 attempts, succeeds on 4th: assert
  4 attempts logged, no duplicate delivery on success.

**Docs**

- README "Integrations" section. Example: forward `cert.expiring` to a
  Slack incoming webhook via a 5-line nginx Lua snippet, or directly via a
  small Python relay.

---

### 5.10 Structured logging + request IDs

**Why.** Current logs are stdlib `logging` with a text formatter. Each
enrollment is multi-step (request → POPO → audit → DB → sign → audit →
response); without a request ID threading through, debugging a CMP/ACME
flow means grepping a timestamp window and hoping nothing else happened
in that millisecond.

**Files to modify**

- `pki_server.py` line 185 (`logger = logging.getLogger("pki-cmpv2")`) —
  add a JSON formatter option.
- All HTTP handlers (CMP, ACME, EST, SCEP, OCSP, REST, Web UI) — generate
  a request ID on entry, store it in a `contextvars.ContextVar`, include
  it in every log record via a custom `LogFilter`.
- Existing OpenTelemetry tracing already does this for spans; the log
  records should carry the same trace ID + span ID for correlation.

**Implementation**

```python
class JsonFormatter(logging.Formatter):
    def format(self, record):
        d = {
            "ts":    self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg":   record.getMessage(),
            "req_id": getattr(record, "req_id", None),
            "trace_id": getattr(record, "otel_trace_id", None),
        }
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d)
```

CLI flag: `--log-format json|text` (default text for back-compat).

**Tests**

- Single ACME order produces N log lines, all carrying the same `req_id`.
- JSON output validates as one JSON object per line (jq round-trip).

---

### 5.11 Metrics depth (Prometheus histograms + gauges)

**Why.** Current metrics are five counters. Counters detect outages but
don't reason about performance. For "is issuance slow today", you need
histograms.

**Files to modify**

- `pki_server.py` — extend the metrics module:
  - `pypki_issuance_duration_seconds` (Histogram, labels: profile, protocol)
  - `pypki_ocsp_duration_seconds` (Histogram)
  - `pypki_acme_order_duration_seconds` (Histogram, labels: challenge_type)
  - `pypki_pending_requests` (Gauge — when 5.4 lands)
  - `pypki_cert_active_total` (Gauge, labels: profile)
  - `pypki_cert_expiring_30d_total` (Gauge)
  - `pypki_db_pool_in_use` (Gauge — when 5.2 lands)

**Tests**

- Issue 100 certs; assert `pypki_issuance_duration_seconds_count == 100`
  for the matching profile label.
- Verify histogram buckets cover realistic latency range (10ms — 5s).

**Docs**

- Update the existing Grafana dashboard (already on disk per the project
  context) with histogram panels: p50/p95/p99 issuance latency, OCSP
  latency, ACME order latency.

---

### 5.12 Documentation deliverables (markdown, no code) — ✅ SHIPPED

These are the credibility-and-onboarding gaps. Each is a day of writing.

**`docs/CPS.md` — Certification Practice Statement (RFC 3647 §6) ✅ SHIPPED.**
Already specified in the Tier 4 RFC 3647 section. Belongs here too because
it's the single highest-leverage piece of documentation: every issued cert
points at it via the `id-qt-cps` qualifier today, and that URL is currently
a 404.

Shipped: `docs/CPS.md` follows the RFC 3647 §6 nine-section outline,
calibrated for self-hosted PyPKI deployments (homelab + small enterprise);
NOT a publicly-trusted CA. Includes contact placeholders, PEN OID
placeholder, full §1 introduction through §9 legal matters, plus references
appendix.

**Wired into code:** `--cps-uri` and `--cps-policy-oid` CLI flags added
to `pki_server.py`; `ServerConfig` carries a deployment-wide
`certificate_policies_default` that flows into every `issue_certificate`
call when no per-profile or per-issuance value is set. Tests in
`TestCPSWiring` verify (1) no extension when unconfigured, (2) extension
present + correct OID + correct CPS URI when configured, (3) explicit
arg overrides default.

**`docs/THREAT_MODEL.md` ✅ SHIPPED.** Defines PyPKI's TCB, three
adversary classes (network, authenticated subscriber, host-compromise),
seven per-component compromise scenarios with concrete bounded blast
radius and recovery procedures, plus a defense-in-depth controls table
and a known-gaps table. Honest about what the software can and cannot
do; the host-compromise scenario explicitly notes that HSM is the only
real mitigation and is Tier 5.1 future work.

**`docs/DEPLOYMENT/`** — one file per common topology, all ✅ SHIPPED:
- ~~`homelab-single-node.md`~~ ✅ — what most users start with
- ~~`kubernetes-cert-manager.md`~~ ✅ — pairs with the sub-CA
  ergonomics work; covers cert-manager `CA` ClusterIssuer, sub-CA
  bootstrap with name constraints, revocation testing, sub-CA renewal
- ~~`pihole-acme-dns01.md`~~ ✅ — Pi-hole/dnsmasq + SSH hook
  pattern for ACME `dns-01` challenges
- ~~`offline-root-online-subca.md`~~ ✅ — two-tier PKI with offline
  root, ceremony procedures, sub-CA renewal/revocation runbooks
- ~~`kubernetes-istio.md`~~ ✅ — service mesh integration; covers
  both plug-in CA certs (Option A) and cert-manager-istio-csr (Option B)
- ~~`iot-devices-est.md`~~ ✅ — EST enrollment for embedded devices,
  SAN pass-through fix verified, simpleenroll + simplereenroll flows
- ~~`vpn-strongswan-cmp.md`~~ ✅ — IPsec gateway + roadwarrior
  enrollment via CMPv2 PBM bootstrap + signature-based renewal

**`docs/COMPATIBILITY.md` ✅ SHIPPED.** Tested-against matrix for
runtime, ACME clients, CMP clients, SCEP clients, EST clients, k8s
ecosystem, OCSP/CRL clients, reverse proxies, operating systems.
Honest about what's actually been tested vs "expected to work" —
contributions explicitly invited to convert "expected" to "tested".

**`docs/MIGRATION.md` ✅ SHIPPED.** Operator-facing version of the
SQLite→Postgres migration spec (the developer spec stays in CLAUDE.md);
also covers PyPKI version upgrade procedure and the emergency
CA-key-compromise migration runbook.

**`docs/STORAGE.md`** (already shipped in a prior session, complements
the above): covers the three deployment shapes (SQLite homelab,
single-node Postgres, HA Postgres) with concrete deployment recipes
for each.

---

### Already implemented (audit confirms)

For the record, several items I'd flagged before checking the source are
in fact present:

- **Revocation reason codes** (`pki_server.py:1300`,
  `revoke_certificate(self, serial, reason=0)`). Wired through to
  `RevokedCertificateBuilder`. Ensure all CRL paths call with an explicit
  reason.
- **Web UI cert search and filter** (`web_ui.py:362`, `:401`). Live filter
  on the cert listing.
- **OpenTelemetry tracing** (`pki_server.py:188`, `:1303`). Spans on
  issuance and revocation; OTLP gRPC exporter wired via `--otel-endpoint`.
  Extend to all handlers as part of 5.10.
- **Expiry monitor thread** (`pki_server.py:2123`,
  `start_expiry_monitor`). Background thread fires audit events for certs
  approaching expiry. The hook from this thread to a webhook (5.9) is the
  missing piece.
- **Key archival + recovery** (`pki_server.py:~2205`,
  `decrypt_archived_key`). Needs documentation and an explicit policy:
  archive only encryption-purpose keys, never signing keys.

---

### Suggested ordering for Tier 5

If everything else in CLAUDE.md is paused and only Tier 5 work proceeds,
here's the order I'd take it in:

1. **5.12** documentation — CPS first (1 day), threat model (1 day),
   homelab + k8s deployment guides (2 days). Total: a week, no code, huge
   credibility delta.
2. **5.1** PKCS#11 — single biggest security improvement.
3. **5.2** Postgres — single biggest operational improvement; do after
   5.1 because the DAL refactor is easier when only key handling has
   already moved through abstraction work.
4. **5.5** ACME EAB — closes the most obvious abuse vector.
5. **5.3** Offline root + ceremony tooling — completes the security story
   started by 5.1.
6. **5.4** RA / approval workflow — only when there's a concrete demand
   for it. Adds significant code volume.
7. **5.10**, **5.11** structured logs + metrics depth — alongside
   whatever is being built; cross-cutting.
8. **5.6, 5.7, 5.8, 5.9** — opportunistic, when the use case appears.

---

## Skip list (low ROI)

Do **not** spend effort on these without explicit user need:

- RFC 5055 — SCVP (effectively dead)
- RFC 6402 — CMC (CMP covers the same ground)
- RFC 3709 — logotype (vanity)
- RFC 5544 / 6019 / 6283 — niche timestamp formats

---

## Suggested execution order

Revised given the audit findings. Highest-impact / lowest-risk first.

1. **Immediate (quick wins, mostly small diffs)**:
   - ~~RFC 5958 (PKCS#8 normalization — four-line change in `cmp_server.py`)~~ ✅ **SHIPPED**
   - ~~RFC 6818 / RFC 5280 (add `cRLNumber` + AKI to CRL)~~ ✅ **SHIPPED**
   - ~~RFC 8954 (OCSP nonce bounds enforcement)~~ ✅ **SHIPPED**
   - ~~RFC 7468 (strict PEM validation)~~ ✅ **SHIPPED**
2. **Security-critical (MUST-violations)**:
   - ~~RFC 4210 §5.1.3 (CMP response signature protection)~~ ✅ **SHIPPED**
   - ~~RFC 4211 §4 (CRMF POPO verification)~~ ✅ **SHIPPED**
3. **Crypto-algorithm coverage** (do together, one refactor):
   - ~~RFC 4055 (PSS for CA signing)~~ ✅ **SHIPPED** (`--sig-algorithm rsa-pss`; OAEP key transport still TODO if CMS path needs it)
   - ~~RFC 5480 + RFC 5758 (ECC in PKIX + ECDSA algorithm IDs)~~ ✅ **SHIPPED** (`--ca-key-type ec-p256/p384/p521`)
   - ~~RFC 8410 (Ed25519/Ed448)~~ ✅ **SHIPPED** (`--ca-key-type ed25519/ed448`; SCEP guardrail in place)
4. **New protocols** (biggest user-visible additions):
   - ~~RFC 3161 + RFC 5816 (TSA server)~~ ✅ **SHIPPED**
   - ~~RFC 8738 (ACME IP identifier)~~ ✅ **SHIPPED**
5. **Hardening**:
   - ~~RFC 5083 + RFC 5084 (AES-GCM / AuthEnvelopedData in CMS)~~ ✅ **SHIPPED**
   - ~~RFC 7292 (PKCS#12 friendlyName)~~ ✅ **SHIPPED** (unencrypted-export rejection still TODO)
   - ~~RFC 6962 (CT pre-cert flow)~~ ✅ **SHIPPED** (CLI wiring + SCT verification still TODO)
   - ~~RFC 8933 (CMS content-type attribute protection)~~ ✅ **SHIPPED**
   - RFC 9481 + RFC 9482 (CMP algorithm requirements + lightweight profile)
6. **Documentation**:
   - RFC 3647 (CPS document — can be drafted in parallel with any code work)
7. **When drafts stabilize**:
   - RFC 9763 (paired certs) + ML-DSA in X.509
   - Composite signature drafts
8. **On demand only**:
   - RFC 8295, 8739, 8398/8399, 8551, 9148
9. **Operational maturity (Tier 5)**: see Tier 5 section for its own
   ordering. Documentation deliverables (5.12) can run in parallel with any
   code work above.

---

## Database design — SQLite + Postgres

This section is the canonical design reference for §5.2 (Postgres backend
+ HA). Read this before writing any DAL code; the decisions here affect
schema shape, migration files, and connection management across the whole
codebase. The goal is **two backends, one codebase, one schema**: SQLite
for homelab and single-node deployments; Postgres for multi-node, HA, or
regulated environments. Users select via `--db-url`.

### Hard requirements (non-negotiable)

1. **Atomic serial-number allocation.** RFC 5280 §4.1.2.2 requires
   uniqueness. Either DB-guaranteed unique sequence/identity, or
   serializable transaction on a counter row. Today SQLite + flock hides
   the race; with multi-writer Postgres it doesn't.
2. **Durable commits.** When `issue_certificate` returns success, the row
   survives power loss. SQLite WAL with `synchronous=FULL`; Postgres with
   `synchronous_commit=on` (the default). Never advise turning these off.
3. **Single writer or proper transactions.** Two CA instances must not
   duplicate serials. Drives multi-node topology design.
4. **Backup + point-in-time recovery.** Losing the audit log loses the
   ability to answer "did we issue this cert?" later. Both DBs need
   documented backup procedures.

### Soft requirements

5. Concurrent read scaling — read replicas for OCSP at high volume.
   Postgres only; SQLite needs Litestream + a separate replica process.
6. Operational footprint — homelab wants no extra process; small business
   wants Postgres on the same VM; HA wants managed Postgres or a real
   cluster.
7. Online schema migrations — `ADD COLUMN` shouldn't lock the world.
   Postgres handles this; SQLite locks the file but it's fast on small DBs.
8. Ecosystem fit — operator's existing infra. Pick the path of least
   surprise per deployment.

### What does NOT matter

- Sub-millisecond writes (RSA signing dominates issuance latency).
- Massive scale (1M certs + 100M OCSP/day still fits one machine).
- Distributed transactions (PyPKI never needs them).
- Rich query language (only point lookups + simple range scans).

### Architecture — thin DAL, no ORM

SQLAlchemy is overkill and introduces magic that hurts in a CA where every
query needs to be auditable. Hand-rolled DAL is ~400 lines.

```
db.py
├── class Database(ABC)
│   ├── execute(sql, params)
│   ├── fetchone(sql, params)
│   ├── fetchall(sql, params)
│   ├── transaction()           # context manager
│   ├── advisory_lock(name)     # context manager — for serial allocation
│   └── now()                   # current unix-seconds; centralized for tests
│
├── class SQLiteDB(Database)
│   └── sqlite3 stdlib, WAL mode, BEGIN IMMEDIATE for advisory_lock
│
└── class PostgresDB(Database)
    └── psycopg 3, ConnectionPool, pg_advisory_xact_lock for advisory_lock
```

`--db-url` parses to pick the implementation:

| URL prefix                            | Backend     |
|---------------------------------------|-------------|
| `sqlite:///path/to/db.sqlite`         | SQLiteDB    |
| `postgresql://user:pass@host:5432/db` | PostgresDB  |
| `postgres://...`                      | PostgresDB  |

If `psycopg` is not installed and `postgresql://` is requested, exit with
a clear actionable error. If `--db-url` is absent, default to
`sqlite:///./pki.db` (matches current behaviour).

### SQL portability — six divergences to manage

**1. Auto-increment.** SQLite `INTEGER PRIMARY KEY AUTOINCREMENT` vs
Postgres `BIGSERIAL`. Hide behind a DDL helper that emits the right
form per backend; in shared `.sql` migration files, use the
`{{auto_pk}}` token.

**2. Parameter style.** SQLite uses `?`, psycopg uses `%s`. Pick one in
the DAL. **Decision: write all SQL with `?`**; `PostgresDB.execute`
translates to `%s` at execution time. Rationale: grepping the codebase
shows consistent SQL.

**3. RETURNING.** Postgres supports it; SQLite supports it from 3.35
(March 2021). **Decision: require SQLite ≥3.35**, document it, drop the
fallback complexity. Most modern distros ship newer.

**4. Upsert.** Both support `INSERT ... ON CONFLICT (col) DO UPDATE SET ...`
with identical syntax. Compatible.

**5. Time / dates.** **Decision: store unix-seconds as `INTEGER`
everywhere.** Identical behaviour on both engines, sortable, no timezone
bugs, no DST surprises. Convert to/from `datetime` at the application
boundary. Do NOT use `TIMESTAMP WITH TIME ZONE` — divergence per backend.

**6. JSON.** Postgres `JSONB` vs SQLite JSON1. **Decision: store as
plain `TEXT`**, `json.dumps`/`json.loads` at the Python boundary. PyPKI
never queries inside JSON values; it reads and writes whole columns. Skip
engine-specific JSON types entirely.

### The serial-number race — the one place backend choice matters

Today SQLite + flock hides the race. With Postgres on multiple writers it
doesn't. Same call site, different mechanics, both correct:

```python
# SQLite — BEGIN IMMEDIATE acquires the database write lock
@contextmanager
def advisory_lock(self, name: str):
    self.conn.execute("BEGIN IMMEDIATE")
    try: yield
    except: self.conn.rollback(); raise
    else:   self.conn.commit()

# Postgres — pg_advisory_xact_lock auto-released on tx end
@contextmanager
def advisory_lock(self, name: str):
    lock_id = stable_int_hash(name)  # int8 from a stable hash of name
    with self.conn.transaction():
        self.conn.execute("SELECT pg_advisory_xact_lock(%s)", (lock_id,))
        yield
```

Issuance becomes:

```python
with self.db.advisory_lock("serial-allocation"):
    row = self.db.fetchone(
        "UPDATE ca_meta SET value = CAST(value AS INTEGER) + 1 "
        "WHERE key = 'last_serial' RETURNING value"
    )
    next_serial = int(row[0])
```

Postgres scales to multi-node; SQLite stays single-writer (which is fine
for SQLite deployments — that's the whole point of choosing it).

### Connection management

**SQLite.** One connection per thread. Python's `sqlite3` is thread-aware
but a connection can't be shared across threads simultaneously.
**Decision: thread-local connections** via `threading.local()`. Simpler
than `check_same_thread=False` + a per-connection lock, and faster.

**Postgres.** Connection pool via `psycopg_pool.ConnectionPool` with
`min_size=2, max_size=20` (tune via CLI flag). Every handler acquires
from pool, returns on completion via context manager.

**Critical rule**: do NOT hold a connection across an RSA signing
operation. Sign first (10-50ms for RSA-2048, more for 4096), then take a
connection to write the result. Holding a connection for the duration of
a sign exhausts the pool under load. Same advice for both backends.

### Schema — single shared definition

Worth nailing down once. SQLite happily accepts most Postgres-flavored
DDL when you avoid the divergences above.

```sql
CREATE TABLE certificates (
    id              {{auto_pk}},               -- BIGSERIAL or INTEGER PK AUTOINCREMENT
    serial_hex      TEXT NOT NULL UNIQUE,      -- hex; accommodates 20-byte serials
    subject_dn      TEXT NOT NULL,
    cn              TEXT,
    not_before      INTEGER NOT NULL,          -- unix seconds
    not_after       INTEGER NOT NULL,
    profile         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'valid',  -- valid | revoked | expired
    cert_der        BLOB NOT NULL,             -- BYTEA on Postgres; same Python bytes
    requester_ip    TEXT,
    requester_id    TEXT,
    created_at      INTEGER NOT NULL,
    revoked_at      INTEGER,
    revocation_reason INTEGER,                 -- RFC 5280 §5.3.1 numeric code
    crl_number_at_revocation INTEGER
);
CREATE INDEX idx_certs_status_not_after ON certificates(status, not_after);
CREATE INDEX idx_certs_cn               ON certificates(cn);
CREATE INDEX idx_certs_subject          ON certificates(subject_dn);

CREATE TABLE ca_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Seeded on first init: last_serial='999', crl_number='0', schema_version='1'

CREATE TABLE audit_log (
    id              {{auto_pk}},
    timestamp       INTEGER NOT NULL,
    event_type      TEXT NOT NULL,
    subject         TEXT,
    serial_hex      TEXT,
    requester_ip    TEXT,
    details_json    TEXT
);
CREATE INDEX idx_audit_ts     ON audit_log(timestamp);
CREATE INDEX idx_audit_serial ON audit_log(serial_hex);

-- ACME state — orders, authorizations, challenges, nonces, accounts
-- CMP replay nonces, SCEP transaction IDs
-- EAB keys (Tier 5 §5.5), pending_requests (§5.4),
-- webhooks_outbox (§5.9) — added when those features land.
```

**Key choices, explicitly:**

- **`serial_hex TEXT`** — not INTEGER. RFC 5280 allows 20-byte serials;
  most engines cap INTEGER at 8 bytes. TEXT (or BLOB) is portable and
  future-proofs for large random serials.
- **`cert_der BLOB`** — store the DER cert as the source of truth. The
  other columns are denormalized projections for query speed; rebuild from
  `cert_der` if they ever drift.
- **Soft delete only.** Never hard-delete an issued cert row; set
  `status = 'revoked'` or `'expired'`. Hard-delete only ACME nonces and
  similar ephemeral state, on a TTL basis.
- **JSON as TEXT.** `audit_log.details_json` is a string; never query
  inside it.

### Migration runner — replace inline ALTER TABLE

The current inline `ALTER TABLE ... ADD COLUMN profile` at
`pki_server.py:785` doesn't scale to two backends. Build a tiny migration
runner alongside the DAL:

```
db_migrations/
├── 001_initial.sql
├── 002_add_profile_column.sql        # port the existing inline migration
├── 003_audit_indices.sql
└── 00N_<feature>.sql                 # one file per Tier 5 schema change
```

**Runner logic:**

1. Read `ca_meta.schema_version` (default 0 if table doesn't exist).
2. List migration files; apply any with version > current, in order.
3. Each file is a transaction; failure rolls back, current version unchanged.
4. After successful apply, bump `ca_meta.schema_version` to the file's number.
5. Idempotent: safe to run on every startup.

**Backend-specific DDL** (rare): `-- @sqlite` and `-- @postgres` blocks
in the migration file. The runner emits only the matching block. Most
migrations don't need either — they're identical.

### Connection-string parsing

No new dependency; use `urllib.parse.urlparse`.

```python
def make_db(url: str) -> Database:
    if url.startswith("sqlite://"):
        # sqlite:///absolute/path — note triple slash for absolute
        # sqlite:///./relative/path.db — for relative
        path = url.removeprefix("sqlite:///")
        return SQLiteDB(path)
    if url.startswith(("postgresql://", "postgres://")):
        return PostgresDB(url)  # psycopg parses query params natively
    raise ValueError(f"Unsupported DB URL scheme: {url!r}")
```

Postgres-specific options ride along inside the URL — `?sslmode=require`,
`?application_name=pypki`, `?target_session_attrs=read-only`. psycopg
parses them; PyPKI just passes the URL through.

### Deployment shapes

**Homelab — keep SQLite (default).**

```bash
pypki --db-url sqlite:///var/lib/pypki/pki.db
# or simply
pypki                              # default sqlite:///./pki.db
```

Add Litestream for production-ish single-node — continuous replication to
S3 or any S3-compatible object store, point-in-time recovery, no code
changes. Documentation deliverable
(`docs/DEPLOYMENT/homelab-single-node.md`), not a feature.

**Small business — single-node Postgres.**

```bash
pypki --db-url postgresql://pypki:pass@localhost/pypki
```

PgBackRest or WAL-G for backup; pg_dump for ad-hoc snapshots. Document
the expected `pg_hba.conf` and SSL setup.

**HA cluster — multi-node Postgres.**

```bash
# Active-active CA + OCSP nodes:
pypki \
  --db-url 'postgresql://pypki:pass@pgbouncer.internal/pypki?sslmode=require' \
  --db-readonly-url 'postgresql://pypki:pass@pgbouncer.internal/pypki?sslmode=require&target_session_attrs=read-only'
```

Routing policy: writes → primary, OCSP/CRL reads → replica, everything
else → primary. The CRL writer wins a single advisory lock so only one
node mints CRL numbers at a time:

```python
with db.advisory_lock("crl-signer"):
    crl = build_and_sign_crl()
    write_crl_artifact(crl)
```

Other CRL aspirants block on the lock and get a no-op when they wake (the
fresh CRL already exists).

### Test strategy

Three layers, all in CI:

1. **Unit tests against both backends.** `pytest --db sqlite` and
   `pytest --db postgres`. Postgres tests use `testcontainers-python` to
   spin up a clean Postgres in Docker for each session. Same test file,
   parameterized fixture.
2. **Concurrency test.** 50 simultaneous `issue_certificate` calls on
   each backend; assert all serials unique. This is the test that catches
   DAL bugs — locking, isolation, race conditions.
3. **Migration test.** Seed an old schema (apply 001 only), run the full
   migration set, assert final shape matches a known-good snapshot. Run
   on both backends.

A failure in (2) is a release blocker. A failure in (3) means the
migration is broken; never ship.

### Version requirements (decisions)

- **Minimum SQLite: 3.35** (March 2021). Gives `RETURNING` and improved
  upsert. Most modern distros ship newer; document the requirement; drop
  the pre-3.35 fallback complexity.
- **Minimum Postgres: 13** (September 2020). Floor for current managed
  services. Gives advisory locks, generated columns, modern JSON, online
  index creation.
- **psycopg: 3.x.** psycopg2 is in maintenance mode. Use psycopg 3
  exclusively. Install hint: `pip install 'psycopg[binary]'` for the
  bundled libpq build.

### Refactor sequence

To keep diffs small and bisectable:

1. **Write `db.py` with both backends + the abstraction.** Pure new file,
   no other changes. Unit tests for the DAL itself.
2. **Replace every `sqlite3.connect(...)` call** in `pki_server.py`
   (15+ sites) with the DAL. Run full test suite against SQLite — should
   be green. No behaviour change.
3. **Add Postgres test target to CI.** Run the same suite. Fix any
   divergences (mostly parameter style and `RETURNING` edge cases caught
   by the DAL — should be near-zero by this point).
4. **Build the migration runner.** Port the existing inline migrations
   into versioned files. Test forward-only migration on a seeded schema.
5. **Concurrency test** on both backends. Tighten any locking gaps
   surfaced.
6. **Documentation** — `docs/STORAGE.md` covering both backends,
   recommended deployment topologies, backup procedures, how to migrate
   SQLite → Postgres.

Total: roughly 3-5 focused days. The bulk is the refactor in step 2; once
the DAL is in place, Postgres support is a few hundred lines.

### Done criteria

- [ ] `db.py` exists; both backends implement the same interface; unit
      tests pass for both.
- [ ] Zero `sqlite3.connect(...)` calls outside `db.py`.
- [ ] CI runs the full test suite against both backends.
- [ ] Migration runner ported all existing inline ALTERs.
- [ ] Concurrency test passes (50 parallel issuances → 50 unique serials)
      on both backends.
- [ ] `docs/STORAGE.md` covers homelab (SQLite + Litestream),
      single-node Postgres, and HA Postgres.
- [ ] CHANGELOG `### Added`: dual-backend storage support; `--db-url`
      flag; SQLite ≥3.35 and Postgres ≥13 minimum versions documented.

---

### SQLite → Postgres data migration

This subsection specifies the one-shot data migration tool that lets a
deployment switch backends without rebuilding state. It is the *answer to
"what if I start on SQLite and outgrow it"* — the design goal is "an hour
of downtime, not a week of code changes." This entire workflow assumes
the DAL refactor (the rest of §5.2) has already shipped; without that the
migration is intractable for reasons documented in `docs/STORAGE.md`.

The deliverable is a single CLI subcommand:

```
pypki migrate-data --from sqlite:///old.db --to postgresql://...
pypki verify-migration --src sqlite:///old.db --dst postgresql://...
```

#### Why this is mechanical, not tricky

The schema decisions in the rest of §5.2 were made specifically to make
this migration boring:

- `serial_hex TEXT` — identical encoding on both backends, no `CAST`
  needed. (If a deployment is on the legacy INTEGER serial column, do a
  schema fix-up migration *first*, before the cross-backend move.)
- `cert_der BLOB` ↔ `BYTEA` — psycopg accepts Python `bytes` directly
  for both, no conversion.
- `INTEGER` unix-seconds for all time fields — identical on both backends,
  no timezone conversion, no DST surprises.
- `TEXT` JSON columns — identical, no `JSONB` cast needed.
- No stored procedures, triggers, or DB-specific functions anywhere.

The only meaningful divergence is auto-increment sequence state, handled
explicitly in step 3 below.

#### `pypki migrate-data` — implementation

```python
TABLES_IN_DEPENDENCY_ORDER = [
    "ca_meta",                # FIRST — has schema_version, serial counter, CRL counter
    "certificates",
    "audit_log",
    "acme_accounts",
    "acme_orders",
    "acme_authorizations",
    "acme_challenges",
    # ACME nonces, CMP replay nonces, SCEP transactions intentionally
    # SKIPPED — ephemeral state, expires in minutes, regenerated naturally
    "eab_keys",               # when §5.5 lands
    "pending_requests",       # when §5.4 lands
    "webhooks_outbox",        # when §5.9 lands
]

EPHEMERAL_TABLES_SKIPPED = {
    "acme_nonces", "cmp_nonces", "scep_transactions",
}

def migrate_data(src: Database, dst: Database, batch: int = 10_000):
    # Pre-flight: assert dst schema is at the same version as src
    src_v = int(src.fetchone(
        "SELECT value FROM ca_meta WHERE key = 'schema_version'")[0])
    dst_v = int(dst.fetchone(
        "SELECT value FROM ca_meta WHERE key = 'schema_version'")[0])
    if src_v != dst_v:
        raise MigrationError(
            f"Schema version mismatch: src={src_v} dst={dst_v}. "
            f"Run `pypki migrate` against the destination first."
        )

    # ca_meta is upsert, not insert — destination already has rows from
    # the schema bootstrap, and we want src values to win.
    for row in src.fetchall("SELECT key, value FROM ca_meta"):
        dst.execute(
            "INSERT INTO ca_meta (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (row["key"], row["value"]),
        )

    for table in TABLES_IN_DEPENDENCY_ORDER[1:]:  # skip ca_meta, done above
        total = src.fetchone(f"SELECT COUNT(*) FROM {table}")[0]
        if total == 0:
            log.info(f"{table}: empty, skipping")
            continue
        log.info(f"{table}: copying {total} rows in batches of {batch}")

        offset = 0
        cols = None
        while offset < total:
            rows = src.fetchall(
                f"SELECT * FROM {table} ORDER BY id LIMIT ? OFFSET ?",
                (batch, offset),
            )
            if not rows:
                break
            if cols is None:
                cols = list(rows[0].keys())
                placeholders = ",".join("?" * len(cols))
                col_list = ",".join(cols)
                sql = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})"
            dst.executemany(sql, [tuple(r[c] for c in cols) for r in rows])
            offset += len(rows)
            log.info(f"  {table}: {offset}/{total}")

        # Resync the auto-increment sequence so the next INSERT doesn't
        # collide with a migrated id.
        dst.fix_sequence(table)
```

**Implementation of `fix_sequence` per backend:**

```python
class SQLiteDB(Database):
    def fix_sequence(self, table: str) -> None:
        # SQLite tracks autoincrement via the sqlite_sequence table.
        # Set its high-water mark to MAX(id), or do nothing if the
        # table uses ROWID without AUTOINCREMENT.
        max_id = self.fetchone(f"SELECT MAX(id) FROM {table}")[0]
        if max_id is None:
            return
        self.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET seq = excluded.seq",
            (table, max_id),
        )

class PostgresDB(Database):
    def fix_sequence(self, table: str) -> None:
        # BIGSERIAL creates an implicit sequence named <table>_id_seq.
        # setval(..., is_called=true) so the *next* nextval returns max+1.
        self.execute(
            "SELECT setval(pg_get_serial_sequence(%s, 'id'), "
            "COALESCE((SELECT MAX(id) FROM " + table + "), 1), true)",
            (table,),
        )
```

#### `pypki verify-migration` — implementation

The verification step is what separates "migration probably worked" from
"migration definitely worked." Three checks, all required:

```python
def verify_migration(src: Database, dst: Database, sample: int = 100):
    errors = []

    # Check 1 — row counts per table, exact match
    for table in TABLES_IN_DEPENDENCY_ORDER:
        sc = src.fetchone(f"SELECT COUNT(*) FROM {table}")[0]
        dc = dst.fetchone(f"SELECT COUNT(*) FROM {table}")[0]
        if sc != dc:
            errors.append(f"{table}: src={sc} dst={dc}")

    # Check 2 — random sample of rows must be byte-identical
    for table in TABLES_IN_DEPENDENCY_ORDER:
        ids = src.fetchall(
            f"SELECT id FROM {table} ORDER BY RANDOM() LIMIT ?", (sample,)
        )
        for (row_id,) in ids:
            sr = src.fetchone(f"SELECT * FROM {table} WHERE id = ?", (row_id,))
            dr = dst.fetchone(f"SELECT * FROM {table} WHERE id = ?", (row_id,))
            if dict(sr) != dict(dr):
                errors.append(f"{table}#{row_id}: row mismatch")

    # Check 3 — critical singletons in ca_meta MUST match exactly.
    # CRL number drift breaks every downstream verifier; serial counter
    # drift causes the next issuance to collide.
    for key in ("last_serial", "crl_number", "schema_version"):
        sv = src.fetchone("SELECT value FROM ca_meta WHERE key = ?", (key,))
        dv = dst.fetchone("SELECT value FROM ca_meta WHERE key = ?", (key,))
        if sv != dv:
            errors.append(f"ca_meta[{key}]: src={sv} dst={dv}")

    # Check 4 — sequence state matches MAX(id), so the next insert succeeds
    for table in TABLES_IN_DEPENDENCY_ORDER:
        if not dst.has_autoincrement(table):
            continue
        max_id = dst.fetchone(f"SELECT MAX(id) FROM {table}")[0]
        if max_id is None:
            continue
        next_id = dst.peek_next_sequence(table)  # nextval/RESTART semantics
        if next_id <= max_id:
            errors.append(
                f"{table}: sequence at {next_id}, MAX(id)={max_id} — "
                f"next INSERT will collide"
            )

    if errors:
        for e in errors: log.error(e)
        raise MigrationError(f"{len(errors)} verification failures")
    log.info("✅ migration verified")
```

#### The full migration runbook

For an operator switching a live deployment:

```
1. Stand up Postgres, empty DB.
   $ createdb pypki
   $ pypki migrate --db-url postgresql://localhost/pypki
   # Schema applied to schema_version of existing SQLite deployment.

2. Verify schema version matches.
   $ pypki schema-version --db-url sqlite:///./pki.db
   $ pypki schema-version --db-url postgresql://localhost/pypki
   # Must be identical. If not, run `pypki migrate` on whichever lags.

3. Stop the live PyPKI process. (DOWNTIME BEGINS)
   $ systemctl stop pypki

4. Run the data migration.
   $ pypki migrate-data --from sqlite:///./pki.db \
                        --to   postgresql://localhost/pypki

5. Verify.
   $ pypki verify-migration --src sqlite:///./pki.db \
                            --dst postgresql://localhost/pypki
   # Failure here = abort, restart with old URL, investigate.

6. Restart with the new URL.
   $ systemctl edit pypki   # change --db-url
   $ systemctl start pypki  # DOWNTIME ENDS
   # CMP/ACME/EST/SCEP/OCSP/REST all back online.

7. (Optional) Archive the SQLite DB; do not delete for at least a week
   in case rollback is needed.
   $ mv pki.db pki.db.pre-postgres-$(date +%Y%m%d)
```

**Expected duration of step 4** scales linearly with row count:

| Total rows in SQLite | Step 4 duration   |
|----------------------|-------------------|
| < 10k                | seconds           |
| 10k — 100k           | tens of seconds   |
| 100k — 1M            | 1-3 minutes       |
| 1M — 10M             | 10-30 minutes     |

Audit log dominates volume in mature deployments. If migration time is a
concern for a 10M+ row audit log, the migration tool should accept
`--audit-log-cutoff <unix_ts>` to bring over only audit rows newer than a
threshold and archive the older rows separately to object storage. This
is a future refinement, not blocking initial implementation.

#### Rollback

If anything goes wrong post-migration and the SQLite DB still exists:

```
$ systemctl stop pypki
$ systemctl edit pypki   # revert --db-url to sqlite://...
$ systemctl start pypki
```

This works **only if no new writes have hit Postgres since cutover**. The
window between step 6 (restart) and discovering a problem is the rollback
window. Cutting any new write to Postgres means losing it on rollback;
the operator decides whether to accept that loss or reconcile manually.

**Best practice**: keep step 7's archived SQLite DB read-only for a week.
After a week of green operation on Postgres, delete it.

#### Tests

A new test class `TestSQLiteToPostgresMigration`:

- **Round-trip**: seed a SQLite DB with a fixture (CA, 100 certs, 10
  revocations, 1000 audit rows, 5 ACME accounts with orders); run
  `migrate_data` to a fresh Postgres testcontainer; run
  `verify_migration`; assert no errors.
- **Sequence safety**: after migration, issue a new cert via the Postgres
  backend; assert the new serial is `MAX(old_serial) + 1`, no collision.
- **CRL number preservation**: pre-migration `crl_number=42`; post-migration
  `crl_number=42`; generate a new CRL; assert it has number `43`, not
  `1` (the bug case).
- **Ephemeral table skip**: pre-populate `acme_nonces` in SQLite; run
  migration; assert Postgres `acme_nonces` is empty (correct behaviour —
  these are scoped to the original instance).
- **Schema version mismatch**: deliberately migrate the destination one
  version ahead; run `migrate_data`; assert it refuses with a clear error.
- **Sample mismatch detection**: migrate, then corrupt a row in the
  destination; run `verify_migration`; assert it detects the mismatch.

#### Done criteria for the migration tool — ✅ SHIPPED

- [x] `migrate-data` subcommand implemented in `pypki_admin.py`; copies
      all canonical tables, skips ephemeral tables (`acme.nonces`),
      batches large tables via LIMIT/OFFSET.
- [x] `verify-migration` subcommand implemented in `pypki_admin.py`;
      row counts, random-sample row comparison, schema-version match,
      Postgres sequence-safety check.
- [x] Sequence resync (`_resync_sequence`) handles both backends —
      `sqlite_sequence` on SQLite, `pg_get_serial_sequence` + `setval`
      on Postgres.
- [x] Round-trip tests pass against SQLite fixtures (`test_migration.py`,
      19 passing); Postgres tests gated on `PYPKI_TEST_POSTGRES_URL`.
- [x] `docs/MIGRATION.md` includes the operator runbook with concrete
      commands and an `--to-db-url-tmpl` template for the common case.
- [x] CHANGELOG `### Added`: SQLite ↔ Postgres data migration tool.

**Implementation notes (post-shipping):**

The shipped tool diverges from the original spec in two ways, neither
material:

1. **Argument shape.** Spec said
   `pypki migrate-data --from sqlite://... --to postgresql://...` as if
   PyPKI used a single database URL. The real PyPKI has four logical
   databases per deployment, so the CLI accepts:

   * `--from-ca-dir DIR` / `--to-ca-dir DIR` (SQLite-files-in-a-directory),
   * `--from-db-url-tmpl 'postgresql://.../{namespace}'` /
     `--to-db-url-tmpl ...` (one DB per namespace),
   * `--from-url-pki URL` / `--to-url-pki URL` etc. (per-namespace
     explicit URLs, useful for partial migration or testing).

   The three forms compose: per-namespace overrides win over the
   template, the template wins over the directory.

2. **`ca_meta` is not a real table.** The spec assumed a single
   `ca_meta` key-value table for schema version + serial counter + CRL
   counter. Real PyPKI uses dedicated tables (`serial_counter`,
   `crl_number`, each a singleton with `id=1`) and per-DB
   `schema_migrations`. The migration tool reflects reality:
   `_assert_schema_versions_match` queries `schema_migrations` directly,
   and `serial_counter` / `crl_number` are migrated as ordinary tables
   with their seeded singletons overwritten by `ON CONFLICT DO UPDATE`.

The shipped CLI is at `pypki_admin.py`, separate from `pki_server.py`
so the running server's 100+ runtime flags don't get tangled up with
offline admin work.

#### What this guarantees the operator

The optionality contract: **stay on SQLite as long as it suits the
deployment; switch to Postgres in an afternoon when needs change.** No
code changes outside of the URL flag. No data loss. No surprises with
serial numbers or CRL numbers. No rebuild of issued certs (they remain
valid against the new backend). No client disruption beyond a brief
restart window.

This is the entire reason §5.2 ranks high in operational importance — not
because Postgres is better than SQLite, but because *not having the
choice* is what makes a project hard to outgrow.

---

## Per-change checklist

Every RFC addition MUST update:

- [ ] Source module(s)
- [ ] `test_pki_server.py` (or dedicated test file if a new module)
- [ ] `README.md` Protocol compliance table
- [ ] `README.md` feature/CLI documentation if user-visible
- [ ] `CHANGELOG.md` under `## [Unreleased]`
- [ ] `pypki-flows.html` if it introduces a new protocol flow
- [ ] Add a badge to README header when a full RFC is supported end-to-end

Run `./run_tests.sh` before presenting any change.
