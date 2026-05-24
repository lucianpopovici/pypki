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

**Docs**: README compliance table updated; CHANGELOG fixed entries added.

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

**Docs**: README OCSP section and compliance table updated; CHANGELOG added entry.

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

**Docs**: README CMP feature table and compliance table updated; CHANGELOG security entry added.

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

**Docs**: README CMP feature table and compliance table updated; CHANGELOG security entry added.

---

### RFC 5958 — Asymmetric Key Package (PKCS#8) normalization ✅ SHIPPED (complete)

**What shipped.** All `PrivateFormat.TraditionalOpenSSL` sites in every
server module have been converted to `PrivateFormat.PKCS8`. Zero PKCS#1 or
SEC1 format remains in any server module.

Initial fix (5 CMP + web UI sites):
- ~~`cmp_server.py:585` — `ir` auto-generated key~~ **FIXED**
- ~~`cmp_server.py:1068` — PKCS#12 bundle construction path~~ **FIXED**
- ~~`cmp_server.py:1171` — API key return~~ **FIXED**
- ~~`cmp_server.py:1195` — enrollment response private key field~~ **FIXED**
- ~~`web_ui.py:1563` — sub-CA export~~ **FIXED**

Follow-up cleanup (3 pki_server.py disk-write sites):
- ~~TLS server key written to disk at startup~~ **FIXED**
- ~~mTLS client key returned from `issue_client_cert()` helper~~ **FIXED**
- ~~CT pre-cert throwaway key written to temp file~~ **FIXED**

`grep -rn "TraditionalOpenSSL" pki_server.py cmp_server.py est_server.py
scep_server.py ipsec_server.py ocsp_server.py acme_server.py tsa_server.py`
returns no results. `get_cert.py` (standalone ACME client utility) retains
TraditionalOpenSSL for `josepy` interop — not a server module.

**Tests**: `TestRFC5958PKCS8` (2 tests) — source-text audit of `cmp_server.py`
and `pki_server.py` asserts TraditionalOpenSSL is absent; round-trip parse
confirms PKCS#8 PrivateKeyInfo wrapper.

**Compliance table**: RFC 5958 `✅ Full`.

---

### Sub-CA issuance ergonomics (Kubernetes / cert-manager readiness) ✅ SHIPPED

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

**Docs**: README compliance table updated (✅ Full); ACME section bullet and CHANGELOG added.

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

### RFC 7292 — PKCS#12 hardening ✅ SHIPPED

**What it requires.** PKCS#12 export already works
(`pki_server.py:1757`). RFC 7292 (v1.1) fixes encoding ambiguities. Modern
guidance (NIST SP 800-132) demands a strong KDF iteration count.

**What shipped** (commit `8fefbf5`)

- `pki_server.py` — `export_pkcs12` now sets `friendly_name` to the cert
  subject CN (falling back to `"cert-<serial>"`), improving UX in Windows
  and macOS certificate import dialogs. `BestAvailableEncryption(password)`
  was already in place, giving AES-256 + HMAC-SHA256 with ≥600k PBKDF2
  iterations via the `cryptography` library.

**Also shipped** (this session)

- `pki_server.py` — `export_pkcs12` now rejects passwordless export by default,
  raising `ValueError` with a clear message. Opt-out via `--p12-allow-unencrypted`
  CLI flag (sets `ca._p12_allow_unencrypted = True`).
- New `TestRFC7292PKCS12Hardening` (5 tests): default rejects passwordless; password
  accepted; `_p12_allow_unencrypted=True` allows passwordless; unknown serial returns
  None; error message references the flag.

**Tests**: `TestPKCS12Export` extended to verify `friendlyName` round-trip.

**Docs**

- README: PKCS#12 section already exists — add note about default encryption
  strength and RFC 7292 alignment.

---

### RFC 6962 / RFC 9162 — Certificate Transparency (hardening) ✅ SHIPPED

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

**Also shipped** (this session)

- **CLI wiring ✅**: `--ct-log-url URL` (repeatable, appended to list),
  `--ct-log-pubkey PATH` (repeatable, aligned by index with log URLs),
  `--ct-require-n N` (minimum SCTs required; 0 = best-effort). Wired into
  `main()` → `ca._ct_log_urls`, `ca._ct_log_pubkeys`, `ca._ct_require_n`.
- **SCT ECDSA signature verification ✅**: `CertificateAuthority.verify_sct_signature`
  static method. Parses the `DigitallySigned` TLS structure (hash_alg + sig_alg +
  length-prefixed signature), reconstructs the `TreeLeafMessage` signed data
  (version 0x00, sig_type 0x00, timestamp 8 bytes, entry_type uint16, signed_entry,
  extensions length-prefixed), and verifies the ECDSA signature against the log's
  PEM-encoded public key via `cryptography`. Wrong key, tampered signature, or
  invalid pubkey → returns `False` without raising.
- **Minimum-SCT-count enforcement ✅**: `issue_certificate_with_ct` raises
  `RuntimeError` when `ct_require_n > 0` and fewer than `ct_require_n` SCTs were
  successfully obtained. Best-effort mode (`ct_require_n=0`) embeds whatever SCTs
  are available.
- New `TestRFC6962CTCLIWiring` (11 tests): attribute defaults, SCT verify valid /
  wrong key / tampered / invalid pubkey; mock submission with wrong pubkey → None;
  require_n enforcement; best-effort mode; URL storage; default n config.

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

### RFC 9481 — Algorithm Requirements for CMP ✅ SHIPPED

**What it requires.** CMP servers should advertise supported algorithm identifiers
via `genm`/`genp` responses for `id-it-signKeyPairTypes`, `id-it-encKeyPairTypes`,
and `id-it-preferredSymmAlg`.

**What shipped** (this session)

- `cmp_server.py` — `_handle_genm_v3` now responds to three new genm OIDs:
  - `OID_IT_SIGNKEYPAIRTYPES` (`1.3.6.1.5.5.7.4.3`) → SEQUENCE OF AlgorithmIdentifier
    advertising RSA (`1.2.840.113549.1.1.1` + NULL params), ECDSA P-256/P-384/P-521
    (`1.2.840.10045.2.1` + named-curve OID param), Ed25519 (`1.3.101.112`),
    Ed448 (`1.3.101.113`).
  - `OID_IT_ENCKEYPAIRTYPES` (`1.3.6.1.5.5.7.4.4`) → RSA only (the only
    key-encipherment type currently supported).
  - `OID_IT_PREFERREDSYMMALG` (`1.3.6.1.5.5.7.4.5`) → AES-256-GCM
    (`2.16.840.1.101.3.4.1.46`).
  - All three use hand-rolled DER AlgorithmIdentifier encoding consistent with the
    existing `_seq`/`_oid` helpers in `scep_server.py`.
- Critical pre-existing bug fixed: `parse_pki_message` in `cmp_server.py` used
  `data[0]` at line 171 before `data` was assigned (`data = outer` at line 176),
  causing `UnboundLocalError` silently caught → `body_type=None` for ALL parsed
  CMP messages. Fixed to `der_data[0]`.
- `TestRFC9481CMPAlgorithms` (9 tests): signKeyPairTypes handled; contains RSA /
  ECDSA / Ed25519 OIDs; encKeyPairTypes contains RSA; preferredSymmAlg is
  AES-256-GCM OID; all-algorithms-supported check.

### RFC 9482 — Lightweight CMP Profile ✅ SHIPPED

**What shipped** (this session)

- `cmp_server.py` — `_handle_cert_request` now accepts and propagates `pvno: int = 2`.
  When invoked from `CMPv3Handler` (pvno=3 client), `response_pvno=3` is threaded
  through `_protected_response` so the response echoes the client's version number
  per RFC 9482 §3.1.
- `CMPv3Handler` routing updated to pass `pvno=response_pvno` to
  `_handle_cert_request` for `ir`/`cr` body types.
- `TestRFC9482LightweightCMP` (7 tests): pvno=3 request → pvno=3 response; pvno=2
  request → pvno=2 response; `GetCACerts` via genm → genp body present; garbage
  input → error response (not crash); protected response has `[0]` field; extraCerts
  has `[1]` field; `signKeyPairTypes` via genm returns supported algorithms.

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

### RFC 8295 — EST extensions ✅ SHIPPED

**What it requires.** `serverkeygen` endpoint (`POST /.well-known/est/serverkeygen`)
where the server generates a key pair, issues a cert, and returns both in a
`multipart/mixed` response. Key in `application/pkcs8`, cert in
`application/pkcs7-mime; smime-type=certs-only`.

**What shipped**

- `est_server.py` — `ESTHandler._handle_serverkeygen`: generates RSA-2048 key,
  issues cert via `ca.issue_certificate`, returns `multipart/mixed` with two
  base64-encoded parts. PKCS#8 key (PKCS#8 `PrivateKeyInfo`, not PKCS#1).
  Optional CSR body: if provided, subject and SANs are extracted; profile-specific
  SAN validation is enforced as in `simpleenroll`.
- `csrattrs` endpoint already returns profile-aware EKU hints (OIDs for SAN,
  EKU, and key type hints) per RFC 7030 §4.5.2.
- `TestRFC8295ESTExtensions` (11 tests): 200 status, `multipart/mixed`
  Content-Type, two parts, cert part is `pkcs7-mime`, cert part DER is PKCS#7,
  key part is `pkcs8`, key DER decodes as PKCS#8 PrivateKeyInfo, key matches
  cert public key, csrattrs returns 200 with `csrattrs` Content-Type and DER
  SEQUENCE body.

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

### RFC 9608 — "No Revocation Available" ✅ SHIPPED (audited)

- `TestRFC9608NoRevAvail` (10 tests) all pass. Extension is emitted on
  `short_lived` profile certs, is non-critical, has value `\x05\x00` (ASN.1
  NULL), CDP is suppressed, AIA OCSP is suppressed, and the extension is
  absent from CA certs. No gaps found in the audit.

### RFC 5755 — Attribute Certificates

- Skip unless a concrete use case lands. Attribute Certs are for
  authorization data bound to an identity, not identity itself. Very niche
  in modern deployments (Kerberos PAC, OAuth, and SAML ate this space).

### RFC 3647 — Certificate Policy / CPS framework ✅ SHIPPED

**What shipped.**

- `docs/CPS.md` — 904-line CPS following the RFC 3647 §6 nine-section
  outline (§1 Introduction through §9 Other Business and Legal Matters),
  calibrated for self-hosted PyPKI deployments. Includes PEN OID
  placeholder, contact info placeholders, and Appendix A (document history)
  + Appendix B (references). §1.3 updated to reflect the shipped RA workflow.
- `--cps-uri URL` and `--cps-policy-oid OID` CLI flags in `pki_server.py`
  wire the CPS URL into the `CertificatePolicies` extension of every issued
  cert. `ServerConfig.certificate_policies_default` carries the deployment-
  wide default; per-profile and per-request values override it.
- Tests in `TestCPSWiring` (3 tests): no extension when unconfigured;
  extension present + correct OID + correct CPS URI when configured;
  explicit arg overrides default.
- README "Deployment-wide CPS URI" subsection added; compliance table row
  `✅ Full`.

**Operator checklist** (customize before publishing):
- §1.2 — replace `<PEN>` with your IANA-assigned Private Enterprise Number
- §1.5 — operator contact info
- §2.1 — actual repository URLs
- §5.5 — backup retention specifics
- §6.4 — passphrase rotation policy
- §9.4 — privacy policy specifics
- §9.10–§9.15 — legal jurisdiction

---

## Tier 5 — Operational maturity

These are the cross-cutting features that move PyPKI from "homelab tool"
to "credible small-business or regulated-environment tool." They are not
RFC items — they are deployment-shape capabilities. Several have partial
implementations already; this section names the gap precisely so the work
isn't accidentally duplicated.

**All Tier 5 items are now shipped.** See the "Suggested ordering for Tier 5"
section at the end of Tier 5 for the implementation sequence.

### 5.1 PKCS#11 / HSM support ✅ SHIPPED

**What shipped** (`hsm_backend.py`, `pki_server.py`).

- `hsm_backend.py` — `HSMConfig` dataclass, `load_hsm_signing_key(cfg)`
  opens a PKCS#11 session and returns `HSMRSAPrivateKey` or `HSMECPrivateKey`
  that subclass the `cryptography` ABCs so `CertificateBuilder.sign()` and
  all existing signing paths work unchanged. Mechanism mapping: RSA PKCS#1 v1.5
  (`CKM_RSA_PKCS`), RSA PSS (`CKM_RSA_PKCS_PSS`), ECDSA per curve
  (`CKM_ECDSA_SHA256` etc.). Raw PKCS#11 r||s ECDSA output is DER-encoded
  inside `_PKCS11ECKeyWrapper`. Uses `python-pkcs11` (optional dep — if not
  installed and HSM not requested, no-op).
- CLI flags: `--hsm-module`, `--hsm-slot`, `--hsm-pin-env`, `--hsm-key-label`,
  `--hsm-init-if-missing`. PIN read from env var, never argv.
- `pki_server.py` — `CertificateAuthority.__init__` calls
  `load_hsm_signing_key` when HSM flags are present; the returned key object
  drops into `self.ca_key` unchanged.
- 16 tests in `TestHSMBackend`.

**CI note.** SoftHSM2 integration tests gated on `PYPKI_TEST_HSM_MODULE`
env var. Unit tests use `_MockPKCS11Key` that mimics `_PKCS11ECKeyWrapper`
(returns DER, not raw r||s).

---

*(original plan retained below for reference)*

**Why.** Today the CA private key sits on disk encrypted with a passphrase.
For anything beyond homelab — a small business, a compliance-bound
deployment, a customer demo — the root key needs to live in hardware. The
industry-standard interface is PKCS#11; supported by SoftHSM (testing),
YubiHSM 2 (~$650, real hardware), Nitrokey HSM, AWS CloudHSM, GCP Cloud
HSM, and any vendor HSM via a vendor-supplied PKCS#11 module.

**CLI flags (shipped)**:
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

### 5.2 Postgres backend + HA ✅ SHIPPED

**What shipped** (`db.py`, `migrations.py`, `pypki_admin.py`).

- `db.py` — hand-rolled DAL: `SQLiteDB` and `PostgresDB` implement the same
  interface (`execute`, `executemany`, `fetchone`, `fetchall`, `transaction()`,
  `advisory_lock(name)`). `advisory_lock` uses `BEGIN IMMEDIATE` on SQLite and
  `pg_advisory_xact_lock` on Postgres — both eliminate the serial-number race.
- `migrations.py` — versioned migration runner reads `schema_migrations` table,
  applies pending `.sql` files in order, rolls back on failure.
- `db_migrations/pki/` — `001_initial.sql`, `002_crl_number.sql`,
  `003_pending_requests.sql`.
- All `sqlite3.connect()` calls in `pki_server.py`, `acme_server.py`,
  `scep_server.py`, `ocsp_server.py`, `ipsec_server.py` replaced with DAL.
- CLI: `--pki-db-url`, `--acme-db-url`, `--scep-db-url` (default
  `sqlite:///./pki.db` etc.).
- `pypki_admin.py` — `migrate-data` and `verify-migration` subcommands
  (row-count check, random-sample comparison, schema-version match, sequence
  resync). 19 tests in `test_migration.py`.
- `docs/STORAGE.md`, `docs/MIGRATION.md` — operator runbooks.
- 7 tests in `TestDatabaseBackend`; Postgres tests gated on
  `PYPKI_TEST_POSTGRES_URL`.

---

### 5.3 Offline root + key ceremony tooling ✅ SHIPPED

**What shipped** (`ceremony.py`, `pypki_admin.py`).

- `ceremony.py` — `export-root`, `sign-csr`, `import-cert` subcommands.
  Bundle encrypted with AES-256-GCM + PBKDF2-SHA256 (600k iterations).
  Optional Shamir M-of-N (`--threshold N --shares M`) uses GF(256) Shamir
  directly (~80 lines). `sign-csr` runs in airgap mode (no DB, no network).
  `import-cert` writes the signed cert into the intermediate CA's chain.
- `docs/DEPLOYMENT/offline-root-online-subca.md` — full ceremony runbook
  with step-by-step commands and verification checklist.
- 13 tests in `TestCeremony`.

---

### 5.4 RA / approval workflow ✅ SHIPPED

**What shipped** (`pki_server.py`, `acme_server.py`, `cmp_server.py`,
`db_migrations/pki/003_pending_requests.sql`).

- `RAPolicy` class evaluates auto-approval rules: `mode="all"` (approve
  everything), `mode="none"` (always require manual review),
  `mode="profile_list"` (per-profile list + `fnmatch` SAN patterns).
  Loaded from `--ra-policy-file PATH` or assembled from CLI flags.
- `RAWorkflow` class manages the `pending_requests` table — `submit()`
  either auto-issues or stores a pending row, `approve()` calls
  `issue_certificate()` and finalises the request, `deny()` records a reason.
- ACME finalization routes through RA when enabled: orders that require
  approval move to `processing` state (RFC 8555 §7.4) with an `ra_request_id`
  foreign key; `GET /acme/order/<id>` transitions to `valid`/`invalid` when
  the RA decision arrives.
- REST API: HTTP 202 `{"status": "pending", "request_id": "..."}` while
  pending. Endpoints: `POST /api/ra/approve/<id>`, `POST /api/ra/deny/<id>`,
  `GET /api/ra/pending`, `GET /api/ra/recent`, `GET /api/ra/request/<id>`.
- CLI flags: `--ra-auto-approve`, `--ra-require-approval`,
  `--ra-auto-approve-profiles PROFILE [...]`, `--ra-policy-file PATH`.
- 22 tests in `TestRAWorkflow`.

**Outstanding (not yet implemented):**
- CMP `waiting` status response while pending.
- EST 202 Retry-After response while pending.
- `web_ui.py` approver dashboard (in-browser approve/deny).

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

**Also shipped** (this session)

- Per-account rate limiting: `--acme-per-account-cert-limit N` and
  `--acme-per-account-window-days N` (default 0 = unlimited, 7 days).
  `ACMEDatabase.count_account_certs_since` joins `certificates` + `orders`.
  `_handle_finalize` returns 429 `rateLimited` when the limit is reached.
  `make_acme_handler` and `start_acme_server` accept the new parameters.
  `TestACMEPerAccountRateLimit` (7 tests): DB counting, window isolation,
  multi-account isolation, handler propagation, CLI defaults.

**Outstanding**

- `web_ui.py` admin UI to mint EAB credentials in-browser — not yet
  implemented. Currently keys must be pre-provisioned via `--acme-eab-file`.

**Docs**

- README ACME section: EAB walkthrough. cert-manager has native EAB
  support in its `ACMEIssuer.externalAccountBinding` spec — show that in
  the example.

---

### 5.6 Cross-signing ✅ SHIPPED

**Why.** Two CAs sign each other's intermediates so trust paths can shift
without re-deploying root trust to every endpoint.

**What shipped**

- `pki_server.py` — new `CertificateAuthority.cross_sign(other_cert, validity_days,
  audit, requester_ip)`. Copies subject DN and SPKI verbatim; generates fresh serial
  from `_next_serial()`; copies BasicConstraints, KeyUsage, SubjectAlternativeName;
  generates fresh SKI/AKI and adds this CA's AIA/CDP URLs; signs with this CA's key.
  Stored in DB with `profile='cross_signed'`; audit-logged with both fingerprints.
- `web_ui.py` — `POST /api/cross-sign` (admin auth required). Accepts
  `{"certificate_pem": "...", "validity_days": N}`; returns
  `{"certificate_pem": "...", "serial": N}`.

**Tests** (`TestCrossSign`, 10 tests):

- Same subject and SPKI on cross-signed cert.
- Fresh serial > 1000 (initial counter value).
- Issuer matches CA B's subject; AKI matches CA B's SKI.
- Signature verifies against CA B's public key.
- BasicConstraints `ca=True` preserved for intermediates; `ca=False` for EE certs.
- Source cert is immutable (DER unchanged after cross-sign call).
- Cross-signed cert stored in DB.

---

### 5.7 OCSP stapling helpers + pre-generated responses ✅ SHIPPED

**What shipped**

- `ocsp_server.py` — new `generate_static_responses(ca, output_dir, validity_hours=24)`:
  queries all certs from the CA DB, builds one signed `OCSPResponse` per cert
  (good/revoked status from DB), writes to
  `<output_dir>/<sha1-issuer-key>/<sha1-issuer-name>/<serial>.ocsp`.
  Returns file count.
- `pypki_admin.py` — new `ocsp-prebuild` subcommand:
  `python pypki_admin.py ocsp-prebuild --ca-dir ./ca --output /var/www/ocsp --validity-hours 24`.

**Tests** (`TestOCSPStaticResponses`, 7 tests):

- Count return ≥ 2 certs; files created; three-level path layout; integer
  serial filenames; valid SEQUENCE DER with `\x80\x01\x00` (status=successful);
  revoked cert has `\xa1` (RevokedInfo context tag); CLI returns exit code 0.

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

### 5.8 SCEP one-time challenge passwords ✅ SHIPPED

**Why.** Static SCEP challenge (one shared secret for all enrollments) is
unsafe in any setting where an enrolling device could be compromised before,
during, or after enrollment.

**What shipped**

- `scep_server.py` — new `SCEPDatabase.add_otp(ttl_seconds=86400)` mints a
  32-char URL-safe base64 token (24 random bytes, stored in new `otp_tokens`
  table); `consume_otp(token)` atomically marks it used via `BEGIN IMMEDIATE`;
  `purge_expired_otps()` cleans up stale rows.
- `scep_server.py` — new `SCEPHandler.use_otp = False` class attribute; when
  `True`, `_handle_pki_request` tries to consume the CSR challengePassword as
  an OTP first, then falls back to the static `challenge` if set (mixed mode).
- `scep_server.py` — new module-level `mint_otp(ca_dir, ttl_seconds)` helper
  for callers without a handler reference.
- `scep_server.py` — `start_scep_server` accepts `use_otp: bool = False`;
  exposes `proxy.scep_db` so the web UI can mint OTPs.
- `web_ui.py` — `POST /api/scep/otp` (admin-auth required) calls
  `scep_module.mint_otp(ca.ca_dir, ttl_seconds)` and returns
  `{"otp": token, "ttl_seconds": n}`.
- `pki_server.py` — `--scep-use-otp` CLI flag wired to `start_scep_server`.

**Tests** (`TestSCEPOneTimePasswords`, 13 tests):

- `add_otp` returns 32-char URL-safe base64; `consume_otp` returns True first
  time, False second time; nonexistent and expired tokens return False.
- `purge_expired_otps` removes consumed and expired rows, keeps valid rows.
- `mint_otp` module helper is consumable via `SCEPDatabase`.
- `start_scep_server` wires `use_otp=False`/`True` and exposes `proxy.scep_db`.
- Mixed mode: `challenge + use_otp` both work independently.

---

### 5.9 Lifecycle hooks (webhooks on event) ✅ SHIPPED

**What shipped** (`hooks.py`, `pki_server.py`).

- `hooks.py` — `WebhookDispatcher` with background worker thread. Events:
  `cert.issued`, `cert.revoked`, `cert.expiring`, `subca.issued`,
  `cross.signed`. Delivery: HTTP POST with JSON body; `X-PyPKI-Signature:
  sha256=<hex>` HMAC-SHA256 header. Exponential backoff up to 5 attempts;
  final failure audit-logged.
- CLI flags: `--webhook-url URL` (repeatable), `--webhook-secret SECRET`,
  `--webhook-events cert.issued,cert.revoked` (default: all events).
- 15 tests in `TestLifecycleHooks`.

---

### 5.10 Structured logging + request IDs ✅ SHIPPED

**What shipped** (`pki_server.py`, `dispatcher_server.py`).

- `JsonFormatter` + `RequestIdFilter` in `pki_server.py`; `configure_logging()`
  sets the root logger. `request_id_var` `ContextVar` is set on each HTTP
  request entry in `dispatcher_server.py` and included in every log record
  via the filter.
- CLI flag: `--log-format json|text` (default `text` for back-compat).
- 11 tests in `TestStructuredLogging`.

---

### 5.11 Metrics depth (Prometheus histograms + gauges) ✅ SHIPPED

**What shipped** (`pki_server.py`, `ocsp_server.py`, `acme_server.py`).

- `_Histogram` class and three module-level instances: `_hist_issuance`
  (labels: `profile`, `protocol`), `_hist_ocsp`, `_hist_acme_order`
  (label: `challenge_type`). Thread-safe via `threading.Lock`. Buckets
  cover 1ms–10s (13 boundaries). Prometheus text format exposition via
  `hist.exposition()` appended to `metrics_prometheus()` output.
- `protocol=` parameter added to `issue_certificate()` (default `""`) so
  callers label observations: `"acme"`, `"cmp"`, `"est"`, `"scep"`,
  `"ipsec"`. Timing via `time.perf_counter()`.
- 14 tests in `TestMetricsDepth`.

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
- **Expiry monitor thread** (`pki_server.py:2123`,
  `start_expiry_monitor`). Background thread fires audit events for certs
  approaching expiry. Webhook dispatch (§5.9 ✅) fires `cert.expiring`
  from this thread.
- **Key archival + recovery** (`pki_server.py:~2205`,
  `decrypt_archived_key`). Needs documentation and an explicit policy:
  archive only encryption-purpose keys, never signing keys.

---

### Suggested ordering for Tier 5

All Tier 5 items are now shipped. For reference, the order they were implemented:

1. ~~**5.12**~~ ✅ documentation (CPS, threat model, deployment guides, compatibility, migration)
2. ~~**5.1**~~ ✅ PKCS#11 / HSM backend
3. ~~**5.2**~~ ✅ Postgres dual-backend + DAL + migration tooling
4. ~~**5.5**~~ ✅ ACME EAB + per-account rate limiting
5. ~~**5.3**~~ ✅ Offline root + key ceremony tooling
6. ~~**5.4**~~ ✅ RA / approval workflow (ACME + REST complete; CMP/EST waiting states outstanding)
7. ~~**5.10**~~, ~~**5.11**~~ ✅ Structured logging + Prometheus histograms
8. ~~**5.9**~~ ✅ Lifecycle webhooks
9. ~~**5.6**~~ ✅ Cross-signing, ~~**5.7**~~ ✅ OCSP prebuild, ~~**5.8**~~ ✅ SCEP OTP challenges

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
   - ~~RFC 7292 (PKCS#12 hardening — friendlyName + unencrypted-export rejection)~~ ✅ **SHIPPED**
   - ~~RFC 6962 (CT pre-cert flow + CLI wiring + SCT ECDSA verification + require-n enforcement)~~ ✅ **SHIPPED**
   - ~~RFC 8933 (CMS content-type attribute protection)~~ ✅ **SHIPPED**
   - ~~RFC 9481 + RFC 9482 (CMP algorithm advertisement + pvno echo)~~ ✅ **SHIPPED**
6. **Documentation**:
   - ~~RFC 3647 (CPS document)~~ ✅ **SHIPPED** (`docs/CPS.md` + `--cps-uri` + `--cps-policy-oid`)
7. **When drafts stabilize**:
   - RFC 9763 (paired certs) + ML-DSA in X.509
   - Composite signature drafts
8. **On demand only**:
   - ~~RFC 8295 (EST serverkeygen + csrattrs)~~ ✅ **SHIPPED**
   - RFC 8739, 8398/8399, 8551, 9148
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
-- EAB keys (§5.5 ✅), pending_requests (§5.4 ✅ — see 003_pending_requests.sql),
-- webhooks_outbox (§5.9 ✅ — delivered in-memory, no persistent outbox table).
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
    "eab_keys",               # §5.5 ✅ shipped
    "pending_requests",       # §5.4 ✅ shipped
    "webhooks_outbox",        # §5.9 ✅ shipped (in-memory queue, no DB table)
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
