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

### RFC 6818 — Updates to RFC 5280

**What it requires.** Errata and clarifications to the cert/CRL profile.
The two relevant gaps in PyPKI today:

1. CRL MUST contain the `cRLNumber` extension (§5.2.3)
2. CRL MUST contain the `authorityKeyIdentifier` extension (§5.2.1)

**Files to modify**

- `pki_server.py` → `CertificateAuthority.generate_crl()` (line ~1316) and
  `generate_crl_der()` (line ~1692)

**Implementation**

- Persist a monotonically-increasing CRL number in the CA database. Add a
  `ca_meta` table (key/value) if one doesn't exist, with row
  `crl_number=<int>`. Load, increment, save atomically inside the CRL build.
- Add `.add_extension(x509.CRLNumber(n), critical=False)` to the builder.
- Add `.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
  self.ca_cert.public_key()), critical=False)`.
- For delta CRLs, also add `DeltaCRLIndicator` pointing at the base CRL
  number (already half-implemented — verify).

**Tests** (extend `TestRFC5280CRL`)

- Parse a freshly-generated CRL with `x509.load_der_x509_crl` and assert
  both extensions are present.
- Assert `cRLNumber` strictly increases across two successive CRL generations.
- Assert AKI matches `SHA-1(CA subjectPublicKey BIT STRING contents)`.

**Docs**

- README compliance table: change RFC 5280 row note to mention CRL extensions.
- Add RFC 6818 row: `✅ Full`.
- CHANGELOG under `### Fixed`: "CRL now includes mandatory `cRLNumber` and
  `authorityKeyIdentifier` extensions (RFC 5280 §5.2.1, §5.2.3 / RFC 6818)."

---

### RFC 8954 — OCSP Nonce Extension Update

**What it requires.** The OCSP nonce value must be a DER-encoded OCTET STRING
of 1–32 bytes. Older clients sometimes sent raw bytes; 8954 profiles it
strictly and recommends SHA-256-sized nonces.

**Files to modify**

- `ocsp_server.py` → nonce parsing (line ~229–243) and response builder
  (line ~349)

**Implementation**

- When parsing: enforce 1 ≤ len(nonce) ≤ 32 after unwrapping the inner
  OCTET STRING. Reject (malformed request) if outside bounds.
- When replying: echo the exact client nonce unchanged inside an OCTET STRING,
  wrapped in the extension. Already appears to be done — verify.
- Add a CLI flag `--ocsp-require-nonce` (default off) that returns
  `unauthorized` when a request without a nonce arrives. Useful for
  high-security profiles.

**Tests** (extend `TestOCSPParsing`)

- Valid 32-byte nonce → accepted, echoed verbatim.
- 33-byte nonce → request rejected.
- 0-byte nonce (empty OCTET STRING) → rejected.
- With `--ocsp-require-nonce`, a nonceless request returns `unauthorized`.

**Docs**

- README OCSP section: add bullet "RFC 8954 nonce profile: 1–32 byte
  enforced; optional strict mode via `--ocsp-require-nonce`."
- CHANGELOG `### Added`: RFC 8954 nonce profile enforcement.

---

### RFC 4055 — RSASSA-PSS and RSAES-OAEP

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

### RFC 7468 — Textual Encoding of PKIX Structures (strict PEM)

**What it requires.** PEM files must use specific BEGIN/END labels, base64
with 64-char lines, and reject label mismatches.

**Files to modify**

- All `load_pem_*` call sites: mostly already correct through `cryptography`.
- Only gap: explicit label validation when we accept multi-object PEM bundles
  (e.g., chain files, PKCS#7 imports in `ca_import/`).

**Implementation**

- Add a helper `_parse_pem_bundle(data: bytes) -> list[tuple[str, bytes]]` in
  `pki_server.py` that tokenizes by `-----BEGIN <LABEL>-----` blocks and
  returns `(label, der_bytes)` pairs.
- When accepting chains, reject unknown labels (only `CERTIFICATE`,
  `X509 CRL`, `PKCS7` accepted for imports).

**Tests** (new class `TestRFC7468PEM`)

- Reject PEM with lowercase `-----begin certificate-----`.
- Reject PEM with trailing data after the END line.
- Accept canonical 64-col wrapping; accept non-wrapped as long as base64 is valid.

**Docs**

- README: mention RFC 7468 compliance in CA Import section.
- Compliance table: add RFC 7468 `✅ Full`.

---

### RFC 4210 — CMPv2 response protection

**What it requires.** §5.1.3: every `PKIMessage` SHOULD carry a
`protection` BIT STRING computed over `PKIHeader || PKIBody`, signed by the
sender. PyPKI parses client protection but does not produce any on
responses.

**Source evidence.** `cmp_server.py:249-327` (`build_pki_message`) writes the
`protectionAlg` OID (`sha256WithRSAEncryption`, line 310) into the header as
a hint, then assembles `header + body` and returns — no `[0] protection`
BIT STRING, no `[1] extraCerts`. Strict clients (EJBCA, some strongSwan pki
builds) reject the response.

**Files to modify**

- `cmp_server.py` → `CMPv2ASN1.build_pki_message` (l.249).
- `cmp_server.py` → every call site that returns the result of
  `build_pki_message` (l.593, 601, 618, 622, 661, 674, 702, 706, 791, 827,
  1004) — audit whether each needs the CA chain included.

**Implementation**

- Extract the DER bytes of the already-built `header` and `body` SEQUENCEs
  (they're constructed in the function; keep them as separate variables
  before wrapping).
- Compute `protectedPart = header_der + body_der` per RFC 4210 §5.1.3 —
  note this is the **concatenation of the two TLVs**, not a re-wrapped
  SEQUENCE.
- Sign: `sig = ca_key.sign(protectedPart, padding.PKCS1v15(), SHA256())`.
- Append `[0] EXPLICIT protection BIT STRING` (tag `0xA0`, inner `0x03` with
  unused-bits byte `0x00` + signature).
- Append `[1] EXPLICIT extraCerts SEQUENCE OF Certificate` (tag `0xA1`)
  containing the CA cert (and any intermediates).
- Pass the CA key + cert into the builder via a new parameter or via a
  closure. Prefer a small refactor: `build_pki_message(..., signer_key,
  signer_cert)`.
- When PSS is added (RFC 4055 work), parameterize padding choice from the
  CA config.

**Tests** (new class `TestRFC4210Protection`)

- Send a signed `ir`; parse the response and assert `[0] protection` is
  present, `[1] extraCerts` contains the CA cert, and the signature
  verifies against the CA public key over `header||body`.
- Corrupt the body after signing; assert verification fails.
- Assert `protectionAlg` in the header matches the actual algorithm used.

**Docs**

- README CMP section: note "Responses are signature-protected per RFC 4210
  §5.1.3" and remove any caveat if present.
- CHANGELOG `### Security`: "CMPv2/v3 responses now carry signature
  protection and the CA cert chain in `extraCerts`, closing RFC 4210 §5.1.3
  gap."

---

### RFC 4211 — CRMF proof-of-possession verification

**What it requires.** §4: when a CRMF `CertReqMsg` is submitted with a
`POPOSigningKey`, the server MUST verify the signature to prove the
requester holds the private key matching the requested public key.

**Source evidence.** `cmp_server.py:395-460`
(`extract_subject_and_pubkey_from_crmf`) walks the CertRequest template and
pulls out `[5] subject` and `[6] publicKey`, but it never reads the
`popo` field ([1] IMPLICIT ProofOfPossession) that sits between `CertRequest`
and the optional `regInfo` inside each `CertReqMsg`.

Not exploitable today because PyPKI's CMP path always requires a protected
PKIMessage, but still a MUST-violation and defense-in-depth matters.

**Files to modify**

- `cmp_server.py` → `extract_subject_and_pubkey_from_crmf` (l.395). Rename
  to `parse_crmf` and return `(subject_str, spki_der, popo_signature,
  popo_alg, certreq_der)`.
- `cmp_server.py` → `_handle_cert_request` (l.540) to call the verification.

**Implementation**

- Per RFC 4211 §4.1 case 2 (signature POPO without POPOSigningKeyInput), the
  signed data is the DER of the `certRequest` itself. Capture its bytes
  during parsing.
- Reconstruct the public key from the SPKI DER via
  `serialization.load_der_public_key`.
- Verify: for RSA PKCS1v15, `pubkey.verify(signature, certreq_der,
  padding.PKCS1v15(), hash_from_alg_oid)`. Map common OIDs: `1.2.840.
  113549.1.1.11` → SHA256, `1.2.840.113549.1.1.12` → SHA384, `1.2.840.
  10045.4.3.2` → ECDSA-SHA256, `1.3.101.112` → Ed25519 (no hash).
- If POPO missing or invalid: respond with `rejection` status code 2,
  failInfo `badPOP` (bit 9). Audit-log the failure.
- Case 3 (POPOSigningKeyInput with authInfo) is not needed unless a CMP
  workflow without CMP protection is added later — skip for now, clearly
  document that only case 2 is accepted.

**Tests** (new class `TestRFC4211POPO`)

- Valid CRMF with correct POPO → accepted.
- CRMF with no POPO field → rejected with `badPOP`.
- CRMF with POPO signed by a different key than the one in certTemplate →
  rejected.
- CRMF with corrupted signature → rejected.

**Docs**

- README CMP section: note "CRMF POPO verification per RFC 4211 §4.1".
- CHANGELOG `### Security`: "Enforce CRMF proof-of-possession per RFC 4211
  §4; prevent cert issuance for third-party public keys."

---

### RFC 5958 — Asymmetric Key Package (PKCS#8) normalization

**What it requires.** §2: private keys delivered to clients should be
encoded as `OneAsymmetricKey` (PKCS#8 v2) or `PrivateKeyInfo` (PKCS#8 v1),
not legacy `RSAPrivateKey` (PKCS#1) or `ECPrivateKey` (SEC1).

**Source evidence.** EST (`est_server.py:520`) and IPsec
(`ipsec_server.py:876`) correctly use `PrivateFormat.PKCS8`. CMP has four
sites using `PrivateFormat.TraditionalOpenSSL` (PKCS#1 for RSA, SEC1 for EC);
the Web UI sub-CA endpoint was a fifth (now fixed):

- `cmp_server.py:585` — `ir` auto-generated key
- `cmp_server.py:1068` — PKCS#12 bundle construction path
- `cmp_server.py:1171` — API key return
- `cmp_server.py:1195` — enrollment response private key field
- ~~`web_ui.py:1563` — sub-CA export~~ **FIXED**

**Files to modify**

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

### EST CSR SAN pass-through + profile-aware csrattrs

**Context.** EST (`est_server.py`) has three related weaknesses around
Subject Alternative Name handling. Item 1 is a functional bug that silently
broke TLS hostname verification for any EST-issued cert; fixed now.
Items 2 and 3 are feature work to make EST useful for profile-scoped
enrollment (device types, SPIFFE identities, etc.).

**1. CSR SANs were dropped on issuance — FIXED.**

`_handle_simpleenroll` (`est_server.py:415`) used to call
`ca.issue_certificate(subject_str=..., public_key=...)` without extracting
SANs from the CSR's `extensionRequest` attribute. A client asking for
`DNS:app.example.com` received a cert with **no SAN at all**. Every other
enrollment path (ACME finalize, CMP p10cr, IPsec `/enroll`, REST
`/api/certs`) reads CSR SANs and threads them through; EST was the outlier.

The fix mirrors the `ipsec_server.py:1963-1975` pattern: extract
`DNSName`, `RFC822Name`, and `IPAddress` entries from the CSR's SAN
extension and pass them as `san_dns`, `san_emails`, `san_ips` to
`issue_certificate`. URI SANs (including SPIFFE) are intentionally skipped
for now — see item 3.

**Tests to add** (extend `TestESTModule`)

- Build a CSR with two DNS SANs + one IP SAN + one email SAN; submit to
  `simpleenroll`; parse the response PKCS#7 degenerate SignedData; verify
  the issued leaf cert's SAN extension contains all four entries.
- Build a CSR with no SAN extension; assert the issued cert also has no
  SAN extension (no silent injection).
- Build a CSR with a URI SAN `spiffe://example.org/ns/default/sa/foo`;
  assert current behaviour (URI silently dropped) until item 3 lands.
  Flag with `@unittest.expectedFailure` once item 3 starts.

**2. EST label routing to certificate profiles — TODO.**

`est_server.py:638-640` already parses `/.well-known/est/<label>/<op>` and
returns `(op, label)`, but every handler currently ignores `label`. Wire it
through to select a CertProfile:

```
/.well-known/est/simpleenroll              → profile="default"
/.well-known/est/tls-server/simpleenroll   → profile="tls_server"
/.well-known/est/tls-client/simpleenroll   → profile="tls_client"
/.well-known/est/ipsec/simpleenroll        → profile="ipsec_end"
/.well-known/est/code-signing/simpleenroll → profile="code_signing"
```

**Files to modify**

- `est_server.py` — plumb `label` from `_parse_path` → `_handle_simpleenroll`
  → `_handle_csrattrs` → `_handle_serverkeygen`.
- `est_server.py` — new mapping `EST_LABEL_PROFILE` with the table above;
  unknown labels default to `"default"` (do not fail — RFC 7030 doesn't
  mandate strict label handling).
- `pki_server.py` — pass `profile=...` through to
  `ca.issue_certificate(...)` at the new call site.

**Tests**

- Label `tls-server` routes to the `tls_server` profile: issued cert has
  `ExtendedKeyUsage` with `serverAuth`.
- Label `code-signing` routes to `code_signing` profile: issued cert has
  `id-kp-codeSigning` EKU and `digitalSignature + contentCommitment` KU.
- Unknown label `widget` silently falls back to default; issuance
  succeeds.

**3. Profile-specific `csrattrs` + server-side SAN format enforcement — TODO.**

Today `build_csrattrs` (`est_server.py:228-254`) returns a single static
hint: RSA, SAN (any shape), EKU `clientAuth`. Make it label-aware, and
**enforce** the hinted constraints on incoming CSRs at `simpleenroll`
rather than merely hinting.

**Implementation**

Add a per-profile csrattrs spec:

```python
EST_CSR_ATTRS = {
    "tls_server": {
        "key_types":      [OID_RSA_ENCRYPTION, OID_EC_PUBLIC_KEY],
        "required_eku":   [OID_SERVER_AUTH],
        "san_required":   True,
        "san_types":      {"DNS", "IP"},
        "forbid_san":     {"URI", "otherName"},
    },
    "tls_client": {
        "required_eku":   [OID_CLIENT_AUTH],
        "san_required":   True,
        "san_types":      {"DNS", "email"},
    },
    "spiffe": {
        "required_eku":   [OID_CLIENT_AUTH, OID_SERVER_AUTH],
        "san_required":   True,
        "san_types":      {"URI"},
        "uri_scheme":     "spiffe",
        "uri_authority":  "cluster.local",  # configurable per-CA
    },
    "ipsec_end": {
        "required_eku":   [OID_IKE_INTERMEDIATE],
        "san_required":   True,
        "san_types":      {"DNS", "IP"},
    },
}
```

Server-side enforcement at `simpleenroll`:

- CSR signature still checked (existing).
- If `san_required` and the CSR has no SAN extension → reject 400
  `"csrattrs for profile <p> requires SAN"`.
- For every SAN entry: if its type is not in `san_types` (or is in
  `forbid_san`) → reject 400 with specific detail.
- For SPIFFE profile: every URI SAN MUST start with
  `spiffe://<uri_authority>/`; path MUST be non-empty. Reject otherwise.
- Profile-specific EKU may be injected by the issuer even if absent from
  the CSR; no client-side requirement beyond the csrattrs hint.

**Files to modify**

- `est_server.py` — `build_csrattrs(profile)` replaces `build_csrattrs()`;
  new `_validate_csr_for_profile(csr, profile)` helper.
- `est_server.py` — `_handle_simpleenroll` calls
  `_validate_csr_for_profile` before `issue_certificate`.
- `pki_server.py` — add URI SAN plumbing to `issue_certificate`
  (`san_uris: Optional[list] = None`) so SPIFFE URIs land in the issued
  cert. Currently URIs only exist in AIA/CDP extensions
  (`pki_server.py:1207, 1225`), never as SAN values.

**Tests** (new class `TestRFC7030ProfileCSRAttrs`)

- `GET /.well-known/est/tls-server/csrattrs` returns attrs including
  `id-kp-serverAuth`.
- `GET /.well-known/est/spiffe/csrattrs` returns attrs hinting URI SAN with
  `spiffe://` scheme.
- `POST /spiffe/simpleenroll` with CSR containing
  `spiffe://cluster.local/ns/default/sa/foo` → accepted; issued cert has
  exactly that URI SAN.
- Same endpoint with `spiffe://wrong-trust-domain/...` → 400.
- Same endpoint with `DNS:foo.example.com` and no URI SAN → 400.
- `POST /tls-server/simpleenroll` with URI SAN (no DNS) → 400.

**Why this matters for Kubernetes / SPIFFE.** Current mainstream SPIFFE
integrations for k8s (Istio via `cert-manager-istio-csr`, SPIRE, csi-driver-
spiffe) do **not** speak EST — they use cert-manager's internal CSI/gRPC
paths. So none of this is blocking the k8s deployment plan discussed
elsewhere. However, EST is still the right answer for non-k8s devices
(VPN clients, IoT nodes, Windows machines enrolling via NDES) that want
SPIFFE-style identities, and there's no other open-source server that does
profile-aware EST today. This lets PyPKI occupy that niche.

---

## Tier 2 — High-value modern additions

### RFC 3161 + RFC 5816 — Time-Stamp Protocol

**What it requires.** A TSA accepts a `TimeStampReq` (hash + nonce + policy)
and returns a `TimeStampResp` containing a CMS SignedData wrapping a `TSTInfo`.
RFC 5816 upgrades the `ESSCertID` to `ESSCertIDv2` with SHA-256. **Always
implement both together.**

**Files to create**

- `tsa_server.py` — mirror the shape of `ocsp_server.py`: its own
  `HTTPServer` with a handler class, a builder class, and integration hooks
  back into `CertificateAuthority`.

**Files to modify**

- `pki_server.py` — add a dedicated TSA signing cert auto-issued from the CA
  (EKU `id-kp-timeStamping`, `1.3.6.1.5.5.7.3.8`, critical; KU
  `digitalSignature` only). Add to `CertProfile` as `tsa_signing`.
- `dispatcher_server.py` — route `/tsa` POST when `--tsa-port` is active.
- ASN.1 primitives: reuse `scep_server.py` helpers.

**Implementation**

- Request parser (`TimeStampReq`):
  ```
  TimeStampReq ::= SEQUENCE {
      version             INTEGER  { v1(1) },
      messageImprint      MessageImprint,
      reqPolicy           TSAPolicyId              OPTIONAL,
      nonce               INTEGER                  OPTIONAL,
      certReq             BOOLEAN                  DEFAULT FALSE,
      extensions      [0] IMPLICIT Extensions      OPTIONAL }
  MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  ```
- Response builder (`TimeStampResp`):
  ```
  TimeStampResp ::= SEQUENCE {
      status                  PKIStatusInfo,
      timeStampToken          TimeStampToken OPTIONAL }
  ```
  `timeStampToken` is a CMS `SignedData` (content type `id-ct-TSTInfo`,
  `1.2.840.113549.1.9.16.1.4`). Build via existing `CMSBuilder`, extended
  for this content type.
- `TSTInfo`: version=1, policy OID (configurable), messageImprint echoed,
  `serialNumber` (monotonic), `genTime` (UTC, must include microseconds if
  accuracy requires), `nonce` echoed.
- **Signed attributes on the TSA signer**:
  - `contentType` = `id-ct-TSTInfo`
  - `messageDigest` = SHA-256 of encapContentInfo
  - `signingTime` (optional; `genTime` is authoritative)
  - **`signingCertificateV2` (RFC 5816)** with `ESSCertIDv2` containing
    SHA-256 hash of the TSA cert. OID `1.2.840.113549.1.9.16.2.47`.
- Policy OID: configurable via `--tsa-policy-oid` (default
  `1.3.6.1.4.1.<your-pen>.1` — document the need for a real OID).
- Nonce handling: echo verbatim; refuse if accuracy can't be met.
- Rate limit + audit log on every request.

**CLI flags**

```
--tsa-port 8083              Enable TSA server on given port
--tsa-policy-oid OID         Policy OID (default is a placeholder)
--tsa-accuracy-seconds N     Declared accuracy (default 1)
--tsa-cert PATH              Pre-provisioned TSA cert (otherwise auto-issued)
--tsa-key PATH               Pre-provisioned TSA key
```

**Tests** (new class `TestRFC3161TSA`)

- Build a `TimeStampReq` with SHA-256 imprint + nonce, POST to `/tsa`, verify:
  - status = granted
  - `TSTInfo.messageImprint` echoes the request
  - `TSTInfo.nonce` echoes the request
  - `signingCertificateV2` present and hash matches TSA cert
  - CMS signature verifies against TSA cert → CA
- Reject: MD5 hash algorithm (policy), missing messageImprint, wrong version.
- OpenSSL round-trip: `openssl ts -verify -in resp.tsr -queryfile req.tsq
  -CAfile ca.crt`.
- Integration: use `openssl cms -sign` to create a `.p7s` with our TSA as
  the countersigner; verify.

**Docs**

- README: new major section "TSA Server (RFC 3161 / RFC 5816)" between EST
  and OCSP. Include endpoint table, CLI flags, OpenSSL `ts` examples.
- Compliance table: RFC 3161 `✅ Full`, RFC 5816 `✅ Full`.
- `pypki-flows.html`: the Software Signing flows already reference an
  external TSA; add a new section "TSA — Request/Response" showing the
  now-internal flow.
- CHANGELOG `### Added`: TSA server with RFC 3161 + RFC 5816 support.

---

### RFC 8738 — ACME IP Identifier

**What it requires.** Support `type: "ip"` identifiers in ACME orders,
enabling cert issuance for IP SANs. Big win for homelab.

**Files to modify**

- `acme_server.py` → order creation, authorization issuance, challenge
  selection, finalize.

**Implementation**

- Accept `{"type": "ip", "value": "192.0.2.1"}` identifiers in
  `new-order`. Parse with `ipaddress.ip_address()`; reject reserved/
  multicast/loopback unless explicitly allowed via
  `--acme-allow-private-ip`.
- Authorization: only `http-01` and `tls-alpn-01` challenges are valid for
  IP identifiers per RFC 8738 §4 (**no `dns-01`**). Enforce this.
- Challenge verification uses the literal IP (no DNS resolution).
- On finalize, the issued cert's SAN must contain `iPAddress`, not `dNSName`.
  Validate the CSR's SAN matches the authorized identifiers exactly.

**Tests** (new class `TestRFC8738ACMEIPId`)

- Full order for `192.0.2.1` via `tls-alpn-01`; verify issued cert has
  `iPAddress` SAN only.
- Reject `dns-01` challenge for an IP identifier.
- Reject order for `10.0.0.1` when `--acme-allow-private-ip` is not set.

**Docs**

- README ACME section: add "IP SAN issuance via RFC 8738".
- Compliance table: RFC 8738 `✅ Full`.

---

### RFC 8410 — Ed25519 and Ed448 in X.509

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

### RFC 5480 + RFC 5758 — ECDSA and EC keys in PKIX

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

### RFC 7292 — PKCS#12 hardening

**What it requires.** PKCS#12 export already works
(`pki_server.py:1757`). RFC 7292 (v1.1) fixes encoding ambiguities. Modern
guidance (NIST SP 800-132) demands a strong KDF iteration count.

**Files to modify**

- `pki_server.py` → `CertificateAuthority.export_pkcs12()`

**Implementation**

- Ensure we use `BestAvailableEncryption(password)` which by default picks
  AES-256 + HMAC-SHA256 with ≥600k PBKDF2 iterations in current
  `cryptography` releases.
- When no password: allow unencrypted only if `--p12-allow-unencrypted`
  is set; otherwise refuse with a clear error.
- Friendly-name attribute: set the cert subject CN as friendlyName for
  better UX in Windows/macOS cert import dialogs.

**Tests** (extend `TestPKCS12Export`)

- Export with password, reopen with `cryptography.hazmat.primitives.
  serialization.pkcs12.load_pkcs12`; verify cert + key + chain + friendlyName.
- Reject unencrypted export without the flag.

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

**What's missing for full compliance.**

- **Pre-certificate flow** (RFC 6962 §3.1). Today the final cert is
  submitted directly to the log, then re-issued with the SCT extension —
  that produces a second cert with the same subject/serial but a different
  signature, which some verifiers treat as distinct. The correct flow is:
  1. Build a pre-cert with the `poison` critical extension (OID
     `1.3.6.1.4.1.11129.2.4.3`).
  2. Submit pre-cert to logs, receive SCTs.
  3. Re-issue: remove poison, add SCT list, keep same serial + TBS fields.
- **CLI wiring.** No `--ct-log-url` flag is plumbed through. Today CT is
  only reachable programmatically via `ca.issue_with_ct()`.
- **Log public keys + signature verification** on received SCTs are not
  checked before embedding.
- **No minimum-SCT-count enforcement** (Chrome wants ≥2 from qualified
  logs).

**Files to modify**

- `pki_server.py` → introduce `_issue_precert()` returning a poisoned cert,
  refactor `issue_with_ct` to use pre-cert flow.
- `pki_server.py` CLI parsing → add `--ct-log-url URL` (repeatable),
  `--ct-log-pubkey PATH` (repeatable, aligned by index), `--ct-require-n N`.
- `pki_server.py` → SCT verification helper that parses the TLS signature
  and verifies with the log's public key.

**Tests** (extend `TestRFC6962CT` — add the class if not present)

- In-process mock CT log that signs SCTs with a known key; verify signature
  check passes on correct key, fails on wrong key.
- Pre-cert flow: intercept the pre-cert; assert poison extension is
  present + critical.
- Final cert: poison removed, SCT list present, serial matches pre-cert.
- `--ct-require-n 2` with only 1 log reachable → issuance aborts.

**Docs**

- README: document `--ct-log-url` and recommended opt-in for publicly-trusted
  CAs only.
- Compliance table: keep RFC 6962 at `✅ Opt-in`, annotate "pre-cert flow"
  in notes.
- CHANGELOG `### Changed`: pre-cert flow + CLI wiring + SCT verification.

---

### RFC 5083 + RFC 5084 — AuthEnvelopedData + AES-GCM in CMS

**What it requires.** AES-GCM content encryption in CMS, eliminating CBC
padding-oracle surface in SCEP.

**Files to modify**

- `scep_server.py` → `CMSBuilder.enveloped_data()` (line ~614) and
  `CMSParser.parse_enveloped_data` (line ~375).

**Implementation**

- Add a new builder method `CMSBuilder.auth_enveloped_data()` producing
  `ContentInfo { contentType = id-ct-authEnvelopedData
  (1.2.840.113549.1.9.16.1.23), content = AuthEnvelopedData }`.
- CEK: 32-byte random; GCM IV: 12-byte random; auth tag: 16-byte.
- Key-transport RecipientInfo unchanged (RSAES), or add RSA-OAEP (RFC 4055).
- Parser: detect the OID, decrypt via `AESGCM.decrypt`.
- Keep CBC paths for compatibility.

**SCEP negotiation**

- SCEP `GetCACaps` — advertise `AES-GCM` and `SHA-256`.
- If device sends AuthEnvelopedData, respond in kind. Otherwise keep CBC.

**Tests** (new class `TestRFC5083CMS`)

- Round-trip: build AuthEnvelopedData → parse → decrypt matches plaintext.
- SCEP PKCSReq with AuthEnvelopedData end-to-end.
- `GetCACaps` returns `AES-GCM`.

**Docs**

- README SCEP section: add capability row.
- Compliance table: RFC 5083, RFC 5084 `✅ Full`.

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

### RFC 8933 — CMS content-type attribute protection

- In `CMSBuilder._build_signer_info` (`scep_server.py:485`), ensure that when
  `signedAttrs` are present, `contentType` attribute is **always** included.
  Required by 8933 MUST.
- Audit: the current code includes `contentType` in `_build_signer_info`
  already (line ~511). Confirm it's never elided and add a test.

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

### 5.5 ACME EAB + per-account rate limiting

**Why.** RFC 8555 §7.3.4 — External Account Binding gates ACME account
creation behind a pre-shared MAC key issued by the CA admin. Without it,
anyone reachable to the ACME endpoint can request any cert that passes
challenges, which on a private CA is most of them. Today
`acme_server.py:881` returns `externalAccountRequired: false` and EAB is
not implemented.

**Files to modify**

- `acme_server.py` — directory metadata (`externalAccountRequired: true`
  when EAB enabled), new-account handler (validate `externalAccountBinding`
  field per RFC 8555 §7.3.4: HS256 JWS over the new-account JWK, signed
  with the EAB MAC key).
- New `eab_keys` table: kid, mac_key_b64, created_by, created_at,
  revoked_at.
- `web_ui.py` — admin UI to mint EAB credentials.

**Per-account rate limits**

- Existing rate limiter is per-IP. Add per-account bucket keyed on the
  ACME account URL hash (or EAB kid where present). Default: 50 orders /
  hour / account.
- Same for EST (per HTTP Basic user) and the REST API (per API key).

**Tests**

- Account creation without EAB when `externalAccountRequired: true` →
  rejected.
- Account creation with valid EAB → accepted; subsequent orders work.
- Account creation with EAB MAC verification failure → rejected with
  `urn:ietf:params:acme:error:unauthorized`.

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

### 5.12 Documentation deliverables (markdown, no code)

These are the credibility-and-onboarding gaps. Each is a day of writing.

**`docs/CPS.md` — Certificate Practice Statement (RFC 3647 §6).**
Already specified in the Tier 4 RFC 3647 section. Belongs here too because
it's the single highest-leverage piece of documentation: every issued cert
points at it via the `id-qt-cps` qualifier today, and that URL is currently
a 404.

**`docs/THREAT_MODEL.md`.** What is PyPKI's TCB? What does compromise of
each component buy an attacker? Specific scenarios: Web UI session theft,
OCSP signer key theft, CA key theft, DB read access, DB write access,
admin API key theft. For each: blast radius and mitigation. Without this
document, no security review can give PyPKI a positive verdict because
they have nothing to review *against*.

**`docs/DEPLOYMENT/`.** One file per common topology:
- `homelab-single-node.md` — what most users start with.
- `offline-root-online-subca.md` — the standard two-tier, ties to §5.3.
- `kubernetes-cert-manager.md` — the deployment we discussed; pairs with
  the sub-CA ergonomics work in §1.
- `kubernetes-istio.md` — service mesh integration via cert-manager-istio-csr.
- `iot-devices-est.md` — device enrollment via EST; ties to the EST
  profile-routing work.
- `pihole-acme-dns01.md` — your existing setup; document for others.
- `vpn-strongswan-cmp.md` — IPsec CA via CMP.

**`docs/COMPATIBILITY.md`.** Tested-against matrix. OpenSSL versions,
strongSwan versions, certbot, acme.sh, cert-manager, Windows
Authenticode tooling, kubeadm versions, openssl `cms` and `ts` versions.
Without this, every user re-discovers the same edge cases.

**`docs/MIGRATION.md`.** SQLite → Postgres (when 5.2 lands). File-backed
key → HSM (when 5.1 lands). v0.x → v1.0 schema. Worth writing each as
the corresponding feature ships, not in advance.

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
   - RFC 5958 (PKCS#8 normalization — four-line change in `cmp_server.py`)
   - RFC 6818 / RFC 5280 (add `cRLNumber` + AKI to CRL)
   - RFC 8954 (OCSP nonce bounds enforcement)
   - RFC 7468 (strict PEM validation)
2. **Security-critical (MUST-violations)**:
   - RFC 4210 §5.1.3 (CMP response signature protection)
   - RFC 4211 §4 (CRMF POPO verification)
3. **Crypto-algorithm coverage** (do together, one refactor):
   - RFC 4055 (PSS/OAEP)
   - RFC 5480 + RFC 5758 (ECC in PKIX + ECDSA algorithm IDs)
   - RFC 8410 (Ed25519/Ed448)
4. **New protocols** (biggest user-visible additions):
   - RFC 3161 + RFC 5816 (TSA server)
   - RFC 8738 (ACME IP identifier)
5. **Hardening**:
   - RFC 5083 + RFC 5084 (AES-GCM / AuthEnvelopedData in CMS)
   - RFC 8933 (CMS content-type attribute protection)
   - RFC 9481 + RFC 9482 (CMP algorithm requirements + lightweight profile)
   - RFC 7292 (PKCS#12 encryption defaults + friendlyName)
   - RFC 6962 (CT pre-cert flow + CLI wiring + SCT verification)
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

#### Done criteria for the migration tool

- [ ] `pypki migrate-data` subcommand implemented; copies all canonical
      tables, skips ephemeral tables, batches large tables.
- [ ] `pypki verify-migration` subcommand implemented; row counts,
      random-sample comparison, ca_meta singleton check, sequence-safety
      check.
- [ ] `fix_sequence` works correctly for both backends.
- [ ] Round-trip tests pass against an SQLite fixture and a Postgres
      testcontainer in CI.
- [ ] `docs/STORAGE.md` includes the runbook from this section verbatim,
      with examples for systemd, Docker Compose, and bare process.
- [ ] CHANGELOG `### Added`: SQLite ↔ Postgres data migration tool.

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
