# IMA/EVM Capability Audit — Findings

**Scope:** Linux X.509-based integrity signing — IMA (`security.ima`), EVM X.509 mode
(`security.evm`), kernel module signing (`scripts/sign-file`), and Secure Boot (`sbsign`).

**Methodology:** Source-only. Every finding cites a searchable string anchor.
No inference, no memory.

---

## 1. Findings table

| Q# | Verdict | File : anchor | Note |
|----|---------|---------------|------|
| Q1 | **YES** | `pki_server.py` : `"eku": [ExtendedKeyUsageOID.CODE_SIGNING]` (line 1599) | Fixed `code_signing` profile emits 1.3.6.1.5.5.7.3.3. Not caller-selectable per-request; must choose the profile. |
| Q2 | **YES** | `pki_server.py` : `"key_usage": dict(digital_signature=True, content_commitment=True` (line 1595); `x509.KeyUsage(**ku)` (line 2488) | `code_signing` profile sets `digitalSignature + contentCommitment`; `issue_certificate()` applies it from `prof["key_usage"]`. |
| Q3 | **YES** | `pki_server.py` : `x509.SubjectKeyIdentifier.from_public_key(public_key)` (line 2481) | Added unconditionally to every cert (CA and leaf) inside `issue_certificate()`. `evmctl` IMA sig-v2 keyid derivation is satisfied. |
| Q4 | **PARTIAL** | `pki_server.py` : `_KEY_GENERATORS` dict (lines 1253–1268) | Classical RSA-2048/3072/4096 and ECDSA P-256/P-384/P-521 fully reachable. ML-DSA also reachable but **kernel-incompatible** — see detail below. |
| Q5 | **PARTIAL** | `web_ui.py` : `_api_cert_download` (line 2006); `_api_issue` response (line 3552) | No DER download endpoint for leaves. Both `/api/certs/<serial>/pem` and `POST /api/issue` return PEM only. CA cert DER available programmatically (`ca_cert_der` property, line 3953) but not exposed as a route. PEM → DER is a trivial one-command conversion. |
| Q6 | **YES (both)** | `web_ui.py` : `csr_pem` branch (line 3497); ephemeral keygen (line 3524) | CSR flow supported: caller submits `csr_pem`, public key extracted, key stays with requester (preferred for IMA/EVM). Without CSR: server generates ephemeral EC-P256, cert returned, key is NOT returned in the response (line 3552). Sub-CA issuance does return `key_pem` (line 2209) — distinct path. |
| Q7 | **NO** (correct scope) | `smime_server.py` : `_handle_sign` (line 855); `tsa_server.py` : `_tsa_sign` (line 354) | No generic artifact/data signing endpoint. S/MIME `/smime/sign` is CMS email signing (caller provides own key+cert); TSA signs timestamp tokens per RFC 3161. Neither is IMA/EVM artifact signing. |
| Q8 | **N/A** (correct scope) | `pki_server.py` : `hsm_cfg … CA signing key is loaded from the HSM` (lines 1892–1893); `--ca-key-backend` (line 5469) | HSM/PKCS#11 secures the **CA signing key** only. Endpoint signing-key custody (for `evmctl`/`sign-file`/`sbsign`) is entirely outside this repo — correct scope boundary. |
| Q9 | **YES** | `pki_server.py` : `"code_signing": {` (line 1594) | Named `code_signing` profile exists and satisfies the combined Q1+Q2+Q3 shape. One call with `profile=code_signing` is sufficient; no assembly from primitives required. |

---

## 2. Profile gap summary

Required property table from the spec, evaluated against the `code_signing` profile
(`pki_server.py:1594–1605`).

| Property | Status | Anchor |
|----------|--------|--------|
| RSA or ECDSA public-key algorithm | **MET** | `_KEY_GENERATORS` at `pki_server.py:1253–1258`; the profile does not restrict algorithm, so RSA-2048/3072/4096 and ECDSA P-256/P-384/P-521 are all reachable. |
| `keyUsage = digitalSignature` | **MET** | `pki_server.py:1595` — `digital_signature=True`; applied via `x509.KeyUsage(**ku)` at line 2488. |
| `extendedKeyUsage = codeSigning` | **MET** | `pki_server.py:1599` — `ExtendedKeyUsageOID.CODE_SIGNING` = 1.3.6.1.5.5.7.3.3. |
| `subjectKeyIdentifier` present | **MET** | `pki_server.py:2481` — `SubjectKeyIdentifier.from_public_key(public_key)` unconditional on all certs. |
| Exportable as DER | **PARTIAL — minor gap** | Cert stored as DER internally (`get_cert_by_serial` returns DER bytes, `web_ui.py:2009`). No `/der` HTTP route. Operator must convert from PEM: `openssl x509 -in cert.pem -outform DER -out cert.der`. CA cert DER available via `ca_cert_der` property (`pki_server.py:3953`) but not routed. |
| Chain exportable as DER | **PARTIAL — minor gap** | `/ca/cert.pem` route (`web_ui.py:1168`) serves PEM chain. PKCS#12 (`/api/certs/<serial>/p12`) bundles cert + chain. No `/ca/cert.der` route. |
| Chains to operator-controlled root | **MET** | This is the entire design of PyPKI — self-controlled root CA enrolled to `.ima`/`.evm` keyring or MOK/db. |

---

## 3. Verdict

**PyPKI can issue an IMA/EVM-suitable signing cert today.**

Issuing `POST /api/issue` with `{"profile": "code_signing", "csr_pem": "..."}` produces a
leaf certificate with `digitalSignature + contentCommitment` KU, `codeSigning` EKU, and a
`subjectKeyIdentifier` — all three fields that `evmctl`, `scripts/sign-file`, and `sbsign`
depend on. The CSR flow keeps the signing key on the endpoint, which is best practice for
IMA/EVM keys.

The only gap is DER download: the API returns PEM, and the operator must run
`openssl x509 -in cert.pem -outform DER -out cert.der` before importing to the `.ima`/`.evm`
keyring or MOK store. This is a two-command conversion, not a crypto gap — the cert shape
is correct. Adding a `/api/certs/<serial>/der` endpoint and a `/ca/cert.der` route would
close it.

---

## 4. Out-of-scope confirmations

### Q7 — Artifact/data signing is correctly NOT PyPKI's job

`smime_server.py:855` (`_handle_sign`) performs CMS SignedData construction for S/MIME
email. It is not IMA/EVM artifact signing: the caller supplies their own private key and
cert, and the output is a MIME-wrapped CMS blob, not a kernel IMA signature.

`tsa_server.py:354` (`_tsa_sign`) signs RFC 3161 timestamp tokens — the TSA signs
metadata about a hash, not arbitrary content.

Neither constitutes a generic "sign these bytes" surface for file/module/firmware
integrity. Artifact signing for IMA/EVM remains correctly endpoint-side
(`evmctl`/`scripts/sign-file`/`sbsign`), outside this repo.

### Q8 — Endpoint signing-key custody is correctly NOT PyPKI's job

`pki_server.py:1892–1893` (`hsm_cfg … CA signing key is loaded from the HSM`) and
`pki_server.py:5469` (`--ca-key-backend pkcs11|aws-kms|gcp-kms|azure-kv`) confirm that
HSM/PKCS#11 support is scoped to the **CA private key** only. There is no code in this
repo that manages endpoint signing keys (the keys used by `evmctl` to sign files, or by
`sign-file` to sign kernel modules). That boundary is correct: endpoint key custody is
the operator's concern, and the best practice of "key on endpoint or PKCS#11 token,
CSR sent to CA" is explicitly supported (`web_ui.py:3497`).

---

## 5. Search log

Every search that returned empty or produced a NO/PARTIAL is logged below.

### DER download endpoint (Q5 partial)

Queries run:
- `grep -n "Encoding\.DER\|\.der\b\|/der\b" web_ui.py` — no `/der` route found in
  `_route_api_cert` (line 1957). Only `pem` and `p12` branches exist in
  `_api_cert_download` (lines 2018–2041).
- `grep -n "ca_cert_der\|/ca/cert\.der\|application/pkix-cert" web_ui.py` — no DER
  route for CA cert. `/ca/cert` (line 1168) serves `application/x-pem-file`.
- `web_ui.py:3545` — `_api_issue` computes `der = cert.public_bytes(_Enc.DER)` for
  fingerprint, but the response JSON at line 3552 includes only `cert_pem`, `chain_pem`,
  `fullchain_pem` — DER bytes are not surfaced.

### Generic artifact signing (Q7)

Queries run:
- `grep -n "pkcs7\|PKCS7\|CMS\|/sign\b\|detached.sign" pki_server.py` — hits are
  CMS primitives for SCEP/CMP protocol handling, not a public signing endpoint.
- `grep -n "def.*sign" smime_server.py` — only `_handle_sign` at line 855, scoped to
  S/MIME email (CMS, caller provides key+cert).
- `grep -n "def.*sign\|/sign" tsa_server.py` — only `_tsa_sign` at line 354, which
  signs RFC 3161 timestamp tokens.
- No `/sign` route in `pki_server.py`, `web_ui.py`, or `portal.py`.

### Endpoint signing-key PKCS#11 (Q8)

Queries run:
- `grep -n "pkcs11\|softhsm\|token.*slot" pki_server.py` — all hits reference
  `--hsm-module` and CA key loading.
- `grep -n "endpoint.*sign\|subject.*key" hsm_backend.py` — no endpoint key management;
  module provides `load_hsm_signing_key` for the CA key only.

---

## 6. ML-DSA / PQ mismatch note (Q4)

PyPKI can issue ML-DSA-44/65/87 leaf certs via the `code_signing` profile (algorithm
selected by the requester, `_KEY_GENERATORS` at `pki_server.py:1261–1263`) or the
`ml_dsa_signing` profile (`pki_server.py:1758`).

**These certs are unusable for kernel IMA/EVM/module/Secure-Boot today.** The Linux
kernel's IMA, EVM, module-sig, and Secure Boot subsystems have no post-quantum signature
verification path. Issuing an ML-DSA leaf and expecting `evmctl` or `scripts/sign-file`
to consume it will fail at verification time, not at issuance time. This is a kernel
limitation, not a PyPKI limitation — but operators must not be misled by the fact that
PyPKI can emit the cert.

The `ml_dsa_signing` profile additionally uses `emailProtection` EKU (line 1763), not
`codeSigning`, making it unsuitable for IMA/EVM on that basis as well.

For IMA/EVM/kernel/Secure-Boot use, always select a classical algorithm (RSA or ECDSA)
with the `code_signing` profile.
