# CLAUDE.md — IMA/EVM Capability Audit

## Purpose

Establish, **from source**, what PyPKI can and cannot do today in support of Linux
X.509-based integrity signing: **IMA** (`security.ima`), **EVM** (`security.evm`
X.509 mode), **kernel module signing** (`scripts/sign-file`), and **Secure Boot**
(`sbsign`). These four mechanisms share one trust model: a static X.509 anchor the
operator controls, with the signing operation performed endpoint-side and the CA's
job being to issue a leaf cert with the correct shape.

This is a **read-only audit**. Do not modify code. Document gaps; do not fix them.
Remediation (if any) belongs in a separate implementation spec.

## Mandatory source-verification gate

- Every finding MUST cite a concrete `path/to/file.py` plus a **searchable string
  anchor** (a distinctive code/text fragment to grep, not a line number — line
  numbers drift).
- Do **not** assert any capability from memory or inference. If the source does not
  resolve a question, the finding is `UNKNOWN` with a note on what was searched.
- If filesystem/repo access is unavailable in this session, **stop and say so
  explicitly** — do not produce a speculative report dressed as findings.
- "Absent" is a valid, valuable finding, but only after a documented search that
  should have found it. Record the queries you ran.

## Scope boundary (read before searching)

PyPKI is a **Certificate Authority**. It is expected to *issue certificates*, not to
*sign arbitrary artifacts*. IMA/EVM/module/Secure-Boot signatures are produced
endpoint-side by `evmctl`, `scripts/sign-file`, and `sbsign` — tools outside this
repo. Therefore most questions below concern **whether PyPKI can issue a leaf cert
of the correct shape for a signing key**, plus **how the key and cert are made
available**. One question (Q7) explicitly checks whether any artifact-signing path
exists at all; the expected answer is "no, and that's correct scope" — but confirm
it rather than assume it.

## Required signing-cert profile (the spec to audit against)

A leaf cert that satisfies all four mechanisms on an internal/self-controlled trust
store needs, at minimum:

| Property | Requirement | Why |
|---|---|---|
| Public-key algorithm | RSA (2048/3072/4096) or ECDSA (P-256/P-384) | Kernel IMA + `sign-file` + `sbsign` support these. **PQ (ML-DSA) is NOT supported by kernel IMA today** — see Q4. |
| `keyUsage` | `digitalSignature` | Kernel module-sig parsing rejects keys lacking it; IMA/EVM verify a signature. |
| `extendedKeyUsage` | `codeSigning` (1.3.6.1.5.5.7.3.3) | `sign-file` rejects an EKU that, *if present*, omits codeSigning. Safe to set for all four. |
| `subjectKeyIdentifier` | present | `evmctl` derives the IMA sig v2 `keyid` from the cert/SKID; mismatch ⇒ kernel can't select the key. |
| Encoding for trust anchor | exportable as **DER** X.509 | Kernel `.ima`/`.evm` keyrings and MOK/db enrollment consume DER. |
| Chain | leaf chains to a root the operator enrolls (`.ima`/`.evm` keyring, or MOK/UEFI db) | This is the "internal trust" ceiling — a feature here, not a limitation. |

Notes for accuracy while auditing:
- EKU specifics and keyUsage enforcement vary by **kernel config**
  (`CONFIG_INTEGRITY_TRUSTED_KEYRING`, `CONFIG_MODULE_SIG_*`). Describe what PyPKI
  *emits*; do not assert what a given kernel *enforces* unless you cite the kernel
  source/docs. PyPKI conformance = "does the CA emit the fields a compliant verifier
  depends on" (same relying-party framing as the RFC 4158 work).
- EVM has two modes: HMAC (TPM-sealed, no CA involved — out of scope) and X.509
  signature (in scope). Only the latter is relevant to PyPKI.

## Investigation questions

For each: run the searches, record the anchor(s), classify as
`YES` / `NO` / `PARTIAL` / `UNKNOWN`, and note the success criterion result.

### Q1 — Can PyPKI issue a cert with `extendedKeyUsage = codeSigning`?
- Search: `ExtendedKeyUsage`, `ExtendedKeyUsageOID`, `CODE_SIGNING`, `code_signing`,
  `1.3.6.1.5.5.7.3.3`, and any profile/template registry that selects EKUs.
- Success criterion: a code path where a leaf cert is built with the codeSigning
  OID in its EKU, OR a definitive finding that EKU is not configurable to that value.
- Note whether it's a fixed profile, caller-selectable, or CSR-passthrough.

### Q2 — Can PyPKI set `keyUsage = digitalSignature` on a leaf?
- Search: `KeyUsage`, `digital_signature`, the keyUsage-construction site.
- Success criterion: confirm digitalSignature is settable on a leaf profile (not
  only on CA certs, which carry keyCertSign).

### Q3 — Does the issued leaf carry a `subjectKeyIdentifier`?
- Search: `SubjectKeyIdentifier`, `from_public_key`, `key_identifier`.
- Success criterion: confirm SKID is added to leaves (not just CA certs). If only
  CA certs get it, that's a `PARTIAL` worth flagging — `evmctl` keyid derivation
  depends on the leaf.

### Q4 — Which public-key algorithms can a leaf use, and is ML-DSA reachable here?
- Search: `EllipticCurve`, `SECP256R1`, `SECP384R1`, `RSA`, `generate_private_key`,
  `MLDSA`, `ML_DSA`, `ml-dsa`, `dilithium`.
- Success criterion: enumerate the algorithms a *signing leaf* can be issued for.
- **Explicitly record the PQ mismatch**: if PyPKI can issue ML-DSA leaves, note that
  these are **unusable for kernel IMA/EVM/module/Secure-Boot** today (kernel lacks
  PQ signature verification for these subsystems). This protects against a future
  "we support PQ code signing" claim that the kernel can't honor. State N/A clearly
  rather than omitting.

### Q5 — Can the issued cert be exported as DER (not only PEM)?
- Search: `Encoding.DER`, `Encoding.PEM`, `public_bytes`, `serialization`,
  export/download handlers, any `/cert` or `/ca` endpoint serialization.
- Success criterion: a path that yields DER X.509 bytes for a leaf and for the
  issuing chain (needed for keyring/MOK/db enrollment). PEM-only ⇒ `PARTIAL` +
  note that conversion is a trivial endpoint-side step.

### Q6 — Key provisioning: does PyPKI sign externally-generated CSRs, generate
keypairs server-side, or both?
- Search: `CertificateSigningRequest`, `load_pem_x509_csr`, CSR-intake handlers,
  any server-side `generate_private_key` used for *subject* keys (not CA keys).
- Success criterion: classify the supported flow(s). Best practice for IMA/EVM is
  **key stays on the endpoint or in a PKCS#11 token; CA signs a CSR** — confirm
  this flow exists. If PyPKI *can* hand back private keys, note it as an option but
  flag the custody downside for signing keys.

### Q7 — Does PyPKI perform ANY artifact/data signing (vs. only cert issuance)?
- Search: `pkcs7`, `PKCS7`, CMS, `sign(`, detached-signature builders, any
  `/sign` route, TSA signing internals.
- Success criterion: confirm whether a generic "sign these bytes" capability exists.
  Expected: **NO** for IMA-style signing (correct scope), with the only signing-ish
  surface being the **RFC 3161 TSA** (which signs timestamp tokens, not artifacts).
  Distinguish the two clearly. If a generic signing path *does* exist, document it —
  it would change the build calculus for an endpoint-side helper later.

### Q8 — PKCS#11 / HSM relevance to the *signing* key (not the CA key)
- Search: the PKCS#11 backend, `pkcs11`, `softhsm`, token/slot handling.
- Success criterion: clarify that PyPKI's HSM work secures **CA keys**, and record
  whether anything in the repo touches **endpoint signing-key** custody. Expected:
  out of scope (endpoint uses `evmctl`/`sign-file` with its own PKCS#11 URI). State
  this boundary explicitly so it isn't conflated with the CA-key HSM roadmap.

### Q9 — Is there a named profile/template that already targets code/integrity signing?
- Search: profile/template definitions, any `server`/`tls`/`signing` profile names,
  config schema for issuance profiles.
- Success criterion: determine whether the required profile (Q1–Q4 combined)
  exists as a single selectable unit, or must be assembled from primitives. This is
  the single biggest signal of how close PyPKI is to "issue an IMA signing cert" in
  one call.

## Deliverable

Produce `IMA_EVM_AUDIT_FINDINGS.md` containing:

1. **Findings table** — one row per question: `Q# | YES/NO/PARTIAL/UNKNOWN |
   file:anchor | one-line note`.
2. **Profile gap summary** — for the required-profile table above, mark each
   property MET / NOT MET / PARTIAL with its anchor.
3. **Verdict** — one paragraph: can PyPKI issue an IMA/EVM-suitable signing cert
   today? If PARTIAL, the shortest gap to "yes" (almost certainly profile assembly +
   DER export, not crypto primitives).
4. **Out-of-scope confirmations** — explicit statements that artifact signing (Q7)
   and endpoint key custody (Q8) are correctly *not* PyPKI's job, with anchors
   showing the boundary.
5. **Search log** — for every `UNKNOWN`/`NO`, the exact queries run, so absence is
   evidenced rather than assumed.

Use explicit `N/A` rather than omitting any row. No claim without an anchor.

## Non-goals (do not do in this pass)
- No implementation, no new profiles, no endpoint tooling, no `evmctl` wrappers.
- No assertion about what any specific kernel enforces unless citing kernel
  source/docs alongside the PyPKI finding.
- No PQ enablement work — Q4 only records the mismatch.
