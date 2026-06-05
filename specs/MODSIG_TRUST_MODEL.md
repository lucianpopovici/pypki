# CLAUDE.md — Module-Signing Trust Model: Per-CA vs Per-Leaf

## Purpose

Resolve, from source and by experiment, whether Linux **kernel module** signature
trust can be made **per-CA** (enroll the PyPKI root once; any `code_signing` leaf
then loads modules) or is inherently **per-leaf** (every signing cert individually
enrolled in a kernel keyring). This determines the module-signing enrollment/
deployment model and what the offering can promise.

**Scope is module-signing only.** The F2-BUILTIN run already settled IMA — see
Background. Do not re-open IMA here.

## Background — established facts (F2-BUILTIN run, 2026-06-05)

- `scripts/sign-file` signs with `CMS_NOCERTS`: the signer cert is **not** embedded
  in the PKCS#7. The kernel identifies the signer by `IssuerAndSerialNumber` and must
  find that exact cert in a trusted keyring. B1 only passed after the **leaf** was
  added to `.secondary_trusted_keys`; trusting the root alone was insufficient.
- **IMA is per-leaf, inherently.** IMA sig v2 carries a keyid (the leaf SKID); the
  kernel matches it against a key that must be **present in `.ima`** (VG2 added leaf
  id 564300624 there). The builtin root only governs *admissibility* to the restricted
  `.ima` keyring — the leaf is addable *because* it chains to a builtin-trusted root —
  not the appraisal match. There is no CA-chain appraisal for IMA. (This corrects an
  earlier assumption that IMA chain-validates.)
- Consequence: signing-leaf enrollment tooling is required for IMA regardless. The
  only open question is whether **modules** can avoid the same per-leaf burden.

## Hypothesis

`CMS_NOCERTS` is the cause. If the signer cert is **embedded** in the PKCS#7 (flag
dropped), the kernel's PKCS#7 trust validation may build the chain leaf→root and
accept the module with **only the root** trusted, eliminating per-leaf module
enrollment. Kernel behavior is version-specific — confirm on 6.19, assume nothing.

## Source-verification gate

- Every finding cites `path:anchor` (searchable string, not line number). No claims
  from memory. If the kernel tree or PyPKI repo is unavailable, stop and say so.
- Record every search that returned empty so "absent" is evidenced.

## Strand 1 — Tooling + kernel source (read-only)

Kernel tree on the build host (`linux-6.19.10`).

- `scripts/sign-file.c` — confirm the exact `CMS_sign()` flag expression. Anchor:
  `CMS_NOCERTS`. Record the full flag set.
- `crypto/asymmetric_keys/pkcs7_trust.c` — `pkcs7_validate_trust`,
  `pkcs7_validate_trust_one`. Determine whether trust validation walks **embedded**
  certs and matches a cert's authority key id against a trusted key (i.e. whether
  chain-to-root is honored when certs are present in the message).
- `kernel/module/signing.c` + `certs/system_keyring.c` — `mod_verify_sig`,
  `verify_pkcs7_signature(..., VERIFYING_MODULE_SIGNATURE, ...)`. Confirm which
  keyrings are consulted and that the generic pkcs7 trust path is used (not a
  leaf-only shortcut).
- Success criterion: a **sourced** yes/no on "does embedded-cert chain validation
  reach a trusted root for module signatures in 6.19."

## Strand 2 — PyPKI leaf emission (read-only)

Chain matching needs the leaf to carry an **authorityKeyIdentifier** matching the
root's SKID, alongside its own SKID (SKID already confirmed present — audit Q3).

- `pki_server.py` — search `AuthorityKeyIdentifier`,
  `from_issuer_subject_key_identifier`, `authority_key_identifier`. Confirm the
  `code_signing` leaf gets AKI; anchor the issuance site.
- Success criterion: AKI present on `code_signing` leaves (YES/NO + anchor). If NO,
  that alone can defeat chain matching — flag as a PyPKI gap (do **not** fix here).

## Strand 3 — VM experiment  `[SNAP]`

On the F2-BUILTIN kernel (PyPKI root in `.builtin_trusted_keys`), disposable VM.

**E0 — control (reproduce the run's finding):**
- Stock `sign-file` (`CMS_NOCERTS`), leaf in **no** keyring, only root in builtin.
- `insmod hello.ko` → expect **FAIL** `unavailable key`. Confirms the cause.

**E1 — test (embed the cert):**
- Patch `scripts/sign-file.c` to drop `CMS_NOCERTS` (confirm the exact flag
  expression first; illustrative only: remove the `CMS_NOCERTS |` term). Rebuild:
  `make scripts/sign-file`.
- Re-sign: `scripts/sign-file sha512 leaf_key.pem leaf_cert.pem hello.ko`. Confirm
  the cert is now embedded (extract the appended PKCS#7 and
  `openssl pkcs7 -inform DER -print_certs`, or equivalent).
- Ensure the leaf is in **no** trusted keyring:
  `keyctl unlink <id> %:.secondary_trusted_keys` (and verify with `keyctl list` on
  `.secondary_trusted_keys`, `.builtin_trusted_keys`, `.machine`).
- `insmod hello.ko`:
  - **E1 PASS** = loads with only the root trusted → **per-CA module trust is
    achievable** via cert embedding.
  - **E1 FAIL** (capture dmesg) = embedding insufficient → per-leaf is inherent for
    modules in 6.19, OR an AKI/matching gap (cross-check Strand 2 before concluding).

Alt (no kernel-script patch): build the signature with
`openssl cms -sign -certfile chain.pem ...` and reassemble the module trailer
(PKCS#7 + `struct module_signature` + `~Module signature appended~\n`). Heavier; use
only if patching `sign-file` is undesirable, and document the method.

## Security tradeoff (must appear in the verdict, not just the convenience framing)

Per-CA module trust means **any** `code_signing` leaf the PyPKI CA ever issues can
load kernel modules — a broad blast radius bound to a single trust decision. Per-leaf
pins exactly which keys may sign modules — narrower, higher operational cost. This is
plausibly *why* distros ship `CMS_NOCERTS` + leaf pinning by default. State the
verdict as a documented **choice** with this tradeoff explicit, not "per-CA is
better." The offering can support both modes.

## Deliverable — `MODSIG_TRUST_FINDINGS.md`

1. **Verdict**: per-CA achievable? YES/NO, with E0/E1 evidence (exit codes + dmesg).
2. Strand-1 source basis — the kernel functions and what they do.
3. Strand-2 PyPKI AKI status — anchor.
4. If YES: the exact **per-CA** signing recipe (patched sign-file or openssl cms)
   *and* the **per-leaf** recipe (stock sign-file + leaf enrollment) — both, so the
   choice is documented.
5. If NO: statement that module trust is inherently per-leaf in this config, with the
   kernel-source reason.
6. **Product implication** (one paragraph): leaf-enrollment tooling is required for
   IMA regardless (established); whether modules add a per-leaf burden or can be
   collapsed to per-CA.

## Non-goals

- No PyPKI source changes. If AKI is missing on leaves, that's a separate spec.
- No re-testing IMA — per-leaf is established.
- No building of enrollment/distribution tooling — that's the downstream product,
  which this verdict informs.
- Patching `sign-file` is an experiment only; this is not a recommendation to ship a
  modified kernel tool.

## Honesty gates

- E1 PASS is valid only if the leaf is **provably absent** from every trusted keyring
  — capture `keyctl list` for each before `insmod`, or it's a false positive.
- On E1 FAIL, distinguish "kernel doesn't chain embedded certs for modules" from
  "AKI/matching gap" using Strand 2; capture the dmesg line and the leaf's AKI/SKID.
- Record kernel version, the `sign-file` patch diff, keyring states, and leaf serial.
  Results are scoped to this exact config.
