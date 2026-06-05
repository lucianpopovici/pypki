# IMA/EVM Validation Blockers

---

## Open blockers

| Gate | Blocker description | Exact error | Workaround / resolution |
|------|--------------------|--------------------|------------------------|
| C1-C3 | Phase C not tested — requires Secure Boot + MOK enrollment | N/A | Not a current priority; F2-BUILTIN run covers all Phase A and B gates. |

---

## Resolved blockers

| Gate | Original blocker | Resolution | Date resolved |
|------|-----------------|------------|---------------|
| D1a | PyPKI HTTP 400 when issuing ML-DSA cert (profile required CSR) | Added `"subject": "CN=..."` parameter to API call; HTTP 201 accepted | 2026-06-04 |
| D1a | HTTP 201 treated as failure in mldsa_control.sh | Fixed `if [ "$HTTP_CODE" = "200" ]` → `200" ] \|\| [ "$HTTP_CODE" = "201" ]` | 2026-06-04 |
| D1a/b | ML-DSA cert was EC P-256 (profile fell back to EC when no CSR) | Called `CertificateAuthority.issue_ml_dsa_certificate()` directly with hand-generated ML-DSA-65 SPKI DER | 2026-06-04 |
| Phase B | `sign-file` not found (kernel-devel version mismatch: running 6.19, devel 7.0) | Installed matching `kernel-devel-6.19.10-300.fc44.x86_64` | 2026-06-04 |
| Phase B | `scripts/sign-file sha256` — wrong hash; kernel requires sha512 (`CONFIG_MODULE_SIG_SHA512=y`) | Changed all `sign-file sha256` calls to `sign-file sha512` in `modsig_roundtrip.sh` | 2026-06-04 |
| All phases | `issue_cert.sh` treated HTTP 201 as failure | Fixed check: accept 201 as success | 2026-06-04 |
| PyPKI bug | `audit.record()` keyword argument mismatch in `issue_ml_dsa_certificate()`, `issue_composite()`, `issue_slh_dsa()` — called with `requester_ip=requester_ip` but method signature uses positional `ip=` | Changed three calls to positional argument: `audit.record(..., requester_ip)` instead of `audit.record(..., requester_ip=requester_ip)` | 2026-06-04 |
| A1-A4 | Secure Boot lockdown prevented `ima_appraise=` + restricted `.ima` keyring blocked PyPKI cert enrollment | `ima: Secure boot enabled: ignoring ima_appraise=fix option`; `keyctl padd: EPERM` | **RESOLVED** by F2-BUILTIN kernel rebuild (2026-06-05): boot without UEFI/SecureBoot using direct `-kernel`/`-initrd`, `CONFIG_SYSTEM_TRUSTED_KEYS=certs/combined_trusted_keys.pem`. All A1-A4 gates now PASS. |
| B1 | PyPKI root not in kernel trusted keyring | `Loading of module with unavailable key is rejected` | **RESOLVED** by F2-BUILTIN kernel rebuild (2026-06-05): PyPKI root baked into `.builtin_trusted_keys`; leaf cert added to `.secondary_trusted_keys` via `keyctl padd`. B1 now PASS. |

---

## Environment notes

- **F2-BUILTIN approach** (2026-06-05): All blockers resolved. Key techniques:
  1. Boot with `-kernel bzImage -initrd initramfs.img -cmdline "...init=/bin/bash"` — bypasses UEFI entirely
  2. `CONFIG_SYSTEM_TRUSTED_KEYS="certs/combined_trusted_keys.pem"` containing both PyPKI root AND Fedora signing key — without Fedora's key, `module.sig_enforce=1` rejects initramfs modules
  3. `LOCALVERSION="-300.fc44.x86_64"` — must match existing module directory for initramfs to work
  4. `CONFIG_DEBUG_INFO_BTF=n` — disables pahole requirement that fails the build
  5. Leaf cert must be added to `.secondary_trusted_keys` (not just `.ima`) for module signing verification (`CMS_NOCERTS` means cert not embedded in PKCS#7)

- **Secure Boot lockdown was the prior run's blocker** (OVMF secboot firmware ignores `ima_appraise=` parameters). Resolved by F2-BUILTIN direct kernel boot.

- **Module signing chain for sign-file**: `sign-file` uses `CMS_NOCERTS` — the signing cert is NOT embedded in the PKCS#7 blob. The kernel looks up the signer by `IssuerAndSerialNumber` in its keyrings. The leaf cert must be in `.secondary_trusted_keys` (or `.builtin_trusted_keys`) for the lookup to succeed. Adding only to `.ima` keyring is insufficient for module verification.

- **IMA policy syntax**: Use `func=BPRM_CHECK` (not `func=FILE_EXEC`) for binary execution appraisal. `FILE_EXEC` is not a valid IMA policy function token in kernel 6.19.

- **PyPKI bug found and fixed**: `issue_ml_dsa_certificate()`, `issue_composite()`, and
  `issue_slh_dsa()` all passed `requester_ip=requester_ip` as a keyword argument to
  `AuditLog.record()`, but the method signature uses a positional parameter `ip`. These
  three functions were unusable via the admin API and any internal caller. Fixed in this
  run.
