# CLAUDE.md — IMA/EVM Round-Trip Validation Spec

## Purpose

Convert the static audit's conclusion into a **demonstrated** one. The audit
(`IMA_EVM_AUDIT_FINDINGS.md`) established from source that PyPKI's `code_signing`
profile emits a leaf with the right fields (`digitalSignature` KU, `codeSigning`
EKU, `subjectKeyIdentifier`). That proves *cert shape*. It does **not** prove a
kernel will appraise a file signed with such a cert. Those are different claims:
"right fields" ≠ "kernel accepts it." This spec proves the second one empirically,
end-to-end, through PyPKI's real issuance path.

Output is a runnable harness + a runbook + an evidence-backed results table, plus
one demo capture (a locked-down box refusing an unsigned binary) — the sellable
artifact.

## ⚠️ ENVIRONMENT — READ FIRST, NON-NEGOTIABLE

Every enforcing step in this spec can **permanently lock you out of a machine**
(can't exec binaries, can't load modules, won't boot). Therefore:

- Run **only** in a disposable VM. Never on the host, never on any machine you care
  about, never on the PyPKI server itself.
- **Snapshot before every step that enables enforcement.** The runbook marks each
  snapshot point `[SNAP]`. Roll back, don't repair.
- Secure Boot phase (C) needs an OVMF/UEFI VM; a bad enrollment can brick the VM's
  boot — snapshot is mandatory, not optional.

## Relationship to PyPKI scope

This harness lives **outside** the PyPKI repo. It exercises PyPKI only as a black-box
issuer via `POST /api/issue`. It adds **no pip dependencies** to PyPKI. Test-VM
tooling (`ima-evm-utils`, `keyutils`, `kmod`, `sbsigntools`, `openssl`) is system
packaged in the VM only and is never imported by any server-side module — same
boundary as `requirements-dev.txt`.

## Honesty / evidence gates (apply to every result)

- A gate is `PASS` **only** if the observed kernel response was captured: the
  command's exit code **and** the corresponding `dmesg` / `auditd` line. No assumed
  passes. "It should reject" is not a result; "`insmod` returned `EKEYREJECTED`,
  dmesg: `Loading of unsigned module …`" is.
- If the trust anchor cannot be enrolled (restricted keyring, locked policy), the
  phase is `BLOCKED` with the exact error — never silently skipped, never `N/A`.
- Record kernel version and the relevant `CONFIG_*` values for **every** run.
  Results are valid only for that config — kernel acceptance is config-dependent
  (same relying-party framing as the RFC 4158 work: behavior lives in the verifier).
- Record the PyPKI commit and the issued leaf's serial, so a result ties to an exact
  cert from an exact build.

## Shared prerequisite — issue the cert through the real path

Do this once; all phases consume its output.

1. Generate the signing keypair **locally in the VM** (key never leaves the
   endpoint — the IMA/EVM best practice the audit confirmed at `web_ui.py:3497`):
   `openssl ecparam -name prime256v1 -genkey -noout -out signing_key.pem`
2. Build a CSR and submit to PyPKI:
   `POST /api/issue` body `{"profile": "code_signing", "csr_pem": "<csr>"}`.
   - Success criterion: response leaf has `keyUsage=digitalSignature`,
     `extendedKeyUsage=codeSigning`, an SKID present. Verify with
     `openssl x509 -in leaf.pem -noout -text` before proceeding.
3. Convert leaf (and issuing chain) to DER — this is the audit's one real gap
   (`web_ui.py:3552` returns PEM only):
   `openssl x509 -in leaf.pem -outform DER -out signing_cert.der`
   `openssl x509 -in chain.pem -outform DER -out chain.der`
4. Prepare a **wrong-key** control: a second EC key + self-signed cert that does
   **not** chain to the PyPKI root. Used for the negative gates.
5. Prepare an **ML-DSA negative control**: issue a leaf with the ML-DSA path
   (`pki_server.py:1758` `ml_dsa_signing`, or `code_signing` + ML-DSA algorithm).
   Used for gate D.

## Trust-anchor enrollment (the config fork)

The PyPKI root/leaf must be trusted by the kernel subsystem under test. Two viable
setups — record which you used; results are scoped to it:

- **(F1) Permissive test kernel** — `.ima` keyring unrestricted
  (`CONFIG_INTEGRITY_TRUSTED_KEYRING` off): `keyctl padd asymmetric` the leaf cert
  directly. Fastest; good for the demo capture.
- **(F2) Realistic anchored kernel** — PyPKI **root** built in as a trusted key
  (`CONFIG_SYSTEM_TRUSTED_KEYS="pypki_root.pem"` for module-sig; `CONFIG_IMA_X509_PATH`
  or `.machine`/MOK for IMA). Any leaf chaining to it is trusted. This is the
  deterministic, reproducible gate and the one that mirrors production.

Recommendation: F2 for the canonical module-sig gate (Phase B), F1 acceptable for
the IMA demo capture (Phase A). State the choice in `RESULTS.md`.

---

## Phase A — IMA appraisal round-trip (best demo; moderate setup)

Most visceral artifact: kernel refuses to exec an unsigned binary. Validates the
SKID→keyid linkage (audit Q3) empirically.

Setup (VM, root, after `[SNAP]`):
- Confirm IMA present: `grep CONFIG_IMA /boot/config-$(uname -r)`;
  `ls /sys/kernel/security/ima/`.
- Enroll anchor per F1/F2; confirm: `keyctl list %keyring:.ima` shows the key, note
  its keyid.
- Sign a target endpoint-side:
  `cp /bin/true /opt/t; evmctl ima_sign --key signing_key.pem -a sha256 /opt/t`;
  confirm xattr: `getfattr -m - -d /opt/t` shows `security.ima`.
- Set appraisal policy + boot with `ima_appraise=enforce` (config-dependent; the
  runbook gives the grub edit + reboot). `ima_appraise=fix` first pass to label,
  then `enforce`.

Gates:

| Gate | Action | Required observation |
|------|--------|----------------------|
| A1 | exec the signed `/opt/t` under enforce | runs; no IMA denial in dmesg/audit |
| A2 | exec an **unsigned** copy | `EACCES`; dmesg/audit shows IMA appraisal failure |
| A3 | tamper a byte in `/opt/t`, exec | `EACCES`; appraisal failure (hash mismatch) |
| A4 | sign with **wrong-key**, load that cert's keyid, exec | rejected (key not trusted / not in `.ima` under F2) |

## Phase B — Kernel module signing (strictest profile check; canonical gate)

This is where the kernel's X.509 parser enforces `keyUsage`/EKU hardest — the best
empirical test that the `code_signing` profile (incl. the extra `contentCommitment`
bit, audit Q2) is actually accepted, not just well-formed.

Setup (VM with F2 anchored kernel: `CONFIG_MODULE_SIG=y`,
`CONFIG_SYSTEM_TRUSTED_KEYS="pypki_root.pem"`, boot `module.sig_enforce=1`, after
`[SNAP]`):
- Build a trivial out-of-tree module (`hello.ko`; Makefile in harness).
- Sign with the PyPKI leaf:
  `scripts/sign-file sha256 signing_key.pem signing_cert.der hello.ko`;
  confirm: `modinfo hello.ko | grep -i sig`.

Gates:

| Gate | Action | Required observation |
|------|--------|----------------------|
| B1 | `insmod hello.ko` (signed by PyPKI leaf) | success; module loaded; no rejection in dmesg |
| B2 | `insmod hello_unsigned.ko` | fail `EKEYREJECTED`; dmesg: loading of unsigned module rejected |
| B3 | `insmod` module signed by **wrong-key** | fail; dmesg: key not in trusted keyring |
| B4 | `insmod` tampered signed module | fail; signature verification failure |

If B1 fails, capture the exact dmesg reason — this is the single most informative
result in the whole spec (it would mean the emitted profile is rejected by the
strictest consumer, e.g. an unexpected keyUsage/EKU interaction).

## Phase C — Secure Boot (OPTIONAL; narrow audience, heaviest setup)

Only run if pursuing the appliance / locked-boot buyer. OVMF VM with Secure Boot on,
`[SNAP]` mandatory.

Setup:
- Enroll PyPKI leaf/root into MOK: `mokutil --import signing_cert.der` (reboot,
  confirm in MokManager).
- Sign an EFI binary (unified kernel image or test EFI):
  `sbsign --key signing_key.pem --cert signing_cert.pem --output signed.efi unsigned.efi`.

Gates:

| Gate | Action | Required observation |
|------|--------|----------------------|
| C1 | boot `signed.efi` | boots; firmware accepts |
| C2 | boot `unsigned.efi` | firmware refuses (Security Violation) |
| C3 | boot EFI signed by **wrong-key** | firmware refuses |

## Phase D — ML-DSA negative control (turns audit Q4 warning into a fact)

The audit *asserted* ML-DSA leaves are kernel-unusable. Demonstrate it.

| Gate | Action | Required observation |
|------|--------|----------------------|
| D1 | attempt `scripts/sign-file` (or `evmctl`) with the ML-DSA leaf | tool or kernel rejects (unsupported algorithm) — capture exact error |

A captured failure here converts "PQ is unusable for kernel signing today" from a
claim into evidence. If, surprisingly, it does *not* fail, that is a significant
finding — record it loudly.

---

## Deliverables

1. `harness/` — `issue_cert.sh` (CSR → PyPKI → DER), `enroll_anchor.sh`,
   `ima_roundtrip.sh`, `modsig_roundtrip.sh`, `secureboot_roundtrip.sh` (optional),
   `mldsa_control.sh`, plus `hello.c` + `Makefile` for the test module. Each script
   prints the observed exit code and the relevant dmesg/audit lines for every gate.
2. `RUNBOOK.md` — VM prep, required `CONFIG_*`, grub edits, the `[SNAP]` points in
   order, and the F1/F2 choice. Written so a cold operator can reproduce.
3. `RESULTS.md` — the gate tables above, each row filled with: observed exit code,
   captured dmesg/audit line, `PASS`/`FAIL`/`BLOCKED`. Header records kernel version,
   relevant config values, F1/F2 choice, PyPKI commit, leaf serial.
4. **Demo capture** — asciinema or screen recording of gate **A2** (unsigned binary
   refused under enforce). This is the artifact that sells the offering.
5. `BLOCKERS.md` — anything that prevented a gate from executing (e.g. anchor
   enrollment refused), with the exact error. Blocked ≠ failed ≠ passed.

## Verdict criterion

The validation **succeeds** iff: B1 PASS and B2/B3/B4 all PASS (module-sig
positive + all negatives), with kernel responses captured. Phase A strengthens the
demo; Phase C is bonus for the secure-boot buyer; Phase D confirms the PQ boundary.
A single captured negative-gate failure (e.g. an unsigned module loading under
enforce) invalidates the run — fix the environment, re-run, don't hand-wave.

## Non-goals (do not do in this pass)

- No changes to PyPKI source. (The DER-download convenience route is a separate,
  trivial follow-up — not required here; `openssl x509 -outform DER` covers it.)
- No building of the endpoint signing-helper product — that's the downstream
  offering, not this proof.
- No attempt at public trust (Microsoft UEFI / SmartScreen) — internal trust store
  only, by design.
- No multi-distro matrix — pin **one** kernel version + config, record it, prove it
  there. Breadth is a later concern.
