# CLAUDE.md — IMA/EVM Rerun (F2-BUILTIN, single config)

## Purpose

One kernel, one boot, **all of Phase A (IMA) and Phase B (module-sig) gates
meaningful** — closing the B1 trust-anchor gap and unblocking Phase A in a single
configuration. Supersedes the split F1/F2-MOK approach from the prior run.

## Why F2-BUILTIN, not F2-MOK

The prior run hit a structural conflict: Phase A needs **Secure Boot OFF** (lockdown
is what made the kernel ignore `ima_appraise=`), but F2-MOK enrollment runs through
**shim**, a Secure Boot construct — `.machine` only populates when SB/shim is active.
"SB off for A" and "MOK enroll for B" cannot both hold in one boot. F2-BUILTIN bakes
the PyPKI root into `.builtin_trusted_keys` at build time, which is **independent of
Secure Boot** — so SB stays off, lockdown stays inactive, `ima_appraise=enforce`
works, *and* module signatures chaining to the PyPKI root validate. One config does
both, for the cost of one kernel build.

## ⚠️ Disposable VM only. Snapshot before each `[SNAP]`. Roll back, don't repair.

## Kernel config deltas

Start from the running config (`/boot/config-$(uname -r)` of `6.19.10-300.fc44`).
Apply exactly these; leave everything else as-is:

| Symbol | From | To | Reason |
|--------|------|----|--------|
| `CONFIG_SYSTEM_TRUSTED_KEYS` | `""` | `"certs/pypki_root.pem"` | Puts PyPKI root in `.builtin_trusted_keys` → leaf-signed modules chain to it; leaf admissible to restricted `.ima`. |
| `CONFIG_IMA_WRITE_POLICY` | (confirm) | `y` | Allows runtime IMA policy load via securityfs (needed to scope appraisal to the test fs). |
| `CONFIG_MODULE_SIG_SHA512` | `y` | `y` (keep) | Matches the running kernel's required hash — `sign-file sha512`. |
| `CONFIG_INTEGRITY_TRUSTED_KEYRING` | `y` | `y` (keep) | Restricted `.ima`; now satisfiable because the root is builtin. |
| `CONFIG_IMA_APPRAISE_BOOTPARAM` | `y` | `y` (keep) | `ima_appraise=` honored (SB off). |
| `CONFIG_MODULE_SIG_FORCE` | not set | leave unset | We pass `module.sig_enforce=1` explicitly (see boot line) — SB-off means lockdown won't auto-set it. |

`certs/pypki_root.pem` = PEM of the PyPKI **root** CA cert (export from PyPKI, then
the audit's known PEM→DER/PEM handling applies). It must contain the root that signs
the `code_signing` leaves.

## Build (vanilla 6.19.10 + deltas; Fedora 44 host)

```
# matching upstream source avoids Fedora SRPM machinery for a test VM
curl -O https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.19.10.tar.xz   # adjust mirror as needed
tar xf linux-6.19.10.tar.xz && cd linux-6.19.10
cp /boot/config-$(uname -r) .config
# place the trust anchor where CONFIG_SYSTEM_TRUSTED_KEYS points
mkdir -p certs && cp /path/to/pypki_root.pem certs/pypki_root.pem
scripts/config --set-str SYSTEM_TRUSTED_KEYS "certs/pypki_root.pem"
scripts/config --enable IMA_WRITE_POLICY
make olddefconfig
make -j"$(nproc)" && sudo make modules_install && sudo make install
```
(Alternative: rebuild the Fedora kernel SRPM with the same `scripts/config` deltas —
heavier, not required for a test VM.)

## VM firmware + boot line

- Firmware: **OVMF without Secure Boot** (`OVMF_CODE.fd` + `OVMF_VARS.fd`), or disable
  Secure Boot in the VM firmware menu. Confirm post-boot: `mokutil --sb-state` →
  `SecureBoot disabled`.
- Boot line — enforcement must be **explicit** now (no lockdown to auto-enable it):
  ```
  module.sig_enforce=1 ima_appraise=enforce
  ```
  Do **not** add `ima_policy=` — leave the policy empty at boot so nothing is
  appraised until the surgical fsuuid rule is loaded (below). Empty policy + enforce
  = nothing breaks at boot.

## Verify-gates (MUST pass before any A/B result is trusted)

These check the version-dependent keyring linkage we agreed not to assume.

| VG | Check | Expected | If it fails |
|----|-------|----------|-------------|
| VG1 | `keyctl list %:.builtin_trusted_keys` | PyPKI root present (by its CN/SKID) | `SYSTEM_TRUSTED_KEYS` PEM malformed or not picked up — rebuild |
| VG2 | `keyctl padd asymmetric "" %keyring:.ima < signing_leaf.der` | exit 0, key added | If `EPERM`: on 6.19 the restricted `.ima` rejected a leaf signed by a builtin-trusted root — capture and investigate before claiming Phase A is possible |
| VG3 | `insmod` of a PyPKI-leaf-signed module (= gate B1) | loads | If `unavailable key`: kernel isn't chaining leaf→builtin-root for modules in this config — capture dmesg, this is a real finding, not a setup nit |

VG2/VG3 are the empirical answers to the two linkage questions; record them as
findings regardless of outcome.

## Phase B — module signing (primary criterion) `[SNAP]`

```
scripts/sign-file sha512 signing_leaf_key.pem signing_leaf.der hello.ko
modinfo hello.ko | grep -i sig        # confirm PKCS#7 / sha512 / signer
```

| Gate | Action | Required observation (capture exit code + dmesg) |
|------|--------|---------------------------------------------------|
| B1 | `insmod hello.ko` (PyPKI-leaf signed) | **loads** (was FAIL last run) — no rejection in dmesg |
| B2 | `insmod hello_unsigned.ko` | fail; `Loading of unsigned module is rejected` |
| B3 | `insmod hello_wrongkey.ko` | fail; `unavailable key` (signer not chaining to builtin root) |
| B4 | `insmod hello_tampered.ko` | fail; `Key was rejected by service` |

B2/B3/B4 already passed under real enforcement last run; the rerun must reproduce
them **and** flip B1 to load.

## Phase A — IMA appraisal, surgically scoped `[SNAP]`

Scope appraisal to a dedicated loopback fs by `fsuuid` so enforcement cannot brick
the VM. Only that filesystem is appraised; the rest of the system is untouched.

```
# dedicated appraised filesystem
dd if=/dev/zero of=/imatest.img bs=1M count=64
mkfs.ext4 /imatest.img
UUID=$(blkid -s UUID -o value /imatest.img)
mkdir -p /mnt/imatest && mount -o loop /imatest.img /mnt/imatest

# admit the signing leaf to .ima (relies on VG2 passing)
keyctl padd asymmetric "" %keyring:.ima < signing_leaf.der

# populate + sign the "good" binary endpoint-side
cp /bin/true /mnt/imatest/good
evmctl ima_sign --key signing_leaf_key.pem -a sha256 /mnt/imatest/good
cp /bin/true /mnt/imatest/unsigned                 # no signature
cp /mnt/imatest/good /mnt/imatest/tampered && printf '\x90' | dd of=/mnt/imatest/tampered bs=1 seek=64 conv=notrunc
# wrong-key: sign with the non-chaining control key
evmctl ima_sign --key wrongkey.pem -a sha256 /mnt/imatest/wrongkey_signed 2>/dev/null || cp /bin/true /mnt/imatest/wrongkey_signed

# load the SCOPED policy LAST — appraises only this fs, enforce already on
echo "appraise fsuuid=${UUID} func=BPRM_CHECK appraise_type=imasig" > /sys/kernel/security/ima/policy
```

| Gate | Action | Required observation |
|------|--------|----------------------|
| A1 | exec `/mnt/imatest/good` | runs (exit 0); no IMA denial |
| A2 | exec `/mnt/imatest/unsigned` | `EACCES`; dmesg `ima: ... appraisal` denial |
| A3 | exec `/mnt/imatest/tampered` | `EACCES` (hash mismatch) — **not** a segfault; confirm the dmesg appraisal line, since last run's A3 "pass" was a corrupted-ELF false positive |
| A4 | exec `/mnt/imatest/wrongkey_signed` | `EACCES` (key not in `.ima`) |

Note A3 specifically: a meaningful pass is an *appraisal denial* in dmesg before
exec, not the process crashing. Capture the dmesg line.

## Success criterion

Full pass = VG1–VG3 green, **B1 loads** with B2/B3/B4 still rejecting, and A1–A4 all
showing the required kernel response (A2/A3/A4 denied via captured dmesg appraisal
lines). That is the demonstrated end-to-end: PyPKI-issued cert → endpoint signature →
kernel accepts the signed artifact and refuses unsigned/tampered/wrong-key.

## Honesty gates

- A gate is PASS only with exit code **and** dmesg/audit line captured. No assumed
  passes; A3 in particular must be an appraisal denial, not a crash.
- VG2/VG3 outcomes are findings either way — if 6.19's restricted `.ima` won't admit
  a builtin-root-signed leaf, or module verification won't chain leaf→builtin-root,
  record it as a result and stop; do not paper over it.
- Record kernel version, the applied config deltas, `mokutil --sb-state`, PyPKI
  commit, and leaf serial in `RESULTS.md`. Results are scoped to this exact config.

## Non-goals
- No F2-MOK and no Phase C in this pass (SB stays off). Secure Boot is a separate
  config + run if the appliance buyer is pursued.
- No PyPKI source changes here (the DER-download convenience route remains optional).
- No multi-distro matrix — this one pinned config, proven.
