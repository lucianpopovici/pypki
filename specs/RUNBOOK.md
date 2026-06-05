# IMA/EVM Validation Runbook

Operator guide for running the `harness/` scripts against a disposable VM.
Read in full before touching a kernel enforcement flag.

---

## 0. Safety

**Never run enforcement steps on a machine you care about.**
A wrong IMA policy or a failed Secure Boot enrollment can make a machine
unbootable. The three rules:

1. **Disposable VM only.** KVM/QEMU recommended. libvirt snapshots or
   `virsh snapshot-create-as` for all `[SNAP]` points.
2. **Snapshot before every enforcement step.** Roll back, don't repair.
3. **Phase C (Secure Boot) needs OVMF/UEFI firmware.** Bad MOK enrollment
   can brick the VM's boot. Snapshot is not optional there.

---

## 1. VM requirements

| Item | Minimum | Notes |
|------|---------|-------|
| OS | Fedora 40+ or Ubuntu 24.04 | Both ship IMA-capable kernels |
| RAM | 2 GB | 4 GB recommended for kernel builds |
| Disk | 20 GB | 40 GB if building kernel from source |
| Firmware | BIOS (Phase A/B), OVMF/UEFI (Phase C) | Phase C mandates UEFI |
| Network | Reachable to PyPKI host | For `issue_cert.sh` |

Fedora package list (covers all phases):

```
dnf install -y \
    ima-evm-utils \
    keyutils \
    attr \
    openssl \
    python3 \
    kernel-devel \
    kmod \
    sbsigntools \
    mokutil \
    shim \
    curl
```

Ubuntu equivalent:

```
apt install -y \
    ima-evm-utils \
    keyutils \
    attr \
    openssl \
    python3 \
    linux-headers-$(uname -r) \
    kmod \
    sbsigntool \
    mokutils \
    shim-signed \
    curl
```

---

## 2. Required kernel CONFIG_* values

Check your running kernel: `grep CONFIG_IMA /boot/config-$(uname -r)`

### Phase A — IMA appraisal

```
CONFIG_IMA=y
CONFIG_IMA_APPRAISE=y
CONFIG_INTEGRITY_SIGNATURE=y
CONFIG_INTEGRITY_ASYMMETRIC_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
```

F1 mode (quick demo):
```
CONFIG_INTEGRITY_TRUSTED_KEYRING=n   # keyring is open; keyctl padd works
```

F2 mode (realistic):
```
CONFIG_INTEGRITY_TRUSTED_KEYRING=y
CONFIG_IMA_X509_PATH="/etc/keys/pypki_root.pem"  # or via CONFIG_SYSTEM_TRUSTED_KEYS
```

### Phase B — Kernel module signing (canonical gate)

```
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_MODULE_SIG_ALL=n           # sign manually in the harness
CONFIG_MODULE_SIG_FORCE=n         # enforce via module.sig_enforce=1 at boot
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS="pypki_root.pem"   # embed PyPKI root at build time
```

> For F2-BUILTIN: copy the PyPKI root PEM into the kernel source tree, then
> set `CONFIG_SYSTEM_TRUSTED_KEYS="pypki_root.pem"` (relative to source root).
> Rebuild and install the kernel.

### Phase C — Secure Boot

```
CONFIG_EFI_STUB=y
CONFIG_SHIM_LOCK=y
```
Plus all Phase B configs. Secure Boot enforcement is handled by UEFI firmware
(OVMF), not kernel config — the kernel just needs to be bootable via shim.

---

## 3. Trust anchor — F1 vs F2

| | F1 (permissive) | F2-MOK | F2-BUILTIN |
|--|---|---|---|
| Kernel rebuild required | No | No | **Yes** |
| Reboot to enroll | No | **Yes** | **Yes** |
| Reproducibility | Good for demo | Good for IMA | Best for module-sig |
| Phase A | Recommended | Works | Works |
| Phase B | Marginal | Works | **Canonical** |
| Phase C | N/A | **Canonical** | N/A |

Run `ENROLL_MODE=F1 harness/enroll_anchor.sh` or `ENROLL_MODE=F2-MOK ...`.

---

## 4. Grub edits

### Enable IMA enforcement (Phase A, pass 2)

```
# Temporary (single boot): press 'e' in grub, find the linux line, append:
ima_appraise=enforce

# Permanent:
echo 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX ima_appraise=enforce"' \
    >> /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg   # Fedora
update-grub                               # Ubuntu
```

For the labelling pass (before enforcement):

```
# Append instead:
ima_appraise=fix
```

### Enable module signature enforcement (Phase B)

```
# Append to kernel cmdline:
module.sig_enforce=1
```

---

## 5. SNAP points (in execution order)

| # | When | Action |
|---|------|--------|
| SNAP-0 | Fresh VM, before any harness steps | Baseline snapshot |
| SNAP-1 | After `issue_cert.sh` completes | Cert artifacts saved |
| SNAP-2 | After `enroll_anchor.sh` F1 | Before IMA labelling |
| SNAP-3 | After `ima_roundtrip.sh --label` | Before rebooting to enforce |
| SNAP-4 | After `enroll_anchor.sh` F2-MOK | Before MOK reboot |
| SNAP-5 | After MOK reboot confirmed | Before Phase B/C |
| SNAP-6 | **Before `module.sig_enforce=1` boot** | Last safe rollback for Phase B |
| SNAP-7 | **Before any Secure Boot EFI boot** | Phase C; brick risk |

Take a snapshot: `virsh snapshot-create-as <domain> snap-<N> "description"`

---

## 6. Step-by-step execution

### Prerequisite: PyPKI running

Ensure PyPKI is reachable from the VM:
```
export PYPKI_URL=https://<pypki-host>:8443
curl -k $PYPKI_URL/api/health
```

If PyPKI requires authentication:
```
export PYPKI_TOKEN=<bearer-token>
```

---

### Phase A — IMA appraisal

```
# SNAP-0
export HARNESS_OUT=/tmp/ima-evm-harness

# Issue cert
bash harness/issue_cert.sh

# SNAP-1

# Enroll trust anchor (F1 for quick demo)
ENROLL_MODE=F1 bash harness/enroll_anchor.sh

# SNAP-2

# Label pass (sign test binaries)
# Boot with: ima_appraise=fix  (or run without enforcement for labelling)
bash harness/ima_roundtrip.sh --label

# SNAP-3

# Reboot with ima_appraise=enforce  (see §4)

# Gate pass — run after reboot
bash harness/ima_roundtrip.sh
# Results: /tmp/ima-evm-harness/phase_a_results.txt
```

---

### Phase B — Kernel module signing

```
# Ensure trust anchor is F2-BUILTIN or F2-MOK (PyPKI root in system keyring)
# Reboot with module.sig_enforce=1  (see §4)

# SNAP-6

export HARNESS_OUT=/tmp/ima-evm-harness
bash harness/modsig_roundtrip.sh
# Results: /tmp/ima-evm-harness/phase_b_results.txt

# B1 PASS is the primary criterion.
```

---

### Phase C — Secure Boot (OPTIONAL)

```
# UEFI VM with Secure Boot enabled (OVMF)
# SNAP-7

export HARNESS_OUT=/tmp/ima-evm-harness
bash harness/secureboot_roundtrip.sh
# Follow interactive prompts; observe firmware responses at each reboot.
# Record C1/C2/C3 in RESULTS.md manually.
```

---

### Phase D — ML-DSA negative control

```
export HARNESS_OUT=/tmp/ima-evm-harness
bash harness/mldsa_control.sh
# Results: /tmp/ima-evm-harness/phase_d_results.txt
# Runs any time; does not require enforcement mode.
```

---

## 7. Recording results

After each phase, fill in `RESULTS.md`:

1. Copy the gate output from `phase_<x>_results.txt`.
2. Fill in the kernel version and config header.
3. Record the PyPKI commit and leaf serial from `$HARNESS_OUT/leaf_serial.txt`.
4. Record any blockers in `BLOCKERS.md`.

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `keyctl padd` fails with `EKEYREJECTED` | `CONFIG_INTEGRITY_TRUSTED_KEYRING=y` — restricted | Use F2 mode or permissive kernel |
| A2 gate FAIL (unsigned binary loads) | IMA not in enforce mode | Boot with `ima_appraise=enforce` |
| B1 gate FAIL with `EKEYREJECTED` | PyPKI root not in system keyring | Rebuild kernel with `CONFIG_SYSTEM_TRUSTED_KEYS` |
| B1 gate FAIL with `EBADMSG` | Bad signature format or key/cert mismatch | Verify `sign-file` used correct key+cert pair |
| `insmod` fails with "not a valid module" | Module built for wrong kernel | Rebuild hello.ko: `make -C /lib/modules/$(uname -r)/build M=$PWD` |
| `evmctl` command not found | `ima-evm-utils` not installed | `dnf install ima-evm-utils` |
| `security.ima` xattr not set | Filesystem doesn't support xattrs | Remount with `user_xattr` or use ext4/xfs |
| `sign-file` not found | `kernel-devel` not installed | `dnf install kernel-devel` |
| Phase C: MokManager not appearing | shim not in boot chain | `dnf install shim; grub2-install` with shim |
