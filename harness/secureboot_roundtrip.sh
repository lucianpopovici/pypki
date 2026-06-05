#!/usr/bin/env bash
# secureboot_roundtrip.sh — Phase C: Secure Boot round-trip (OPTIONAL).
#
# Signs an EFI binary with the PyPKI leaf, enrolls the trust anchor via
# MOK, and validates that the UEFI firmware accepts / rejects binaries
# appropriately under Secure Boot enforcement.
#
# MANDATORY SAFETY NOTES:
#   - Run ONLY in an OVMF/UEFI VM. A bad Secure Boot enrollment can make
#     the VM unbootable.
#   - [SNAP] Snapshot the VM before running this script AND before rebooting.
#   - Do not run on a bare-metal machine you care about.
#
# Preconditions:
#   - issue_cert.sh has been run
#   - UEFI VM with Secure Boot enabled (OVMF firmware)
#   - sbsigntools installed: dnf install sbsigntools
#   - mokutil installed: dnf install mokutil
#   - shim present: dnf install shim  (for MokManager)
#
# Environment:
#   HARNESS_OUT     (default: /tmp/ima-evm-harness)
#   EFI_TARGET      EFI binary to sign (default: /boot/efi/EFI/BOOT/BOOTX64.EFI copy)

set -euo pipefail

OUT="${HARNESS_OUT:-/tmp/ima-evm-harness}"
GATE_FILE="$OUT/phase_c_results.txt"
EFI_TARGET="${EFI_TARGET:-}"

log()  { echo "[secureboot_roundtrip] $*"; }
warn() { echo "[secureboot_roundtrip] WARNING: $*" >&2; }

gate() {
    local g="$1" s="$2"; shift 2
    printf "[GATE %-2s] %-7s %s\n" "$g" "$s" "$*" | tee -a "$GATE_FILE"
}

# ── Preflight ─────────────────────────────────────────────────────────────────
[ "$EUID" -eq 0 ] || { echo "ERROR: must be root" >&2; exit 1; }
[ -f "$OUT/signing_key.pem" ]  || { log "ERROR: Run issue_cert.sh first."; exit 1; }
[ -f "$OUT/leaf.pem" ]         || { log "ERROR: Run issue_cert.sh first."; exit 1; }
[ -f "$OUT/wrong_key.pem" ]    || { log "ERROR: Run issue_cert.sh first."; exit 1; }

> "$GATE_FILE"

# Check Secure Boot status
SB_STATE=""
if command -v mokutil &>/dev/null; then
    SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "unknown")
    log "Secure Boot state: $SB_STATE"
fi
if [ -f /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c ]; then
    SB_BYTE=$(od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | tail -1 | tr -s ' ' | cut -d' ' -f2 || echo "?")
    log "SecureBoot EFI var last byte: $SB_BYTE (1=enabled)"
fi

for cmd in sbsign sbverify mokutil; do
    if ! command -v "$cmd" &>/dev/null; then
        gate C0 BLOCKED "$cmd not found — install sbsigntools (sbsign/sbverify) and mokutil"
        log "Install: dnf install sbsigntools mokutil  or  apt install sbsigntool mokutils"
        exit 2
    fi
done

# ── Find or prepare an EFI binary to sign ────────────────────────────────────
if [ -z "$EFI_TARGET" ]; then
    # Use a copy of the system's bootloader EFI (never modify the live one)
    for candidate in \
        /boot/efi/EFI/BOOT/BOOTX64.EFI \
        /boot/efi/EFI/fedora/shim.efi \
        /boot/efi/EFI/ubuntu/grubx64.efi; do
        if [ -f "$candidate" ]; then
            EFI_TARGET="$candidate"
            break
        fi
    done
fi

if [ -z "$EFI_TARGET" ] || [ ! -f "$EFI_TARGET" ]; then
    gate C0 BLOCKED "No EFI binary found. Set EFI_TARGET=/path/to/something.efi"
    log "Example: EFI_TARGET=/boot/efi/EFI/BOOT/BOOTX64.EFI ./secureboot_roundtrip.sh"
    exit 2
fi

log "EFI target: $EFI_TARGET"

# Work with copies — never modify the live EFI binary
cp "$EFI_TARGET" "$OUT/test_unsigned.efi"
log "  Unsigned copy: $OUT/test_unsigned.efi"

# ── Enroll trust anchor via MOK ───────────────────────────────────────────────
log ""
log "=== Step 1: Enroll PyPKI cert into MOK ==="

# Prefer issuing CA (chain.der), fall back to leaf
if [ -f "$OUT/chain.der" ] && [ -s "$OUT/chain.der" ]; then
    ENROLL_DER="$OUT/chain.der"
    ENROLL_PEM="$OUT/chain.pem"
    log "  Enrolling issuing CA cert (chain.der)"
else
    ENROLL_DER="$OUT/signing_cert.der"
    ENROLL_PEM="$OUT/leaf.pem"
    warn "chain.der not present; enrolling leaf cert directly."
fi

log "  Running: mokutil --import $ENROLL_DER"
log "  [SNAP] Snapshot now before continuing."
echo ""
read -rp "  Press Enter when ready to enroll (you will set a MOK password)..."
mokutil --import "$ENROLL_DER"
echo ""
log "  MOK staged. Reboot now and confirm in MokManager:"
log "    1. Press any key → Enroll MOK → Continue → Yes → enter password"
log "    2. After reboot, verify: mokutil --list-enrolled | grep -A4 PyPKI"
echo ""
read -rp "  Press Enter after confirming enrollment post-reboot to continue..."

# Verify enrollment
log "  Checking MOK enrollment..."
if mokutil --list-enrolled 2>/dev/null | grep -qi "pypki\|ima-evm-harness\|$(openssl x509 -in "$ENROLL_PEM" -noout -subject 2>/dev/null | cut -d= -f2- | head -c40)"; then
    log "  -> PyPKI cert found in MOK list."
else
    warn "PyPKI cert not clearly found in mokutil --list-enrolled."
    warn "Proceed with caution. Gate C1 will reveal if enrollment actually worked."
fi

# ── Sign EFI binaries ─────────────────────────────────────────────────────────
log ""
log "=== Step 2: Sign EFI binaries ==="

# Signed by PyPKI leaf (gate C1)
sbsign --key "$OUT/signing_key.pem" \
       --cert "$OUT/leaf.pem" \
       --output "$OUT/test_signed.efi" \
       "$OUT/test_unsigned.efi"
log "  PyPKI-signed:   $OUT/test_signed.efi"

# Verify signature locally
sbverify --cert "$OUT/leaf.pem" "$OUT/test_signed.efi" && \
    log "  sbverify: OK" || warn "  sbverify: FAILED (unusual; check key/cert match)"

# Signed by wrong key (gate C3)
sbsign --key "$OUT/wrong_key.pem" \
       --cert "$OUT/wrong_cert.pem" \
       --output "$OUT/test_wrongkey.efi" \
       "$OUT/test_unsigned.efi"
log "  Wrong-key signed: $OUT/test_wrongkey.efi"

# ── Gates C1–C3: instruction-based (require VM reboot + console observation) ──
log ""
log "=== Phase C gates (require VM reboot and console observation) ==="
log ""
log "Gates C1–C3 cannot be automated from within the running OS — they require"
log "booting the EFI binaries and observing firmware acceptance/rejection."
log "Follow the steps below and record results in RESULTS.md."
log ""
log "--- Gate C1: boot PyPKI-signed EFI binary ---"
log "  1. Copy $OUT/test_signed.efi to the EFI partition:"
log "       cp $OUT/test_signed.efi /boot/efi/EFI/test/test_c1.efi"
log "  2. Add a boot entry: efibootmgr --create --label 'C1-signed' --loader /EFI/test/test_c1.efi"
log "  3. Reboot into that entry."
log "  PASS criterion: firmware accepts the binary and it boots (or hands off to OS normally)."
log "  FAIL criterion: 'Security Violation' or similar firmware rejection."
log ""
log "--- Gate C2: boot unsigned EFI binary ---"
log "  1. Copy $OUT/test_unsigned.efi to /boot/efi/EFI/test/test_c2.efi"
log "  2. Add boot entry: efibootmgr --create --label 'C2-unsigned' --loader /EFI/test/test_c2.efi"
log "  3. Reboot into that entry."
log "  PASS criterion: firmware REFUSES with 'Security Violation'."
log ""
log "--- Gate C3: boot wrong-key signed EFI binary ---"
log "  1. Copy $OUT/test_wrongkey.efi to /boot/efi/EFI/test/test_c3.efi"
log "  2. Add boot entry: efibootmgr --create --label 'C3-wrongkey' --loader /EFI/test/test_c3.efi"
log "  3. Reboot into that entry."
log "  PASS criterion: firmware REFUSES (wrong-key cert not in db/MOK)."
log ""
log "Record results and firmware error messages in RESULTS.md."

gate C1 PENDING "Manual: boot test_signed.efi — expected: firmware accepts"
gate C2 PENDING "Manual: boot test_unsigned.efi — expected: Security Violation"
gate C3 PENDING "Manual: boot test_wrongkey.efi — expected: Security Violation"

echo ""
log "Phase C setup complete. EFI binaries ready in $OUT/."
log "See gate instructions above. Update RESULTS.md with observed firmware responses."
