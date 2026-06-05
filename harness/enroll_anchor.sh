#!/usr/bin/env bash
# enroll_anchor.sh — Enroll the PyPKI trust anchor into the kernel keyring.
#
# Two modes (set ENROLL_MODE):
#
#   F1  — permissive test kernel (CONFIG_INTEGRITY_TRUSTED_KEYRING=off).
#          Uses keyctl to add the leaf cert directly to .ima/@u.
#          Fastest path; good for the Phase A demo capture.
#
#   F2-MOK  — realistic path via Machine Owner Key (MOK) store.
#              Uses mokutil to stage the PyPKI issuing-CA cert; a reboot
#              into MokManager confirms enrollment. After reboot, certs
#              signed by PyPKI chain to the MOK and are trusted.
#
#   F2-BUILTIN — documents the compile-time CONFIG_SYSTEM_TRUSTED_KEYS path
#                 (kernel rebuild required; most reproducible for Phase B).
#
# Environment:
#   ENROLL_MODE   F1 | F2-MOK | F2-BUILTIN  (default: F1)
#   HARNESS_OUT   output directory from issue_cert.sh (default: /tmp/ima-evm-harness)
#   PYPKI_URL     needed only for F2-BUILTIN root-cert download guidance

set -euo pipefail

OUT="${HARNESS_OUT:-/tmp/ima-evm-harness}"
MODE="${ENROLL_MODE:-F1}"
PYPKI_URL="${PYPKI_URL:-https://localhost:8443}"

log()  { echo "[enroll_anchor] $*"; }
warn() { echo "[enroll_anchor] WARNING: $*" >&2; }
die()  { echo "[enroll_anchor] ERROR: $*" >&2; exit 1; }

[ -f "$OUT/signing_cert.der" ] || die "$OUT/signing_cert.der not found. Run issue_cert.sh first."

# ── F1: keyctl padd to .ima keyring ──────────────────────────────────────────
enroll_f1() {
    log "Mode F1: enrolling leaf cert into .ima keyring via keyctl"
    log ""

    [ "$EUID" -eq 0 ] || die "F1 enrollment requires root."

    command -v keyctl &>/dev/null || die "keyctl not found. Install: dnf install keyutils"

    # Locate the .ima keyring. On kernels with CONFIG_IMA=y it exists as a
    # named keyring. Try the most common names.
    IMA_RING=""
    for name in ".ima" "_ima" "ima"; do
        if keyctl search @u keyring "$name" &>/dev/null; then
            IMA_RING=$(keyctl search @u keyring "$name")
            log "  Found .ima keyring by name '$name': id=$IMA_RING"
            break
        fi
    done

    if [ -z "$IMA_RING" ]; then
        # Fall back to the user keyring (@u) — works on permissive kernels
        warn ".ima named keyring not found; enrolling into user keyring (@u)."
        warn "On kernels with CONFIG_INTEGRITY_TRUSTED_KEYRING=y this will not"
        warn "satisfy the .ima trust constraint. Use F2-MOK or F2-BUILTIN instead."
        IMA_RING="@u"
    fi

    KEY_ID=$(keyctl padd asymmetric "pypki-ima-leaf" "$IMA_RING" < "$OUT/signing_cert.der" 2>&1) && {
        echo "$KEY_ID" > "$OUT/ima_key_id.txt"
        log "  -> Enrolled. Key ID: $KEY_ID"
        log "  Keyring contents:"
        keyctl list "$IMA_RING"
    } || {
        log "  keyctl padd returned: $KEY_ID"
        log ""
        log "  BLOCKED: Cannot enroll into .ima keyring."
        log "  This is expected when CONFIG_INTEGRITY_TRUSTED_KEYRING=y (the keyring"
        log "  is restricted; only keys that chain to a built-in root are accepted)."
        log "  Options:"
        log "    - Use a test kernel built with CONFIG_INTEGRITY_TRUSTED_KEYRING=n (F1 works)"
        log "    - Use F2-MOK or F2-BUILTIN to anchor the PyPKI root at boot/build time"
        exit 2
    }

    log ""
    log "F1 enrollment complete."
    log "Key ID saved to $OUT/ima_key_id.txt"
    log "Proceed with ima_roundtrip.sh"
}

# ── F2-MOK: mokutil enrollment (requires shim + Secure Boot) ─────────────────
enroll_f2_mok() {
    log "Mode F2-MOK: staging cert for MOK enrollment"
    log ""

    [ "$EUID" -eq 0 ] || die "MOK enrollment requires root."

    command -v mokutil &>/dev/null || die "mokutil not found. Install: dnf install mokutil"

    # Prefer to enroll the issuing CA (chain.der) so any leaf it signs is trusted.
    # Fall back to the leaf itself.
    if [ -f "$OUT/chain.der" ] && [ -s "$OUT/chain.der" ]; then
        ENROLL_DER="$OUT/chain.der"
        log "  Will enroll: issuing CA cert ($OUT/chain.der)"
    else
        ENROLL_DER="$OUT/signing_cert.der"
        warn "chain.der not found; enrolling leaf cert directly."
        warn "If PyPKI issued from an intermediate CA, you may need to also"
        warn "enroll the root. Export it: curl -k $PYPKI_URL/ca/cert.pem | openssl x509 -outform DER > $OUT/root.der"
        warn "Then re-run with ENROLL_DER=$OUT/root.der mokutil --import \$ENROLL_DER"
    fi

    log "  Running: mokutil --import $ENROLL_DER"
    log "  You will be prompted to set a MOK enrollment password."
    echo ""
    mokutil --import "$ENROLL_DER"
    echo ""
    log "  MOK enrollment staged."
    log ""
    log "  [SNAP] Snapshot the VM now before rebooting."
    log ""
    log "  Reboot, then at the MokManager screen:"
    log "    1. Press any key to enter MokManager"
    log "    2. Select 'Enroll MOK'"
    log "    3. Select 'Continue' → 'Yes' → enter the password you set above"
    log "    4. Reboot"
    log ""
    log "  After reboot, verify: mokutil --list-enrolled | grep -A4 'PyPKI\|ima-evm'"
    log "  Then proceed with phase scripts."
}

# ── F2-BUILTIN: documents the kernel rebuild path ────────────────────────────
enroll_f2_builtin() {
    log "Mode F2-BUILTIN: documentation for CONFIG_SYSTEM_TRUSTED_KEYS path"
    log ""
    log "This mode does not execute commands — it documents the kernel rebuild"
    log "required to embed the PyPKI root as a built-in trusted key."
    log ""
    log "Steps:"
    log "  1. Export the PyPKI root cert:"
    log "       curl -k $PYPKI_URL/ca/cert.pem > /path/to/kernel-src/pypki_root.pem"
    log ""
    log "  2. Set these in your kernel .config:"
    log "       CONFIG_SYSTEM_TRUSTED_KEYS=\"pypki_root.pem\""
    log "       CONFIG_MODULE_SIG=y"
    log "       CONFIG_MODULE_SIG_SHA256=y"
    log "       CONFIG_MODULE_SIG_ALL=n      (sign manually in the harness)"
    log "       CONFIG_MODULE_SIG_FORCE=n    (we set module.sig_enforce=1 at boot)"
    log "       CONFIG_SYSTEM_TRUSTED_KEYRING=y"
    log "       CONFIG_INTEGRITY_TRUSTED_KEYRING=y  (for IMA to chain to system keyring)"
    log "       CONFIG_IMA=y"
    log "       CONFIG_IMA_APPRAISE=y"
    log "       CONFIG_INTEGRITY_SIGNATURE=y"
    log "       CONFIG_INTEGRITY_ASYMMETRIC_KEYS=y"
    log "       CONFIG_ASYMMETRIC_KEY_TYPE=y"
    log "       CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y"
    log "       CONFIG_X509_CERTIFICATE_PARSER=y"
    log "       CONFIG_PKCS7_MESSAGE_PARSER=y"
    log ""
    log "  3. Build and install the kernel, then boot into it."
    log ""
    log "  4. Verify: keyctl list %keyring:.system_keyring"
    log "     The PyPKI root should appear."
    log ""
    log "  5. For IMA: verify the PyPKI root is in the trusted keyring:"
    log "     keyctl list %keyring:.ima"
    log ""
    log "  This is the canonical F2 setup used for Phase B's B1-B4 gates."
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "$MODE" in
    F1)          enroll_f1        ;;
    F2-MOK)      enroll_f2_mok    ;;
    F2-BUILTIN)  enroll_f2_builtin ;;
    *)
        echo "Usage: ENROLL_MODE=F1|F2-MOK|F2-BUILTIN ./enroll_anchor.sh"
        echo ""
        echo "  F1          — keyctl padd to .ima keyring (permissive kernel, fastest)"
        echo "  F2-MOK      — mokutil stage + reboot into MokManager (UEFI/SB required)"
        echo "  F2-BUILTIN  — prints kernel rebuild instructions (most reproducible)"
        exit 1 ;;
esac
