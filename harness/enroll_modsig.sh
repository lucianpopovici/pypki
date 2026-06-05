#!/usr/bin/env bash
# enroll_modsig.sh — Enroll module-signing trust anchors into kernel keyrings.
#
# Handles both module-signing trust models established by MODSIG_TRUST_FINDINGS.md:
#
#   TRUST_MODE=leaf (default)
#       Enroll the signing LEAF cert into .secondary_trusted_keys.
#       Use stock sign-file / modsig-sign --mode leaf to sign modules.
#       Narrower blast radius; cert rotation requires re-enrollment per host.
#
#   TRUST_MODE=ca
#       Enroll the PyPKI ROOT CA cert into .secondary_trusted_keys.
#       Modules must be signed with embedded cert (modsig-sign --mode ca).
#       Broader blast radius; one-time enrollment per machine.
#
# IMA is always per-leaf — use enroll_anchor.sh (ENROLL_MODE=F1/F2-MOK/F2-BUILTIN)
# for IMA .ima keyring enrollment; this script covers module signing only.
#
# Enrollment methods (ENROLL_METHOD):
#   keyctl    — volatile runtime enrollment (cleared on reboot)
#   mok       — persistent via mokutil (UEFI/Secure Boot; requires reboot)
#   dracut    — persistent via initramfs hook (survives reboots, no MOK needed)
#   show      — print commands without executing (default for non-root)
#
# Environment:
#   TRUST_MODE       leaf | ca             (default: leaf)
#   ENROLL_METHOD    keyctl | mok | dracut | show  (default: keyctl if root, else show)
#   HARNESS_OUT      directory from issue_cert.sh  (default: /tmp/ima-evm-harness)
#   PYPKI_URL        PyPKI server URL for CA cert download (default: https://localhost:8443)

set -euo pipefail

TRUST_MODE="${TRUST_MODE:-leaf}"
HARNESS_OUT="${HARNESS_OUT:-/tmp/ima-evm-harness}"
PYPKI_URL="${PYPKI_URL:-https://localhost:8443}"

if [ -z "${ENROLL_METHOD:-}" ]; then
    [ "$EUID" -eq 0 ] && ENROLL_METHOD="keyctl" || ENROLL_METHOD="show"
fi

log()  { echo "[enroll_modsig] $*"; }
warn() { echo "[enroll_modsig] WARNING: $*" >&2; }
die()  { echo "[enroll_modsig] ERROR: $*" >&2; exit 1; }

# ── Validate inputs ───────────────────────────────────────────────────────────
case "$TRUST_MODE" in
    leaf|ca) ;;
    *) die "TRUST_MODE must be 'leaf' or 'ca', got '$TRUST_MODE'" ;;
esac

case "$ENROLL_METHOD" in
    keyctl|mok|dracut|show) ;;
    *) die "ENROLL_METHOD must be keyctl|mok|dracut|show, got '$ENROLL_METHOD'" ;;
esac

log "Trust mode  : $TRUST_MODE"
log "Method      : $ENROLL_METHOD"
log ""

# ── Resolve the cert to enroll ────────────────────────────────────────────────
if [ "$TRUST_MODE" = "ca" ]; then
    # Enroll the CA root cert
    CA_CERT_DER="$HARNESS_OUT/ca_root.der"
    ENROLL_LABEL="pypki-modsig-root"
    ENROLL_KEYRING="%:.secondary_trusted_keys"

    if [ ! -f "$CA_CERT_DER" ]; then
        log "CA root DER not found at $CA_CERT_DER"
        log "Fetching from $PYPKI_URL/ca/cert.pem ..."
        curl -sk "$PYPKI_URL/ca/cert.pem" \
            | openssl x509 -outform DER -out "$CA_CERT_DER"
        log "  -> $CA_CERT_DER"
    fi
    ENROLL_DER="$CA_CERT_DER"
    SUBJECT=$(openssl x509 -inform DER -in "$ENROLL_DER" -noout -subject 2>/dev/null | sed 's/subject=//')
    log "Cert to enroll (CA root): $SUBJECT"
else
    # Enroll the signing leaf cert
    [ -f "$HARNESS_OUT/signing_cert.der" ] \
        || die "$HARNESS_OUT/signing_cert.der not found. Run issue_cert.sh first."
    ENROLL_DER="$HARNESS_OUT/signing_cert.der"
    ENROLL_LABEL="pypki-modsig-leaf"
    ENROLL_KEYRING="%:.secondary_trusted_keys"
    SUBJECT=$(openssl x509 -inform DER -in "$ENROLL_DER" -noout -subject 2>/dev/null | sed 's/subject=//')
    log "Cert to enroll (leaf): $SUBJECT"
fi

log ""

# ── Show mode — print without executing ──────────────────────────────────────
do_show() {
    echo ""
    echo "  # ── Volatile (keyctl) ──────────────────────────────────────────"
    echo "  keyctl padd asymmetric '$ENROLL_LABEL' $ENROLL_KEYRING < $ENROLL_DER"
    echo ""
    echo "  # ── Persistent via MOK (UEFI/Secure Boot) ─────────────────────"
    echo "  mokutil --import $ENROLL_DER"
    echo "  # Then reboot and confirm enrollment in MokManager"
    echo ""
    echo "  # ── Persistent via dracut initramfs hook ───────────────────────"
    echo "  # Run ENROLL_METHOD=dracut to generate and install the hook, then:"
    echo "  dracut --force"
    echo ""
    echo "  # ── Verify after enrollment ────────────────────────────────────"
    echo "  keyctl list $ENROLL_KEYRING"
    echo ""
    if [ "$TRUST_MODE" = "ca" ]; then
        echo "  # Sign modules with embedded cert for per-CA trust:"
        echo "  pypki_admin modsig-sign mymodule.ko --key signing_key.pem --cert signing_cert.pem --mode ca"
    else
        echo "  # Sign modules with stock (no cert) format:"
        echo "  pypki_admin modsig-sign mymodule.ko --key signing_key.pem --cert signing_cert.pem --mode leaf"
        echo "  # Or use the kernel's sign-file directly:"
        echo "  scripts/sign-file sha512 signing_key.pem signing_cert.der mymodule.ko"
    fi
}

# ── keyctl — volatile runtime enrollment ─────────────────────────────────────
do_keyctl() {
    [ "$EUID" -eq 0 ] || die "keyctl enrollment requires root."
    command -v keyctl &>/dev/null || die "keyctl not found. Install: dnf install keyutils"

    log "Enrolling $ENROLL_LABEL into $ENROLL_KEYRING ..."
    KEY_ID=$(keyctl padd asymmetric "$ENROLL_LABEL" "$ENROLL_KEYRING" < "$ENROLL_DER" 2>&1)
    RC=$?
    if [ $RC -ne 0 ]; then
        log "keyctl padd failed (exit $RC): $KEY_ID"
        log ""
        log "If the keyring is restricted (CONFIG_SECONDARY_TRUSTED_KEYRING + chain check),"
        log "the cert must chain to a key already in .builtin_trusted_keys or .secondary_trusted_keys."
        if [ "$TRUST_MODE" = "ca" ]; then
            log "For per-CA mode: the PyPKI root must be in the builtin trusted keys"
            log "(CONFIG_SYSTEM_TRUSTED_KEYS at build time) or the MOK keyring."
        else
            log "For per-leaf mode: the signing leaf must chain to a trusted root."
            log "If the PyPKI root is enrolled, the leaf should be accepted."
        fi
        exit 1
    fi

    log "  -> Enrolled. Key ID: $KEY_ID"
    echo "$KEY_ID" > "$HARNESS_OUT/${TRUST_MODE}_modsig_key_id.txt"
    log ""
    log "Current $ENROLL_KEYRING contents:"
    keyctl list "$ENROLL_KEYRING"
}

# ── mok — persistent via UEFI MokManager ─────────────────────────────────────
do_mok() {
    [ "$EUID" -eq 0 ] || die "MOK enrollment requires root."
    command -v mokutil &>/dev/null || die "mokutil not found. Install: dnf install mokutil"

    log "Staging $ENROLL_LABEL for MOK enrollment ..."
    echo ""
    mokutil --import "$ENROLL_DER"
    echo ""
    log "Staged."
    log ""
    log "  [SNAP] Snapshot the VM now before rebooting."
    log ""
    log "  Reboot, then at the MokManager screen:"
    log "    1. Press any key when prompted"
    log "    2. Select 'Enroll MOK' → 'Continue' → 'Yes'"
    log "    3. Enter the password you just set"
    log "    4. Reboot"
    log ""
    log "  After reboot, verify:"
    log "    mokutil --list-enrolled | grep -A4 PyPKI"
    log "    keyctl list $ENROLL_KEYRING"
}

# ── dracut — persistent initramfs hook ───────────────────────────────────────
do_dracut() {
    [ "$EUID" -eq 0 ] || die "dracut install requires root."

    HOOK_DIR="/usr/lib/dracut/hooks/pre-udev"
    CONF_DIR="/etc/dracut.conf.d"
    CERT_DIR="/etc/pypki/enrollment"
    HOOK_NAME="99-pypki-modsig-${TRUST_MODE}.sh"
    CONF_NAME="pypki-modsig-${TRUST_MODE}.conf"

    mkdir -p "$HOOK_DIR" "$CONF_DIR" "$CERT_DIR"

    # Install the DER cert
    install -m 0644 "$ENROLL_DER" "$CERT_DIR/$(basename "$ENROLL_DER")"
    log "  Installed cert: $CERT_DIR/$(basename "$ENROLL_DER")"

    # Generate the hook script (embeds cert as base64)
    B64=$(base64 -w0 "$ENROLL_DER")
    cat > "$HOOK_DIR/$HOOK_NAME" << HOOKEOF
#!/bin/sh
# pypki modsig enrollment hook — TRUST_MODE=$TRUST_MODE
# Generated by enroll_modsig.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
if command -v keyctl >/dev/null 2>&1; then
    printf '%s' '$B64' | base64 -d | \\
        keyctl padd asymmetric '$ENROLL_LABEL' '$ENROLL_KEYRING' >/dev/null 2>&1 && \\
        echo "pypki: enrolled '$ENROLL_LABEL' into $ENROLL_KEYRING" || \\
        echo "pypki: enrollment of '$ENROLL_LABEL' failed (keyring restricted or cert already present)"
else
    echo "pypki: keyctl not found — skipping modsig enrollment"
fi
HOOKEOF
    chmod 755 "$HOOK_DIR/$HOOK_NAME"
    log "  Installed hook: $HOOK_DIR/$HOOK_NAME"

    # Generate dracut conf to include both in initramfs
    cat > "$CONF_DIR/$CONF_NAME" << CONFEOF
# pypki module-signing enrollment — TRUST_MODE=$TRUST_MODE
install_items+=" $CERT_DIR/$(basename "$ENROLL_DER") "
install_items+=" $HOOK_DIR/$HOOK_NAME "
CONFEOF
    log "  Installed conf: $CONF_DIR/$CONF_NAME"

    echo ""
    log "Dracut artifacts installed. Rebuild the initramfs:"
    log "  dracut --force"
    log ""
    log "The hook will run at next boot before udev and enroll the cert."
    log "Verify after reboot: keyctl list $ENROLL_KEYRING"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "$ENROLL_METHOD" in
    show)    do_show   ;;
    keyctl)  do_keyctl ;;
    mok)     do_mok    ;;
    dracut)  do_dracut ;;
esac

echo ""
log "=== enroll_modsig.sh complete ==="
if [ "$ENROLL_METHOD" != "show" ] && [ "$ENROLL_METHOD" != "mok" ]; then
    log ""
    log "Next: sign modules and test loading:"
    if [ "$TRUST_MODE" = "ca" ]; then
        log "  Sign:  pypki_admin modsig-sign hello.ko --key key.pem --cert cert.pem --mode ca"
        log "  Test:  insmod hello.ko  (leaf NOT enrolled; only root enrolled)"
    else
        log "  Sign:  pypki_admin modsig-sign hello.ko --key key.pem --cert cert.pem --mode leaf"
        log "  Test:  insmod hello.ko"
    fi
fi
