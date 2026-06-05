"""
modsig_enroll.py — Kernel module signing and IMA/EVM enrollment tooling.

Two module-signing trust models (controlled by ModsigSigner.embed_cert):

  embed_cert=False  — per-leaf (default, stock sign-file behavior):
      PKCS#7 carries no embedded cert; kernel looks up the signer by
      IssuerAndSerial directly in the trusted keyring. Leaf cert must be
      enrolled on every host that loads the module.

  embed_cert=True   — per-CA:
      Signer cert is embedded in the PKCS#7. kernel's pkcs7_validate_trust_one
      walks leaf→root via AKI, accepting the module with only the CA root
      trusted. Source basis: linux/crypto/asymmetric_keys/pkcs7_trust.c,
      anchor pkcs7_validate_trust. Empirically confirmed on 6.19.10
      (MODSIG_TRUST_FINDINGS.md, gate E1).

IMA appraisal is always per-leaf — IMA sig v2 embeds the signing key's SKID;
the kernel matches it against a key present in .ima. See IMAEnroller.

Signing uses 'openssl cms' subprocess; no new pip dependencies.
"""

from __future__ import annotations

import base64
import dataclasses
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

# Appended verbatim by the kernel's module loader to verify the trailer
MODULE_SIG_STRING = b"~Module signature appended~\n"

# PKEY_ID_PKCS7 = 2 (kernel include/linux/module_signature.h)
_PKEY_ID_PKCS7 = 2


# ── Data types ────────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class SignedModule:
    path: Path
    sig_len: int
    embed_cert: bool
    hash_algo: str


@dataclasses.dataclass(frozen=True)
class EnrollmentRecipe:
    """All artifacts needed to enroll a cert into kernel keyrings."""
    mode: str                       # "ca", "leaf", or "ima-leaf"
    cert_der: bytes                 # the DER cert to enroll
    cert_filename: str              # suggested filename for the DER cert
    keyctl_volatile: str            # keyctl command for runtime (volatile) enrollment
    mokutil_cmd: Optional[str]      # mokutil command for MOK persistent enrollment
    dracut_hook_sh: str             # shell script for dracut pre-udev hook
    dracut_conf: str                # /etc/dracut.conf.d fragment
    summary: str


# ── Core helpers ──────────────────────────────────────────────────────────────

def _strip_module_sig(data: bytes) -> bytes:
    """Remove an existing module signature trailer from module bytes, if present."""
    if not data.endswith(MODULE_SIG_STRING):
        return data
    body = data[: -len(MODULE_SIG_STRING)]
    if len(body) < 12:
        return data
    sig_struct = body[-12:]
    signer_len  = sig_struct[3]
    key_id_len  = sig_struct[4]
    sig_len     = struct.unpack(">I", sig_struct[8:12])[0]
    total_tail  = signer_len + key_id_len + sig_len + 12
    if total_tail > len(body):
        return data
    return body[:-total_tail]


def _assemble_module_sig(module_body: bytes, pkcs7: bytes) -> bytes:
    """Append PKCS#7 + struct module_signature + MODULE_SIG_STRING to module body.

    struct module_signature layout (12 bytes, big-endian sig_len):
      u8  algo       = 0
      u8  hash       = 0
      u8  id_type    = PKEY_ID_PKCS7 (2)
      u8  signer_len = 0
      u8  key_id_len = 0
      u8  pad[3]     = 0,0,0
      be32 sig_len   = len(pkcs7)
    """
    sig_struct = bytes([0, 0, _PKEY_ID_PKCS7, 0, 0, 0, 0, 0]) + struct.pack(">I", len(pkcs7))
    return module_body + pkcs7 + sig_struct + MODULE_SIG_STRING


def _count_embedded_certs(pkcs7_der: bytes) -> int:
    """Return the number of X.509 certificates embedded in a DER PKCS#7 blob."""
    result = subprocess.run(
        ["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-noout"],
        input=pkcs7_der,
        capture_output=True,
    )
    return result.stdout.count(b"subject=")


def extract_module_pkcs7(module_path: str | Path) -> bytes:
    """Extract the raw PKCS#7 DER blob from a signed .ko file."""
    data = Path(module_path).read_bytes()
    if not data.endswith(MODULE_SIG_STRING):
        raise ValueError(f"{module_path}: no module signature trailer")
    body = data[: -len(MODULE_SIG_STRING)]
    if len(body) < 12:
        raise ValueError(f"{module_path}: trailer too short")
    sig_struct  = body[-12:]
    signer_len  = sig_struct[3]
    key_id_len  = sig_struct[4]
    sig_len     = struct.unpack(">I", sig_struct[8:12])[0]
    pkcs7_start = len(body) - (signer_len + key_id_len + sig_len + 12)
    return body[pkcs7_start : pkcs7_start + sig_len]


# ── Module signer ─────────────────────────────────────────────────────────────

class ModsigSigner:
    """Signs kernel modules using openssl cms.

    embed_cert=False  — per-leaf: -nocerts passed; cert NOT in PKCS#7.
    embed_cert=True   — per-CA:  cert embedded; kernel chains via AKI.
    """

    def __init__(
        self,
        key_path: str | Path,
        cert_path: str | Path,
        hash_algo: str = "sha512",
        embed_cert: bool = False,
    ) -> None:
        self.key_path  = Path(key_path)
        self.cert_path = Path(cert_path)
        self.hash_algo = hash_algo
        self.embed_cert = embed_cert

    def sign(
        self,
        module_path: str | Path,
        output_path: Optional[str | Path] = None,
    ) -> SignedModule:
        """Sign a kernel module. Returns SignedModule describing the result.

        If output_path is None or the same as module_path, the file is signed
        in-place. Otherwise it is copied to output_path first.
        """
        module_path = Path(module_path)
        output_path = Path(output_path) if output_path else module_path
        if output_path != module_path:
            shutil.copy2(module_path, output_path)

        module_body = _strip_module_sig(output_path.read_bytes())

        with tempfile.TemporaryDirectory() as td:
            body_file = Path(td) / "body.bin"
            sig_file  = Path(td) / "sig.der"
            body_file.write_bytes(module_body)

            cmd = [
                "openssl", "cms", "-sign",
                "-binary", "-nosmimecap",
                "-md", self.hash_algo,
                "-signer", str(self.cert_path),
                "-inkey", str(self.key_path),
                "-in", str(body_file),
                "-outform", "DER",
                "-out", str(sig_file),
            ]
            if not self.embed_cert:
                cmd.append("-nocerts")

            proc = subprocess.run(cmd, capture_output=True)
            if proc.returncode != 0:
                raise RuntimeError(
                    f"openssl cms -sign failed:\n{proc.stderr.decode()}"
                )

            pkcs7 = sig_file.read_bytes()

        output_path.write_bytes(_assemble_module_sig(module_body, pkcs7))
        return SignedModule(
            path=output_path,
            sig_len=len(pkcs7),
            embed_cert=self.embed_cert,
            hash_algo=self.hash_algo,
        )


# ── Enrollment helpers ────────────────────────────────────────────────────────

def _make_dracut_hook(cert_der: bytes, target_keyring: str, label: str) -> str:
    """Generate a dracut pre-udev hook script that enrolls cert_der at boot."""
    b64 = base64.b64encode(cert_der).decode()
    return f"""\
#!/bin/sh
# pypki enrollment hook — generated by pypki_admin
# target keyring: {target_keyring}
if command -v keyctl >/dev/null 2>&1; then
    printf '%s' '{b64}' | base64 -d | \\
        keyctl padd asymmetric '{label}' '%:{target_keyring}' >/dev/null 2>&1 && \\
        echo "pypki: enrolled '{label}' into {target_keyring}" || \\
        echo "pypki: enrollment of '{label}' into {target_keyring} failed (keyring restricted?)"
else
    echo "pypki: keyctl not found, skipping enrollment"
fi
"""


def _make_dracut_conf(hook_name: str, cert_filename: str) -> str:
    return (
        f'install_items+=" /etc/pypki/enrollment/{cert_filename} "\n'
        f'install_items+=" /usr/lib/dracut/hooks/pre-udev/{hook_name} "\n'
    )


# ── EnrollmentRecipe generators ───────────────────────────────────────────────

class ModsigEnroller:
    """Generates enrollment recipes for kernel module signing.

    ca_cert_der: DER of the PyPKI root CA (always required).
    leaf_cert_der: DER of the signing leaf (required for leaf mode).
    """

    def __init__(
        self,
        ca_cert_der: bytes,
        leaf_cert_der: Optional[bytes] = None,
    ) -> None:
        self.ca_cert_der   = ca_cert_der
        self.leaf_cert_der = leaf_cert_der

    def recipe(self, mode: str = "leaf") -> EnrollmentRecipe:
        """Return an EnrollmentRecipe for the given trust mode.

        mode='leaf' — enroll the signing leaf into .secondary_trusted_keys.
        mode='ca'   — enroll the CA root into .secondary_trusted_keys.
        """
        if mode not in ("ca", "leaf"):
            raise ValueError(f"mode must be 'ca' or 'leaf', got {mode!r}")

        if mode == "ca":
            cert_der      = self.ca_cert_der
            cert_filename = "pypki_root_ca.der"
            label         = "pypki-modsig-root"
            keyctl = (
                f"keyctl padd asymmetric '{label}' "
                f"%:.secondary_trusted_keys < {cert_filename}"
            )
            mokutil = f"mokutil --import {cert_filename}"
            summary = (
                "Per-CA mode: enroll the PyPKI root CA cert once per machine. "
                "Any code_signing leaf the CA issues can load modules without "
                "per-host leaf re-enrollment. "
                "Blast radius: any current or future leaf from this CA. "
                "Requires modules signed with embed_cert=True (cert in PKCS#7)."
            )
        else:
            if self.leaf_cert_der is None:
                raise ValueError("leaf_cert_der required for mode='leaf'")
            cert_der      = self.leaf_cert_der
            cert_filename = "pypki_signing_leaf.der"
            label         = "pypki-modsig-leaf"
            keyctl = (
                f"keyctl padd asymmetric '{label}' "
                f"%:.secondary_trusted_keys < {cert_filename}"
            )
            mokutil = f"mokutil --import {cert_filename}"
            summary = (
                "Per-leaf mode: enroll the exact signing leaf on each machine. "
                "Stock sign-file behavior (no cert embedded). "
                "Blast radius: only the enrolled leaf. "
                "Cert rotation requires re-enrollment on every host."
            )

        hook_name   = f"99-pypki-modsig-{mode}.sh"
        hook_sh     = _make_dracut_hook(cert_der, ".secondary_trusted_keys", label)
        dracut_conf = _make_dracut_conf(hook_name, cert_filename)

        return EnrollmentRecipe(
            mode=mode,
            cert_der=cert_der,
            cert_filename=cert_filename,
            keyctl_volatile=keyctl,
            mokutil_cmd=mokutil,
            dracut_hook_sh=hook_sh,
            dracut_conf=dracut_conf,
            summary=summary,
        )


class IMAEnroller:
    """Generates enrollment recipes for IMA appraisal (always per-leaf).

    IMA sig v2 embeds the signing key's SKID. The kernel matches it against a
    key present in the .ima restricted keyring. The CA root governs admissibility
    to .ima (adds leaf only if it chains to a builtin root); the leaf is the
    actual appraisal key. There is no chain appraisal in IMA.
    """

    def __init__(self, leaf_cert_der: bytes) -> None:
        self.leaf_cert_der = leaf_cert_der

    def recipe(self) -> EnrollmentRecipe:
        cert_filename = "pypki_ima_leaf.der"
        label         = "pypki-ima-leaf"
        keyctl = (
            f"keyctl padd asymmetric '{label}' %:.ima < {cert_filename}"
        )
        hook_name   = "99-pypki-ima.sh"
        hook_sh     = _make_dracut_hook(self.leaf_cert_der, ".ima", label)
        dracut_conf = _make_dracut_conf(hook_name, cert_filename)

        return EnrollmentRecipe(
            mode="ima-leaf",
            cert_der=self.leaf_cert_der,
            cert_filename=cert_filename,
            keyctl_volatile=keyctl,
            mokutil_cmd=None,
            dracut_hook_sh=hook_sh,
            dracut_conf=dracut_conf,
            summary=(
                "IMA enrollment is always per-leaf. "
                "The signing cert SKID must be present in the .ima keyring; "
                "the CA root governs admissibility (leaf addable only if it chains to a "
                "builtin-trusted root). "
                "Cert rotation requires re-enrollment and re-signing of all labelled files."
            ),
        )


def install_recipe(
    recipe: EnrollmentRecipe,
    dest_dir: str | Path = "/etc/pypki/enrollment",
    dracut_conf_dir: str | Path = "/etc/dracut.conf.d",
    dracut_hooks_dir: str | Path = "/usr/lib/dracut/hooks/pre-udev",
) -> None:
    """Write enrollment artifacts to the filesystem (requires root)."""
    import os

    dest_dir        = Path(dest_dir)
    dracut_conf_dir = Path(dracut_conf_dir)
    dracut_hooks_dir = Path(dracut_hooks_dir)

    dest_dir.mkdir(parents=True, exist_ok=True)
    dracut_conf_dir.mkdir(parents=True, exist_ok=True)
    dracut_hooks_dir.mkdir(parents=True, exist_ok=True)

    cert_path = dest_dir / recipe.cert_filename
    cert_path.write_bytes(recipe.cert_der)
    cert_path.chmod(0o644)

    conf_name = f"pypki-{recipe.mode}.conf"
    conf_path = dracut_conf_dir / conf_name
    conf_path.write_text(recipe.dracut_conf)
    conf_path.chmod(0o644)

    hook_name = f"99-pypki-{recipe.mode}.sh"
    hook_path = dracut_hooks_dir / hook_name
    hook_path.write_text(recipe.dracut_hook_sh)
    hook_path.chmod(0o755)
