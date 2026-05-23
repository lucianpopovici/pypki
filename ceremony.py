#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
ceremony.py — §5.3 Offline root CA key ceremony tooling.

Subcommands (invoked via pypki_admin.py):

  export-root  [--ca-dir DIR] --out BUNDLE.tar.gz [--passphrase ENV_VAR]
               Package the offline root CA key + cert + counters into an
               AES-256-GCM encrypted tar.gz bundle.

  sign-csr     --in CSR.pem --bundle BUNDLE.tar.gz --out CERT.pem
               [--passphrase ENV_VAR] [--validity-days N] [--path-length N]
               [--permitted-dns DOMAIN ...] [--excluded-dns DOMAIN ...]
               Issue a sub-CA certificate from the offline root, writing
               the signed cert to CERT.pem.  Runs entirely from the bundle;
               no DB writes, no network.

  import-cert  [--ca-dir DIR] --in CERT.pem
               Import a previously-issued sub-CA cert back into an online
               intermediate CA directory (updates ca-chain.pem).

Shamir M-of-N secret sharing (GF(256)) is available for the bundle
passphrase.  Pass --threshold M --shares N to export-root to split the
passphrase into N shares; collect any M shares in sign-csr via --share
(repeatable, M times).

Bundle format (inside the .tar.gz, encrypted with AES-256-GCM + PBKDF2):
  root.key.pem   — CA private key (PKCS#8)
  root.crt.pem   — CA self-signed certificate
  last_serial    — last issued serial number (plain text integer)
  crl_number     — last CRL number (plain text integer)
  audit.log      — last N lines of the audit log (plain text)
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import io
import logging
import os
import secrets
import struct
import tarfile
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat,
)
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

logger = logging.getLogger("pypki.ceremony")

# ---------------------------------------------------------------------------
# Encryption helpers — AES-256-GCM + PBKDF2-SHA256
# ---------------------------------------------------------------------------

_SALT_LEN = 16
_NONCE_LEN = 12
_PBKDF2_ITER = 600_000


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITER,
    )
    return kdf.derive(passphrase)


def _encrypt(plaintext: bytes, passphrase: bytes) -> bytes:
    """Return salt‖nonce‖ciphertext (GCM tag appended by AESGCM)."""
    salt = secrets.token_bytes(_SALT_LEN)
    nonce = secrets.token_bytes(_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def _decrypt(blob: bytes, passphrase: bytes) -> bytes:
    salt, nonce = blob[:_SALT_LEN], blob[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
    ct = blob[_SALT_LEN + _NONCE_LEN:]
    key = _derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


# ---------------------------------------------------------------------------
# GF(256) Shamir Secret Sharing (M-of-N)
# ---------------------------------------------------------------------------
# Arithmetic in GF(2^8) with the AES irreducible polynomial x^8+x^4+x^3+x+1.
# Coefficients are random bytes; shares are (x, y) pairs where x ∈ [1..255].

_GF_POLY = 0x11B  # AES reducing polynomial


def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= _GF_POLY
        b >>= 1
    return result & 0xFF


def _gf_pow(base: int, exp: int) -> int:
    result = 1
    while exp:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


def _gf_inv(a: int) -> int:
    return _gf_pow(a, 254)  # Fermat: a^(256-2) = a^-1


def _shamir_split(secret: bytes, threshold: int, num_shares: int) -> List[Tuple[int, bytes]]:
    """Split *secret* into *num_shares* shares, any *threshold* of which reconstruct it."""
    if threshold < 2 or num_shares < threshold:
        raise ValueError("threshold must be ≥2 and ≤num_shares")
    if num_shares > 255:
        raise ValueError("num_shares ≤ 255")
    shares: List[Tuple[int, bytes]] = []
    for _ in range(num_shares):
        shares.append((0, b""))
    # Process each byte independently
    result: List[bytearray] = [bytearray() for _ in range(num_shares)]
    for byte in secret:
        # Random polynomial: f(0) = byte, degree = threshold-1
        coeffs = [byte] + [secrets.randbits(8) for _ in range(threshold - 1)]
        for i, x in enumerate(range(1, num_shares + 1)):
            y = 0
            for coeff in reversed(coeffs):
                y = _gf_mul(y, x) ^ coeff
            result[i].append(y)
    return [(x + 1, bytes(result[x])) for x in range(num_shares)]


def _shamir_reconstruct(shares: List[Tuple[int, bytes]]) -> bytes:
    """Reconstruct the secret from *shares* (any threshold subset)."""
    if not shares:
        raise ValueError("no shares provided")
    secret_len = len(shares[0][1])
    out = bytearray(secret_len)
    for i in range(secret_len):
        points = [(x, s[i]) for x, s in shares]
        # Lagrange interpolation at x=0
        val = 0
        for j, (xj, yj) in enumerate(points):
            num = yj
            den = 1
            for k, (xk, _) in enumerate(points):
                if k != j:
                    num = _gf_mul(num, xk)
                    den = _gf_mul(den, xj ^ xk)
            val ^= _gf_mul(num, _gf_inv(den))
        out[i] = val
    return bytes(out)


def encode_share(x: int, y: bytes) -> str:
    """Encode a share as a base64 string for display."""
    return base64.b64encode(bytes([x]) + y).decode()


def decode_share(s: str) -> Tuple[int, bytes]:
    raw = base64.b64decode(s.encode())
    return raw[0], raw[1:]


# ---------------------------------------------------------------------------
# Bundle I/O
# ---------------------------------------------------------------------------

def _build_bundle(
    ca_key_pem: bytes,
    ca_crt_pem: bytes,
    last_serial: int,
    crl_number: int,
    audit_tail: str,
    passphrase: bytes,
) -> bytes:
    """Build an in-memory encrypted tar.gz bundle."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def _add(name: str, data: bytes):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        _add("root.key.pem", ca_key_pem)
        _add("root.crt.pem", ca_crt_pem)
        _add("last_serial", str(last_serial).encode())
        _add("crl_number", str(crl_number).encode())
        _add("audit.log", audit_tail.encode())
    plaintext = buf.getvalue()
    return _encrypt(plaintext, passphrase)


def _open_bundle(blob: bytes, passphrase: bytes) -> dict:
    """Decrypt and parse a bundle; return a dict of its files."""
    plaintext = _decrypt(blob, passphrase)
    files: dict = {}
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as tf:
        for member in tf.getmembers():
            f = tf.extractfile(member)
            if f is not None:
                files[member.name] = f.read()
    return files


# ---------------------------------------------------------------------------
# Passphrase handling
# ---------------------------------------------------------------------------

def _read_passphrase(env_var: Optional[str], confirm: bool = False) -> bytes:
    if env_var and os.environ.get(env_var):
        return os.environ[env_var].encode()
    phrase = getpass.getpass("Bundle passphrase: ")
    if confirm:
        phrase2 = getpass.getpass("Confirm passphrase: ")
        if phrase != phrase2:
            raise ValueError("Passphrases do not match")
    return phrase.encode()


def _read_passphrase_from_shares(share_strs: List[str]) -> bytes:
    shares = [decode_share(s) for s in share_strs]
    return _shamir_reconstruct(shares)


# ---------------------------------------------------------------------------
# Sub-command: export-root
# ---------------------------------------------------------------------------

def cmd_export_root(args) -> int:
    ca_dir = Path(args.ca_dir)
    key_path = ca_dir / "ca.key"
    crt_path = ca_dir / "ca.crt"
    db_path  = ca_dir / "certificates.db"
    audit_path = ca_dir / "audit.db"

    if not key_path.exists():
        logger.error("CA key not found: %s", key_path)
        return 1
    if not crt_path.exists():
        logger.error("CA cert not found: %s", crt_path)
        return 1

    ca_key_pem = key_path.read_bytes()
    ca_crt_pem = crt_path.read_bytes()

    # Read counters from SQLite
    import sqlite3
    last_serial = 0
    crl_number = 0
    if db_path.exists():
        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT MAX(serial) FROM certificates").fetchone()
        if row and row[0]:
            last_serial = int(row[0])
        conn.close()
    crl_db = ca_dir / "crl_number.db"
    if crl_db.exists():
        conn = sqlite3.connect(str(crl_db))
        row = conn.execute("SELECT crl_number FROM crl_counter WHERE id=1").fetchone()
        if row:
            crl_number = int(row[0])
        conn.close()

    # Audit tail (last 200 lines)
    audit_tail = ""
    if audit_path.exists():
        try:
            import sqlite3 as _sq
            conn = _sq.connect(str(audit_path))
            rows = conn.execute(
                "SELECT ts, event, detail, ip FROM audit ORDER BY id DESC LIMIT 200"
            ).fetchall()
            conn.close()
            lines = [f"{r[0]} {r[1]} {r[2] or ''} {r[3] or ''}" for r in rows]
            audit_tail = "\n".join(reversed(lines))
        except Exception as exc:
            logger.warning("Could not read audit log: %s", exc)

    # Passphrase / Shamir
    threshold: int = getattr(args, "threshold", 0)
    num_shares: int = getattr(args, "shares", 0)
    share_lines: List[str] = []

    if threshold >= 2 and num_shares >= threshold:
        raw_passphrase = secrets.token_bytes(32)
        share_tuples = _shamir_split(raw_passphrase, threshold, num_shares)
        share_lines = [encode_share(x, y) for x, y in share_tuples]
        passphrase = raw_passphrase
        print(f"\nShamir {threshold}-of-{num_shares} shares (distribute securely):")
        for i, sh in enumerate(share_lines, 1):
            print(f"  Share {i}: {sh}")
        print()
    else:
        env_var = getattr(args, "passphrase_env", None)
        passphrase = _read_passphrase(env_var, confirm=True)

    blob = _build_bundle(ca_key_pem, ca_crt_pem, last_serial, crl_number, audit_tail, passphrase)
    out_path = Path(args.out)
    out_path.write_bytes(blob)
    logger.info("Bundle written to %s (%d bytes)", out_path, len(blob))
    print(f"Bundle: {out_path} ({len(blob)} bytes)")
    return 0


# ---------------------------------------------------------------------------
# Sub-command: sign-csr
# ---------------------------------------------------------------------------

def cmd_sign_csr(args) -> int:
    import datetime
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives.asymmetric import padding as _padding

    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        logger.error("Bundle not found: %s", bundle_path)
        return 1

    blob = bundle_path.read_bytes()

    # Passphrase
    share_strs: List[str] = getattr(args, "share", []) or []
    if share_strs:
        try:
            passphrase = _read_passphrase_from_shares(share_strs)
        except Exception as exc:
            logger.error("Share reconstruction failed: %s", exc)
            return 1
    else:
        env_var = getattr(args, "passphrase_env", None)
        passphrase = _read_passphrase(env_var, confirm=False)

    try:
        files = _open_bundle(blob, passphrase)
    except Exception as exc:
        logger.error("Could not decrypt bundle: %s", exc)
        return 1

    ca_key_pem = files["root.key.pem"]
    ca_crt_pem = files["root.crt.pem"]
    last_serial = int(files["last_serial"].decode().strip()) + 1

    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_crt_pem)

    csr_pem = Path(args.csr_in).read_bytes()
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        logger.error("CSR signature is invalid")
        return 1

    validity_days: int = getattr(args, "validity_days", 1825)
    path_length: Optional[int] = getattr(args, "path_length", None)
    permitted_dns: List[str] = getattr(args, "permitted_dns", []) or []
    excluded_dns: List[str] = getattr(args, "excluded_dns", []) or []

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(last_serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    if permitted_dns or excluded_dns:
        permitted = [x509.DNSName(d) for d in permitted_dns]
        excluded  = [x509.DNSName(d) for d in excluded_dns]
        builder = builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=permitted or None,
                excluded_subtrees=excluded or None,
            ),
            critical=True,
        )

    cert = _sign_builder(builder, ca_key)

    out_pem = cert.public_bytes(Encoding.PEM)
    Path(args.cert_out).write_bytes(out_pem)
    logger.info(
        "Signed sub-CA cert serial=%d subject=%s → %s",
        last_serial, csr.subject.rfc4514_string(), args.cert_out,
    )
    print(f"Signed: {args.cert_out} (serial {last_serial})")
    return 0


def _sign_builder(builder: x509.CertificateBuilder, key) -> x509.Certificate:
    """Sign a builder with the correct hash for the key type."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
    from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
    if isinstance(key, rsa.RSAPrivateKey):
        return builder.sign(key, SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        curve_hash = {
            ec.SECP256R1: SHA256, ec.SECP384R1: SHA384, ec.SECP521R1: SHA512,
        }
        h = next(
            (H for C, H in curve_hash.items() if isinstance(key.curve, C)), SHA256
        )
        return builder.sign(key, h())
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return builder.sign(key, None)
    raise TypeError(f"Unsupported key type: {type(key).__name__}")


# ---------------------------------------------------------------------------
# Sub-command: import-cert
# ---------------------------------------------------------------------------

def cmd_import_cert(args) -> int:
    ca_dir = Path(args.ca_dir)
    cert_pem = Path(args.cert_in).read_bytes()

    # Validate the cert is parseable
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as exc:
        logger.error("Could not parse certificate: %s", exc)
        return 1

    chain_path = ca_dir / "ca-chain.pem"
    if chain_path.exists():
        existing = chain_path.read_bytes()
        # Prepend the new cross-cert if not already present
        fp = cert.fingerprint(hashes.SHA256()).hex()
        if fp.encode() in existing or cert_pem in existing:
            logger.warning("Certificate already present in ca-chain.pem; skipping")
            print("Already present — no change.")
            return 0
        chain_path.write_bytes(cert_pem + b"\n" + existing)
    else:
        chain_path.write_bytes(cert_pem)

    logger.info(
        "Imported cert serial=%d subject=%s into %s",
        cert.serial_number, cert.subject.rfc4514_string(), chain_path,
    )
    print(f"Imported serial {cert.serial_number} into {chain_path}")
    return 0
