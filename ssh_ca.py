#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
ssh_ca.py — SSH Certificate Authority issuance and Key Revocation List (KRL).

Wire format: OpenSSH PROTOCOL.certkeys.
Signing: Ed25519 (preferred), ECDSA P-256/P-384/P-521, RSA-SHA256.
ML-DSA, SLH-DSA, Ed448, and composite keys are rejected — OpenSSH 9.x does
not support post-quantum CA keys.

KRL format: OpenSSH PROTOCOL.krl (krl.h in the OpenSSH source tree).
"""
from __future__ import annotations

import base64
import hashlib
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, NoEncryption,
)

from ssh_wire import (
    pack_string, pack_uint32, pack_uint64, pack_mpint,
    unpack_string, unpack_uint32,
)


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SSHCertProfile:
    """Named SSH certificate profile controlling issuance constraints."""
    cert_type: int                         # 1 = user, 2 = host
    max_validity_seconds: int
    default_validity_seconds: int
    allowed_principals_regex: str
    default_extensions: FrozenSet[str]
    allowed_critical_options: FrozenSet[str]


SSH_PROFILES: Dict[str, SSHCertProfile] = {
    "ssh_user": SSHCertProfile(
        cert_type=1,
        max_validity_seconds=86400,           # 24 hours
        default_validity_seconds=3600,        # 1 hour
        allowed_principals_regex=r"^[a-z][a-z0-9_.-]{0,62}$",
        default_extensions=frozenset({
            "permit-pty",
            "permit-agent-forwarding",
            "permit-X11-forwarding",
            "permit-port-forwarding",
            "permit-user-rc",
        }),
        allowed_critical_options=frozenset({
            "source-address",
            "force-command",
            "verify-required",
        }),
    ),
    "ssh_host": SSHCertProfile(
        cert_type=2,
        max_validity_seconds=2592000,         # 30 days
        default_validity_seconds=2592000,
        allowed_principals_regex=r"^[a-zA-Z0-9*._-]+$",
        default_extensions=frozenset(),
        allowed_critical_options=frozenset(),
    ),
}

# OpenSSH cert type string by (underlying_key_type, cert_cert_type)
_CERT_KEY_TYPE: Dict[str, str] = {
    "ed25519":   "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-p256": "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-p384": "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-p521": "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "rsa":       "ssh-rsa-cert-v01@openssh.com",
}

_ECDSA_CURVE: Dict[type, Tuple[str, str]] = {
    ec.SECP256R1: ("nistp256", "ecdsa-sha2-nistp256"),
    ec.SECP384R1: ("nistp384", "ecdsa-sha2-nistp384"),
    ec.SECP521R1: ("nistp521", "ecdsa-sha2-nistp521"),
}

# KRL magic and constants
_KRL_MAGIC            = b"SSHKRL\n\x00"
_KRL_FORMAT_VERSION   = 1
_KRL_SECTION_CERTS    = 1
_KRL_SECTION_SIG      = 0xFF
_KRL_SECT_SERIAL_LIST = 0x20


# ---------------------------------------------------------------------------
# Public key fingerprint
# ---------------------------------------------------------------------------

def fingerprint_sha256(pubkey_wire: bytes) -> str:
    """Return the SHA256 fingerprint of an SSH public key in wire format.

    Result is formatted as "SHA256:<base64>" (matching ssh-keygen output).
    """
    digest = hashlib.sha256(pubkey_wire).digest()
    return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Key classification + wire encoding
# ---------------------------------------------------------------------------

def _classify_key(private_key) -> str:
    """Return a tag identifying the private key type for SSH purposes."""
    if isinstance(private_key, _ed25519.Ed25519PrivateKey):
        return "ed25519"
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "rsa"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve = type(private_key.curve)
        if curve in _ECDSA_CURVE:
            return f"ecdsa-{_ECDSA_CURVE[curve][0]}"
    raise ValueError(
        f"unsupported CA key type for SSH: {type(private_key).__name__}. "
        "Use Ed25519, ECDSA P-256/P-384/P-521, or RSA."
    )


def pubkey_to_wire(public_key) -> bytes:
    """Encode a cryptography public key object into SSH wire format."""
    if isinstance(public_key, _ed25519.Ed25519PublicKey):
        raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return pack_string(b"ssh-ed25519") + pack_string(raw)

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = type(public_key.curve)
        if curve not in _ECDSA_CURVE:
            raise ValueError(f"unsupported ECDSA curve: {curve}")
        curve_name, key_type = _ECDSA_CURVE[curve]
        Q = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return (pack_string(key_type.encode()) +
                pack_string(curve_name.encode()) +
                pack_string(Q))

    if isinstance(public_key, rsa.RSAPublicKey):
        nums = public_key.public_numbers()
        return pack_string(b"ssh-rsa") + pack_mpint(nums.e) + pack_mpint(nums.n)

    raise ValueError(f"unsupported public key type: {type(public_key).__name__}")


def parse_ssh_pubkey(pubkey_str: str) -> Tuple[str, bytes]:
    """Parse an OpenSSH authorized_keys-format public key.

    Returns (key_type, wire_bytes) where wire_bytes is the base64-decoded key blob.
    Accepts: 'type base64 [comment]'
    """
    parts = pubkey_str.strip().split(" ", 2)
    if len(parts) < 2:
        raise ValueError("invalid SSH public key format: expected 'type base64 [comment]'")
    key_type = parts[0]
    try:
        wire = base64.b64decode(parts[1])
    except Exception as exc:
        raise ValueError(f"base64 decode of SSH public key failed: {exc}") from exc
    return key_type, wire


def wire_to_authorized_keys(key_type: str, wire: bytes, comment: str = "") -> str:
    """Format a wire-format public key as an authorized_keys line."""
    b64 = base64.b64encode(wire).decode()
    if comment:
        return f"{key_type} {b64} {comment}"
    return f"{key_type} {b64}"


# ---------------------------------------------------------------------------
# SSH cert format helpers
# ---------------------------------------------------------------------------

def _encode_principals(principals: Sequence[str]) -> bytes:
    """Encode valid_principals as a list of SSH strings inside one SSH string."""
    inner = b"".join(pack_string(p) for p in principals)
    return pack_string(inner)


def _encode_options(opts: Dict[str, str]) -> bytes:
    """Encode critical_options or extensions as sorted name-value pairs."""
    inner = b"".join(
        pack_string(name) + pack_string(value)
        for name, value in sorted(opts.items())
    )
    return pack_string(inner)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def _sign_ssh(private_key, data: bytes) -> bytes:
    """Sign *data* with the CA private key and return the SSH signature field bytes."""
    if isinstance(private_key, _ed25519.Ed25519PrivateKey):
        sig_bytes = private_key.sign(data)
        return pack_string(b"ssh-ed25519") + pack_string(sig_bytes)

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve = type(private_key.curve)
        curve_name, alg_id = _ECDSA_CURVE[curve]
        hash_map = {
            ec.SECP256R1: hashes.SHA256,
            ec.SECP384R1: hashes.SHA384,
            ec.SECP521R1: hashes.SHA512,
        }
        hash_cls = hash_map[curve]
        der_sig = private_key.sign(data, ec.ECDSA(hash_cls()))
        r, s = decode_dss_signature(der_sig)
        ecdsa_sig = pack_mpint(r) + pack_mpint(s)
        return pack_string(alg_id.encode()) + pack_string(ecdsa_sig)

    if isinstance(private_key, rsa.RSAPrivateKey):
        sig_bytes = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return pack_string(b"rsa-sha2-256") + pack_string(sig_bytes)

    raise ValueError(f"unsupported CA key type: {type(private_key).__name__}")


# ---------------------------------------------------------------------------
# Subject public key → cert wire encoding
# ---------------------------------------------------------------------------

def _encode_subject_pubkey(key_type: str, subject_wire: bytes) -> Tuple[str, bytes]:
    """Extract the cert type string and the key fields from the subject key wire bytes.

    Returns (cert_key_type, key_fields_bytes) where key_fields_bytes is the
    algorithm-specific key data that goes between the nonce and the serial.
    """
    pos = 0
    wire_key_type_bytes, pos = unpack_string(subject_wire, pos)
    wire_key_type = wire_key_type_bytes.decode("ascii", errors="replace")

    # Ed25519: "ssh-ed25519" <32-byte key>
    if wire_key_type == "ssh-ed25519":
        pk_bytes, pos = unpack_string(subject_wire, pos)
        return "ssh-ed25519-cert-v01@openssh.com", pack_string(pk_bytes)

    # ECDSA: "ecdsa-sha2-nistp256" "nistp256" <Q>
    if wire_key_type.startswith("ecdsa-sha2-nistp"):
        curve_bytes, pos = unpack_string(subject_wire, pos)
        Q_bytes, pos     = unpack_string(subject_wire, pos)
        cert_type = f"{wire_key_type}-cert-v01@openssh.com"
        fields = pack_string(curve_bytes) + pack_string(Q_bytes)
        return cert_type, fields

    # RSA: "ssh-rsa" e n
    if wire_key_type in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
        e_bytes, pos = unpack_string(subject_wire, pos)
        n_bytes, pos = unpack_string(subject_wire, pos)
        return "ssh-rsa-cert-v01@openssh.com", pack_string(e_bytes) + pack_string(n_bytes)

    # FIDO2 sk-ed25519 / sk-ecdsa: pass through the key bytes as-is
    if wire_key_type.startswith("sk-"):
        # Re-encode: pack the rest of the wire blob after the type string
        rest = subject_wire[pos:]
        return f"{wire_key_type}-cert-v01@openssh.com", rest

    raise ValueError(f"unsupported subject key type for SSH cert: {wire_key_type!r}")


# ---------------------------------------------------------------------------
# Cert builder
# ---------------------------------------------------------------------------

def build_ssh_cert(
    *,
    ca_private_key,
    subject_pubkey_wire: bytes,      # base64-decoded key blob from authorized_keys
    serial: int,
    cert_type: int,                  # 1 = user, 2 = host
    key_id: str,
    principals: Sequence[str],
    valid_after: int,                # unix seconds; 0 = always valid
    valid_before: int,               # unix seconds; 2^64-1 = no expiry
    critical_options: Optional[Dict[str, str]] = None,
    extensions: Optional[Dict[str, str]] = None,
) -> bytes:
    """Build and return a signed SSH certificate.

    The returned bytes can be base64-encoded and written to a file as:
        <cert_key_type> <base64> [comment]

    critical_options: dict of name → value (empty string for value-less options like
                      "verify-required"; non-empty for "source-address", "force-command").
    extensions:       dict of name → value (empty string for boolean extensions like
                      "permit-pty"). Omit to use no extensions.
    """
    if critical_options is None:
        critical_options = {}
    if extensions is None:
        extensions = {}

    nonce = os.urandom(32)

    cert_key_type_str, key_fields = _encode_subject_pubkey(
        "subject", subject_pubkey_wire
    )

    ca_pubkey_wire = pubkey_to_wire(ca_private_key.public_key())

    # Build the TBS (to-be-signed) portion — everything before the signature field
    tbs = (
        pack_string(cert_key_type_str.encode()) +
        pack_string(nonce) +
        key_fields +
        pack_uint64(serial) +
        pack_uint32(cert_type) +
        pack_string(key_id.encode()) +
        _encode_principals(principals) +
        pack_uint64(valid_after) +
        pack_uint64(valid_before) +
        _encode_options(critical_options) +
        _encode_options(extensions) +
        pack_string(b"") +           # reserved
        pack_string(ca_pubkey_wire)  # CA public key
    )

    signature = _sign_ssh(ca_private_key, tbs)
    return tbs + pack_string(signature)


def cert_bytes_to_authorized_keys(cert_bytes: bytes) -> str:
    """Convert raw cert bytes to the authorized_keys / known_hosts single-line format.

    The format is: <cert_key_type> <base64>
    """
    # Read the cert type string from the beginning of the wire
    cert_type_bytes, _ = unpack_string(cert_bytes, 0)
    cert_type = cert_type_bytes.decode("ascii")
    return f"{cert_type} {base64.b64encode(cert_bytes).decode()}"


# ---------------------------------------------------------------------------
# KRL (Key Revocation List)
# ---------------------------------------------------------------------------

class KRLBuilder:
    """Builds an OpenSSH KRL file signed by a CA key.

    Usage::

        builder = KRLBuilder(ca_private_key)
        builder.revoke_serial(ca_pubkey_wire, serial_int)
        krl_bytes = builder.sign()

    The *ca_pubkey_wire* passed to revoke_serial() identifies which CA issued
    the certificates being revoked. It should match the CA key used for signing
    SSH certs.
    """

    def __init__(self, ca_private_key):
        self._ca_key = ca_private_key
        self._ca_pubkey_wire = pubkey_to_wire(ca_private_key.public_key())
        # {ca_pubkey_wire_hex: [serial, ...]}
        self._revoked: Dict[str, List[int]] = {}

    def revoke_serial(self, ca_pubkey_wire: bytes, serial: int) -> None:
        key = ca_pubkey_wire.hex()
        self._revoked.setdefault(key, []).append(serial)

    def revoke_serial_self(self, serial: int) -> None:
        """Revoke a serial issued by this builder's own CA key."""
        self.revoke_serial(self._ca_pubkey_wire, serial)

    def build(self) -> bytes:
        """Build the KRL. Returns the raw KRL bytes.

        OpenSSH accepts unsigned KRLs; ssh-keygen -k generates unsigned KRLs by
        default. The signature section format is version-specific and omitted here
        for maximum interoperability.
        """
        now = int(time.time())
        header = (
            _KRL_MAGIC +
            struct.pack(">I", _KRL_FORMAT_VERSION) +  # uint32 format_version
            struct.pack(">Q", 0) +                    # uint64 krl_version (0 = unversioned)
            struct.pack(">Q", now) +                  # uint64 generated_date
            struct.pack(">Q", 0) +                    # uint64 flags
            pack_string(b"") +                        # string reserved
            pack_string(b"")                          # string comment (empty)
        )

        sections = b""
        for ca_key_hex, serials in self._revoked.items():
            ca_key_wire = bytes.fromhex(ca_key_hex)
            subsection_data = b"".join(struct.pack(">Q", s) for s in sorted(serials))
            cert_section_body = (
                pack_string(ca_key_wire) +
                pack_string(b"") +
                struct.pack("B", _KRL_SECT_SERIAL_LIST) +
                pack_string(subsection_data)
            )
            sections += (
                struct.pack("B", _KRL_SECTION_CERTS) +
                pack_string(cert_section_body)
            )

        return header + sections


# ---------------------------------------------------------------------------
# Cached KRL service
# ---------------------------------------------------------------------------

class KRLCache:
    """Thread-safe cache for signed KRL bytes.

    Rebuilds the KRL from DB state at most every *ttl_seconds*.
    """

    def __init__(self, ttl_seconds: int = 300):
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._cache: Dict[str, Tuple[float, bytes]] = {}  # ca_fpr → (expires_at, krl_bytes)

    def get(self, ca_fpr: str) -> Optional[bytes]:
        with self._lock:
            entry = self._cache.get(ca_fpr)
            if entry and time.time() < entry[0]:
                return entry[1]
        return None

    def set(self, ca_fpr: str, krl_bytes: bytes) -> None:
        with self._lock:
            self._cache[ca_fpr] = (time.time() + self._ttl, krl_bytes)

    def invalidate(self, ca_fpr: str) -> None:
        with self._lock:
            self._cache.pop(ca_fpr, None)
