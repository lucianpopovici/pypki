#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
onion.py — Tor v3 hidden-service address decoding and ACME onion-csr-01 support.

RFC 9799: ACME for .onion Hidden Services.

Tor v3 onion addresses encode an Ed25519 public key. The 56-char base32
string decodes to 35 bytes: pubkey(32) || checksum(2) || version(1).
The checksum is SHA3-256(".onion checksum" || pubkey || version)[:2].
"""
from __future__ import annotations

import base64
import hashlib
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography import x509

# CA/Browser Forum OIDs for .onion certificates (draft-ietf-lamps-cab-onion)
OID_CABF_ONION_NONCE = x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1")
OID_CABF_ONION_CAA   = x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.2")

_ONION_CHECKSUM_CTX = b".onion checksum"


def decode_v3_onion(addr: str) -> Ed25519PublicKey:
    """Parse a Tor v3 .onion address and return the embedded Ed25519 public key.

    addr must include the '.onion' suffix (e.g. 'facebookwkhpilnemxj7asber7cytxmhwt7t.onion').
    Raises ValueError for malformed or non-v3 addresses.
    """
    low = addr.lower()
    if not low.endswith(".onion"):
        raise ValueError("not an onion address")
    body = low[:-len(".onion")]
    if len(body) != 56:
        raise ValueError(f"not a v3 onion address: expected 56 base32 chars, got {len(body)}")
    try:
        raw = base64.b32decode(body.upper())
    except Exception as exc:
        raise ValueError(f"base32 decode failed: {exc}") from exc
    if len(raw) != 35:
        raise ValueError(f"decoded length wrong: expected 35, got {len(raw)}")
    pubkey_bytes = raw[:32]
    checksum     = raw[32:34]
    version      = raw[34]
    if version != 0x03:
        raise ValueError(f"only v3 onion addresses supported (version byte={version:#04x})")
    expected_cksum = hashlib.sha3_256(
        _ONION_CHECKSUM_CTX + pubkey_bytes + bytes([version])
    ).digest()[:2]
    if checksum != expected_cksum:
        raise ValueError("onion address checksum mismatch")
    return Ed25519PublicKey.from_public_bytes(pubkey_bytes)


def is_valid_v3_onion(addr: str) -> bool:
    """Return True if addr is a syntactically valid Tor v3 .onion address."""
    try:
        decode_v3_onion(addr)
        return True
    except ValueError:
        return False


def extract_onion_nonce(csr: x509.CertificateSigningRequest) -> Optional[bytes]:
    """Return the raw nonce bytes from the cabf-onion-nonce CSR extension, or None.

    The extension value is an OCTET STRING whose content is the raw nonce bytes.
    `cryptography` returns UnrecognizedExtension.value as the DER of the extension
    value (content of the extnValue OCTET STRING), so we parse the inner OCTET STRING.
    """
    try:
        for ext in csr.extensions:
            if ext.oid == OID_CABF_ONION_NONCE:
                raw: bytes = ext.value.value  # DER of the extension value
                # Extension value is OCTET STRING: tag=0x04, length, data
                if len(raw) >= 2 and raw[0] == 0x04:
                    # Handle short-form length (≤127 bytes)
                    if raw[1] < 0x80:
                        length = raw[1]
                        if len(raw) >= 2 + length:
                            return raw[2:2 + length]
                    # Long-form length (rare for a nonce, but handle it)
                    else:
                        n_bytes = raw[1] & 0x7F
                        if len(raw) >= 2 + n_bytes:
                            length = int.from_bytes(raw[2:2 + n_bytes], "big")
                            start = 2 + n_bytes
                            if len(raw) >= start + length:
                                return raw[start:start + length]
                # Fallback: return raw as-is if not a wrapped OCTET STRING
                return raw
    except Exception:
        pass
    return None


def verify_onion_csr(
    csr: x509.CertificateSigningRequest,
    onion_addr: str,
    expected_nonce: bytes,
) -> Tuple[bool, str]:
    """Verify an ACME onion-csr-01 CSR.

    Checks:
    1. The cabf-onion-nonce extension is present and matches *expected_nonce*.
    2. The CSR signature is valid against the Ed25519 key in *onion_addr*.

    Returns (ok, detail).
    """
    try:
        public_key = decode_v3_onion(onion_addr)
    except ValueError as exc:
        return False, f"invalid onion address: {exc}"

    nonce = extract_onion_nonce(csr)
    if nonce is None:
        return False, "CSR is missing the cabf-onion-nonce extension"
    if nonce != expected_nonce:
        return False, (
            f"cabf-onion-nonce mismatch: expected {expected_nonce.hex()!r}, "
            f"got {nonce.hex()!r}"
        )

    try:
        public_key.verify(csr.signature, csr.tbs_certrequest_bytes)
    except Exception as exc:
        return False, f"CSR signature verification failed: {exc}"

    return True, "ok"
