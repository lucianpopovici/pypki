"""
der_codec.py — Shared DER/ASN.1 encoding and decoding primitives.

All PyPKI protocol servers import from here instead of carrying local
copies.  The canonical implementations below are used as the authority;
when discrepancies existed between local copies, these rules apply:

  encode_length  — loop-based (handles any length, not just ≤0xFFFF)
  integer()      — loop-based with explicit sign-bit insertion (correct
                   for all non-negative integers; n.to_bytes() with the
                   (bit_length+8)//8 formula silently mis-encodes 128–255)
  decode_oid_bytes — loop-based base-128 decoder shared by all sites
"""

from __future__ import annotations

import datetime
from typing import Tuple


# ---------------------------------------------------------------------------
# Length encoding / decoding
# ---------------------------------------------------------------------------

def encode_length(n: int) -> bytes:
    """DER definite-form length encoding."""
    if n < 0x80:
        return bytes([n])
    lb: list[int] = []
    while n:
        lb.append(n & 0xFF)
        n >>= 8
    lb.reverse()
    return bytes([0x80 | len(lb)]) + bytes(lb)


def decode_length(data: bytes, pos: int) -> Tuple[int, int]:
    """Return (length, next_pos)."""
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    n_bytes = b & 0x7F
    length = int.from_bytes(data[pos + 1: pos + 1 + n_bytes], "big")
    return length, pos + 1 + n_bytes


# ---------------------------------------------------------------------------
# TLV
# ---------------------------------------------------------------------------

def tlv(tag: int, body: bytes) -> bytes:
    """Raw TLV: tag || DER-length || body."""
    return bytes([tag]) + encode_length(len(body)) + body


def decode_tlv(data: bytes, pos: int = 0) -> Tuple[int, bytes, int]:
    """Return (tag, value_bytes, next_pos)."""
    tag = data[pos]
    length, vstart = decode_length(data, pos + 1)
    return tag, data[vstart: vstart + length], vstart + length


# ---------------------------------------------------------------------------
# Structured types
# ---------------------------------------------------------------------------

def seq(body: bytes) -> bytes:
    return tlv(0x30, body)


def set_(body: bytes) -> bytes:
    """SEQUENCE SET — trailing underscore avoids shadowing Python built-in."""
    return tlv(0x31, body)


def ctx(n: int, body: bytes, constructed: bool = True) -> bytes:
    """Context-tagged wrapper [n]."""
    tag = (0xA0 if constructed else 0x80) | n
    return bytes([tag]) + encode_length(len(body)) + body


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def integer(val: int) -> bytes:
    """DER INTEGER for non-negative val."""
    if val == 0:
        return b"\x02\x01\x00"
    raw: list[int] = []
    n = val
    while n:
        raw.append(n & 0xFF)
        n >>= 8
    raw.reverse()
    if raw[0] & 0x80:
        raw.insert(0, 0)
    return b"\x02" + encode_length(len(raw)) + bytes(raw)


def octet_string(val: bytes) -> bytes:
    return tlv(0x04, val)


def bit_string(val: bytes, unused: int = 0) -> bytes:
    return tlv(0x03, bytes([unused]) + val)


def null() -> bytes:
    return b"\x05\x00"


def bool_(val: bool) -> bytes:
    return b"\x01\x01" + (b"\xff" if val else b"\x00")


# ---------------------------------------------------------------------------
# String types
# ---------------------------------------------------------------------------

def utf8_string(val: str) -> bytes:
    b = val.encode("utf-8")
    return tlv(0x0C, b)


def printable_string(val: str) -> bytes:
    b = val.encode("ascii")
    return tlv(0x13, b)


def ia5_string(val: str) -> bytes:
    b = val.encode("ascii")
    return tlv(0x16, b)


# ---------------------------------------------------------------------------
# Time types
# ---------------------------------------------------------------------------

def utc_time(dt: datetime.datetime) -> bytes:
    return tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode())


def generalized_time(dt: datetime.datetime) -> bytes:
    return tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode())


def validity(not_before: datetime.datetime, not_after: datetime.datetime) -> bytes:
    """X.509 Validity SEQUENCE: UTCTime for years < 2050, GeneralizedTime otherwise."""
    enc_nb = utc_time if not_before.year < 2050 else generalized_time
    enc_na = utc_time if not_after.year < 2050 else generalized_time
    return seq(enc_nb(not_before) + enc_na(not_after))


# ---------------------------------------------------------------------------
# OID encoding / decoding
# ---------------------------------------------------------------------------

def oid(dotted: str) -> bytes:
    """Encode a dotted OID string to DER."""
    parts = list(map(int, dotted.split(".")))
    enc = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            enc += b"\x00"
        else:
            buf: list[int] = []
            while p:
                buf.append(p & 0x7F)
                p >>= 7
            buf.reverse()
            for i, x in enumerate(buf):
                enc += bytes([x | (0x80 if i < len(buf) - 1 else 0)])
    return tlv(0x06, enc)


def decode_oid_bytes(data: bytes) -> str:
    """Decode DER OID value bytes (without tag/length) to dotted string."""
    if not data:
        return ""
    parts = [data[0] // 40, data[0] % 40]
    i, cur = 1, 0
    while i < len(data):
        cur = (cur << 7) | (data[i] & 0x7F)
        if not (data[i] & 0x80):
            parts.append(cur)
            cur = 0
        i += 1
    return ".".join(map(str, parts))


# ---------------------------------------------------------------------------
# PKI-specific helpers
# ---------------------------------------------------------------------------

def ext(oid_dotted: str, value_der: bytes, critical: bool = False) -> bytes:
    """Build DER for a single X.509 Extension TLV."""
    body = oid(oid_dotted)
    if critical:
        body += b"\x01\x01\xff"
    body += octet_string(value_der)
    return seq(body)


# ---------------------------------------------------------------------------
# Well-known OID constants
# ---------------------------------------------------------------------------

# Hash algorithms
OID_SHA1   = "1.3.14.3.2.26"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"

# RSA
OID_RSA_ENCRYPTION  = "1.2.840.113549.1.1.1"
OID_RSAES_OAEP      = "1.2.840.113549.1.1.7"
OID_MGF1            = "1.2.840.113549.1.1.8"
OID_SHA1_WITH_RSA   = "1.2.840.113549.1.1.5"
OID_MD5_WITH_RSA    = "1.2.840.113549.1.1.4"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_SHA384_WITH_RSA = "1.2.840.113549.1.1.12"
OID_SHA512_WITH_RSA = "1.2.840.113549.1.1.13"

# ECDSA
OID_EC_PUBLIC_KEY  = "1.2.840.10045.2.1"
OID_SECP256R1      = "1.2.840.10045.3.1.7"
OID_SECP384R1      = "1.3.132.0.34"
OID_SECP521R1      = "1.3.132.0.35"
OID_ECDSA_SHA256   = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384   = "1.2.840.10045.4.3.3"
OID_ECDSA_SHA512   = "1.2.840.10045.4.3.4"

# ECDH
OID_ECDH_SHA256KDF = "1.3.132.1.11"  # dhSinglePass-stdDH-sha256kdf-scheme

# CMS content types
OID_DATA             = "1.2.840.113549.1.7.1"
OID_SIGNED_DATA      = "1.2.840.113549.1.7.2"
OID_ENVELOPED_DATA   = "1.2.840.113549.1.7.3"
OID_AUTH_ENVELOPED_DATA = "1.2.840.113549.1.9.16.1.23"  # id-ct-authEnvelopedData (RFC 5083)

# CMS authenticated attributes
OID_CONTENT_TYPE   = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME   = "1.2.840.113549.1.9.5"
OID_SMIME_CAP      = "1.2.840.113549.1.9.15"

# TSA
OID_TST_INFO        = "1.2.840.113549.1.9.16.1.4"   # id-ct-TSTInfo
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"  # id-aa-signingCertificateV2 (RFC 5816)

# OCSP
OID_BASIC_OCSP_RESP    = "1.3.6.1.5.5.7.48.1.1"
OID_OCSP_NONCE         = "1.3.6.1.5.5.7.48.1.2"
OID_OCSP_NOCHECK       = "1.3.6.1.5.5.7.48.1.5"
OID_ID_PKIX_OCSP       = "1.3.6.1.5.5.7.48.1"

# X.509 extensions
OID_EXTENDED_KEY_USAGE = "2.5.29.37"
OID_COMMON_NAME        = "2.5.4.3"

# EKU values
OID_EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
OID_EKU_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"  # id-kp-timeStamping (RFC 3161 §2.3)

# SCEP
OID_TRANSACTION_ID     = "2.16.840.1.113733.1.9.7"
OID_SENDER_NONCE       = "2.16.840.1.113733.1.9.5"
OID_RECIPIENT_NONCE    = "2.16.840.1.113733.1.9.6"
OID_PKI_STATUS         = "2.16.840.1.113733.1.9.3"
OID_FAIL_INFO          = "2.16.840.1.113733.1.9.4"
OID_MESSAGE_TYPE       = "2.16.840.1.113733.1.9.2"
OID_CHALLENGE_PASSWORD = "1.2.840.113549.1.9.7"

# Symmetric encryption
OID_DES_CBC     = "1.3.14.3.2.7"
OID_DES_EDE3_CBC = "1.2.840.113549.3.7"
OID_AES_128_CBC = "2.16.840.1.101.3.4.1.2"
OID_AES_192_CBC = "2.16.840.1.101.3.4.1.22"
OID_AES_256_CBC = "2.16.840.1.101.3.4.1.42"
OID_AES_128_GCM = "2.16.840.1.101.3.4.1.6"
OID_AES_256_GCM = "2.16.840.1.101.3.4.1.46"
OID_AES_256_WRAP = "2.16.840.1.101.3.4.1.45"

# EST
OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14"
OID_EC_P256           = "1.2.840.10045.3.1.7"
