#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
# MIT License — see LICENSE file in the root of this repository
"""
SCEP Server — RFC 8894 (Simple Certificate Enrolment Protocol)
===============================================================
Implements SCEP for automated certificate issuance, primarily used by
network devices (routers, switches, VPNs, MDM-enrolled endpoints).

Supported operations:
  - GetCACert        : Download the CA certificate (or chain)
  - PKCSReq          : Enrolment request (PKCS#10 CSR wrapped in CMS/PKCS#7)
  - CertPoll         : Poll for a pending certificate
  - GetCert          : Retrieve an issued certificate by serial + issuer
  - GetCRL           : Retrieve the current CRL
  - GetNextCACert    : Preview the next CA certificate (for rollover)

SCEP flow (RFC 8894 §3):
  1. GET /scep?operation=GetCACert&message=<ca-id>
       → Returns CA cert DER (or p7c chain if multiple CAs)
  2. POST /scep?operation=PKCSReq
       Body: CMS SignedData envelope containing PKCS#10 CSR
       → Returns CMS SignedData with issued cert, or PENDING/FAILURE
  3. GET /scep?operation=CertPoll&message=<base64-transaction-id>
       → Returns cert if ready, or PENDING
  4. GET /scep?operation=GetCert&message=<serial-hex>
       → Returns issued cert wrapped in CMS

Authentication:
  - Challenge password (shared secret) for initial enrolment
    (set via --scep-challenge or PATCH /config {"scep":{"challenge":"..."}})
  - Renewal: existing cert used to sign the CMS envelope (no challenge needed)

Dependencies (same as pki_cmpv2_server.py):
    pip install cryptography

Usage:
    Standalone:
        python scep_server.py [--host 0.0.0.0] [--port 8889] [--ca-dir ./ca]
                               [--challenge mysecret]

    Integrated (via pki_cmpv2_server.py --scep-port 8889):
        python pki_cmpv2_server.py --scep-port 8889 [--scep-challenge mysecret]
"""

import argparse
import base64
import datetime
import hashlib
import http.server
import json
import logging
import os
import sqlite3
import struct
import threading
import time
import traceback
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID

logger = logging.getLogger("scep")

# ---------------------------------------------------------------------------
# ASN.1 / DER / CMS helpers (no external ASN.1 lib required)
# ---------------------------------------------------------------------------

def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    length_bytes = []
    while n:
        length_bytes.append(n & 0xFF)
        n >>= 8
    length_bytes.reverse()
    return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)


def _decode_length(data: bytes, pos: int) -> Tuple[int, int]:
    """Return (length, next_pos)."""
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    n_bytes = b & 0x7F
    length = int.from_bytes(data[pos + 1: pos + 1 + n_bytes], "big")
    return length, pos + 1 + n_bytes


def _decode_tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
    """Return (tag, value_bytes, next_pos)."""
    tag = data[pos]
    length, vstart = _decode_length(data, pos + 1)
    return tag, data[vstart: vstart + length], vstart + length


def _seq(content: bytes) -> bytes:
    return b"\x30" + _encode_length(len(content)) + content


def _set(content: bytes) -> bytes:
    return b"\x31" + _encode_length(len(content)) + content


def _ctx(n: int, content: bytes, constructed: bool = True) -> bytes:
    tag = (0xA0 | n) if constructed else (0x80 | n)
    return bytes([tag]) + _encode_length(len(content)) + content


def _oid(dotted: str) -> bytes:
    parts = list(map(int, dotted.split(".")))
    encoded = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            encoded += b"\x00"
        else:
            buf = []
            while p:
                buf.append(p & 0x7F)
                p >>= 7
            buf.reverse()
            for i, b_ in enumerate(buf):
                encoded += bytes([b_ | (0x80 if i < len(buf) - 1 else 0)])
    return b"\x06" + _encode_length(len(encoded)) + encoded


def _integer(val: int) -> bytes:
    if val == 0:
        return b"\x02\x01\x00"
    n = val
    raw = []
    while n:
        raw.append(n & 0xFF)
        n >>= 8
    raw.reverse()
    if raw[0] & 0x80:
        raw.insert(0, 0)
    return b"\x02" + _encode_length(len(raw)) + bytes(raw)


def _octet_string(val: bytes) -> bytes:
    return b"\x04" + _encode_length(len(val)) + val


def _printable_string(val: str) -> bytes:
    b = val.encode("ascii")
    return b"\x13" + _encode_length(len(b)) + b


def _utf8_string(val: str) -> bytes:
    b = val.encode("utf-8")
    return b"\x0c" + _encode_length(len(b)) + b


def _null() -> bytes:
    return b"\x05\x00"


def _bool(val: bool) -> bytes:
    return b"\x01\x01" + (b"\xff" if val else b"\x00")


# Well-known OIDs
OID_RSA_ENCRYPTION        = "1.2.840.113549.1.1.1"
OID_SHA1_WITH_RSA         = "1.2.840.113549.1.1.5"
OID_SHA256_WITH_RSA       = "1.2.840.113549.1.1.11"
OID_MD5_WITH_RSA          = "1.2.840.113549.1.1.4"
OID_DATA                  = "1.2.840.113549.1.7.1"
OID_SIGNED_DATA           = "1.2.840.113549.1.7.2"
OID_ENVELOPED_DATA        = "1.2.840.113549.1.7.3"
OID_CONTENT_TYPE          = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST        = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME          = "1.2.840.113549.1.9.5"
OID_SMIME_CAP             = "1.2.840.113549.1.9.15"
OID_TRANSACTION_ID        = "2.16.840.1.113733.1.9.7"
OID_SENDER_NONCE          = "2.16.840.1.113733.1.9.5"
OID_RECIPIENT_NONCE       = "2.16.840.1.113733.1.9.6"
OID_PKI_STATUS            = "2.16.840.1.113733.1.9.3"
OID_FAIL_INFO             = "2.16.840.1.113733.1.9.4"
OID_MESSAGE_TYPE          = "2.16.840.1.113733.1.9.2"
OID_CHALLENGE_PASSWORD    = "1.2.840.113549.1.9.7"
OID_DES_CBC               = "1.3.14.3.2.7"
OID_DES_EDE3_CBC          = "1.2.840.113549.3.7"
OID_AES_256_CBC           = "2.16.840.1.101.3.4.1.42"
OID_SHA1                  = "1.3.14.3.2.26"
OID_SHA256                = "2.16.840.1.101.3.4.2.1"
OID_COMMON_NAME           = "2.5.4.3"

# SCEP message type codes (PrintableString)
MSG_PKCSREQ     = "19"
MSG_CERTRESP    = "3"
MSG_GETCERTINITIAL = "20"  # CertPoll
MSG_GETCERT     = "21"
MSG_GETCRL      = "22"

# SCEP PKIStatus codes
STATUS_SUCCESS  = "0"
STATUS_FAILURE  = "2"
STATUS_PENDING  = "3"

# SCEP FailInfo codes
FAIL_BAD_ALG         = "0"
FAIL_BAD_MESSAGE_CHECK = "1"
FAIL_BAD_REQUEST     = "2"
FAIL_BAD_TIME        = "3"
FAIL_BAD_CERT_ID     = "4"

# ---------------------------------------------------------------------------
# CMS / PKCS#7 parser
# ---------------------------------------------------------------------------

class CMSParser:
    """Minimal CMS SignedData and EnvelopedData parser."""

    @staticmethod
    def parse_signed_data(der: bytes) -> Dict[str, Any]:
        """
        Parse a CMS ContentInfo wrapping a SignedData.
        Returns dict with keys: content_type, version, digest_algorithms,
        encap_content_info, signer_infos, certificates, inner_content.
        """
        result: Dict[str, Any] = {}
        try:
            # ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
            pos = 0
            tag, val, pos = _decode_tlv(der, pos)
            if tag != 0x30:
                raise ValueError(f"Expected SEQUENCE, got 0x{tag:02x}")

            # contentType OID
            ci_pos = 0
            tag, oid_val, ci_pos = _decode_tlv(val, ci_pos)
            if tag != 0x06:
                raise ValueError("Expected OID for contentType")
            # content [0]
            tag, content_val, ci_pos = _decode_tlv(val, ci_pos)
            if tag != 0xA0:
                raise ValueError(f"Expected [0] for content, got 0x{tag:02x}")
            # unwrap the explicit [0]
            sd_der = content_val

            # SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
            #                           [0] certificates, [1] crls, signerInfos }
            tag, sd_val, _ = _decode_tlv(sd_der, 0)
            if tag != 0x30:
                raise ValueError("SignedData must be SEQUENCE")

            sd_pos = 0
            # version
            tag, ver_val, sd_pos = _decode_tlv(sd_val, sd_pos)
            result["version"] = int.from_bytes(ver_val, "big")

            # digestAlgorithms SET
            tag, da_val, sd_pos = _decode_tlv(sd_val, sd_pos)
            result["digest_algorithms"] = da_val

            # encapContentInfo
            tag, eci_val, sd_pos = _decode_tlv(sd_val, sd_pos)
            # encapContentInfo = SEQUENCE { eContentType OID, [0] OCTET STRING }
            eci_pos = 0
            tag, ect_oid, eci_pos = _decode_tlv(eci_val, eci_pos)
            inner_content = b""
            if eci_pos < len(eci_val):
                tag, eci_inner, eci_pos = _decode_tlv(eci_val, eci_pos)
                if tag == 0xA0 and eci_inner:
                    # unwrap OCTET STRING inside [0]
                    tag2, inner_content, _ = _decode_tlv(eci_inner, 0)
            result["inner_content"] = inner_content

            # optional certificates [0], crls [1], and signerInfos SET
            certs_der: list = []
            signer_infos_raw = b""
            while sd_pos < len(sd_val):
                tag, field_val, sd_pos = _decode_tlv(sd_val, sd_pos)
                if tag == 0xA0:
                    # certificates: parse each cert
                    cp = 0
                    while cp < len(field_val):
                        ctag, cval, cp = _decode_tlv(field_val, cp)
                        if ctag == 0x30:
                            certs_der.append(b"\x30" + _encode_length(len(cval)) + cval)
                elif tag == 0x31:
                    signer_infos_raw = field_val

            result["certificates"] = certs_der
            result["signer_infos_raw"] = signer_infos_raw

            # Parse first SignerInfo
            if signer_infos_raw:
                result["signer_info"] = CMSParser._parse_signer_info(signer_infos_raw)

        except Exception as e:
            result["parse_error"] = str(e)

        return result

    @staticmethod
    def _parse_signer_info(raw: bytes) -> Dict[str, Any]:
        """Parse first SignerInfo from SET contents."""
        si: Dict[str, Any] = {}
        try:
            # First element of the SET
            tag, si_val, _ = _decode_tlv(raw, 0)
            si_pos = 0

            # version
            tag, ver, si_pos = _decode_tlv(si_val, si_pos)
            si["version"] = int.from_bytes(ver, "big")

            # sid: IssuerAndSerialNumber
            tag, sid_val, si_pos = _decode_tlv(si_val, si_pos)
            si["sid_raw"] = sid_val

            # digestAlgorithm
            tag, da, si_pos = _decode_tlv(si_val, si_pos)
            si["digest_algorithm_raw"] = da

            # signedAttrs [0]
            if si_pos < len(si_val) and si_val[si_pos] == 0xA0:
                tag, sa_val, si_pos = _decode_tlv(si_val, si_pos)
                si["signed_attrs_raw"] = sa_val
                si["signed_attrs"] = CMSParser._parse_signed_attrs(sa_val)

            # signatureAlgorithm
            if si_pos < len(si_val):
                tag, sig_alg, si_pos = _decode_tlv(si_val, si_pos)
                si["signature_algorithm_raw"] = sig_alg

            # signature OCTET STRING
            if si_pos < len(si_val):
                tag, sig_val, si_pos = _decode_tlv(si_val, si_pos)
                si["signature"] = sig_val

        except Exception as e:
            si["parse_error"] = str(e)

        return si

    @staticmethod
    def _parse_signed_attrs(raw: bytes) -> Dict[str, Any]:
        """Parse signed attributes into a dict keyed by OID dotted string."""
        attrs: Dict[str, Any] = {}
        pos = 0
        while pos < len(raw):
            try:
                tag, attr_val, pos = _decode_tlv(raw, pos)
                if tag != 0x30:
                    continue
                # Attribute ::= SEQUENCE { attrType OID, attrValues SET }
                a_pos = 0
                tag2, oid_val, a_pos = _decode_tlv(attr_val, a_pos)
                oid_str = _decode_oid_bytes(oid_val)
                tag3, values_val, a_pos = _decode_tlv(attr_val, a_pos)
                # attrValues SET — take first element
                if values_val:
                    tag4, first_val, _ = _decode_tlv(values_val, 0)
                    attrs[oid_str] = first_val
            except Exception:
                break
        return attrs

    @staticmethod
    def parse_enveloped_data(der: bytes, private_key: RSAPrivateKey) -> bytes:
        """
        Parse a CMS EnvelopedData and decrypt the inner content.
        Supports RSA + AES-256-CBC and RSA + 3DES-EDE-CBC.
        """
        # ContentInfo wrapper
        tag, ci_val, _ = _decode_tlv(der, 0)
        # contentType OID
        ci_pos = 0
        tag, oid_val, ci_pos = _decode_tlv(ci_val, ci_pos)
        # content [0]
        tag, ev_outer, ci_pos = _decode_tlv(ci_val, ci_pos)
        # EnvelopedData SEQUENCE
        tag, ev_val, _ = _decode_tlv(ev_outer, 0)

        ev_pos = 0
        # version
        tag, ver, ev_pos = _decode_tlv(ev_val, ev_pos)

        # recipientInfos SET
        tag, ri_set, ev_pos = _decode_tlv(ev_val, ev_pos)

        # encryptedContentInfo
        tag, eci_val, ev_pos = _decode_tlv(ev_val, ev_pos)

        # Parse recipientInfo to get encrypted key
        encrypted_key = None
        enc_alg_oid = None

        ri_pos = 0
        while ri_pos < len(ri_set):
            tag, ri_val, ri_pos = _decode_tlv(ri_set, ri_pos)
            if tag != 0x30:
                continue
            r_pos = 0
            tag, ri_ver, r_pos = _decode_tlv(ri_val, r_pos)
            # sid (IssuerAndSerialNumber)
            tag, ri_sid, r_pos = _decode_tlv(ri_val, r_pos)
            # keyEncryptionAlgorithm
            tag, ri_kea, r_pos = _decode_tlv(ri_val, r_pos)
            # encryptedKey OCTET STRING
            if r_pos < len(ri_val):
                tag, ri_ek, r_pos = _decode_tlv(ri_val, r_pos)
                encrypted_key = ri_ek
                break  # use first recipient

        if encrypted_key is None:
            raise ValueError("No usable RecipientInfo found")

        # Decrypt the content encryption key with the CA's private key
        try:
            cek = private_key.decrypt(
                encrypted_key,
                asym_padding.PKCS1v15()
            )
        except Exception as e:
            raise ValueError(f"Could not decrypt content encryption key: {e}")

        # Parse encryptedContentInfo for content algorithm and IV
        eci_pos = 0
        tag, ct_oid_val, eci_pos = _decode_tlv(eci_val, eci_pos)   # contentType OID
        tag, ca_seq, eci_pos = _decode_tlv(eci_val, eci_pos)       # contentEncryptionAlgorithm
        ca_pos = 0
        tag, ce_oid_val, ca_pos = _decode_tlv(ca_seq, ca_pos)      # algorithm OID
        enc_alg_oid = _decode_oid_bytes(ce_oid_val)
        tag, iv_val, ca_pos = _decode_tlv(ca_seq, ca_pos)          # IV (OCTET STRING)
        tag, ec_val, eci_pos = _decode_tlv(eci_val, eci_pos)       # encryptedContent [0]

        # The encryptedContent may be wrapped in [0] implicit OCTET STRING
        if ec_val and ec_val[0] == 0x80:
            _, ec_val, _ = _decode_tlv(ec_val, 0)

        # Decrypt
        if enc_alg_oid in (OID_AES_256_CBC, "2.16.840.1.101.3.4.1.22",  # AES-192-CBC
                            "2.16.840.1.101.3.4.1.2"):                   # AES-128-CBC
            key_size = {
                "2.16.840.1.101.3.4.1.2":  16,
                "2.16.840.1.101.3.4.1.22": 24,
                OID_AES_256_CBC:            32,
            }[enc_alg_oid]
            cipher = Cipher(algorithms.AES(cek[:key_size]), modes.CBC(iv_val))
        elif enc_alg_oid == OID_DES_EDE3_CBC:
            cipher = Cipher(algorithms.TripleDES(cek[:24]), modes.CBC(iv_val))
        elif enc_alg_oid == OID_DES_CBC:
            cipher = Cipher(algorithms.TripleDES(cek[:8] * 3), modes.CBC(iv_val))
        else:
            raise ValueError(f"Unsupported content encryption algorithm: {enc_alg_oid}")

        decryptor = cipher.decryptor()
        padded = decryptor.update(ec_val) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(cipher.algorithm.block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()


def _decode_oid_bytes(data: bytes) -> str:
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
# CMS builder helpers
# ---------------------------------------------------------------------------

class CMSBuilder:
    """Build CMS SignedData and EnvelopedData messages for SCEP responses."""

    @staticmethod
    def signed_data(
        ca: "CertificateAuthority",
        message_type: str,
        pki_status: str,
        transaction_id: str,
        sender_nonce: bytes,
        recipient_nonce: bytes,
        inner_der: bytes,
        fail_info: Optional[str] = None,
    ) -> bytes:
        """
        Build a CMS SignedData response for SCEP.
        inner_der: the payload — either a cert DER, CRL DER, or empty bytes.
        Wraps inner_der in a degenerate SignedData (certs-only) when non-empty,
        then signs the outer response attributes.
        """
        now = datetime.datetime.utcnow()

        # ---- Signed attributes ----
        def attr(oid_str: str, value: bytes) -> bytes:
            return _seq(_oid(oid_str) + _set(value))

        signed_attrs = (
            attr(OID_CONTENT_TYPE,   _oid(OID_DATA))
            + attr(OID_MESSAGE_TYPE, _printable_string(message_type))
            + attr(OID_PKI_STATUS,   _printable_string(pki_status))
            + attr(OID_TRANSACTION_ID, _printable_string(transaction_id))
            + attr(OID_SENDER_NONCE,   _octet_string(sender_nonce))
            + attr(OID_RECIPIENT_NONCE, _octet_string(recipient_nonce))
        )
        if fail_info is not None:
            signed_attrs += attr(OID_FAIL_INFO, _printable_string(fail_info))

        # Signing time attribute
        gt = now.strftime("%Y%m%d%H%M%SZ").encode()
        signing_time = b"\x18" + _encode_length(len(gt)) + gt
        signed_attrs += attr(OID_SIGNING_TIME, signing_time)

        # Compute digest of signed attributes (as SET OF)
        signed_attrs_set = b"\x31" + _encode_length(len(signed_attrs)) + signed_attrs
        digest = hashlib.sha256(signed_attrs_set).digest()

        # ---- Sign ----
        ca_cert = ca.ca_cert
        ca_key = ca.ca_key
        # For signing, signedAttrs bytes are re-encoded as SET for the signature
        signature = ca_key.sign(signed_attrs_set, asym_padding.PKCS1v15(), SHA256())

        # ---- IssuerAndSerialNumber ----
        issuer_der = ca_cert.issuer.public_bytes()
        serial_int = ca_cert.serial_number
        ian = _seq(issuer_der + _integer(serial_int))

        # ---- SignerInfo ----
        digest_alg = _seq(_oid(OID_SHA256) + _null())
        sig_alg = _seq(_oid(OID_SHA256_WITH_RSA) + _null())
        signer_info = _seq(
            _integer(1)              # version
            + ian                    # sid
            + digest_alg             # digestAlgorithm
            + _ctx(0, signed_attrs)  # signedAttrs [0] IMPLICIT
            + sig_alg                # signatureAlgorithm
            + _octet_string(signature)  # signature
        )

        # ---- EncapContentInfo ----
        # SCEP CertRep: inner_der is the issued cert wrapped in a degenerate p7c,
        # or empty for FAILURE/PENDING.
        if inner_der:
            # Degenerate SignedData (certs-only, no signers) — standard p7c format
            degen = CMSBuilder._degenerate_certs(inner_der, ca_cert.public_bytes(Encoding.DER))
            eci_content = _octet_string(degen)
        else:
            eci_content = b""

        eci = _seq(
            _oid(OID_DATA)
            + (_ctx(0, eci_content) if eci_content else b"")
        )

        # ---- CA cert in certificates [0] ----
        ca_cert_der = ca_cert.public_bytes(Encoding.DER)
        certs = _ctx(0, ca_cert_der)

        # ---- DigestAlgorithms SET ----
        digest_algs = _set(digest_alg)

        # ---- SignedData ----
        signed_data_inner = (
            _integer(1)          # version
            + digest_algs        # digestAlgorithms
            + eci                # encapContentInfo
            + certs              # [0] certificates
            + _set(signer_info)  # signerInfos
        )
        signed_data = _seq(signed_data_inner)

        # ---- ContentInfo ----
        content_info = _seq(
            _oid(OID_SIGNED_DATA)
            + _ctx(0, signed_data)
        )

        return content_info

    @staticmethod
    def _degenerate_certs(cert_der: bytes, ca_cert_der: bytes) -> bytes:
        """Build a degenerate CMS SignedData containing only certificates."""
        certs = _ctx(0, cert_der + ca_cert_der)
        eci = _seq(_oid(OID_DATA))
        signed_data_inner = (
            _integer(1)   # version
            + _set(b"")   # digestAlgorithms (empty)
            + eci          # encapContentInfo
            + certs        # [0] certificates
            + _set(b"")   # signerInfos (empty)
        )
        return _seq(
            _oid(OID_SIGNED_DATA)
            + _ctx(0, _seq(signed_data_inner))
        )

    @staticmethod
    def enveloped_data(plaintext: bytes, recipient_cert: x509.Certificate) -> bytes:
        """
        Encrypt plaintext for the given recipient using RSA + AES-256-CBC.
        Returns DER-encoded CMS EnvelopedData wrapped in ContentInfo.
        """
        # Generate CEK and IV
        cek = os.urandom(32)
        iv  = os.urandom(16)

        # Encrypt content
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(cek), modes.CBC(iv))
        enc = cipher.encryptor()
        encrypted_content = enc.update(padded) + enc.finalize()

        # Encrypt CEK with recipient's public key
        pub_key = recipient_cert.public_key()
        encrypted_key = pub_key.encrypt(cek, asym_padding.PKCS1v15())

        # IssuerAndSerialNumber for recipient
        issuer_der = recipient_cert.issuer.public_bytes()
        serial_int = recipient_cert.serial_number
        ian = _seq(issuer_der + _integer(serial_int))

        # KeyTransRecipientInfo
        kea = _seq(_oid(OID_RSA_ENCRYPTION) + _null())
        ri = _seq(
            _integer(0)            # version
            + ian                  # rid
            + kea                  # keyEncryptionAlgorithm
            + _octet_string(encrypted_key)
        )

        # EncryptedContentInfo
        ce_alg = _seq(
            _oid(OID_AES_256_CBC)
            + _octet_string(iv)
        )
        # encryptedContent as [0] IMPLICIT OCTET STRING
        ec_tag = b"\x80" + _encode_length(len(encrypted_content)) + encrypted_content
        eci = _seq(
            _oid(OID_DATA)
            + ce_alg
            + ec_tag
        )

        # EnvelopedData
        ev = _seq(
            _integer(0)   # version
            + _set(ri)    # recipientInfos
            + eci          # encryptedContentInfo
        )

        # ContentInfo
        return _seq(
            _oid(OID_ENVELOPED_DATA)
            + _ctx(0, ev)
        )


# ---------------------------------------------------------------------------
# SCEP database
# ---------------------------------------------------------------------------

class SCEPDatabase:
    """SQLite store for pending SCEP enrolments."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scep_transactions (
                    transaction_id  TEXT PRIMARY KEY,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    subject         TEXT,
                    csr_pem         TEXT,
                    cert_pem        TEXT,
                    fail_info       TEXT,
                    fail_reason     TEXT,
                    requester_ip    TEXT,
                    created_at      REAL,
                    updated_at      REAL
                );
            """)
            conn.commit()
        finally:
            conn.close()

    def create_transaction(self, txid: str, subject: str, csr_pem: str, ip: str):
        conn = self._conn()
        try:
            now = time.time()
            conn.execute(
                "INSERT OR REPLACE INTO scep_transactions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (txid, "pending", subject, csr_pem, None, None, None, ip, now, now)
            )
            conn.commit()
        finally:
            conn.close()

    def set_success(self, txid: str, cert_pem: str):
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE scep_transactions SET status='success', cert_pem=?, updated_at=? WHERE transaction_id=?",
                (cert_pem, time.time(), txid)
            )
            conn.commit()
        finally:
            conn.close()

    def set_failure(self, txid: str, fail_info: str, reason: str):
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE scep_transactions SET status='failure', fail_info=?, fail_reason=?, updated_at=? WHERE transaction_id=?",
                (fail_info, reason, time.time(), txid)
            )
            conn.commit()
        finally:
            conn.close()

    def get(self, txid: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM scep_transactions WHERE transaction_id=?", (txid,)).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def all_transactions(self) -> list:
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM scep_transactions ORDER BY created_at DESC").fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# SCEP Request Handler
# ---------------------------------------------------------------------------

class SCEPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for SCEP (RFC 8894)."""

    ca: "CertificateAuthority" = None
    db: SCEPDatabase = None
    challenge: str = ""           # shared challenge password (empty = no check)
    auto_issue: bool = True       # auto-issue on valid PKCSReq vs manual approval

    def log_message(self, fmt, *args):
        logger.info(f"SCEP {self.client_address[0]} - {fmt % args}")

    # ------------------------------------------------------------------
    # HTTP routing
    # ------------------------------------------------------------------

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def _dispatch(self):
        try:
            path = self.path.split("?")[0].rstrip("/")
            params = self._parse_query()
            operation = params.get("operation", "")
            message = params.get("message", "")

            if path not in ("/scep", "/cgi-bin/pkiclient.exe", "/scep/pkiclient.exe"):
                self._send_error_plain(404, "Not found")
                return

            logger.info(f"SCEP operation={operation!r} message={repr(message)[:40]}")

            if operation == "GetCACert":
                self._handle_get_ca_cert(message)
            elif operation == "GetCACaps":
                self._handle_get_ca_caps()
            elif operation == "PKCSReq":
                body = self._read_body()
                self._handle_pki_request(body, "PKCSReq")
            elif operation == "CertPoll" or operation == "GetCertInitial":
                body = self._read_body()
                self._handle_cert_poll(body)
            elif operation == "GetCert":
                body = self._read_body()
                self._handle_get_cert(body)
            elif operation == "GetCRL":
                body = self._read_body()
                self._handle_get_crl(body)
            elif operation == "GetNextCACert":
                self._handle_get_next_ca_cert()
            else:
                self._send_error_plain(400, f"Unknown operation: {operation!r}")

        except Exception as e:
            logger.error(f"SCEP dispatch error: {e}\n{traceback.format_exc()}")
            self._send_error_plain(500, "Internal server error")

    # ------------------------------------------------------------------
    # SCEP operations
    # ------------------------------------------------------------------

    def _handle_get_ca_cert(self, ca_id: str):
        """
        Return CA certificate.
        RFC 8894 §4.2 — GetCACert returns DER for single CA, p7c chain for multiple.
        """
        ca_der = self.ca.ca_cert.public_bytes(Encoding.DER)
        # We have a single CA, so return plain DER with mimetype application/x-x509-ca-cert
        self.send_response(200)
        self.send_header("Content-Type", "application/x-x509-ca-cert")
        self.send_header("Content-Length", str(len(ca_der)))
        self.end_headers()
        self.wfile.write(ca_der)
        logger.info("GetCACert: sent CA certificate")

    def _handle_get_ca_caps(self):
        """
        Return server capabilities as newline-delimited string.
        RFC 8894 §4.1.
        """
        caps = "\n".join([
            "AES",           # supports AES encryption
            "SHA-256",       # supports SHA-256 digest
            "SHA-512",       # supports SHA-512 digest
            "Renewal",       # supports renewal without challenge
            "POSTPKIOperation",  # supports HTTP POST for PKI operations
        ])
        body = caps.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        logger.info("GetCACaps: sent capabilities")

    def _handle_pki_request(self, body: bytes, op: str):
        """
        Handle PKCSReq (initial enrolment) and RenewalReq.
        body is base64-encoded or raw CMS SignedData (DER).
        """
        # body may come as raw DER (POST) or base64 (GET message= param)
        cms_der = self._decode_cms_body(body)
        if not cms_der:
            self._scep_error("Could not decode CMS body", FAIL_BAD_MESSAGE_CHECK)
            return

        # Parse the outer SignedData
        try:
            signed = CMSParser.parse_signed_data(cms_der)
        except Exception as e:
            self._scep_error(f"CMS parse error: {e}", FAIL_BAD_MESSAGE_CHECK)
            return

        if "parse_error" in signed:
            self._scep_error(f"CMS parse error: {signed['parse_error']}", FAIL_BAD_MESSAGE_CHECK)
            return

        # Extract SCEP attributes from SignerInfo
        si = signed.get("signer_info", {})
        attrs = si.get("signed_attrs", {})

        transaction_id = attrs.get(OID_TRANSACTION_ID, b"").decode("ascii", errors="replace").strip()
        sender_nonce = attrs.get(OID_SENDER_NONCE, os.urandom(16))
        msg_type = attrs.get(OID_MESSAGE_TYPE, b"").decode("ascii", errors="replace").strip()
        recipient_nonce = os.urandom(16)

        if not transaction_id:
            transaction_id = hashlib.sha256(cms_der).hexdigest()[:32]

        logger.info(f"PKCSReq txid={transaction_id} msg_type={msg_type}")

        # The inner content is an EnvelopedData containing the PKCS#10 CSR
        inner_cms = signed.get("inner_content", b"")
        if not inner_cms:
            self._scep_error("Missing inner EnvelopedData", FAIL_BAD_MESSAGE_CHECK,
                             transaction_id, sender_nonce, recipient_nonce)
            return

        # Decrypt EnvelopedData to get the PKCS#10 CSR
        try:
            csr_der = CMSParser.parse_enveloped_data(inner_cms, self.ca.ca_key)
        except Exception as e:
            logger.warning(f"EnvelopedData decrypt failed: {e}")
            self._scep_error(f"Decrypt failed: {e}", FAIL_BAD_MESSAGE_CHECK,
                             transaction_id, sender_nonce, recipient_nonce)
            return

        # Parse the PKCS#10 CSR
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except Exception as e:
            self._scep_error(f"Bad CSR: {e}", FAIL_BAD_REQUEST,
                             transaction_id, sender_nonce, recipient_nonce)
            return

        if not csr.is_signature_valid:
            self._scep_error("CSR signature invalid", FAIL_BAD_REQUEST,
                             transaction_id, sender_nonce, recipient_nonce)
            return

        subject_str = csr.subject.rfc4514_string()

        # Challenge password verification
        # Extract challengePassword from the CSR attributes
        challenge_ok = True
        if self.challenge:
            csr_challenge = self._extract_csr_challenge(csr_der)
            if not csr_challenge:
                logger.warning(f"No challengePassword in CSR from {subject_str}")
                challenge_ok = False
            elif not hmac_compare(csr_challenge.encode(), self.challenge.encode()):
                logger.warning(f"Wrong challengePassword from {subject_str}")
                challenge_ok = False

        if not challenge_ok:
            # Check if this is a renewal (requester presents an existing cert)
            requester_certs = signed.get("certificates", [])
            is_renewal = self._verify_renewal(requester_certs)
            if not is_renewal:
                logger.warning(f"Rejecting PKCSReq — bad challenge and not a valid renewal")
                self._scep_failure(transaction_id, sender_nonce, recipient_nonce,
                                   FAIL_BAD_REQUEST, "Invalid challenge password")
                return

        # Issue the certificate
        try:
            cert = self.ca.issue_certificate(
                subject_str=subject_str,
                public_key=csr.public_key(),
            )
            cert_pem = cert.public_bytes(Encoding.PEM).decode()
            self.db.set_success(transaction_id, cert_pem)

            logger.info(f"SCEP: issued cert for '{subject_str}' serial={cert.serial_number} txid={transaction_id}")

            cert_der = cert.public_bytes(Encoding.DER)
            self._scep_success(transaction_id, sender_nonce, recipient_nonce, cert_der)

        except Exception as e:
            logger.error(f"SCEP cert issuance failed: {e}")
            self.db.set_failure(transaction_id, FAIL_BAD_REQUEST, str(e))
            self._scep_failure(transaction_id, sender_nonce, recipient_nonce,
                               FAIL_BAD_REQUEST, str(e))

    def _handle_cert_poll(self, body: bytes):
        """Handle CertPoll / GetCertInitial — return cert if ready."""
        cms_der = self._decode_cms_body(body)
        if not cms_der:
            self._send_error_plain(400, "Could not decode CMS")
            return

        try:
            signed = CMSParser.parse_signed_data(cms_der)
        except Exception as e:
            self._send_error_plain(400, f"CMS parse error: {e}")
            return

        si = signed.get("signer_info", {})
        attrs = si.get("signed_attrs", {})
        transaction_id = attrs.get(OID_TRANSACTION_ID, b"").decode("ascii", errors="replace").strip()
        sender_nonce = attrs.get(OID_SENDER_NONCE, os.urandom(16))
        recipient_nonce = os.urandom(16)

        if not transaction_id:
            self._send_error_plain(400, "Missing transactionID")
            return

        row = self.db.get(transaction_id)
        if not row:
            self._scep_failure(transaction_id, sender_nonce, recipient_nonce,
                               FAIL_BAD_CERT_ID, "Unknown transactionID")
            return

        if row["status"] == "success" and row["cert_pem"]:
            cert = x509.load_pem_x509_certificate(row["cert_pem"].encode())
            self._scep_success(transaction_id, sender_nonce, recipient_nonce,
                               cert.public_bytes(Encoding.DER))
        elif row["status"] == "failure":
            self._scep_failure(transaction_id, sender_nonce, recipient_nonce,
                               row.get("fail_info", FAIL_BAD_REQUEST),
                               row.get("fail_reason", "Request failed"))
        else:
            self._scep_pending(transaction_id, sender_nonce, recipient_nonce)

    def _handle_get_cert(self, body: bytes):
        """GetCert — return a certificate by serial number."""
        cms_der = self._decode_cms_body(body)
        if not cms_der:
            self._send_error_plain(400, "Could not decode CMS")
            return

        try:
            signed = CMSParser.parse_signed_data(cms_der)
        except Exception as e:
            self._send_error_plain(400, f"CMS parse error: {e}")
            return

        si = signed.get("signer_info", {})
        attrs = si.get("signed_attrs", {})
        transaction_id = attrs.get(OID_TRANSACTION_ID, b"").decode("ascii", errors="replace").strip()
        sender_nonce = attrs.get(OID_SENDER_NONCE, os.urandom(16))
        recipient_nonce = os.urandom(16)

        # inner content is IssuerAndSerialNumber
        inner = signed.get("inner_content", b"")
        serial = self._extract_serial_from_ian(inner)

        if serial is None:
            self._scep_failure(transaction_id, sender_nonce, recipient_nonce,
                               FAIL_BAD_CERT_ID, "Cannot parse IssuerAndSerialNumber")
            return

        cert_pem = self.ca.get_certificate_by_serial(serial)
        if not cert_pem:
            self._scep_failure(transaction_id, sender_nonce, recipient_nonce,
                               FAIL_BAD_CERT_ID, f"Certificate not found: serial={serial}")
            return

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        self._scep_success(transaction_id, sender_nonce, recipient_nonce,
                           cert.public_bytes(Encoding.DER))

    def _handle_get_crl(self, body: bytes):
        """Return the current CRL wrapped in a degenerate SignedData."""
        crl_der = self.ca.generate_crl_der()
        # Return as raw DER with correct MIME type
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pkcs7-crl")
        self.send_header("Content-Length", str(len(crl_der)))
        self.end_headers()
        self.wfile.write(crl_der)

    def _handle_get_next_ca_cert(self):
        """
        GetNextCACert — for CA rollover. We return the current CA cert
        since we don't implement rollover, which is RFC-compliant behaviour.
        """
        ca_der = self.ca.ca_cert.public_bytes(Encoding.DER)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-x509-next-ca-cert")
        self.send_header("Content-Length", str(len(ca_der)))
        self.end_headers()
        self.wfile.write(ca_der)

    # ------------------------------------------------------------------
    # SCEP response builders
    # ------------------------------------------------------------------

    def _scep_success(self, txid: str, sender_nonce: bytes, recipient_nonce: bytes,
                      cert_der: bytes):
        """Send a CertRep with PKIStatus=SUCCESS and the issued certificate."""
        response = CMSBuilder.signed_data(
            ca=self.ca,
            message_type=MSG_CERTRESP,
            pki_status=STATUS_SUCCESS,
            transaction_id=txid,
            sender_nonce=sender_nonce,
            recipient_nonce=recipient_nonce,
            inner_der=cert_der,
        )
        self._send_cms(response)

    def _scep_pending(self, txid: str, sender_nonce: bytes, recipient_nonce: bytes):
        """Send a CertRep with PKIStatus=PENDING."""
        response = CMSBuilder.signed_data(
            ca=self.ca,
            message_type=MSG_CERTRESP,
            pki_status=STATUS_PENDING,
            transaction_id=txid,
            sender_nonce=sender_nonce,
            recipient_nonce=recipient_nonce,
            inner_der=b"",
        )
        self._send_cms(response)

    def _scep_failure(self, txid: str, sender_nonce: bytes, recipient_nonce: bytes,
                      fail_info: str, reason: str = ""):
        """Send a CertRep with PKIStatus=FAILURE."""
        if txid:
            self.db.set_failure(txid, fail_info, reason)
        logger.warning(f"SCEP failure txid={txid} failInfo={fail_info} reason={reason}")
        response = CMSBuilder.signed_data(
            ca=self.ca,
            message_type=MSG_CERTRESP,
            pki_status=STATUS_FAILURE,
            transaction_id=txid,
            sender_nonce=sender_nonce,
            recipient_nonce=recipient_nonce,
            inner_der=b"",
            fail_info=fail_info,
        )
        self._send_cms(response)

    def _scep_error(self, msg: str, fail_info: str,
                    txid: str = "", sender_nonce: bytes = b"",
                    recipient_nonce: bytes = b""):
        logger.warning(f"SCEP error: {msg}")
        if not txid:
            txid = ""
        if not sender_nonce:
            sender_nonce = os.urandom(16)
        if not recipient_nonce:
            recipient_nonce = os.urandom(16)
        self._scep_failure(txid, sender_nonce, recipient_nonce, fail_info, msg)

    def _send_cms(self, der: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pki-message")
        self.send_header("Content-Length", str(len(der)))
        self.end_headers()
        self.wfile.write(der)

    def _send_error_plain(self, code: int, msg: str):
        body = msg.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _parse_query(self) -> Dict[str, str]:
        params: Dict[str, str] = {}
        if "?" in self.path:
            qs = self.path.split("?", 1)[1]
            for pair in qs.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    params[k] = v
        return params

    def _decode_cms_body(self, body: bytes) -> Optional[bytes]:
        """Accept raw DER or base64-encoded DER."""
        if not body:
            return None
        # Try raw DER first (starts with SEQUENCE tag 0x30)
        if body[0:1] == b"\x30":
            return body
        # Try base64
        try:
            return base64.b64decode(body)
        except Exception:
            pass
        # Try URL-encoded base64
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(body.decode("ascii", errors="replace"))
            return base64.b64decode(decoded)
        except Exception:
            return None

    def _extract_csr_challenge(self, csr_der: bytes) -> Optional[str]:
        """
        Extract challengePassword from a PKCS#10 CSR's attributes.
        CSR attributes are in certificationRequestInfo.attributes [0].
        """
        try:
            # PKCS#10 CSR:
            # SEQUENCE {
            #   CertificationRequestInfo,
            #   AlgorithmIdentifier,
            #   BIT STRING (signature)
            # }
            # CertificationRequestInfo:
            # SEQUENCE {
            #   version INTEGER,
            #   subject Name,
            #   subjectPublicKeyInfo,
            #   attributes [0] IMPLICIT Attributes
            # }
            tag, cri_val, _ = _decode_tlv(csr_der, 0)    # outer SEQUENCE
            tag, cri_seq, cri_next = _decode_tlv(cri_val, 0)  # CertificationRequestInfo
            cri_pos = 0
            # version
            tag, ver, cri_pos = _decode_tlv(cri_seq, cri_pos)
            # subject
            tag, subj, cri_pos = _decode_tlv(cri_seq, cri_pos)
            # subjectPublicKeyInfo
            tag, spki, cri_pos = _decode_tlv(cri_seq, cri_pos)
            # attributes [0]
            while cri_pos < len(cri_seq):
                tag, attr_set, cri_pos = _decode_tlv(cri_seq, cri_pos)
                if tag != 0xA0:
                    continue
                # Walk attributes
                apos = 0
                while apos < len(attr_set):
                    tag, attr_seq, apos = _decode_tlv(attr_set, apos)
                    if tag != 0x30:
                        continue
                    a_pos = 0
                    tag2, oid_bytes, a_pos = _decode_tlv(attr_seq, a_pos)
                    oid_str = _decode_oid_bytes(oid_bytes)
                    if oid_str == "1.2.840.113549.1.9.7":  # challengePassword
                        tag3, values, a_pos = _decode_tlv(attr_seq, a_pos)
                        # attrValues SET — first element
                        tag4, pw_bytes, _ = _decode_tlv(values, 0)
                        return pw_bytes.decode("utf-8", errors="replace").strip()
        except Exception as e:
            logger.debug(f"challengePassword extraction failed: {e}")
        return None

    def _extract_serial_from_ian(self, data: bytes) -> Optional[int]:
        """Extract serial number integer from IssuerAndSerialNumber DER."""
        try:
            tag, ian_val, _ = _decode_tlv(data, 0)
            pos = 0
            # issuer Name
            tag, issuer, pos = _decode_tlv(ian_val, pos)
            # serialNumber INTEGER
            tag, serial_bytes, pos = _decode_tlv(ian_val, pos)
            return int.from_bytes(serial_bytes, "big")
        except Exception:
            return None

    def _verify_renewal(self, cert_ders: list) -> bool:
        """
        Check if any certificate in the CMS envelope was issued by our CA.
        If so, treat this as a valid renewal (no challenge required).
        """
        ca_ski = self.ca.ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.key_identifier
        for cert_der in cert_ders:
            try:
                cert = x509.load_der_x509_certificate(cert_der)
                try:
                    aki = cert.extensions.get_extension_for_class(
                        x509.AuthorityKeyIdentifier
                    ).value.key_identifier
                    if aki == ca_ski:
                        return True
                except x509.ExtensionNotFound:
                    # Fallback: check issuer name
                    if cert.issuer == self.ca.ca_cert.subject:
                        return True
            except Exception:
                continue
        return False


def hmac_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks on challenge check."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ---------------------------------------------------------------------------
# Standalone entry point / integration helper
# ---------------------------------------------------------------------------

def start_scep_server(
    host: str,
    port: int,
    ca: "CertificateAuthority",
    ca_dir: Path,
    challenge: str = "",
    auto_issue: bool = True,
) -> http.server.HTTPServer:
    """
    Start the SCEP server in a background thread.
    Returns the HTTPServer instance so the caller can shut it down.
    """
    db_path = str(ca_dir / "scep.db")
    db = SCEPDatabase(db_path)

    class BoundSCEPHandler(SCEPHandler):
        pass

    BoundSCEPHandler.ca = ca
    BoundSCEPHandler.db = db
    BoundSCEPHandler.challenge = challenge
    BoundSCEPHandler.auto_issue = auto_issue

    import http.server as _hs
    class _ThreadedServer(_hs.ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = _ThreadedServer((host, port), BoundSCEPHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info(f"SCEP server listening on http://{host}:{port}/scep")
    return srv


def main():
    parser = argparse.ArgumentParser(description="SCEP Server (RFC 8894)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8889)
    parser.add_argument("--ca-dir", default="./ca")
    parser.add_argument("--challenge", default="",
                        help="Shared challenge password (empty = no challenge required)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level)

    # Import CA from pki_cmpv2_server
    try:
        from pki_cmpv2_server import CertificateAuthority, ServerConfig
    except ImportError:
        print("ERROR: pki_cmpv2_server.py not found — place it in the same directory.")
        raise SystemExit(1)

    ca_dir = Path(args.ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    config = ServerConfig(ca_dir=ca_dir)
    ca = CertificateAuthority(ca_dir=args.ca_dir, config=config)

    srv = start_scep_server(
        host=args.host,
        port=args.port,
        ca=ca,
        ca_dir=ca_dir,
        challenge=args.challenge,
    )

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║               PyPKI SCEP Server (RFC 8894)                      ║
╠══════════════════════════════════════════════════════════════════╣
║  Endpoint  : http://{args.host}:{args.port}/scep{' ' * (38 - len(str(args.port)))}║
║  CA Dir    : {args.ca_dir:<51}║
║  Challenge : {'set' if args.challenge else 'none (open enrolment)':<51}║
╠══════════════════════════════════════════════════════════════════╣
║  Operations:                                                    ║
║    GetCACaps     GET  /scep?operation=GetCACaps                 ║
║    GetCACert     GET  /scep?operation=GetCACert                 ║
║    PKCSReq       POST /scep?operation=PKCSReq                   ║
║    CertPoll      POST /scep?operation=CertPoll                  ║
║    GetCert       POST /scep?operation=GetCert                   ║
║    GetCRL        POST /scep?operation=GetCRL                    ║
╠══════════════════════════════════════════════════════════════════╣
║  Test with sscep or openssl + scep plugin:                      ║
║    sscep getca -u http://{args.host}:{args.port}/scep -c ca.crt{' ' * max(0, 16 - len(str(args.port)))}║
╚══════════════════════════════════════════════════════════════════╝
""")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down SCEP server...")
        srv.shutdown()


if __name__ == "__main__":
    main()
