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

Dependencies (same as pki_server.py):
    pip install cryptography

Usage:
    Standalone:
        python scep_server.py [--host 0.0.0.0] [--port 8889] [--ca-dir ./ca]
                               [--challenge mysecret]

    Integrated (via pki_server.py --scep-port 8889):
        python pki_server.py --scep-port 8889 [--scep-challenge mysecret]
"""

import argparse
import base64
import datetime
import hashlib
import http.server
import json
import logging
import os
from db import make_db, Database
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID

logger = logging.getLogger("scep")

from der_codec import (
    encode_length as _encode_length, decode_length as _decode_length,
    decode_tlv as _decode_tlv, seq as _seq, set_ as _set, ctx as _ctx,
    oid as _oid, integer as _integer, octet_string as _octet_string,
    printable_string as _printable_string, utf8_string as _utf8_string,
    null as _null, bool_ as _bool, decode_oid_bytes as _decode_oid_bytes,
    OID_RSA_ENCRYPTION, OID_SHA1_WITH_RSA, OID_SHA256_WITH_RSA, OID_MD5_WITH_RSA,
    OID_DATA, OID_SIGNED_DATA, OID_ENVELOPED_DATA, OID_AUTH_ENVELOPED_DATA,
    OID_CONTENT_TYPE, OID_MESSAGE_DIGEST, OID_SIGNING_TIME, OID_SMIME_CAP,
    OID_TRANSACTION_ID, OID_SENDER_NONCE, OID_RECIPIENT_NONCE,
    OID_PKI_STATUS, OID_FAIL_INFO, OID_MESSAGE_TYPE, OID_CHALLENGE_PASSWORD,
    OID_DES_CBC, OID_DES_EDE3_CBC,
    OID_AES_128_CBC, OID_AES_192_CBC, OID_AES_256_CBC,
    OID_AES_128_GCM, OID_AES_256_GCM,
    OID_SHA1, OID_SHA256, OID_COMMON_NAME,
)

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
    def parse_enveloped_data(der: bytes, private_key) -> bytes:
        """
        Parse a CMS ContentInfo wrapping either EnvelopedData (CBC, RFC 5652)
        or AuthEnvelopedData (AES-GCM, RFC 5083 / RFC 5084) and return the
        decrypted plaintext.

        Dispatches on the content-type OID:
          id-envelopedData     (1.2.840.113549.1.7.3) → AES-CBC / 3DES-CBC
          id-ct-authEnvelopedData (1.2.840.113549.1.9.16.1.23) → AES-GCM
        """
        # ContentInfo: SEQUENCE { contentType OID, content [0] }
        tag, ci_val, _ = _decode_tlv(der, 0)
        ci_pos = 0
        tag, oid_val, ci_pos = _decode_tlv(ci_val, ci_pos)
        content_type = _decode_oid_bytes(oid_val)
        tag, ev_outer, ci_pos = _decode_tlv(ci_val, ci_pos)

        if content_type == OID_AUTH_ENVELOPED_DATA:
            return CMSParser._decrypt_auth_enveloped(ev_outer, private_key)
        return CMSParser._decrypt_enveloped(ev_outer, private_key)

    @staticmethod
    def _decrypt_enveloped(ev_outer: bytes, private_key) -> bytes:
        """Decrypt a CMS EnvelopedData value (AES-CBC or 3DES-CBC)."""
        # EnvelopedData SEQUENCE
        tag, ev_val, _ = _decode_tlv(ev_outer, 0)

        ev_pos = 0
        tag, _ver, ev_pos = _decode_tlv(ev_val, ev_pos)          # version
        tag, ri_set, ev_pos = _decode_tlv(ev_val, ev_pos)        # recipientInfos SET
        tag, eci_val, ev_pos = _decode_tlv(ev_val, ev_pos)       # encryptedContentInfo

        encrypted_key = None
        ri_pos = 0
        while ri_pos < len(ri_set):
            tag, ri_val, ri_pos = _decode_tlv(ri_set, ri_pos)
            if tag != 0x30:
                continue
            r_pos = 0
            _, _, r_pos = _decode_tlv(ri_val, r_pos)  # version
            _, _, r_pos = _decode_tlv(ri_val, r_pos)  # sid
            _, _, r_pos = _decode_tlv(ri_val, r_pos)  # keyEncryptionAlgorithm
            if r_pos < len(ri_val):
                _, ri_ek, _ = _decode_tlv(ri_val, r_pos)
                encrypted_key = ri_ek
                break

        if encrypted_key is None:
            raise ValueError("No usable RecipientInfo found")

        try:
            cek = private_key.decrypt(encrypted_key, asym_padding.PKCS1v15())
        except Exception as e:
            raise ValueError(f"Could not decrypt content encryption key: {e}")

        eci_pos = 0
        _, _, eci_pos = _decode_tlv(eci_val, eci_pos)        # contentType OID
        tag, ca_seq, eci_pos = _decode_tlv(eci_val, eci_pos) # contentEncryptionAlgorithm
        ca_pos = 0
        tag, ce_oid_val, ca_pos = _decode_tlv(ca_seq, ca_pos)
        enc_alg_oid = _decode_oid_bytes(ce_oid_val)
        tag, iv_val, _ = _decode_tlv(ca_seq, ca_pos)
        tag, ec_val, _ = _decode_tlv(eci_val, eci_pos)

        if ec_val and ec_val[0] == 0x80:
            _, ec_val, _ = _decode_tlv(ec_val, 0)

        if enc_alg_oid in (OID_AES_256_CBC, OID_AES_192_CBC, OID_AES_128_CBC):
            key_size = {OID_AES_128_CBC: 16, OID_AES_192_CBC: 24, OID_AES_256_CBC: 32}[enc_alg_oid]
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

    @staticmethod
    def _decrypt_auth_enveloped(ev_outer: bytes, private_key) -> bytes:
        """
        Decrypt a CMS AuthEnvelopedData value (AES-256-GCM).

        RFC 5083 §2 / RFC 5084 §3.1.  The MAC (auth tag) is a separate
        ``mac`` field at the end of the AuthEnvelopedData SEQUENCE; the
        cryptography library expects ciphertext || tag when decrypting.
        """
        # AuthEnvelopedData SEQUENCE
        tag, ev_val, _ = _decode_tlv(ev_outer, 0)
        ev_pos = 0
        _, _ver,     ev_pos = _decode_tlv(ev_val, ev_pos)   # version

        # optional originatorInfo [0]
        if ev_pos < len(ev_val) and ev_val[ev_pos] == 0xA0:
            _, _, ev_pos = _decode_tlv(ev_val, ev_pos)

        _, ri_set,   ev_pos = _decode_tlv(ev_val, ev_pos)   # recipientInfos SET
        _, aci_val,  ev_pos = _decode_tlv(ev_val, ev_pos)   # authEncryptedContentInfo

        # optional authAttrs [1] IMPLICIT
        if ev_pos < len(ev_val) and ev_val[ev_pos] == 0xA1:
            _, _, ev_pos = _decode_tlv(ev_val, ev_pos)

        # mac OCTET STRING — auth tag (16 bytes for AES-256-GCM)
        _, mac_tag, _ = _decode_tlv(ev_val, ev_pos)

        # Decrypt CEK using RSA PKCS#1v15
        encrypted_key = None
        ri_pos = 0
        while ri_pos < len(ri_set):
            tag, ri_val, ri_pos = _decode_tlv(ri_set, ri_pos)
            if tag != 0x30:
                continue
            r_pos = 0
            _, _, r_pos = _decode_tlv(ri_val, r_pos)  # version
            _, _, r_pos = _decode_tlv(ri_val, r_pos)  # sid
            _, _, r_pos = _decode_tlv(ri_val, r_pos)  # keyEncryptionAlgorithm
            if r_pos < len(ri_val):
                _, ri_ek, _ = _decode_tlv(ri_val, r_pos)
                encrypted_key = ri_ek
                break

        if encrypted_key is None:
            raise ValueError("No usable RecipientInfo in AuthEnvelopedData")

        try:
            cek = private_key.decrypt(encrypted_key, asym_padding.PKCS1v15())
        except Exception as e:
            raise ValueError(f"AuthEnvelopedData: could not decrypt CEK: {e}")

        # Parse authEncryptedContentInfo: { contentType, contentEncAlg, [0] encryptedContent }
        aci_pos = 0
        _, _, aci_pos = _decode_tlv(aci_val, aci_pos)          # contentType OID
        _, ca_seq, aci_pos = _decode_tlv(aci_val, aci_pos)     # contentEncryptionAlgorithm

        ca_pos = 0
        _, ce_oid_val, ca_pos = _decode_tlv(ca_seq, ca_pos)
        enc_alg_oid = _decode_oid_bytes(ce_oid_val)

        if enc_alg_oid not in (OID_AES_256_GCM, OID_AES_128_GCM):
            raise ValueError(
                f"AuthEnvelopedData: unsupported algorithm {enc_alg_oid}; "
                "only AES-128-GCM and AES-256-GCM are supported"
            )

        # GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING, aes-ICVlen INTEGER DEFAULT 12 }
        _, gcm_params, _ = _decode_tlv(ca_seq, ca_pos)
        gp_pos = 0
        _, nonce, gp_pos = _decode_tlv(gcm_params, gp_pos)

        # encryptedContent [0] IMPLICIT — raw ciphertext (no tag, tag follows separately)
        _, ec_val, _ = _decode_tlv(aci_val, aci_pos)
        if ec_val and ec_val[0] == 0x80:
            _, ec_val, _ = _decode_tlv(ec_val, 0)

        key_size = 32 if enc_alg_oid == OID_AES_256_GCM else 16
        aesgcm = AESGCM(cek[:key_size])
        # Reassemble ciphertext + auth tag for library decryption
        return aesgcm.decrypt(nonce, ec_val + mac_tag, None)


def _cms_content_type(der: bytes) -> str:
    """
    Return the contentType OID dotted string from a DER-encoded ContentInfo,
    or an empty string if the structure cannot be parsed.

    Used to detect whether an incoming inner CMS payload is ``EnvelopedData``
    (classic CBC) or ``AuthEnvelopedData`` (AES-GCM) without fully parsing it.
    """
    try:
        _, ci_val, _ = _decode_tlv(der, 0)
        _, oid_val, _ = _decode_tlv(ci_val, 0)
        return _decode_oid_bytes(oid_val)
    except Exception:
        return ""


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

    @staticmethod
    def auth_enveloped_data(plaintext: bytes, recipient_cert: x509.Certificate) -> bytes:
        """
        Encrypt *plaintext* for *recipient_cert* using RSA PKCS#1v15 key transport
        and AES-256-GCM content encryption.  Returns DER-encoded CMS
        ``AuthEnvelopedData`` wrapped in ``ContentInfo``.

        RFC 5083 §2 / RFC 5084 §3.1.

        Structure::

          ContentInfo {
            id-ct-authEnvelopedData
            AuthEnvelopedData {
              version v0
              recipientInfos { KeyTransRecipientInfo (RSA-PKCS1v15, encrypted CEK) }
              authEncryptedContentInfo {
                id-data
                GCM AlgorithmIdentifier { id-aes256-GCM, GCMParameters { nonce, ICVlen=16 } }
                [0] ciphertext        -- without the 16-byte auth tag
              }
              mac = 16-byte GCM auth tag
            }
          }

        Compared to :meth:`enveloped_data` (AES-256-CBC):

        - No PKCS#7 padding — GCM is a stream mode.
        - 12-byte random nonce instead of 16-byte IV.
        - 16-byte auth tag provides integrity; stored in the ``mac`` field.
        - Eliminates CBC padding-oracle surface (RFC 5083 motivation).
        """
        # CEK + GCM nonce
        cek   = os.urandom(32)   # 256-bit key
        nonce = os.urandom(12)   # 96-bit nonce (GCM recommended)

        # Encrypt — output is ciphertext || 16-byte tag
        ct_with_tag = AESGCM(cek).encrypt(nonce, plaintext, None)
        ciphertext  = ct_with_tag[:-16]
        mac_tag     = ct_with_tag[-16:]

        # Encrypt CEK with recipient's RSA public key
        encrypted_key = recipient_cert.public_key().encrypt(cek, asym_padding.PKCS1v15())

        # KeyTransRecipientInfo
        ian = _seq(
            recipient_cert.issuer.public_bytes()
            + _integer(recipient_cert.serial_number)
        )
        ri = _seq(
            _integer(0)
            + ian
            + _seq(_oid(OID_RSA_ENCRYPTION) + _null())
            + _octet_string(encrypted_key)
        )

        # GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING, aes-ICVlen INTEGER DEFAULT 12 }
        # We use 16-byte tag (not the default 12), so ICVlen must be explicit.
        gcm_params = _seq(_octet_string(nonce) + _integer(16))

        # authEncryptedContentInfo
        # encryptedContent as [0] IMPLICIT (primitive, context 0)
        ec_tag = b"\x80" + _encode_length(len(ciphertext)) + ciphertext
        auth_eci = _seq(
            _oid(OID_DATA)
            + _seq(_oid(OID_AES_256_GCM) + gcm_params)
            + ec_tag
        )

        # AuthEnvelopedData (version v0: no originator info, RSAES recipient)
        auth_ev = _seq(
            _integer(0)           # version
            + _set(ri)            # recipientInfos
            + auth_eci            # authEncryptedContentInfo
            # no authAttrs [1]
            + _octet_string(mac_tag)  # mac (GCM auth tag)
        )

        # ContentInfo
        return _seq(
            _oid(OID_AUTH_ENVELOPED_DATA)
            + _ctx(0, auth_ev)
        )


# ---------------------------------------------------------------------------
# SCEP database
# ---------------------------------------------------------------------------

class SCEPDatabase:
    """DAL-backed store for SCEP enrolments and OTP tokens.

    Accepts a ``Database`` object so the backend is configurable — SQLite for
    single-node deployments, PostgreSQL for HA (§5.2).
    """

    def __init__(self, db):
        if isinstance(db, str):
            from db import make_db
            db = make_db(f"sqlite:///{db}")
        self._db = db
        self._init_db()

    def _init_db(self):
        self._db.execute("""
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
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS otp_tokens (
                token       TEXT PRIMARY KEY,
                created_at  REAL NOT NULL,
                expires_at  REAL NOT NULL,
                consumed_at REAL
            )
        """)

    # ------------------------------------------------------------------
    # One-time password (OTP) helpers
    # ------------------------------------------------------------------

    def add_otp(self, ttl_seconds: int = 86400) -> str:
        """Mint a single-use SCEP challenge OTP. Returns the token string."""
        import base64
        token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
        now = time.time()
        self._db.execute(
            "INSERT INTO otp_tokens (token, created_at, expires_at) VALUES (?, ?, ?)",
            (token, now, now + ttl_seconds),
        )
        return token

    def consume_otp(self, token: str) -> bool:
        """Atomically consume an OTP. Returns True iff the token was valid and unused."""
        now = time.time()
        try:
            with self._db.advisory_lock("scep-otp"):
                row = self._db.fetchone(
                    "SELECT consumed_at, expires_at FROM otp_tokens WHERE token = ?",
                    (token,),
                )
                if row is None or row["consumed_at"] is not None or row["expires_at"] < now:
                    return False
                self._db.execute(
                    "UPDATE otp_tokens SET consumed_at = ? WHERE token = ?",
                    (now, token),
                )
            return True
        except Exception:
            return False

    def purge_expired_otps(self) -> int:
        """Delete consumed or expired OTP rows. Returns count deleted."""
        rows_before = self._db.fetchone("SELECT COUNT(*) FROM otp_tokens")[0]
        self._db.execute(
            "DELETE FROM otp_tokens WHERE consumed_at IS NOT NULL OR expires_at < ?",
            (time.time(),),
        )
        rows_after = self._db.fetchone("SELECT COUNT(*) FROM otp_tokens")[0]
        return rows_before - rows_after

    def create_transaction(self, txid: str, subject: str, csr_pem: str, ip: str):
        now = time.time()
        self._db.execute(
            "INSERT OR REPLACE INTO scep_transactions VALUES (?,?,?,?,?,?,?,?,?,?)",
            (txid, "pending", subject, csr_pem, None, None, None, ip, now, now)
        )

    def set_success(self, txid: str, cert_pem: str):
        self._db.execute(
            "UPDATE scep_transactions SET status='success', cert_pem=?, updated_at=? WHERE transaction_id=?",
            (cert_pem, time.time(), txid)
        )

    def set_failure(self, txid: str, fail_info: str, reason: str):
        self._db.execute(
            "UPDATE scep_transactions SET status='failure', fail_info=?, fail_reason=?, updated_at=? WHERE transaction_id=?",
            (fail_info, reason, time.time(), txid)
        )

    def get(self, txid: str) -> Optional[Dict[str, Any]]:
        row = self._db.fetchone(
            "SELECT * FROM scep_transactions WHERE transaction_id=?", (txid,)
        )
        return dict(row) if row else None

    def all_transactions(self) -> list:
        rows = self._db.fetchall(
            "SELECT * FROM scep_transactions ORDER BY created_at DESC"
        )
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# SCEP Request Handler
# ---------------------------------------------------------------------------

class SCEPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for SCEP (RFC 8894)."""

    ca: "CertificateAuthority" = None
    db: SCEPDatabase = None
    challenge: str = ""           # shared challenge password (empty = no check)
    use_otp: bool = False         # also accept single-use OTP challenges
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

            if path not in ("/", "/pkiclient.exe", "/cgi-bin/pkiclient.exe"):
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
        RFC 8894 §4.2 — GetCACert returns DER for a single CA, p7c (PKCS#7
        degenerate SignedData) when running as an intermediate CA with a chain.
        """
        chain_ders = self.ca.ca_chain_ders   # [leaf_der, parent_der, ..., root_der]

        if len(chain_ders) == 1:
            # Root CA — return plain DER per RFC 8894 §4.2
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Length", str(len(chain_ders[0])))
            self.end_headers()
            self.wfile.write(chain_ders[0])
            logger.info("GetCACert: sent CA certificate (root mode)")
        else:
            # Intermediate CA — wrap full chain in PKCS#7 degenerate SignedData
            # per RFC 8894 §4.2 ("If the CA has multiple CA certificates, a p7c
            # chain will be returned").
            from cryptography.hazmat.primitives.serialization import pkcs7 as _p7
            # Build a minimal degenerate CMS/PKCS#7 certs-only structure.
            # We re-use the EST helper which produces the same encoding.
            cert_bytes = b"".join(chain_ders)

            def _seq(b): n=len(b); return (b"0"+(bytes([n]) if n<128 else bytes([0x80|(len(n:=n.to_bytes((n.bit_length()+7)//8,"big")))]+list(n)))+b)
            def _ctx(n,b): l=len(b); return (bytes([0xa0|n])+(bytes([l]) if l<128 else bytes([0x80|(len(ll:=l.to_bytes((l.bit_length()+7)//8,"big")))]+list(ll)))+b)
            def _oid(o):
                parts=[int(x) for x in o.split(".")];v=parts[0]*40+parts[1];r=b""
                for p in [v]+parts[2:]:
                    g=[];g.insert(0,p&0x7f);p>>=7
                    while p:g.insert(0,(p&0x7f)|0x80);p>>=7
                    r+=bytes(g)
                return b""+bytes([len(r)])+r
            def _set(b): n=len(b); return b"1"+(bytes([n]) if n<128 else bytes([0x80|(len(nn:=n.to_bytes((n.bit_length()+7)//8,"big")))]+list(nn)))+b
            def _int(v): return b""+bytes([v])

            OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
            OID_DATA        = "1.2.840.113549.1.7.1"
            sd_inner = (
                _int(1)
                + _set(b"")
                + _seq(_oid(OID_DATA))
                + _ctx(0, cert_bytes)
                + _set(b"")
            )
            p7_der = _seq(_oid(OID_SIGNED_DATA) + _ctx(0, _seq(sd_inner)))

            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-ra-cert")
            self.send_header("Content-Length", str(len(p7_der)))
            self.end_headers()
            self.wfile.write(p7_der)
            logger.info(
                "GetCACert: sent CA chain as p7c (%d certs, intermediate mode)",
                len(chain_ders),
            )

    def _handle_get_ca_caps(self):
        """
        Return server capabilities as newline-delimited string.
        RFC 8894 §4.1.
        """
        caps = "\n".join([
            "AES",              # AES-CBC content encryption (RFC 8894)
            "AES-GCM",          # AES-GCM AuthEnvelopedData (RFC 5083 / RFC 5084)
            "SHA-256",
            "SHA-512",
            "Renewal",
            "POSTPKIOperation",
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

        # Detect encryption scheme: EnvelopedData (CBC) or AuthEnvelopedData (GCM)
        enc_scheme = "gcm" if _cms_content_type(inner_cms) == OID_AUTH_ENVELOPED_DATA else "cbc"
        logger.info(f"PKCSReq txid={transaction_id} encryption={enc_scheme.upper()}")

        # Decrypt EnvelopedData / AuthEnvelopedData to get the PKCS#10 CSR
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

        # Challenge password verification (static shared secret and/or single-use OTP)
        challenge_ok = True
        if self.challenge or self.use_otp:
            csr_challenge = self._extract_csr_challenge(csr_der)
            if not csr_challenge:
                logger.warning(f"No challengePassword in CSR from {subject_str}")
                challenge_ok = False
            else:
                accepted = False
                # Try OTP path first (single-use, consumed atomically)
                if self.use_otp and self.db.consume_otp(csr_challenge):
                    accepted = True
                    logger.info(f"SCEP OTP consumed for {subject_str}")
                # Fall back to static shared secret
                if not accepted and self.challenge:
                    if hmac_compare(csr_challenge.encode(), self.challenge.encode()):
                        accepted = True
                if not accepted:
                    logger.warning(f"Wrong or expired challengePassword from {subject_str}")
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
                protocol="scep",
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

def mint_otp(ca_dir, ttl_seconds: int = 86400) -> str:
    """
    Mint a single-use SCEP challenge OTP from outside the handler.

    Useful for web-UI admin endpoints and CLI tooling that need to
    produce OTPs without a reference to the running handler instance.
    """
    db = SCEPDatabase(make_db(f"sqlite:///{Path(ca_dir) / 'scep.db'}"))
    return db.add_otp(ttl_seconds)


def start_scep_server(
    route_table,
    prefix: str,
    ca: "CertificateAuthority",
    ca_dir: Path,
    challenge: str = "",
    auto_issue: bool = True,
    use_otp: bool = False,
    db_url: str = "",
):
    """
    Register the SCEP handler with *route_table* under *prefix*.

    Returns a _RouteProxy whose .shutdown() unregisters the SCEP routes.

    SCEP is CMS-based (RFC 8894 §3 cites RFC 5652). CMS SignerInfo carries
    a named digestAlgorithm; EdDSA (RFC 8410) signs internally with no
    separate hash and is therefore incompatible with this code path.
    ECDSA support is not yet wired here either — the signer below
    hardcodes RSA-PKCS1v15. Fail fast at startup so the operator sees the
    incompatibility before any client enrolls.
    """
    from dispatcher_server import _RouteProxy

    # RFC compatibility guardrail. PSS-capable RSA keys still work because
    # this signer issues PKCS#1 v1.5 specifically (which RFC 8894 allows).
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        if not isinstance(ca.ca_key, _rsa.RSAPrivateKey):
            raise RuntimeError(
                "SCEP requires an RSA CA key. The current CA key is "
                f"{type(ca.ca_key).__name__}; SCEP CMS SignedData (RFC 5652) "
                "cannot use ECDSA or EdDSA in this server. Either run with "
                "--ca-key-type rsa-... or disable SCEP."
            )
    except ImportError:
        pass

    _scep_url = db_url or f"sqlite:///{ca_dir / 'scep.db'}"
    db = SCEPDatabase(make_db(_scep_url))

    class BoundSCEPHandler(SCEPHandler):
        pass

    BoundSCEPHandler.ca = ca
    BoundSCEPHandler.db = db
    BoundSCEPHandler.challenge = challenge
    BoundSCEPHandler.use_otp = use_otp
    BoundSCEPHandler.auto_issue = auto_issue

    route_table.register(prefix, BoundSCEPHandler)
    logger.info(f"SCEP handler registered at prefix {prefix!r}")
    proxy = _RouteProxy(route_table, prefix, label="scep")
    proxy.scep_db = db   # expose for web UI OTP minting
    return proxy


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

    # Import CA from pki_server
    try:
        from pki_server import CertificateAuthority, ServerConfig
    except ImportError:
        print("ERROR: pki_server.py not found — place it in the same directory.")
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
