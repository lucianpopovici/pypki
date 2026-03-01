#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
#
# cmp_server.py — CMPv2 / CMPv3 server module
# ============================================
# RFC 4210  CMPv2 — Certificate Management Protocol v2
# RFC 9480  CMPv3 — CMP Updates (pvno=3, new genm types, extended polling)
# RFC 6712  CMP over HTTP
# RFC 9811  CMP well-known URI paths
# RFC 9483  Lightweight CMP Profile (ALPN "cmpc")
#
# Extracted from pki_server.py so the CMP logic lives in its own module,
# consistent with acme_server.py, scep_server.py, est_server.py, ocsp_server.py.
#
# Public API
# ----------
#   CMPv2ASN1              ASN.1 DER parser/builder for PKIMessages
#   CMPv2Handler           RFC 4210 request handler
#   CMPv3Handler           RFC 9480 handler (extends CMPv2Handler)
#   CMPv2HTTPHandler       HTTP transport handler (RFC 6712)
#   ThreadedHTTPServer     Threaded HTTPServer
#   TLSServer              TLS-capable server (one-way and mTLS)
#   MTLSServer             Backwards-compatible alias for TLSServer
#   make_handler()         Bind CA + handler for CMPv2
#   make_cmpv3_handler()   Bind CA + handler for CMPv3
#   start_cmp_server()     Start CMP in a background thread
#   start_bootstrap_server() Plain-HTTP bootstrap endpoint

import argparse
import base64
import datetime
import hashlib
import hmac
import http.server
import json
import logging
import os
import re
import socket
import sqlite3
import ssl
import struct
import tempfile
import threading
import time
import traceback
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

try:
    from pyasn1.type import univ, namedtype, tag, constraint, namedval, useful
    from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
    from pyasn1.codec.native import decoder as nat_decoder
    from pyasn1 import error as asn1_error
    HAS_PYASN1 = True
except ImportError:
    HAS_PYASN1 = False

# pki_server core — CA engine and supporting classes
from pki_server import (
    CertificateAuthority,
    AuditLog,
    RateLimiter,
    CertProfile,
    ServerConfig,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pki-cmpv2")

class CMPv2ASN1:
    """
    Hand-rolled ASN.1 DER parser/builder for CMP messages.
    Uses pyasn1 when available, falls back to manual parsing.
    """

    # CMP PKIBody types (RFC 4210 Section 5.3)
    BODY_TYPES = {
        0:  "ir",       # Initialization Request
        1:  "ip",       # Initialization Response
        2:  "cr",       # Certification Request
        3:  "cp",       # Certification Response
        4:  "p10cr",    # PKCS#10 Cert Request
        5:  "popdecc",  # POP Challenge
        6:  "popdecr",  # POP Response
        7:  "kur",      # Key Update Request
        8:  "kup",      # Key Update Response
        9:  "krr",      # Key Recovery Request
        10: "krp",      # Key Recovery Response
        11: "rr",       # Revocation Request
        12: "rp",       # Revocation Response
        13: "ccr",      # Cross-Cert Request
        14: "ccp",      # Cross-Cert Response
        15: "ckuann",   # CA Key Update Announcement
        16: "cann",     # Certificate Announcement
        17: "rann",     # Revocation Announcement
        18: "crlann",   # CRL Announcement
        19: "pkiconf",  # PKI Confirmation
        20: "nested",   # Nested Message
        21: "genm",     # General Message
        22: "genp",     # General Response
        23: "error",    # Error Message
        24: "certConf", # Certificate Confirmation
        25: "pollReq",  # Polling Request
        26: "pollRep",  # Polling Response
    }

    @staticmethod
    def _encode_length(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        elif length < 0x10000:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])

    @staticmethod
    def _decode_length(data: bytes, offset: int) -> Tuple[int, int]:
        first = data[offset]
        if first < 0x80:
            return first, offset + 1
        num_bytes = first & 0x7F
        length = 0
        for i in range(num_bytes):
            length = (length << 8) | data[offset + 1 + i]
        return length, offset + 1 + num_bytes

    @classmethod
    def _decode_tlv(cls, data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
        """Returns (tag, value_bytes, next_offset)"""
        tag_byte = data[offset]
        offset += 1
        length, offset = cls._decode_length(data, offset)
        value = data[offset:offset + length]
        return tag_byte, value, offset + length

    @classmethod
    def parse_pki_message(cls, der_data: bytes) -> Dict[str, Any]:
        """
        Parse a DER-encoded PKIMessage (RFC 4210).
        Returns a dict with header, body type, and raw body bytes.
        """
        result = {
            "raw": der_data,
            "header": {},
            "body_type": None,
            "body_raw": None,
            "protection": None,
            "extra_certs": None,
        }

        try:
            # PKIMessage ::= SEQUENCE { header, body, [0] protection, [1] extraCerts }
            if data[0] != 0x30:
                raise ValueError(f"Expected SEQUENCE (0x30), got 0x{data[0]:02x}")

            # Unwrap outer SEQUENCE
            _, outer, _ = cls._decode_tlv(der_data, 0)
            data = outer
            pos = 0

            # Parse PKIHeader (SEQUENCE)
            tag_b, header_bytes, pos = cls._decode_tlv(data, pos)
            result["header"] = cls._parse_pki_header(header_bytes)

            # Parse PKIBody (CHOICE with context tags [0]..[26])
            if pos < len(data):
                body_tag = data[pos]
                body_len, body_val_start = cls._decode_length(data, pos + 1)
                body_val = data[body_val_start:body_val_start + body_len]

                # Context tag number = body type index
                ctx_tag = body_tag & 0x1F
                result["body_type"] = cls.BODY_TYPES.get(ctx_tag, f"unknown_{ctx_tag}")
                result["body_raw"] = body_val
                result["body_tag"] = ctx_tag
                pos = body_val_start + body_len

            # Parse optional protection [0] and extraCerts [1]
            while pos < len(data):
                opt_tag = data[pos]
                opt_len, opt_val_start = cls._decode_length(data, pos + 1)
                opt_val = data[opt_val_start:opt_val_start + opt_len]
                if opt_tag == 0xA0:
                    result["protection"] = opt_val
                elif opt_tag == 0xA1:
                    result["extra_certs"] = opt_val
                pos = opt_val_start + opt_len

        except Exception as e:
            logger.debug(f"ASN.1 parse error: {e}")
            result["parse_error"] = str(e)

        return result

    @classmethod
    def _parse_pki_header(cls, header_bytes: bytes) -> Dict[str, Any]:
        header = {}
        pos = 0
        field_idx = 0

        while pos < len(header_bytes):
            try:
                tag_b, val, pos = cls._decode_tlv(header_bytes, pos)
                if field_idx == 0:
                    header["pvno"] = int.from_bytes(val, "big") if val else 2
                elif field_idx == 1:
                    header["sender"] = val
                elif field_idx == 2:
                    header["recipient"] = val
                elif field_idx == 3:
                    header["messageTime"] = val
                elif field_idx == 4:
                    header["protectionAlg"] = val
                elif field_idx == 5:
                    header["senderKID"] = val
                elif field_idx == 6:
                    header["recipKID"] = val
                elif field_idx == 7:
                    header["transactionID"] = val
                elif field_idx == 8:
                    header["senderNonce"] = val
                elif field_idx == 9:
                    header["recipNonce"] = val
                field_idx += 1
            except Exception:
                break

        return header

    @classmethod
    def build_pki_message(
        cls,
        body_type: int,
        body_content: bytes,
        transaction_id: bytes,
        sender_nonce: bytes,
        recip_nonce: bytes = b"",
        status_code: int = 0,
        pvno: int = 2,
    ) -> bytes:
        """Build a minimal DER-encoded PKIMessage response.

        pvno=2 for CMPv2 (RFC 4210), pvno=3 for CMPv3 (RFC 9480).
        """

        def seq(content: bytes) -> bytes:
            return b"\x30" + cls._encode_length(len(content)) + content

        def ctx(n: int, content: bytes, constructed: bool = True) -> bytes:
            tag = (0xA0 | n) if constructed else (0x80 | n)
            return bytes([tag]) + cls._encode_length(len(content)) + content

        def integer(val: int, length: int = 1) -> bytes:
            v = val.to_bytes(length, "big")
            return b"\x02" + cls._encode_length(len(v)) + v

        def octet_string(val: bytes) -> bytes:
            return b"\x04" + cls._encode_length(len(val)) + val

        def generalizedtime(dt: datetime.datetime) -> bytes:
            s = dt.strftime("%Y%m%d%H%M%SZ").encode()
            return b"\x18" + cls._encode_length(len(s)) + s

        def null() -> bytes:
            return b"\x05\x00"

        def oid(dotted: str) -> bytes:
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
            return b"\x06" + cls._encode_length(len(encoded)) + encoded

        # Build PKIHeader
        pvno_field = integer(pvno)

        # sender/recipient: use NULL GeneralName (directoryName with empty DN)
        sender = ctx(4, seq(b""), constructed=True)   # GeneralName [4] directoryName
        recipient = ctx(4, seq(b""), constructed=True)

        msg_time = ctx(0, generalizedtime(datetime.datetime.now(datetime.timezone.utc)), constructed=False)

        # sha256WithRSAEncryption OID for protection alg hint
        prot_alg = ctx(1, seq(oid("1.2.840.113549.1.1.11") + null()), constructed=False)

        tid = ctx(4, octet_string(transaction_id), constructed=False)
        snonce = ctx(5, octet_string(sender_nonce), constructed=False)

        header_content = pvno_field + sender + recipient + msg_time + prot_alg + tid + snonce
        if recip_nonce:
            header_content += ctx(6, octet_string(recip_nonce), constructed=False)

        header = seq(header_content)

        # Build PKIBody
        body = ctx(body_type, body_content)

        # Combine into PKIMessage
        pki_msg = seq(header + body)
        return pki_msg

    @classmethod
    def build_ip_cp_body(
        cls,
        cert_der: bytes,
        status: int = 0,           # 0=accepted, 1=grantedWithMods, 2=rejection
        fail_info: Optional[int] = None,
        request_id: int = 0,
    ) -> bytes:
        """Build CertRepMessage body for ip/cp responses."""

        def seq(c): return b"\x30" + cls._encode_length(len(c)) + c
        def integer(v, length=1): v_b = v.to_bytes(max(length, (v.bit_length()+8)//8), "big"); return b"\x02" + cls._encode_length(len(v_b)) + v_b
        def ctx(n, c, constructed=True): t = (0xA0 | n) if constructed else (0x80 | n); return bytes([t]) + cls._encode_length(len(c)) + c
        def ctx_nc(n, c): return bytes([0x80 | n]) + cls._encode_length(len(c)) + c

        # PKIStatusInfo
        pki_status = seq(integer(status))

        # CertifiedKeyPair (only on success)
        if status in (0, 1) and cert_der:
            # certOrEncCert CHOICE [0] certificate
            cert_choice = ctx(0, ctx(0, cert_der))
            cert_key_pair = seq(cert_choice)
            cert_response = seq(integer(request_id) + pki_status + cert_key_pair)
        else:
            cert_response = seq(integer(request_id) + pki_status)

        # CertRepMessage ::= SEQUENCE { [1] caPubs OPTIONAL, response SEQUENCE }
        response_seq = seq(cert_response)
        cert_rep = seq(response_seq)

        return cert_rep

    @classmethod
    def build_error_body(cls, status: int, text: str) -> bytes:
        def seq(c): return b"\x30" + cls._encode_length(len(c)) + c
        def integer(v): v_b = v.to_bytes(1, "big"); return b"\x02\x01" + v_b
        def utf8str(s):
            e = s.encode()
            return b"\x0c" + cls._encode_length(len(e)) + e

        status_info = seq(integer(status) + utf8str(text))
        return seq(status_info)

    @classmethod
    def build_pkiconf_body(cls) -> bytes:
        return b"\x05\x00"  # NULL

    @classmethod
    def build_rp_body(cls, status: int = 0) -> bytes:
        def seq(c): return b"\x30" + cls._encode_length(len(c)) + c
        def integer(v): v_b = v.to_bytes(1, "big"); return b"\x02\x01" + v_b
        status_info = seq(integer(status))
        return seq(status_info)

    @classmethod
    def parse_cert_request_from_body(cls, body_raw: bytes) -> Optional[bytes]:
        """
        Try to extract a DER-encoded PKCS#10 CSR or CRMF CertRequest
        from a CMPv2 ir/cr/kur body.
        Returns DER bytes or None.
        """
        # CRMF CertReqMessages ::= SEQUENCE OF CertReqMsg
        # Try to find embedded public key / subject info
        # For simplicity we return the whole body for processing
        return body_raw

    @classmethod
    def extract_subject_and_pubkey_from_crmf(cls, body_raw: bytes) -> Tuple[Optional[str], Optional[bytes]]:
        """
        Walk the CRMF body to extract the subject DN string and subjectPublicKeyInfo DER.
        Returns (subject_str, spki_der) or (None, None).
        """
        # We'll do a best-effort DER walk looking for known OIDs
        subject_str = "CN=CMPv2 Client"
        spki_der = None

        try:
            # body_raw is CertReqMessages = SEQUENCE OF CertReqMsg
            # Each CertReqMsg: SEQUENCE { certReq CertRequest, ... }
            # CertRequest: SEQUENCE { certReqId INTEGER, certTemplate, ... }
            # certTemplate: SEQUENCE with optional fields tagged [0]..[8]

            pos = 0
            # Unwrap CertReqMessages SEQUENCE
            if body_raw[pos] != 0x30:
                return subject_str, spki_der
            msg_len, pos = cls._decode_length(body_raw, 1)
            inner = body_raw[pos:pos + msg_len]

            # First CertReqMsg
            if not inner or inner[0] != 0x30:
                return subject_str, spki_der
            crm_len, p2 = cls._decode_length(inner, 1)
            crm = inner[p2:p2 + crm_len]

            # CertRequest
            if not crm or crm[0] != 0x30:
                return subject_str, spki_der
            cr_len, p3 = cls._decode_length(crm, 1)
            cr = crm[p3:p3 + cr_len]

            # skip certReqId INTEGER
            id_len, p4 = cls._decode_length(cr, 1)
            p4 += id_len

            # certTemplate SEQUENCE
            if p4 >= len(cr) or cr[p4] != 0x30:
                return subject_str, spki_der
            tmpl_len, p5 = cls._decode_length(cr, p4 + 1)
            tmpl = cr[p5:p5 + tmpl_len]

            # Walk template fields (all OPTIONAL, context-tagged)
            tpos = 0
            while tpos < len(tmpl):
                ftag = tmpl[tpos]
                flen, fnext = cls._decode_length(tmpl, tpos + 1)
                fval = tmpl[fnext:fnext + flen]
                field_num = ftag & 0x1F

                if field_num == 5:  # [5] subject
                    subject_str = cls._parse_dn(fval) or subject_str
                elif field_num == 6:  # [6] publicKey
                    spki_der = fval

                tpos = fnext + flen

        except Exception as e:
            logger.debug(f"CRMF parse error: {e}")

        return subject_str, spki_der

    @classmethod
    def _parse_dn(cls, data: bytes) -> Optional[str]:
        """Parse a DER Name into a string like CN=Foo,O=Bar"""
        try:
            parts = []
            # Name ::= SEQUENCE OF RDN
            pos = 0
            while pos < len(data):
                tag_b, rdn_bytes, pos = cls._decode_tlv(data, pos)
                # RDN ::= SET OF AttributeTypeAndValue
                rpos = 0
                while rpos < len(rdn_bytes):
                    _, atav_bytes, rpos = cls._decode_tlv(rdn_bytes, rpos)
                    # AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
                    _, oid_bytes, apos = cls._decode_tlv(atav_bytes, 0)
                    _, val_bytes, _ = cls._decode_tlv(atav_bytes, apos)
                    oid_str = cls._decode_oid(oid_bytes)
                    val_str = val_bytes.decode("utf-8", errors="replace")
                    attr = {
                        "2.5.4.3": "CN",
                        "2.5.4.6": "C",
                        "2.5.4.7": "L",
                        "2.5.4.8": "ST",
                        "2.5.4.10": "O",
                        "2.5.4.11": "OU",
                    }.get(oid_str, oid_str)
                    parts.append(f"{attr}={val_str}")
            return ",".join(parts) if parts else None
        except Exception:
            return None

    @staticmethod
    def _decode_oid(data: bytes) -> str:
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
# CMPv2 Request Handler
# ---------------------------------------------------------------------------

class CMPv2Handler:
    """Process incoming CMPv2 PKIMessages and generate responses."""

    SUPPORTED_BODY_TYPES = {"ir", "cr", "kur", "rr", "certConf", "genm", "p10cr"}

    def __init__(self, ca: CertificateAuthority):
        self.ca = ca
        self._pending_confirmations: Dict[bytes, bytes] = {}  # txid -> cert_der
        self._lock = threading.Lock()

    def handle(self, der_data: bytes) -> bytes:
        """Main entry point. Returns DER-encoded PKIMessage response."""
        try:
            msg = CMPv2ASN1.parse_pki_message(der_data)

            if "parse_error" in msg and not msg.get("body_type"):
                logger.warning(f"Failed to parse CMPv2 message: {msg['parse_error']}")
                return self._build_error(
                    b"\x00" * 16, b"\x00" * 16, b"\x00" * 16,
                    2, "Could not parse PKIMessage"
                )

            body_type = msg.get("body_type", "unknown")
            header = msg.get("header", {})
            txid = header.get("transactionID", os.urandom(16))
            snonce = header.get("senderNonce", os.urandom(16))

            logger.info(f"CMPv2 request: body_type={body_type} txid={txid.hex() if txid else 'none'}")

            if body_type in ("ir", "cr"):
                return self._handle_cert_request(msg, txid, snonce, body_type)
            elif body_type == "kur":
                return self._handle_key_update(msg, txid, snonce)
            elif body_type == "rr":
                return self._handle_revocation(msg, txid, snonce)
            elif body_type == "certConf":
                return self._handle_cert_confirm(msg, txid, snonce)
            elif body_type == "genm":
                return self._handle_genm(msg, txid, snonce)
            elif body_type == "p10cr":
                return self._handle_p10cr(msg, txid, snonce)
            else:
                logger.warning(f"Unsupported body type: {body_type}")
                return self._build_error(txid, snonce, os.urandom(16), 2, f"Unsupported body type: {body_type}")

        except Exception as e:
            logger.error(f"Error handling CMPv2 message: {e}\n{traceback.format_exc()}")
            return self._build_error(
                os.urandom(16), os.urandom(16), os.urandom(16),
                2, f"Internal server error: {e}"
            )

    def _handle_cert_request(self, msg: dict, txid: bytes, snonce: bytes, req_type: str) -> bytes:
        """Handle ir (Initialization Request) or cr (Certification Request)."""
        body_raw = msg.get("body_raw", b"")
        resp_body_type = 1 if req_type == "ir" else 3  # ip=1, cp=3

        try:
            subject_str, spki_der = CMPv2ASN1.extract_subject_and_pubkey_from_crmf(body_raw)

            if spki_der:
                # Parse the SubjectPublicKeyInfo to get a public key
                pub_key = serialization.load_der_public_key(spki_der)
                cert = self.ca.issue_certificate(subject_str or "CN=CMPv2 Client", pub_key)
                cert_der = cert.public_bytes(Encoding.DER)
                private_key_pem = None
            else:
                # No public key provided — generate one server-side
                logger.info("No public key in request, generating key pair server-side.")
                priv_key, cert = self.ca.generate_ephemeral_key_and_cert(
                    subject_str or "CN=CMPv2 Client"
                )
                cert_der = cert.public_bytes(Encoding.DER)
                private_key_pem = priv_key.private_bytes(
                    Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                )

            # Store pending for certConf
            with self._lock:
                self._pending_confirmations[txid] = cert_der

            body = CMPv2ASN1.build_ip_cp_body(cert_der, status=0, request_id=0)
            resp = CMPv2ASN1.build_pki_message(resp_body_type, body, txid, os.urandom(16), snonce)

            logger.info(f"Certificate issued for '{subject_str}', serial={cert.serial_number}")
            return resp

        except Exception as e:
            logger.error(f"Certificate issuance failed: {e}")
            body = CMPv2ASN1.build_ip_cp_body(b"", status=2)
            return CMPv2ASN1.build_pki_message(resp_body_type, body, txid, os.urandom(16), snonce)

    def _handle_p10cr(self, msg: dict, txid: bytes, snonce: bytes) -> bytes:
        """Handle PKCS#10 Certificate Request."""
        body_raw = msg.get("body_raw", b"")
        try:
            # body_raw is directly the PKCS#10 CSR DER
            csr = x509.load_der_x509_csr(body_raw)
            subject_str = csr.subject.rfc4514_string()
            pub_key = csr.public_key()
            cert = self.ca.issue_certificate(subject_str, pub_key)
            cert_der = cert.public_bytes(Encoding.DER)

            with self._lock:
                self._pending_confirmations[txid] = cert_der

            body = CMPv2ASN1.build_ip_cp_body(cert_der, status=0, request_id=0)
            return CMPv2ASN1.build_pki_message(3, body, txid, os.urandom(16), snonce)
        except Exception as e:
            logger.error(f"p10cr failed: {e}")
            body = CMPv2ASN1.build_error_body(2, str(e))
            return CMPv2ASN1.build_pki_message(23, body, txid, os.urandom(16), snonce)

    def _handle_key_update(self, msg: dict, txid: bytes, snonce: bytes) -> bytes:
        """Handle Key Update Request (kur -> kup)."""
        # Treat like a cert request
        return self._handle_cert_request(msg, txid, snonce, "cr")

    def _handle_revocation(self, msg: dict, txid: bytes, snonce: bytes) -> bytes:
        """Handle Revocation Request (rr -> rp)."""
        body_raw = msg.get("body_raw", b"")

        # Try to extract serial from RevDetails (very simplified)
        serial = None
        try:
            # Walk the body looking for an INTEGER that could be a serial
            pos = 0
            depth = 0
            while pos < len(body_raw) and depth < 20:
                if pos + 2 > len(body_raw):
                    break
                tag = body_raw[pos]
                length, next_pos = CMPv2ASN1._decode_length(body_raw, pos + 1)
                val = body_raw[next_pos:next_pos + length]
                if tag == 0x02 and 1 <= length <= 20:  # INTEGER
                    candidate = int.from_bytes(val, "big")
                    if candidate > 1000:  # likely a serial
                        serial = candidate
                        break
                pos = next_pos + length
                depth += 1
        except Exception:
            pass

        if serial and self.ca.revoke_certificate(serial):
            body = CMPv2ASN1.build_rp_body(0)
        else:
            logger.warning(f"Revocation: serial {serial} not found or already revoked")
            body = CMPv2ASN1.build_rp_body(2)

        return CMPv2ASN1.build_pki_message(12, body, txid, os.urandom(16), snonce)

    def _handle_cert_confirm(self, msg: dict, txid: bytes, snonce: bytes) -> bytes:
        """Handle Certificate Confirmation (certConf -> pkiconf)."""
        with self._lock:
            cert_der = self._pending_confirmations.pop(txid, None)

        if cert_der:
            logger.info(f"Certificate confirmed for txid={txid.hex()}")
        else:
            logger.warning(f"CertConf for unknown txid={txid.hex()}")

        body = CMPv2ASN1.build_pkiconf_body()
        return CMPv2ASN1.build_pki_message(19, body, txid, os.urandom(16), snonce)

    def _handle_genm(self, msg: dict, txid: bytes, snonce: bytes) -> bytes:
        """Handle General Message — respond with CA cert info."""
        # Build GenRepContent with CA cert
        ca_der = self.ca.ca_cert_der

        def seq(c): return b"\x30" + CMPv2ASN1._encode_length(len(c)) + c
        def octet_string(v): return b"\x04" + CMPv2ASN1._encode_length(len(v)) + v
        def oid(dotted):
            parts = list(map(int, dotted.split(".")))
            enc = bytes([40 * parts[0] + parts[1]])
            for p in parts[2:]:
                if p == 0:
                    enc += b"\x00"
                else:
                    buf = []
                    while p:
                        buf.append(p & 0x7F)
                        p >>= 7
                    buf.reverse()
                    enc += bytes([(b | 0x80) if i < len(buf)-1 else b for i, b in enumerate(buf)])
            return b"\x06" + CMPv2ASN1._encode_length(len(enc)) + enc

        # OID 1.3.6.1.5.5.7.4.2 = id-it-caProtEncCert  (CA Cert)
        info_value = seq(oid("1.3.6.1.5.5.7.4.2") + octet_string(ca_der))
        genp_body = seq(info_value)

        return CMPv2ASN1.build_pki_message(22, genp_body, txid, os.urandom(16), snonce)

    def _build_error(self, txid: bytes, snonce: bytes, recip_nonce: bytes, status: int, text: str) -> bytes:
        body = CMPv2ASN1.build_error_body(status, text)
        return CMPv2ASN1.build_pki_message(23, body, txid, os.urandom(16), snonce)


# ---------------------------------------------------------------------------
# CMPv3 Handler (RFC 9480 — CMP Updates)
# ---------------------------------------------------------------------------

# RFC 9480 / RFC 9483 OIDs for new genm info types
OID_IT_GETCACERTS           = "1.3.6.1.5.5.7.4.17"   # id-it 17
OID_IT_GETROOTCAUPDATE      = "1.3.6.1.5.5.7.4.18"   # id-it 18
OID_IT_GETROOTCAUPDATE_RESP = "1.3.6.1.5.5.7.4.20"   # id-it 20  (RootCaKeyUpdateContent)
OID_IT_GETCERTREQTEMPLATE   = "1.3.6.1.5.5.7.4.19"   # id-it 19
OID_IT_CRLSTATUSLIST        = "1.3.6.1.5.5.7.4.21"   # id-it 21  (CRL update request)
OID_IT_CRLUPDATERESP        = "1.3.6.1.5.5.7.4.22"   # id-it 22  (CRL update response)
OID_IT_CAPROTENCERT         = "1.3.6.1.5.5.7.4.2"    # original id-it-caProtEncCert
OID_IT_SIGNKEYPAIRTYPES     = "1.3.6.1.5.5.7.4.3"    # id-it-signKeyPairTypes
OID_IT_ENCKEYPAIRTYPES      = "1.3.6.1.5.5.7.4.4"    # id-it-encKeyPairTypes
OID_IT_PREFERREDSYMMALG     = "1.3.6.1.5.5.7.4.5"    # id-it-preferredSymmAlg
OID_IT_CACERTS              = "1.3.6.1.5.5.7.4.17"

# Well-known URI prefix (RFC 9480 / RFC 9811)
CMP_WELL_KNOWN_PATH = "/.well-known/cmp"


class CMPv3Handler(CMPv2Handler):
    """
    CMPv3 handler extending CMPv2Handler with RFC 9480 / RFC 9483 features:
      - pvno=3 version negotiation
      - Extended polling (pollReq/pollRep for all message types)
      - New genm types: GetCACerts, GetRootCACertUpdate, GetCertReqTemplate,
        CRLStatusList / CRLUpdateRetrieve
      - Well-known URI path routing (/.well-known/cmp[/p/<label>])
    """

    PVNO_CMP2021 = 3   # CMPv3 version number per RFC 9480
    PVNO_CMP2000 = 2   # CMPv2 version number per RFC 4210

    # poll period in seconds when a request is queued for async processing
    POLL_PERIOD = 5

    def __init__(self, ca: "CertificateAuthority"):
        super().__init__(ca)
        # txid -> {"status": "waiting"|"ready"|"error", "response": bytes, "deadline": float}
        self._polling_table: Dict[bytes, Dict] = {}
        self._poll_lock = threading.Lock()

    def handle(self, der_data: bytes) -> bytes:
        """Override: detect pvno=3 and route to CMPv3-aware handling."""
        try:
            msg = CMPv2ASN1.parse_pki_message(der_data)
            pvno = msg.get("header", {}).get("pvno", 2)
            body_type = msg.get("body_type", "unknown")
            header = msg.get("header", {})
            txid = header.get("transactionID", os.urandom(16))
            snonce = header.get("senderNonce", os.urandom(16))

            # Echo back pvno=3 if client sent pvno=3
            response_pvno = self.PVNO_CMP2021 if pvno == 3 else self.PVNO_CMP2000

            logger.info(
                f"CMPv3 request: body_type={body_type} pvno={pvno} "
                f"txid={txid.hex() if txid else 'none'}"
            )

            # pollReq — check the polling table
            if body_type == "pollReq":
                return self._handle_poll_req(msg, txid, snonce, response_pvno)

            # Route to appropriate handler
            if body_type in ("ir", "cr"):
                resp = self._handle_cert_request(msg, txid, snonce, body_type)
            elif body_type == "kur":
                resp = self._handle_key_update(msg, txid, snonce)
            elif body_type == "rr":
                resp = self._handle_revocation(msg, txid, snonce)
            elif body_type == "certConf":
                resp = self._handle_cert_confirm(msg, txid, snonce)
            elif body_type == "genm":
                resp = self._handle_genm_v3(msg, txid, snonce, response_pvno)
            elif body_type == "p10cr":
                resp = self._handle_p10cr(msg, txid, snonce)
            elif body_type == "error":
                # RFC 9480: client may send error — acknowledge it
                logger.warning(f"Client sent error message txid={txid.hex()}")
                body = CMPv2ASN1.build_pkiconf_body()
                resp = CMPv2ASN1.build_pki_message(
                    19, body, txid, os.urandom(16), snonce, pvno=response_pvno
                )
            else:
                logger.warning(f"Unsupported body type: {body_type}")
                resp = self._build_error_v3(
                    txid, snonce, os.urandom(16), 2,
                    f"Unsupported body type: {body_type}", response_pvno
                )

            return resp

        except Exception as e:
            logger.error(f"CMPv3 handler error: {e}\n{traceback.format_exc()}")
            return self._build_error(
                os.urandom(16), os.urandom(16), os.urandom(16),
                2, f"Internal server error: {e}"
            )

    # ------------------------------------------------------------------
    # Extended genm (RFC 9480 new info types)
    # ------------------------------------------------------------------

    def _handle_genm_v3(self, msg: dict, txid: bytes, snonce: bytes, pvno: int) -> bytes:
        """
        Handle General Message with RFC 9480 extended info types.
        Falls back to CMPv2 CA cert response for unknown OIDs.
        """
        body_raw = msg.get("body_raw", b"")
        req_oid = self._extract_genm_oid(body_raw)

        logger.info(f"genm OID: {req_oid!r}")

        def _build_genp(info_value_der: bytes) -> bytes:
            def seq(c): return b"\x30" + CMPv2ASN1._encode_length(len(c)) + c
            genp_body = seq(info_value_der)
            return CMPv2ASN1.build_pki_message(
                22, genp_body, txid, os.urandom(16), snonce, pvno=pvno
            )

        def _oid_bytes(dotted: str) -> bytes:
            parts = list(map(int, dotted.split(".")))
            enc = bytes([40 * parts[0] + parts[1]])
            for p in parts[2:]:
                if p == 0:
                    enc += b"\x00"
                else:
                    buf = []
                    while p:
                        buf.append(p & 0x7F)
                        p >>= 7
                    buf.reverse()
                    enc += bytes([(b | 0x80) if i < len(buf)-1 else b for i, b in enumerate(buf)])
            return b"\x06" + CMPv2ASN1._encode_length(len(enc)) + enc

        def _seq(c): return b"\x30" + CMPv2ASN1._encode_length(len(c)) + c
        def _oct(v): return b"\x04" + CMPv2ASN1._encode_length(len(v)) + v

        if req_oid == OID_IT_GETCACERTS:
            # RFC 9480 §4.3.3 — GetCACerts: return ALL CA certs in the chain.
            # For a root CA this is just [ca_cert]; for an intermediate CA this
            # includes ca_cert + every parent up to the root so that clients can
            # build the full path without additional round-trips.
            # CACertSeq = SEQUENCE OF Certificate (concatenated DER inside SEQUENCE)
            all_ders = self.ca.ca_chain_ders   # [leaf, parent, ..., root]
            ca_seq = _seq(b"".join(all_ders))
            info_val = _seq(_oid_bytes(OID_IT_GETCACERTS) + _seq(ca_seq))
            logger.info(
                "genm GetCACerts: returning %d certificate(s)", len(all_ders)
            )
            return _build_genp(info_val)

        elif req_oid == OID_IT_GETROOTCAUPDATE:
            # RFC 9480 §4.3.4 — GetRootCACertUpdate: return newWithNew
            # We have no separate "next CA" so we return current cert as newWithNew.
            # RootCaKeyUpdateContent ::= SEQUENCE { newWithNew Cert, [0] newWithOld OPTIONAL, [1] oldWithNew OPTIONAL }
            ca_der = self.ca.ca_cert_der
            root_update = _seq(ca_der)  # just newWithNew
            info_val = _seq(_oid_bytes(OID_IT_GETCACERTS) + root_update)
            logger.info("genm GetRootCACertUpdate: returning current CA cert as newWithNew")
            return _build_genp(info_val)

        elif req_oid == OID_IT_GETCERTREQTEMPLATE:
            # RFC 9480 §4.3.5 — GetCertReqTemplate: return template hints
            # CertReqTemplateContent ::= SEQUENCE {
            #   certTemplate CertTemplate OPTIONAL,
            #   keySpec Controls OPTIONAL
            # }
            # We return a minimal template indicating RSA-2048 is preferred.
            def _int(v): return b"\x02\x01" + bytes([v])
            def _ctx_impl(n, c): return bytes([0xA0 | n]) + CMPv2ASN1._encode_length(len(c)) + c

            # OID for rsaEncryption key type
            rsa_oid = _oid_bytes("1.2.840.113549.1.1.1")
            # AlgorithmIdentifier { rsaEncryption, NULL }
            alg_id = _seq(rsa_oid + b"\x05\x00")
            # keySpec [0] Controls ::= SEQUENCE OF AttributeTypeAndValue
            # Simplified: just wrap the AlgorithmIdentifier
            key_spec = _ctx_impl(1, _seq(alg_id))

            template_content = _seq(key_spec)
            info_val = _seq(_oid_bytes(OID_IT_GETCERTREQTEMPLATE) + template_content)
            logger.info("genm GetCertReqTemplate: returning RSA-2048 template hint")
            return _build_genp(info_val)

        elif req_oid == OID_IT_CRLSTATUSLIST:
            # RFC 9480 §4.3.6 — CRLUpdateRetrieve: return current CRL
            crl_der = self.ca.generate_crl_der()
            # CRLSource = CHOICE { dpn [0] DistributionPointName, issuer [1] GeneralNames }
            # We return the CRL directly in the genp value as CRLs SEQUENCE OF CertificateList
            crls = _seq(crl_der)
            info_val = _seq(_oid_bytes(OID_IT_CRLUPDATERESP) + crls)
            logger.info("genm CRLStatusList: returning current CRL")
            return _build_genp(info_val)

        else:
            # Fallback: original CMPv2 CA cert info (id-it-caProtEncCert)
            ca_der = self.ca.ca_cert_der
            info_val = _seq(_oid_bytes(OID_IT_CAPROTENCERT) + _oct(ca_der))
            logger.info(f"genm unknown OID {req_oid!r}: falling back to caProtEncCert")
            return _build_genp(info_val)

    def _extract_genm_oid(self, body_raw: bytes) -> Optional[str]:
        """Extract the first InfoTypeAndValue OID from a GenMsgContent body."""
        try:
            # GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
            # InfoTypeAndValue ::= SEQUENCE { infoType OID, infoValue ANY OPTIONAL }
            pos = 0
            # outer SEQUENCE
            tag, outer, pos = CMPv2ASN1._decode_tlv(body_raw, 0)
            # first InfoTypeAndValue
            tag2, itav, _ = CMPv2ASN1._decode_tlv(outer, 0)
            # OID
            tag3, oid_val, _ = CMPv2ASN1._decode_tlv(itav, 0)
            if tag3 == 0x06:
                return self._decode_oid_bytes(oid_val)
        except Exception as e:
            logger.debug(f"genm OID extraction failed: {e}")
        return None

    @staticmethod
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

    # ------------------------------------------------------------------
    # Extended polling (RFC 9480 §3.4)
    # ------------------------------------------------------------------

    def queue_for_polling(self, txid: bytes, response: bytes, delay_secs: int = 0):
        """Store a ready or pending response in the polling table."""
        with self._poll_lock:
            self._polling_table[txid] = {
                "status": "ready" if delay_secs == 0 else "waiting",
                "response": response,
                "deadline": time.time() + delay_secs,
            }

    def _handle_poll_req(self, msg: dict, txid: bytes, snonce: bytes, pvno: int) -> bytes:
        """
        Handle pollReq (body type 25) — RFC 9480 §3.4 extended polling.
        RFC 4210 only defined polling for ir/cr/kur. RFC 9480 extends it
        to p10cr, certConf, rr, genm, and error responses.
        """
        def _seq(c): return b"\x30" + CMPv2ASN1._encode_length(len(c)) + c
        def _int(v): return b"\x02\x01" + bytes([v & 0xFF])
        def _int_big(v):
            if v == 0: return b"\x02\x01\x00"
            raw = []
            n = v
            while n:
                raw.append(n & 0xFF)
                n >>= 8
            raw.reverse()
            if raw[0] & 0x80:
                raw.insert(0, 0)
            return b"\x02" + CMPv2ASN1._encode_length(len(raw)) + bytes(raw)

        with self._poll_lock:
            entry = self._polling_table.get(txid)

        if entry is None:
            # Unknown txid — send error
            return self._build_error_v3(
                txid, snonce, os.urandom(16), 2,
                f"Unknown transactionID in pollReq", pvno
            )

        if entry["status"] == "ready" or time.time() >= entry["deadline"]:
            # Return the queued response
            with self._poll_lock:
                self._polling_table.pop(txid, None)
            logger.info(f"pollReq: txid={txid.hex()!r} — returning ready response")
            return entry["response"]

        # Still waiting — send pollRep
        # PollRepContent ::= SEQUENCE OF SEQUENCE { certReqId INTEGER, checkAfter INTEGER, reason UTF8String }
        check_after = max(1, int(entry["deadline"] - time.time()))
        poll_entry = _seq(
            _int_big(0)           # certReqId
            + _int_big(check_after)  # checkAfter (seconds)
        )
        poll_rep_body = _seq(poll_entry)
        logger.info(f"pollReq: txid={txid.hex()!r} — still waiting, checkAfter={check_after}s")
        return CMPv2ASN1.build_pki_message(
            26, poll_rep_body, txid, os.urandom(16), snonce, pvno=pvno
        )

    def _build_error_v3(
        self, txid: bytes, snonce: bytes, recip_nonce: bytes,
        status: int, text: str, pvno: int
    ) -> bytes:
        body = CMPv2ASN1.build_error_body(status, text)
        return CMPv2ASN1.build_pki_message(
            23, body, txid, os.urandom(16), snonce, pvno=pvno
        )


# ---------------------------------------------------------------------------
# HTTP Server (RFC 6712 - CMP over HTTP)
# ---------------------------------------------------------------------------

class CMPv2HTTPHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP handler for CMPv2 as per RFC 6712.
    POST /<path> with Content-Type: application/pkixcmp
    """

    cmp_handler: CMPv2Handler = None  # Set by server
    ca: CertificateAuthority = None
    audit_log: "AuditLog" = None
    rate_limiter: "RateLimiter" = None

    def log_message(self, format, *args):
        client_cn = self._get_client_cn()
        prefix = f"[mTLS:{client_cn}] " if client_cn else ""
        logger.info(f"HTTP {prefix}{self.address_string()} - {format % args}")

    def _get_client_cn(self) -> Optional[str]:
        """Return the CN from the peer's client certificate, or None."""
        try:
            peer_cert = self.connection.getpeercert()
            if peer_cert:
                for field in peer_cert.get("subject", []):
                    for k, v in field:
                        if k == "commonName":
                            return v
        except Exception:
            pass
        return None

    def do_POST_api(self, path: str, body: bytes):
        """Handle POST requests to /api/* management endpoints."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json({"error": "invalid JSON"}, 400)
            return

        if path == "/api/sub-ca":
            cn = data.get("cn", "PyPKI Intermediate CA")
            validity_days = int(data.get("validity_days", 1825))
            try:
                key, cert = self.ca.issue_sub_ca(
                    cn=cn, validity_days=validity_days, audit=self.audit_log
                )
                cert_pem = cert.public_bytes(Encoding.PEM).decode()
                key_pem = key.private_bytes(Encoding.PEM,
                                            PrivateFormat.TraditionalOpenSSL,
                                            NoEncryption()).decode()
                if self.audit_log:
                    self.audit_log.record("issue_sub_ca",
                                          f"cn={cn} serial={cert.serial_number}",
                                          self.client_address[0])
                self._send_json({
                    "ok": True,
                    "serial": cert.serial_number,
                    "subject": cert.subject.rfc4514_string(),
                    "cert_pem": cert_pem,
                    "key_pem": key_pem,
                })
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif re.match(r"^/api/certs/\d+/renew$", path):
            # Feature 9: POST /api/certs/<serial>/renew
            try:
                serial = int(path.split("/")[3])
                validity_days = data.get("validity_days")
                new_cert = self.ca.renew_certificate(
                    serial=serial,
                    validity_days=int(validity_days) if validity_days else None,
                    audit=self.audit_log,
                    requester_ip=self.client_address[0],
                )
                if new_cert is None:
                    self._send_json({"error": "certificate not found"}, 404)
                else:
                    self._send_json({
                        "ok": True,
                        "old_serial": serial,
                        "new_serial": new_cert.serial_number,
                        "subject": new_cert.subject.rfc4514_string(),
                        "not_after": new_cert.not_valid_after_utc.isoformat(),
                        "cert_pem": new_cert.public_bytes(Encoding.PEM).decode(),
                    })
            except (ValueError, IndexError):
                self._send_json({"error": "invalid serial"}, 400)

        elif path == "/api/revoke":
            serial = data.get("serial")
            reason = int(data.get("reason", 0))
            if serial is None:
                self._send_json({"error": "serial required"}, 400)
                return
            ok = self.ca.revoke_certificate(int(serial), reason)
            if self.audit_log:
                self.audit_log.record("revoke",
                                      f"serial={serial} reason={reason}",
                                      self.client_address[0])
            self._send_json({"ok": ok, "serial": serial})

        elif re.match(r"^/api/certs/\d+/archive$", path):
            # Feature 6: POST /api/certs/<serial>/archive  — key archival
            try:
                serial = int(path.split("/")[3])
                key_pem = data.get("key_pem", "")
                if not key_pem:
                    self._send_json({"error": "key_pem required in request body"}, 400)
                    return
                ok = self.ca.archive_private_key(serial, key_pem.encode())
                self._send_json({"ok": ok, "serial": serial, "archived": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif re.match(r"^/api/certs/\d+/recover$", path):
            # Feature 6: POST /api/certs/<serial>/recover  — key recovery
            try:
                serial = int(path.split("/")[3])
                key_pem = self.ca.recover_private_key(serial)
                if key_pem is None:
                    self._send_json({"error": "no archived key for this serial"}, 404)
                else:
                    self._send_json({"ok": True, "serial": serial, "key_pem": key_pem.decode()})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == "/api/name-constrained-ca":
            # Feature 7: POST /api/name-constrained-ca — issue a name-constrained sub-CA
            try:
                cn = data.get("cn", "Name-Constrained Sub-CA")
                validity_days = int(data.get("validity_days", 1825))
                permitted_dns  = data.get("permitted_dns", [])
                excluded_dns   = data.get("excluded_dns", [])
                permitted_emails = data.get("permitted_emails", [])
                excluded_ips   = data.get("excluded_ips", [])
                priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
                cert = self.ca.issue_certificate_with_name_constraints(
                    subject_str=f"CN={cn},O=PyPKI Constrained CA",
                    public_key=priv_key.public_key(),
                    validity_days=validity_days,
                    permitted_dns=permitted_dns,
                    excluded_dns=excluded_dns,
                    permitted_emails=permitted_emails,
                    excluded_ips=excluded_ips,
                )
                self._send_json({
                    "ok": True,
                    "serial": cert.serial_number,
                    "subject": cert.subject.rfc4514_string(),
                    "cert_pem": cert.public_bytes(Encoding.PEM).decode(),
                    "key_pem": priv_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode(),
                })
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == "/api/issue":
            # POST /api/issue — issue an end-entity certificate via REST
            # Body: {subject, public_key_pem?, validity_days?, san_dns?, san_emails?,
            #        san_ips?, profile?, ocsp_url?, crl_url?, no_rev_avail?}
            try:
                subject_str = data.get("subject", "").strip()
                if not subject_str:
                    self._send_json({"error": "subject is required"}, 400)
                    return
                # Resolve public key — generate RSA-2048 if not supplied
                priv_key_pem = None
                pubkey_pem = data.get("public_key_pem", "").strip()
                if pubkey_pem:
                    from cryptography.hazmat.primitives.serialization import load_pem_public_key
                    pub_key = load_pem_public_key(pubkey_pem.encode())
                else:
                    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    pub_key = priv.public_key()
                    priv_key_pem = priv.private_bytes(
                        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                    ).decode()

                kwargs = {
                    "subject_str":   subject_str,
                    "public_key":    pub_key,
                    "profile":       data.get("profile", "default"),
                    "audit":         self.audit_log,
                    "requester_ip":  self.client_address[0],
                }
                if data.get("validity_days"):
                    kwargs["validity_days"] = int(data["validity_days"])
                if data.get("san_dns"):
                    kwargs["san_dns"] = data["san_dns"]
                if data.get("san_emails"):
                    kwargs["san_emails"] = data["san_emails"]
                if data.get("san_ips"):
                    kwargs["san_ips"] = data["san_ips"]
                if data.get("ocsp_url"):
                    kwargs["ocsp_url"] = data["ocsp_url"]
                if data.get("crl_url"):
                    kwargs["crl_url"] = data["crl_url"]
                if "no_rev_avail" in data:
                    kwargs["no_rev_avail"] = bool(data["no_rev_avail"])
                if data.get("certificate_policies"):
                    kwargs["certificate_policies"] = data["certificate_policies"]

                cert = self.ca.issue_certificate(**kwargs)
                resp = {
                    "ok":       True,
                    "serial":   cert.serial_number,
                    "subject":  cert.subject.rfc4514_string(),
                    "not_after": cert.not_valid_after_utc.isoformat(),
                    "profile":  data.get("profile", "default"),
                    "cert_pem": cert.public_bytes(Encoding.PEM).decode(),
                }
                if priv_key_pem:
                    resp["key_pem"] = priv_key_pem
                self._send_json(resp, 201)
            except Exception as e:
                logger.exception("POST /api/issue failed")
                self._send_json({"error": str(e)}, 500)

        elif path == "/api/reload-tls":
            # Trigger an immediate TLS certificate reload from disk.
            # Designed for use as a certbot / acme.sh deploy-hook:
            #   certbot renew --deploy-hook \
            #     'curl -sf -X POST https://<host>:<port>/api/reload-tls'
            #
            # The server must have been started with --tls or --mtls for this
            # to have any effect; on plain-HTTP servers it returns 409.
            server = self.server
            reload_fn = getattr(server, "reload_tls", None)
            if reload_fn is None:
                self._send_json({"error": "TLS not active on this server"}, 409)
                return
            ok = reload_fn()
            if ok:
                if self.audit_log:
                    self.audit_log.record(
                        "reload_tls",
                        "manual TLS certificate reload via API",
                        self.client_address[0],
                    )
                self._send_json({"ok": True, "message": "TLS context reloaded"})
            else:
                self._send_json({"error": "TLS reload failed — check server logs"}, 500)

        else:
            self._send_json({"error": "unknown API endpoint"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        req_path = self.path.split("?")[0].rstrip("/")

        # Management API (POST /api/*)
        if req_path.startswith("/api/"):
            self.do_POST_api(req_path, body)
            return

        content_type = self.headers.get("Content-Type", "")
        if content_type not in ("application/pkixcmp", "application/pkixcmp-poll",
                                 "application/octet-stream"):
            logger.warning(f"Unexpected Content-Type: {content_type}")

        # Log authenticated client identity
        client_cn = self._get_client_cn()
        if client_cn:
            logger.info(f"Authenticated mTLS client: CN={client_cn}")

        # Rate limiting
        if self.rate_limiter:
            ip = self.client_address[0]
            if not self.rate_limiter.allow(ip):
                logger.warning(f"Rate limit exceeded for {ip}")
                self.send_response(429)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Retry-After", "60")
                rl_body = b"Rate limit exceeded. Try again in 60 seconds."
                self.send_header("Content-Length", str(len(rl_body)))
                self.end_headers()
                self.wfile.write(rl_body)
                return

        # RFC 9480/9811 well-known CMP URI (/.well-known/cmp[/p/<label>])
        cmp_path = self.path.split("?")[0]
        if cmp_path.startswith(CMP_WELL_KNOWN_PATH):
            label = self._extract_cmp_label(cmp_path)
            if label:
                logger.info(f"CMP well-known URI — CA label: {label!r}")

        try:
            response_der = self.cmp_handler.handle(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/pkixcmp")
            self.send_header("Content-Length", str(len(response_der)))
            self.end_headers()
            self.wfile.write(response_der)
        except Exception as e:
            logger.error(f"Handler error: {e}")
            self.send_response(500)
            self.end_headers()

    @staticmethod
    def _extract_cmp_label(path: str) -> Optional[str]:
        """
        Extract the CA label from a well-known CMP URI.
        /.well-known/cmp/p/<label>/...  → label
        /.well-known/cmp/<op>           → None
        """
        rest = path[len(CMP_WELL_KNOWN_PATH):].lstrip("/")
        parts = rest.split("/")
        if len(parts) >= 2 and parts[0] == "p":
            return parts[1]
        return None

    def do_PATCH(self):
        """PATCH /config — live-update validity periods and other settings."""
        if self.path.rstrip("/") != "/config":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            updates = json.loads(body)
        except json.JSONDecodeError as e:
            self._send_json({"error": f"Invalid JSON: {e}"}, 400)
            return

        # Validate numeric validity values if present
        validity = updates.get("validity", {})
        for key, val in validity.items():
            if not isinstance(val, int) or val < 1:
                self._send_json({"error": f"validity.{key} must be a positive integer"}, 400)
                return
            if val > 36500:
                self._send_json({"error": f"validity.{key} exceeds maximum of 36500 days"}, 400)
                return

        result = self.ca.config.patch(updates)
        logger.info(f"Config patched by {self.address_string()}: {updates}")
        self._send_json({"ok": True, "config": result})

    def do_GET(self):
        """Simple HTTP API for management."""
        path = self.path.split("?")[0].rstrip("/")

        if path == "/config":
            if self.ca.config:
                self._send_json(self.ca.config.as_dict())
            else:
                self._send_json(DEFAULT_CONFIG)
            return

        elif path == "/ca/cert" or path == "/ca/cert.pem":
            # Serve full chain PEM (leaf + intermediates) for intermediate CA mode.
            # For a root CA this is identical to ca_cert_pem.
            data = self.ca.ca_chain_pem
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        elif path == "/ca/cert.der":
            # DER can only encode a single certificate; serve the leaf (this CA).
            # Clients that need the full chain should use /ca/cert.pem instead.
            data = self.ca.ca_cert_der
            self.send_response(200)
            self.send_header("Content-Type", "application/pkix-cert")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        elif path == "/ca/crl":
            try:
                data = self.ca.generate_crl()
                self.send_response(200)
                self.send_header("Content-Type", "application/pkix-crl")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == "/api/certs":
            # Feature 12: optional filters ?profile=tls_server&expiring_in=30
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            params: dict = {}
            for kv in qs.split("&"):
                if "=" in kv:
                    k, _, v = kv.partition("=")
                    params[k] = v
            profile_filter = params.get("profile")
            expiring_in    = params.get("expiring_in")
            if expiring_in is not None:
                try:
                    days = int(expiring_in)
                    certs = self.ca.expiring_certificates(days_ahead=days)
                    if profile_filter:
                        certs = [c for c in certs if c.get("profile") == profile_filter]
                    self._send_json({"certificates": certs, "filter": "expiring", "days_ahead": days})
                except ValueError:
                    self._send_json({"error": "expiring_in must be an integer"}, 400)
            else:
                certs = self.ca.list_certificates()
                if profile_filter:
                    certs = [c for c in certs if c.get("profile") == profile_filter]
                self._send_json({"certificates": certs})

        elif path == "/api/whoami":
            # Returns the authenticated client's certificate subject
            client_cn = self._get_client_cn()
            try:
                peer = self.connection.getpeercert()
            except Exception:
                peer = None
            self._send_json({
                "authenticated": client_cn is not None,
                "common_name": client_cn,
                "peer_cert": str(peer) if peer else None,
            })

        elif path == "/bootstrap":
            # Plain-HTTP endpoint: issues a fresh client cert (use only on bootstrap port)
            cn = self.headers.get("X-Client-CN") or self.path.split("?cn=")[-1] or "bootstrap-client"
            # Also accept ?cn= query param
            if "?" in self.path:
                for param in self.path.split("?")[1].split("&"):
                    if param.startswith("cn="):
                        cn = param[3:]
            try:
                cert_pem, key_pem = self.ca.issue_client_cert(cn)
                # Include full chain so clients can verify the bootstrap cert path
                bundle = cert_pem + key_pem + self.ca.ca_chain_pem
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pem-file")
                self.send_header("Content-Disposition", f'attachment; filename="{cn}-bundle.pem"')
                self.send_header("Content-Length", str(len(bundle)))
                self.end_headers()
                self.wfile.write(bundle)
                logger.info(f"Bootstrap: issued client cert CN={cn}")
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == "/health":
            self._send_json({
                "status": "ok",
                "ca_subject": self.ca.ca_cert.subject.rfc4514_string(),
                "ca_serial": self.ca.ca_cert.serial_number,
            })

        elif path == "/metrics":
            # Feature 11: Prometheus-compatible metrics endpoint
            body = self.ca.metrics_prometheus().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/expiring":
            # Feature 8: GET /api/expiring?days=30
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = {}
            for kv in qs.split("&"):
                if "=" in kv:
                    k, _, v = kv.partition("=")
                    params[k] = v
            raw_days = params.get("days", "30")
            try:
                days = int(raw_days)
                if days < 0:
                    raise ValueError("negative")
            except ValueError:
                self._send_json(
                    {"error": f"Invalid 'days' parameter: {raw_days!r} — must be a non-negative integer"},
                    400,
                )
                return
            expiring = self.ca.expiring_certificates(days_ahead=days)
            self._send_json({"expiring": expiring, "days_ahead": days, "count": len(expiring)})

        elif path == "/ca/delta-crl":
            try:
                data = self.ca.generate_delta_crl()
                self.send_response(200)
                self.send_header("Content-Type", "application/pkix-crl")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path.startswith("/api/certs/") and path.endswith("/p12"):
            # GET /api/certs/<serial>/p12
            try:
                serial = int(path.split("/")[3])
                p12 = self.ca.export_pkcs12(serial)
                if p12 is None:
                    self._send_json({"error": "certificate not found"}, 404)
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-pkcs12")
                    self.send_header("Content-Disposition",
                                     f'attachment; filename="cert-{serial}.p12"')
                    self.send_header("Content-Length", str(len(p12)))
                    self.end_headers()
                    self.wfile.write(p12)
            except (ValueError, IndexError):
                self._send_json({"error": "invalid serial"}, 400)

        elif path.startswith("/api/certs/") and path.endswith("/pem"):
            try:
                serial = int(path.split("/")[3])
                der = self.ca.get_cert_by_serial(serial)
                if not der:
                    self._send_json({"error": "certificate not found"}, 404)
                else:
                    pem = x509.load_der_x509_certificate(der).public_bytes(Encoding.PEM)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-pem-file")
                    self.send_header("Content-Disposition",
                                     f'attachment; filename="cert-{serial}.pem"')
                    self.send_header("Content-Length", str(len(pem)))
                    self.end_headers()
                    self.wfile.write(pem)
            except (ValueError, IndexError):
                self._send_json({"error": "invalid serial"}, 400)

        elif path == "/api/audit":
            if self.audit_log:
                self._send_json({"events": self.audit_log.recent(200)})
            else:
                self._send_json({"events": []})

        elif path == "/api/rate-limit":
            if self.rate_limiter:
                ip = self.client_address[0]
                self._send_json(self.rate_limiter.status(ip))
            else:
                self._send_json({"rate_limiting": "disabled"})

        elif path.startswith(CMP_WELL_KNOWN_PATH):
            # RFC 9811: GET /.well-known/cmp -> return CA certificate (full chain)
            label = self._extract_cmp_label(path)
            data = self.ca.ca_chain_pem
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", str(len(data)))
            if label:
                self.send_header("X-CMP-CA-Label", label)
            self.end_headers()
            self.wfile.write(data)

        else:
            self._send_json({
                "endpoints": {
                    "POST /": "CMPv2/CMPv3 endpoint (application/pkixcmp)",
                    "POST /.well-known/cmp": "RFC 9811 well-known CMP URI",
                    "POST /.well-known/cmp/p/<label>": "Named CA well-known CMP URI (RFC 9811)",
                    "GET  /config": "View current configuration",
                    "PATCH /config": "Live-update: PATCH /config with JSON {validity:{end_entity_days:90}}",
                    "GET /ca/cert.pem": "CA certificate (PEM)",
                    "GET /ca/cert.der": "CA certificate (DER)",
                    "GET /ca/crl": "Certificate Revocation List (DER)",
                    "GET /ca/delta-crl": "Delta CRL (RFC 5280 §5.2.4)",
                    "GET /api/certs": "List issued certificates (JSON)",
                    "GET /api/certs/<serial>/pem": "Download certificate as PEM",
                    "GET /api/certs/<serial>/p12": "Download certificate as PKCS#12 bundle",
                    "POST /api/issue": "Issue end-entity certificate {subject, public_key_pem?, validity_days?, san_dns?, profile?, ...}",
                    "POST /api/sub-ca": "Issue subordinate CA certificate",
                    "POST /api/revoke": "Revoke certificate {serial, reason}",
                    "GET /api/audit": "Structured audit log (last 200 events)",
                    "GET /api/rate-limit": "Rate limit status for calling IP",
                    "GET /api/whoami": "Show authenticated mTLS client identity",
                    "GET /bootstrap?cn=<n>": "Issue client cert bundle (bootstrap port only)",
                    "GET /health": "Health check",
                    "GET /metrics": "Prometheus text-format metrics",
                    "GET /api/expiring?days=30": "Certificates expiring within N days",
                    "GET /.well-known/cmp": "RFC 9811 well-known CMP CA cert (GET)",
                    "POST /api/certs/<serial>/renew": "Renew certificate (same key + profile)",
                    "POST /api/certs/<serial>/archive": "Archive subscriber private key (key escrow)",
                    "POST /api/certs/<serial>/recover": "Recover archived private key",
                    "POST /api/name-constrained-ca": "Issue name-constrained sub-CA",
                    "POST /api/reload-tls": "Reload TLS certificate from disk (certbot deploy-hook target)",
                }
            })

    def _send_json(self, data: dict, code: int = 200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# TLS context holder — enables zero-downtime certificate reload
# ---------------------------------------------------------------------------

class TLSContextHolder:
    """
    Thread-safe, atomically-swappable wrapper around an ssl.SSLContext.

    All three TLS-capable servers (CMP, EST, IPsec) hold a reference to one
    of these and call :meth:`get` on every incoming connection.  When certbot
    renews the certificate, :meth:`swap` replaces the context and all *new*
    connections immediately use the updated certificate — in-flight TLS
    handshakes are unaffected.

    Usage::

        holder = TLSContextHolder(initial_ctx)
        # …in get_request():
        tls_sock = holder.get().wrap_socket(sock, server_side=True)
        # …in reload thread / deploy-hook:
        holder.swap(new_ctx)
    """

    def __init__(self, ctx: ssl.SSLContext):
        self._lock = threading.Lock()
        self._ctx  = ctx

    def get(self) -> ssl.SSLContext:
        """Return the current SSLContext (lock-free fast path via GIL)."""
        return self._ctx

    def swap(self, new_ctx: ssl.SSLContext) -> None:
        """Replace the SSLContext atomically."""
        with self._lock:
            self._ctx = new_ctx

    # Keep the old ssl_context attribute name working for code that sets it directly
    @property
    def ssl_context(self) -> ssl.SSLContext:
        return self._ctx

    @ssl_context.setter
    def ssl_context(self, ctx: ssl.SSLContext) -> None:
        self.swap(ctx)


# ---------------------------------------------------------------------------
# Background TLS cert watcher — polls mtime, reloads on change
# ---------------------------------------------------------------------------

class TlsCertWatcher:
    """
    Background thread that watches a PEM certificate file for changes and
    rebuilds the :class:`TLSContextHolder` when the file's mtime advances.

    This is the recommended way to integrate with certbot / acme.sh / any
    ACME client that writes renewed certificates to disk:

    * No deploy-hook needed for the file-watcher path (poll interval default
      60 s — far shorter than any certificate's validity).
    * For instant propagation, POST ``/api/reload-tls`` from the deploy-hook:
      ``certbot renew --deploy-hook 'curl -s -X POST https://…/api/reload-tls'``

    Parameters
    ----------
    holder          : :class:`TLSContextHolder` to update on change.
    cert_path       : Path to the PEM certificate file (e.g. ``fullchain.pem``).
    key_path        : Path to the PEM private key file (e.g. ``privkey.pem``).
    build_ctx       : Callable ``(cert_path, key_path) -> ssl.SSLContext``
                      that builds a fresh context.  Usually
                      ``ca.build_tls_context``.
    poll_interval   : Seconds between mtime checks (default: 60).
    """

    def __init__(
        self,
        holder: TLSContextHolder,
        cert_path: str,
        key_path: str,
        build_ctx,
        poll_interval: int = 60,
    ):
        self._holder        = holder
        self._cert_path     = Path(cert_path)
        self._key_path      = Path(key_path)
        self._build_ctx     = build_ctx
        self._poll_interval = poll_interval
        self._stop_evt      = threading.Event()
        # Record the mtime we started with so the first reload is triggered
        # only by a genuine change, not just by startup.
        self._last_mtime    = self._cert_mtime()
        self._thread        = threading.Thread(
            target=self._run, daemon=True, name="tls-cert-watcher"
        )

    def _cert_mtime(self) -> float:
        try:
            return self._cert_path.stat().st_mtime
        except OSError:
            return 0.0

    def _run(self) -> None:
        logger.debug(
            "TlsCertWatcher: watching %s (poll every %ds)",
            self._cert_path, self._poll_interval,
        )
        while not self._stop_evt.wait(self._poll_interval):
            mtime = self._cert_mtime()
            if mtime != self._last_mtime:
                self._reload(mtime)

    def _reload(self, new_mtime: float) -> None:
        try:
            new_ctx = self._build_ctx(
                str(self._cert_path), str(self._key_path)
            )
            self._holder.swap(new_ctx)
            self._last_mtime = new_mtime
            logger.info(
                "TlsCertWatcher: reloaded TLS context from %s (mtime changed)",
                self._cert_path,
            )
        except Exception as exc:
            logger.error(
                "TlsCertWatcher: failed to reload TLS context from %s: %s",
                self._cert_path, exc,
            )
            # Keep the old context — do not update _last_mtime so we retry
            # on the next poll cycle.

    def reload_now(self) -> bool:
        """Force an immediate reload regardless of mtime.  Returns True on success."""
        try:
            new_ctx = self._build_ctx(
                str(self._cert_path), str(self._key_path)
            )
            self._holder.swap(new_ctx)
            self._last_mtime = self._cert_mtime()
            logger.info(
                "TlsCertWatcher: forced reload of TLS context from %s",
                self._cert_path,
            )
            return True
        except Exception as exc:
            logger.error(
                "TlsCertWatcher: forced reload failed for %s: %s",
                self._cert_path, exc,
            )
            return False

    def start(self) -> "TlsCertWatcher":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop_evt.set()
        self._thread.join(timeout=self._poll_interval + 2)


# ---------------------------------------------------------------------------
# TLS-capable threaded HTTP server
# ---------------------------------------------------------------------------

class TLSServer(ThreadedHTTPServer):
    """
    HTTPS server that wraps each accepted socket with an SSLContext.

    The context is read from :attr:`ctx_holder` on **every** connection, so
    replacing the holder's context (via :meth:`TLSContextHolder.swap`) takes
    effect immediately for all new connections — no restart needed.

    Modes (controlled by the SSLContext verify_mode):
      - One-way TLS  (ssl.CERT_NONE)     : --tls   (server cert only)
      - Mutual  TLS  (ssl.CERT_REQUIRED) : --mtls  (client cert required)
    """
    ctx_holder: TLSContextHolder = None

    # Legacy attribute shim — code that sets srv.ssl_context directly still works
    @property
    def ssl_context(self) -> ssl.SSLContext:
        return self.ctx_holder.get() if self.ctx_holder else None

    @ssl_context.setter
    def ssl_context(self, ctx: ssl.SSLContext) -> None:
        if self.ctx_holder is None:
            self.ctx_holder = TLSContextHolder(ctx)
        else:
            self.ctx_holder.swap(ctx)

    def get_request(self):
        sock, addr = super().get_request()
        try:
            tls_sock = self.ctx_holder.get().wrap_socket(sock, server_side=True)
            return tls_sock, addr
        except ssl.SSLError as e:
            logger.warning(f"TLS handshake failed from {addr}: {e}")
            sock.close()
            raise

# Backwards-compatible alias
MTLSServer = TLSServer


# ---------------------------------------------------------------------------
# CLI / Main
# ---------------------------------------------------------------------------

def make_handler(ca: CertificateAuthority, cmp_handler: CMPv2Handler,
                 audit_log: Optional[AuditLog] = None,
                 rate_limiter: Optional[RateLimiter] = None):
    class BoundHandler(CMPv2HTTPHandler):
        pass
    BoundHandler.ca = ca
    BoundHandler.cmp_handler = cmp_handler
    BoundHandler.audit_log = audit_log
    BoundHandler.rate_limiter = rate_limiter
    return BoundHandler


def make_cmpv3_handler(ca: CertificateAuthority, cmp_handler: CMPv3Handler,
                       audit_log: Optional[AuditLog] = None,
                       rate_limiter: Optional[RateLimiter] = None):
    """Make an HTTP handler that uses CMPv3Handler (with well-known URI support)."""
    class BoundHandler(CMPv2HTTPHandler):
        pass
    BoundHandler.ca = ca
    BoundHandler.cmp_handler = cmp_handler
    BoundHandler.audit_log = audit_log
    BoundHandler.rate_limiter = rate_limiter
    return BoundHandler


def start_bootstrap_server(host: str, port: int, ca: CertificateAuthority, cmp_handler: CMPv2Handler):
    """
    Start a plain-HTTP server on a separate port for bootstrapping client certs.
    This should only be accessible on a trusted network / localhost.
    """
    handler_class = make_handler(ca, cmp_handler)
    srv = ThreadedHTTPServer((host, port), handler_class)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info(f"Bootstrap HTTP server listening on http://{host}:{port}")
    return srv




# ---------------------------------------------------------------------------
# Public entry point  (mirrors start_*_server() in the other modules)
# ---------------------------------------------------------------------------

def start_cmp_server(
    host: str,
    port: int,
    ca: "CertificateAuthority",
    audit_log: Optional["AuditLog"] = None,
    rate_limiter: Optional["RateLimiter"] = None,
    use_cmpv3: bool = True,
    tls_cert_path: Optional[str] = None,
    tls_key_path: Optional[str] = None,
    require_client_cert: bool = False,
    tls13_only: bool = False,
    alpn_protocols: Optional[List[str]] = None,
    bootstrap_port: Optional[int] = None,
    tls_reload_interval: int = 60,
):
    """
    Start the CMP server in a background thread and return the server object.

    Parameters
    ----------
    host, port           : bind address and port
    ca                   : CertificateAuthority instance
    audit_log            : optional AuditLog
    rate_limiter         : optional RateLimiter
    use_cmpv3            : True  → CMPv3Handler (RFC 9480, default)
                           False → CMPv2Handler only
    tls_cert_path /
    tls_key_path         : PEM cert+key for HTTPS; None → plain HTTP
    require_client_cert  : True → mutual TLS (client cert required)
    tls13_only           : restrict to TLS 1.3
    alpn_protocols       : ALPN list (default: ["http/1.1"])
    bootstrap_port       : if set, also start a plain-HTTP bootstrap server
    tls_reload_interval  : seconds between cert-file mtime checks for
                           automatic zero-downtime reload (default: 60).
                           Set 0 to disable the watcher (use POST /api/reload-tls
                           from a certbot deploy-hook instead).
    """
    if use_cmpv3:
        cmp_handler = CMPv3Handler(ca)
        handler_cls = make_cmpv3_handler(ca, cmp_handler, audit_log, rate_limiter)
    else:
        cmp_handler = CMPv2Handler(ca)
        handler_cls = make_handler(ca, cmp_handler, audit_log, rate_limiter)

    if tls_cert_path and tls_key_path:
        def _build_ctx(cert_path, key_path):
            return ca.build_tls_context(
                cert_path=cert_path,
                key_path=key_path,
                require_client_cert=require_client_cert,
                alpn_protocols=alpn_protocols or [CertificateAuthority.ALPN_HTTP1],
                tls13_only=tls13_only,
            )

        ssl_ctx = _build_ctx(tls_cert_path, tls_key_path)
        holder  = TLSContextHolder(ssl_ctx)

        srv = TLSServer((host, port), handler_cls)
        srv.ctx_holder = holder

        # Attach watcher for automatic zero-downtime reload when cert file changes
        if tls_reload_interval > 0:
            watcher = TlsCertWatcher(
                holder=holder,
                cert_path=tls_cert_path,
                key_path=tls_key_path,
                build_ctx=_build_ctx,
                poll_interval=tls_reload_interval,
            ).start()
            srv._tls_watcher = watcher      # kept alive + stoppable via srv
        else:
            srv._tls_watcher = None

        # Expose a reload_tls() convenience method on the server object so the
        # POST /api/reload-tls handler (and certbot deploy-hooks) can call it.
        def _reload_tls() -> bool:
            if srv._tls_watcher:
                return srv._tls_watcher.reload_now()
            # No watcher — rebuild manually
            try:
                new_ctx = _build_ctx(tls_cert_path, tls_key_path)
                holder.swap(new_ctx)
                logger.info("CMP TLS context reloaded via reload_tls()")
                return True
            except Exception as exc:
                logger.error("CMP TLS reload failed: %s", exc)
                return False

        srv.reload_tls = _reload_tls
        scheme = "https"
    else:
        srv = ThreadedHTTPServer((host, port), handler_cls)
        srv._tls_watcher = None
        srv.reload_tls   = lambda: False
        scheme = "http"

    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info("CMP server listening on %s://%s:%s", scheme, host, port)

    if bootstrap_port:
        start_bootstrap_server(host, bootstrap_port, ca, cmp_handler)

    return srv


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def _standalone_main():
    parser = argparse.ArgumentParser(
        description="CMPv2/CMPv3 server — RFC 4210 / RFC 9480"
    )
    parser.add_argument("--host",      default="0.0.0.0")
    parser.add_argument("--port",      type=int, default=8080)
    parser.add_argument("--ca-dir",    default="./ca")
    parser.add_argument(
        "--no-cmpv3", dest="cmpv3", action="store_false", default=True,
        help="Force CMPv2 only (no RFC 9480 features)",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level)
    ca_dir = Path(args.ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    config = ServerConfig(ca_dir=ca_dir)
    ca = CertificateAuthority(ca_dir=str(ca_dir), config=config)

    srv = start_cmp_server(host=args.host, port=args.port, ca=ca,
                           use_cmpv3=args.cmpv3)
    proto = "CMPv3 (RFC 9480)" if args.cmpv3 else "CMPv2 (RFC 4210)"
    print(f"CMP server [{proto}] → http://{args.host}:{args.port}/")
    print(f"Well-known URI       → http://{args.host}:{args.port}/.well-known/cmp")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down CMP server...")
        srv.shutdown()


if __name__ == "__main__":
    _standalone_main()
