#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
PKI Server with CMPv2 Support (RFC 4210 / RFC 4211) + mTLS
===========================================================
A production-grade Certificate Management Protocol v2 server.

Features:
  - Full CA (Certificate Authority) with RSA key generation
  - CMPv2 message parsing and construction (ASN.1/DER)
  - HTTP transport for CMP (RFC 6712)
  - Supported operations:
      * ir  - Initialization Request
      * cr  - Certification Request
      * kur - Key Update Request
      * rr  - Revocation Request
      * certConf - Certificate Confirmation
      * genm/genp - General Message/Response (for CA info)
  - Certificate store (SQLite)
  - CRL generation
  - mTLS (mutual TLS) support:
      * Server presents its own TLS certificate
      * Clients must present a valid certificate signed by the CA
      * Client certificate subject logged and made available to handlers
      * Bootstrap endpoint (plain HTTP) to issue an initial client cert

Dependencies:
    pip install cryptography pyasn1 pyasn1-modules

Usage:
    # Plain HTTP (no mTLS)
    python pki_cmpv2_server.py [--host 0.0.0.0] [--port 8080] [--ca-dir ./ca]

    # mTLS enabled
    python pki_cmpv2_server.py --mtls --port 8443 [--ca-dir ./ca]

    # mTLS + ACME on a second port
    python pki_cmpv2_server.py --mtls --port 8443 --acme-port 8888 [--ca-dir ./ca]

    # ACME with dns-01 auto-approve (testing/internal CA only)
    python pki_cmpv2_server.py --acme-port 8888 --acme-auto-approve-dns
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import http.server
import json
import logging
import os
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

# Cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# ACME server module (optional — loaded if --acme-port is specified)
try:
    import acme_server as _acme_module
    HAS_ACME = True
except ImportError:
    HAS_ACME = False

# SCEP server module (optional — loaded if --scep-port is specified)
try:
    import scep_server as _scep_module
    HAS_SCEP = True
except ImportError:
    HAS_SCEP = False

# ASN.1 imports for CMPv2 message parsing
try:
    from pyasn1.type import univ, namedtype, tag, constraint, namedval, useful
    from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
    from pyasn1.codec.native import decoder as nat_decoder
    from pyasn1 import error as asn1_error
    HAS_PYASN1 = True
except ImportError:
    HAS_PYASN1 = False
    print("WARNING: pyasn1 not found. Install with: pip install pyasn1 pyasn1-modules")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pki-cmpv2")


# ---------------------------------------------------------------------------
# Live Server Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "validity": {
        "end_entity_days":  365,    # ir / cr / kur / p10cr issued certs
        "client_cert_days": 365,    # mTLS bootstrap client certs
        "tls_server_days":  365,    # server TLS certificate
        "ca_days":          3650,   # CA self-signed cert (only on first creation)
    }
}


class ServerConfig:
    """
    Thread-safe, hot-reloadable server configuration.

    Priority (highest → lowest):
      1. Live edits via PATCH /config  (in-memory)
      2. config.json on disk           (reloaded on every read if mtime changed)
      3. CLI arguments                 (set once at startup)
      4. Built-in defaults
    """

    def __init__(self, ca_dir: Path, cli_overrides: Optional[Dict[str, Any]] = None):
        self._ca_dir     = ca_dir
        self._config_path = ca_dir / "config.json"
        self._lock       = threading.RLock()
        self._data: Dict[str, Any] = {}
        self._file_mtime: float = 0.0
        self._cli        = cli_overrides or {}

        # Write defaults + CLI overrides to disk if no file exists yet
        if not self._config_path.exists():
            self._write_defaults()

        self._reload_file()

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    def get(self, *keys, default=None):
        """config.get('validity', 'end_entity_days', default=365)"""
        self._maybe_reload()
        with self._lock:
            val = self._effective()
            for k in keys:
                if not isinstance(val, dict):
                    return default
                val = val.get(k, default)
            return val

    @property
    def end_entity_days(self) -> int:
        return int(self.get("validity", "end_entity_days", default=365))

    @property
    def client_cert_days(self) -> int:
        return int(self.get("validity", "client_cert_days", default=365))

    @property
    def tls_server_days(self) -> int:
        return int(self.get("validity", "tls_server_days", default=365))

    @property
    def ca_days(self) -> int:
        return int(self.get("validity", "ca_days", default=3650))

    def as_dict(self) -> Dict[str, Any]:
        self._maybe_reload()
        with self._lock:
            import copy
            return copy.deepcopy(self._effective())

    # ------------------------------------------------------------------
    # Live update (PATCH /config)
    # ------------------------------------------------------------------

    def patch(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep-merge `updates` into the in-memory config and persist to disk.
        Returns the full resulting config dict.
        """
        with self._lock:
            self._deep_merge(self._data, updates)
            self._save_file()
            logger.info(f"Config updated: {updates}")
            return self.as_dict()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _effective(self) -> Dict[str, Any]:
        """Merge: defaults ← file ← CLI overrides ← in-memory edits."""
        import copy
        result = copy.deepcopy(DEFAULT_CONFIG)
        self._deep_merge(result, self._data)
        self._deep_merge(result, self._cli)
        return result

    def _maybe_reload(self):
        try:
            mtime = self._config_path.stat().st_mtime
            if mtime != self._file_mtime:
                self._reload_file()
        except FileNotFoundError:
            pass

    def _reload_file(self):
        try:
            with self._lock:
                with open(self._config_path) as f:
                    self._data = json.load(f)
                self._file_mtime = self._config_path.stat().st_mtime
            logger.info(f"Config loaded from {self._config_path}")
        except Exception as e:
            logger.warning(f"Could not load config file: {e}")

    def _save_file(self):
        with open(self._config_path, "w") as f:
            json.dump(self._effective(), f, indent=2)
        self._file_mtime = self._config_path.stat().st_mtime

    def _write_defaults(self):
        import copy
        merged = copy.deepcopy(DEFAULT_CONFIG)
        self._deep_merge(merged, self._cli)
        with open(self._config_path, "w") as f:
            json.dump(merged, f, indent=2)
        logger.info(f"Default config written to {self._config_path}")

    @staticmethod
    def _deep_merge(base: dict, override: dict):
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                ServerConfig._deep_merge(base[k], v)
            else:
                base[k] = v




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
    ) -> bytes:
        """Build a minimal DER-encoded PKIMessage response."""

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
        pvno = integer(2)

        # sender/recipient: use NULL GeneralName (directoryName with empty DN)
        sender = ctx(4, seq(b""), constructed=True)   # GeneralName [4] directoryName
        recipient = ctx(4, seq(b""), constructed=True)

        msg_time = ctx(0, generalizedtime(datetime.datetime.utcnow()), constructed=False)

        # sha256WithRSAEncryption OID for protection alg hint
        prot_alg = ctx(1, seq(oid("1.2.840.113549.1.1.11") + null()), constructed=False)

        tid = ctx(4, octet_string(transaction_id), constructed=False)
        snonce = ctx(5, octet_string(sender_nonce), constructed=False)

        header_content = pvno + sender + recipient + msg_time + prot_alg + tid + snonce
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
# Certificate Authority
# ---------------------------------------------------------------------------

class CertificateAuthority:
    """Self-signed CA with certificate issuance and revocation."""

    def __init__(self, ca_dir: str = "./ca", config: Optional["ServerConfig"] = None):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.ca_dir / "certificates.db"
        self.config  = config  # may be None (uses hardcoded defaults as fallback)
        self._init_db()
        self._load_or_create_ca()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                serial      INTEGER PRIMARY KEY,
                subject     TEXT NOT NULL,
                not_before  TEXT NOT NULL,
                not_after   TEXT NOT NULL,
                der         BLOB NOT NULL,
                revoked     INTEGER DEFAULT 0,
                revoked_at  TEXT,
                reason      INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS serial_counter (
                id    INTEGER PRIMARY KEY,
                value INTEGER NOT NULL
            )
        """)
        conn.execute("INSERT OR IGNORE INTO serial_counter VALUES (1, 1000)")
        conn.commit()
        conn.close()

    def _next_serial(self) -> int:
        conn = sqlite3.connect(str(self.db_path))
        try:
            row = conn.execute("SELECT value FROM serial_counter WHERE id=1").fetchone()
            serial = row[0]
            conn.execute("UPDATE serial_counter SET value=? WHERE id=1", (serial + 1,))
            conn.commit()
            return serial
        finally:
            conn.close()

    def _cfg(self, attr: str, default: int) -> int:
        """Read a validity value from config, falling back to default."""
        if self.config:
            return getattr(self.config, attr, default)
        return default

    def _load_or_create_ca(self):
        ca_key_path = self.ca_dir / "ca.key"
        ca_cert_path = self.ca_dir / "ca.crt"

        if ca_key_path.exists() and ca_cert_path.exists():
            logger.info("Loading existing CA key and certificate.")
            with open(ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
        else:
            logger.info("Generating new CA key and self-signed certificate...")
            self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyPKI CMPv2"),
                x509.NameAttribute(NameOID.COMMON_NAME, "PyPKI Root CA"),
            ])

            now = datetime.datetime.utcnow()
            ca_days = self._cfg("ca_days", 3650)
            self.ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(self.ca_key.public_key())
                .serial_number(1)
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=ca_days))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True, content_commitment=True,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=True,
                        crl_sign=True, encipher_only=False, decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                    critical=False,
                )
                .sign(self.ca_key, SHA256())
            )

            with open(ca_key_path, "wb") as f:
                f.write(self.ca_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
            with open(ca_cert_path, "wb") as f:
                f.write(self.ca_cert.public_bytes(Encoding.PEM))

            logger.info(f"CA certificate written to {ca_cert_path}")

    def issue_certificate(
        self,
        subject_str: str,
        public_key: RSAPublicKey,
        validity_days: Optional[int] = None,
        is_ca: bool = False,
        san_dns: Optional[list] = None,
    ) -> x509.Certificate:
        """Issue a certificate signed by this CA."""
        if validity_days is None:
            validity_days = self._cfg("end_entity_days", 365)

        # Parse subject string like "CN=Foo,O=Bar"
        attrs = []
        for part in subject_str.split(","):
            part = part.strip()
            if "=" not in part:
                continue
            key, _, val = part.partition("=")
            oid_map = {
                "CN": NameOID.COMMON_NAME,
                "O": NameOID.ORGANIZATION_NAME,
                "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
                "C": NameOID.COUNTRY_NAME,
                "L": NameOID.LOCALITY_NAME,
                "ST": NameOID.STATE_OR_PROVINCE_NAME,
            }
            if key.strip().upper() in oid_map:
                attrs.append(x509.NameAttribute(oid_map[key.strip().upper()], val.strip()))

        if not attrs:
            attrs = [x509.NameAttribute(NameOID.COMMON_NAME, subject_str)]

        subject = x509.Name(attrs)
        serial = self._next_serial()
        now = datetime.datetime.utcnow()

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=True,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=is_ca,
                    crl_sign=is_ca, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
        )

        if san_dns:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
                critical=False,
            )

        cert = builder.sign(self.ca_key, SHA256())

        # Store in DB
        conn = sqlite3.connect(str(self.db_path))
        conn.execute(
            "INSERT INTO certificates VALUES (?,?,?,?,?,0,NULL,NULL)",
            (
                serial,
                subject_str,
                now.isoformat(),
                (now + datetime.timedelta(days=validity_days)).isoformat(),
                cert.public_bytes(Encoding.DER),
            ),
        )
        conn.commit()
        conn.close()

        logger.info(f"Issued certificate serial={serial} subject='{subject_str}'")
        return cert

    def generate_ephemeral_key_and_cert(self, subject_str: str) -> Tuple[RSAPrivateKey, x509.Certificate]:
        """Generate a new RSA key pair and issue a certificate (for ir without provided key)."""
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = self.issue_certificate(subject_str, priv_key.public_key())
        return priv_key, cert

    def revoke_certificate(self, serial: int, reason: int = 0) -> bool:
        conn = sqlite3.connect(str(self.db_path))
        try:
            row = conn.execute("SELECT serial FROM certificates WHERE serial=? AND revoked=0", (serial,)).fetchone()
            if not row:
                return False
            now = datetime.datetime.utcnow().isoformat()
            conn.execute(
                "UPDATE certificates SET revoked=1, revoked_at=?, reason=? WHERE serial=?",
                (now, reason, serial),
            )
            conn.commit()
            logger.info(f"Revoked certificate serial={serial} reason={reason}")
            return True
        finally:
            conn.close()

    def generate_crl(self) -> bytes:
        """Generate a DER-encoded CRL."""
        conn = sqlite3.connect(str(self.db_path))
        revoked = conn.execute(
            "SELECT serial, revoked_at, reason FROM certificates WHERE revoked=1"
        ).fetchall()
        conn.close()

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(datetime.datetime.utcnow())
            .next_update(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        )

        for serial, revoked_at, reason in revoked:
            rev_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(
                    datetime.datetime.fromisoformat(revoked_at)
                    if revoked_at
                    else datetime.datetime.utcnow()
                )
                .build()
            )
            builder = builder.add_revoked_certificate(rev_cert)

        crl = builder.sign(self.ca_key, SHA256())
        return crl.public_bytes(Encoding.DER)

    def get_cert_by_serial(self, serial: int) -> Optional[bytes]:
        conn = sqlite3.connect(str(self.db_path))
        row = conn.execute("SELECT der FROM certificates WHERE serial=?", (serial,)).fetchone()
        conn.close()
        return row[0] if row else None

    def list_certificates(self) -> list:
        conn = sqlite3.connect(str(self.db_path))
        rows = conn.execute(
            "SELECT serial, subject, not_before, not_after, revoked FROM certificates"
        ).fetchall()
        conn.close()
        return [
            {"serial": r[0], "subject": r[1], "not_before": r[2], "not_after": r[3], "revoked": bool(r[4])}
            for r in rows
        ]

    def provision_tls_server_cert(self, hostname: str = "localhost") -> Tuple[Path, Path]:
        """
        Issue (or reuse) a TLS server certificate for this hostname.
        Returns (cert_pem_path, key_pem_path) inside ca_dir.
        """
        cert_path = self.ca_dir / "server.crt"
        key_path = self.ca_dir / "server.key"

        if cert_path.exists() and key_path.exists():
            # Re-use if still valid for at least 1 day
            try:
                with open(cert_path, "rb") as f:
                    existing = x509.load_pem_x509_certificate(f.read())
                if existing.not_valid_after_utc > (
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
                ):
                    logger.info(f"Reusing existing TLS server certificate: {cert_path}")
                    return cert_path, key_path
            except Exception:
                pass

        logger.info(f"Generating TLS server certificate for '{hostname}'...")
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        tls_days = self._cfg("tls_server_days", 365)
        cert = self.issue_certificate(
            subject_str=f"CN={hostname},O=PyPKI CMPv2 Server",
            public_key=priv_key.public_key(),
            validity_days=tls_days,
            san_dns=[hostname, "localhost", "127.0.0.1"],
        )

        with open(key_path, "wb") as f:
            f.write(priv_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

        logger.info(f"TLS server certificate written to {cert_path}")
        return cert_path, key_path

    def issue_client_cert(
        self,
        common_name: str,
        org: str = "CMPv2 Clients",
        validity_days: Optional[int] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Issue a client certificate and private key suitable for mTLS.
        Returns (cert_pem, key_pem).
        """
        if validity_days is None:
            validity_days = self._cfg("client_cert_days", 365)
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject_str = f"CN={common_name},O={org}"

        now = datetime.datetime.utcnow()
        serial = self._next_serial()
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(priv_key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=True,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(priv_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False,
            )
            .sign(self.ca_key, SHA256())
        )

        # Persist in DB
        conn = sqlite3.connect(str(self.db_path))
        conn.execute(
            "INSERT INTO certificates VALUES (?,?,?,?,?,0,NULL,NULL)",
            (
                serial, subject_str, now.isoformat(),
                (now + datetime.timedelta(days=validity_days)).isoformat(),
                cert.public_bytes(Encoding.DER),
            ),
        )
        conn.commit()
        conn.close()

        logger.info(f"Issued client certificate serial={serial} CN={common_name}")
        cert_pem = cert.public_bytes(Encoding.PEM)
        key_pem = priv_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        return cert_pem, key_pem

    # ALPN protocol identifiers
    ALPN_HTTP1   = "http/1.1"
    ALPN_H2      = "h2"
    ALPN_CMP     = "cmpc"          # RFC 9483 — CMP over TLS
    ALPN_ACME    = "acme-tls/1"   # RFC 8737 — tls-alpn-01 challenge

    def build_tls_context(
        self,
        cert_path: str,
        key_path: str,
        require_client_cert: bool = False,
        alpn_protocols: Optional[List[str]] = None,
    ) -> ssl.SSLContext:
        """
        Build a server-side SSLContext with ALPN support.

        Args:
            cert_path:            PEM path to the server certificate
            key_path:             PEM path to the server private key
            require_client_cert:  True  → mutual TLS (CERT_REQUIRED)
                                  False → one-way TLS (CERT_NONE)
            alpn_protocols:       List of ALPN protocol strings to advertise.
                                  Common values (use the class constants):
                                    CertificateAuthority.ALPN_HTTP1  = "http/1.1"
                                    CertificateAuthority.ALPN_H2     = "h2"
                                    CertificateAuthority.ALPN_CMP    = "cmpc"
                                    CertificateAuthority.ALPN_ACME   = "acme-tls/1"
                                  If None, defaults to ["http/1.1"] (no ALPN negotiation
                                  beyond the baseline).

        ALPN negotiation follows RFC 7301: the server advertises its supported
        list; the client picks the first mutually supported protocol.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Harden: disable weak ciphers and compression
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!RC4:!DES:!MD5"
        )

        # Load server certificate + private key
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        if require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ca_pem_path = self.ca_dir / "ca.crt"
            ctx.load_verify_locations(str(ca_pem_path))
            logger.info("TLS mode: mutual (client certificate required)")
        else:
            ctx.verify_mode = ssl.CERT_NONE
            logger.info("TLS mode: one-way (server certificate only)")

        # ALPN — advertise supported application protocols (RFC 7301)
        protos = alpn_protocols if alpn_protocols is not None else [self.ALPN_HTTP1]
        ctx.set_alpn_protocols(protos)
        logger.info(f"ALPN protocols advertised: {protos}")

        return ctx

    def build_acme_tls_alpn_context(
        self,
        domain: str,
        acme_key_auth_digest: bytes,
    ) -> ssl.SSLContext:
        """
        Build a one-shot SSLContext for the tls-alpn-01 challenge (RFC 8737).

        The context presents a self-signed certificate containing the
        id-pe-acmeIdentifier extension with the SHA-256 key-authorization
        digest, and advertises only the "acme-tls/1" ALPN protocol.

        Args:
            domain:                The domain being validated (goes in the cert SAN).
            acme_key_auth_digest:  SHA-256 digest of the key authorization string
                                   (32 raw bytes).

        Returns an SSLContext that should be used for a *single* incoming
        connection on port 443 while the challenge is pending.
        """
        # id-pe-acmeIdentifier OID: 1.3.6.1.5.5.7.1.31
        ACME_ID_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.31")

        # Generate a throwaway key for this challenge cert
        throwaway_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.utcnow()

        # Build the challenge certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, domain)
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, domain)
            ]))
            .public_key(throwaway_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain)]),
                critical=True,
            )
            .add_extension(
                # id-pe-acmeIdentifier: critical DER-encoded SHA-256 digest (ASN.1 OCTET STRING)
                x509.UnrecognizedExtension(
                    ACME_ID_OID,
                    b" " + acme_key_auth_digest,   # OCTET STRING (32 bytes)
                ),
                critical=True,
            )
            .sign(throwaway_key, SHA256())
        )

        # Write to temp files (SSLContext.load_cert_chain needs file paths)
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
            cf.write(cert.public_bytes(Encoding.PEM))
            cert_tmp = cf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
            kf.write(throwaway_key.private_bytes(
                Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, NoEncryption()
            ))
            key_tmp = kf.name

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert_tmp, keyfile=key_tmp)
        ctx.set_alpn_protocols([self.ALPN_ACME])   # MUST advertise only acme-tls/1
        ctx.verify_mode = ssl.CERT_NONE

        os.unlink(cert_tmp)
        os.unlink(key_tmp)

        logger.info(f"tls-alpn-01 challenge context built for {domain}")
        return ctx

    def build_ssl_context(self, server_side: bool = True) -> ssl.SSLContext:
        """
        Legacy helper — kept for backwards compatibility.
        Prefer build_tls_context() for new code.
        """
        if server_side:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        ca_pem_path = self.ca_dir / "ca.crt"
        ctx.load_verify_locations(str(ca_pem_path))
        return ctx

    def get_certificate_by_serial(self, serial: int) -> Optional[str]:
        """Return PEM string for the certificate with the given serial number, or None."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT cert_pem FROM certificates WHERE serial=?", (serial,)
            ).fetchone()
            return row["cert_pem"] if row else None
        finally:
            conn.close()

    def generate_crl_der(self) -> bytes:
        """Generate and return the current CRL in DER format."""
        # Build a real CRL from the revoked serials in the DB
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(datetime.datetime.utcnow())
            .next_update(datetime.datetime.utcnow() + datetime.timedelta(days=7))
        )
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT serial, revoked_at FROM certificates WHERE revoked=1"
            ).fetchall()
            for row in rows:
                revoked_cert = (
                    x509.RevokedCertificateBuilder()
                    .serial_number(row["serial"])
                    .revocation_date(
                        datetime.datetime.utcfromtimestamp(row["revoked_at"])
                        if row["revoked_at"]
                        else datetime.datetime.utcnow()
                    )
                    .build()
                )
                builder = builder.add_revoked_certificate(revoked_cert)
        finally:
            conn.close()
        crl = builder.sign(private_key=self.ca_key, algorithm=SHA256())
        return crl.public_bytes(Encoding.DER)

    @property
    def ca_cert_der(self) -> bytes:
        return self.ca_cert.public_bytes(Encoding.DER)

    @property
    def ca_cert_pem(self) -> bytes:
        return self.ca_cert.public_bytes(Encoding.PEM)


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
# HTTP Server (RFC 6712 - CMP over HTTP)
# ---------------------------------------------------------------------------

class CMPv2HTTPHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP handler for CMPv2 as per RFC 6712.
    POST /<path> with Content-Type: application/pkixcmp
    """

    cmp_handler: CMPv2Handler = None  # Set by server
    ca: CertificateAuthority = None

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

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        content_type = self.headers.get("Content-Type", "")
        if content_type not in ("application/pkixcmp", "application/pkixcmp-poll",
                                 "application/octet-stream"):
            logger.warning(f"Unexpected Content-Type: {content_type}")

        # Log authenticated client identity
        client_cn = self._get_client_cn()
        if client_cn:
            logger.info(f"Authenticated mTLS client: CN={client_cn}")

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
            data = self.ca.ca_cert_pem
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        elif path == "/ca/cert.der":
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
            self._send_json({"certificates": self.ca.list_certificates()})

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
                bundle = cert_pem + key_pem + self.ca.ca_cert_pem
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

        else:
            self._send_json({
                "endpoints": {
                    "POST /": "CMPv2 endpoint (Content-Type: application/pkixcmp)",
                    "GET  /config": "View current configuration (validity periods etc.)",
                    "PATCH /config": "Live-update: PATCH /config with JSON {validity:{end_entity_days:90}}",
                    "GET /ca/cert.pem": "CA certificate (PEM)",
                    "GET /ca/cert.der": "CA certificate (DER)",
                    "GET /ca/crl": "Certificate Revocation List (DER)",
                    "GET /api/certs": "List issued certificates (JSON)",
                    "GET /api/whoami": "Show authenticated mTLS client identity",
                    "GET /bootstrap?cn=<name>": "Issue client cert bundle (bootstrap port only)",
                    "GET /health": "Health check",
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


class TLSServer(ThreadedHTTPServer):
    """
    HTTPS server that wraps each accepted socket with an SSLContext.

    Modes (controlled by the SSLContext verify_mode):
      - One-way TLS  (ssl.CERT_NONE)     : --tls   (server cert only)
      - Mutual  TLS  (ssl.CERT_REQUIRED) : --mtls  (client cert required)
    """
    ssl_context: ssl.SSLContext = None

    def get_request(self):
        sock, addr = super().get_request()
        try:
            tls_sock = self.ssl_context.wrap_socket(sock, server_side=True)
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

def make_handler(ca: CertificateAuthority, cmp_handler: CMPv2Handler):
    class BoundHandler(CMPv2HTTPHandler):
        pass
    BoundHandler.ca = ca
    BoundHandler.cmp_handler = cmp_handler
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


def main():
    parser = argparse.ArgumentParser(description="PKI Server with CMPv2 Support + mTLS")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument("--ca-dir", default="./ca", help="CA data directory (default: ./ca)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    tls_group = parser.add_argument_group(
        "TLS options",
        "Use --tls for one-way TLS (server cert only) or --mtls for mutual TLS. "
        "These flags are mutually exclusive. By default the CA auto-issues a server "
        "certificate; supply --tls-cert/--tls-key to use your own."
    )
    tls_mode = tls_group.add_mutually_exclusive_group()
    tls_mode.add_argument(
        "--tls", action="store_true",
        help="Enable HTTPS with server certificate only (one-way TLS)"
    )
    tls_mode.add_argument(
        "--mtls", action="store_true",
        help="Enable HTTPS with mutual TLS (client certificate required)"
    )
    tls_group.add_argument(
        "--tls-hostname", default="localhost",
        help="Hostname for the auto-issued server TLS certificate SAN (default: localhost)"
    )
    tls_group.add_argument(
        "--tls-cert", metavar="PATH",
        help="Path to an existing PEM server certificate (skips auto-issuance)"
    )
    tls_group.add_argument(
        "--tls-key", metavar="PATH",
        help="Path to the PEM private key for --tls-cert"
    )
    parser.add_argument(
        "--bootstrap-port", type=int, default=None,
        help="If set, also start a plain-HTTP bootstrap server on this port "
             "for issuing initial client certs (use only on trusted networks)"
    )

    alpn_group = parser.add_argument_group(
        "ALPN options (RFC 7301)",
        "Control which application protocols are advertised in the TLS handshake. "
        "Only relevant when --tls or --mtls is set."
    )
    alpn_group.add_argument(
        "--alpn-http", action="store_true", default=True,
        help="Advertise http/1.1 via ALPN (default: on)"
    )
    alpn_group.add_argument(
        "--no-alpn-http", dest="alpn_http", action="store_false",
        help="Do not advertise http/1.1 via ALPN"
    )
    alpn_group.add_argument(
        "--alpn-h2", action="store_true", default=False,
        help="Advertise h2 (HTTP/2) via ALPN (default: off — requires an HTTP/2 capable server)"
    )
    alpn_group.add_argument(
        "--alpn-cmp", action="store_true", default=False,
        help="Advertise cmpc (CMP over TLS, RFC 9483) via ALPN"
    )
    alpn_group.add_argument(
        "--alpn-acme", action="store_true", default=False,
        help="Advertise acme-tls/1 (RFC 8737 tls-alpn-01) via ALPN. "
             "Also enables the tls-alpn-01 challenge type in the ACME server."
    )

    acme_group = parser.add_argument_group(
        "ACME options (RFC 8555)",
        "Enable the ACME protocol for automated certificate issuance. "
        "Requires acme_server.py in the same directory."
    )
    acme_group.add_argument(
        "--acme-port", type=int, default=None, metavar="PORT",
        help="Start ACME server on this port (e.g. 8888)"
    )
    acme_group.add_argument(
        "--acme-base-url", default=None, metavar="URL",
        help="Public base URL for ACME (default: http://<host>:<acme-port>)"
    )
    acme_group.add_argument(
        "--acme-auto-approve-dns", action="store_true",
        help="Auto-approve dns-01 challenges without DNS lookup (testing/internal CA only)"
    )

    scep_group = parser.add_argument_group(
        "SCEP options (RFC 8894)",
        "Enable the SCEP protocol for network device certificate enrolment. "
        "Requires scep_server.py in the same directory."
    )
    scep_group.add_argument(
        "--scep-port", type=int, default=None, metavar="PORT",
        help="Start SCEP server on this port (e.g. 8889)"
    )
    scep_group.add_argument(
        "--scep-challenge", default="", metavar="SECRET",
        help="Challenge password for SCEP enrolment (empty = no challenge required)"
    )

    validity_group = parser.add_argument_group(
        "validity periods",
        "Initial certificate lifetime defaults (can also be changed live via PATCH /config)"
    )
    validity_group.add_argument("--end-entity-days", type=int, default=None,
                                metavar="DAYS", help="End-entity cert lifetime (default: 365)")
    validity_group.add_argument("--client-cert-days", type=int, default=None,
                                metavar="DAYS", help="mTLS client cert lifetime (default: 365)")
    validity_group.add_argument("--tls-server-days", type=int, default=None,
                                metavar="DAYS", help="TLS server cert lifetime (default: 365)")
    validity_group.add_argument("--ca-days", type=int, default=None,
                                metavar="DAYS", help="CA cert lifetime on first creation (default: 3650)")

    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level)

    # Build CLI overrides dict (only keys the user explicitly set)
    cli_validity = {}
    if args.end_entity_days:  cli_validity["end_entity_days"]  = args.end_entity_days
    if args.client_cert_days: cli_validity["client_cert_days"] = args.client_cert_days
    if args.tls_server_days:  cli_validity["tls_server_days"]  = args.tls_server_days
    if args.ca_days:          cli_validity["ca_days"]          = args.ca_days
    cli_overrides = {"validity": cli_validity} if cli_validity else {}

    ca_dir = Path(args.ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    config = ServerConfig(ca_dir=ca_dir, cli_overrides=cli_overrides)

    ca = CertificateAuthority(ca_dir=args.ca_dir, config=config)
    cmp_handler = CMPv2Handler(ca)
    handler_class = make_handler(ca, cmp_handler)

    scheme = "http"
    tls_mode_label = "plain HTTP"

    if args.tls or args.mtls:
        # Resolve server cert/key — use BYO files if supplied, else auto-issue from CA
        if args.tls_cert and args.tls_key:
            cert_path = args.tls_cert
            key_path  = args.tls_key
            logger.info(f"Using provided TLS certificate: {cert_path}")
        else:
            cert_path, key_path = ca.provision_tls_server_cert(args.tls_hostname)
            cert_path = str(cert_path)
            key_path  = str(key_path)

        require_client = args.mtls

        # Build ALPN protocol list from flags
        alpn_protos: List[str] = []
        if args.alpn_h2:
            alpn_protos.append(CertificateAuthority.ALPN_H2)
        if getattr(args, "alpn_http", True):
            alpn_protos.append(CertificateAuthority.ALPN_HTTP1)
        if args.alpn_cmp:
            alpn_protos.append(CertificateAuthority.ALPN_CMP)
        if args.alpn_acme:
            alpn_protos.append(CertificateAuthority.ALPN_ACME)
        if not alpn_protos:
            alpn_protos = [CertificateAuthority.ALPN_HTTP1]

        ssl_ctx = ca.build_tls_context(
            cert_path=cert_path,
            key_path=key_path,
            require_client_cert=require_client,
            alpn_protocols=alpn_protos,
        )

        server = TLSServer((args.host, args.port), handler_class)
        server.ssl_context = ssl_ctx
        scheme = "https"

        if args.mtls:
            tls_mode_label = "mutual TLS (client cert required)"
            logger.info(f"mTLS — clients must present a cert signed by: {ca.ca_dir / 'ca.crt'}")
        else:
            tls_mode_label = "TLS (server cert only)"
    else:
        server = ThreadedHTTPServer((args.host, args.port), handler_class)

    bootstrap_srv = None
    if args.bootstrap_port:
        bootstrap_srv = start_bootstrap_server(args.host, args.bootstrap_port, ca, cmp_handler)

    # Start ACME server if requested
    acme_srv = None
    if args.acme_port:
        if not HAS_ACME:
            print("WARNING: acme_server.py not found — ACME support disabled.")
            print("         Place acme_server.py in the same directory as pki_cmpv2_server.py.")
        else:
            acme_base = args.acme_base_url or f"http://{args.host}:{args.acme_port}"
            acme_srv = _acme_module.start_acme_server(
                host=args.host,
                port=args.acme_port,
                ca=ca,
                ca_dir=ca_dir,
                auto_approve_dns=args.acme_auto_approve_dns,
                base_url=acme_base,
            )

    # Start SCEP server if requested
    scep_srv = None
    if args.scep_port:
        if not HAS_SCEP:
            print("WARNING: scep_server.py not found — SCEP support disabled.")
            print("         Place scep_server.py in the same directory as pki_cmpv2_server.py.")
        else:
            scep_srv = _scep_module.start_scep_server(
                host=args.host,
                port=args.scep_port,
                ca=ca,
                ca_dir=ca_dir,
                challenge=args.scep_challenge,
            )

    acme_line = f"http://{args.host}:{args.acme_port}/acme/directory" if (args.acme_port and HAS_ACME) else "disabled"
    scep_line = f"http://{args.host}:{args.scep_port}/scep" if (args.scep_port and HAS_SCEP) else "disabled"
    boot_line = f"http://{args.host}:{args.bootstrap_port}/bootstrap?cn=<n>" if args.bootstrap_port else "disabled"

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║         PyPKI CMPv2 + ACME Server (RFC 4210 / RFC 8555 + TLS)  ║
╠══════════════════════════════════════════════════════════════════╣
║  Listening (CMPv2): {scheme}://{args.host}:{args.port:<32}║
║  Listening (ACME) : {acme_line:<47}║
║  CA Dir           : {args.ca_dir:<47}║
║  TLS Mode         : {tls_mode_label:<47}║
║  Bootstrap        : {boot_line:<47}║
║  Listening (SCEP) : {scep_line:<47}║
╠══════════════════════════════════════════════════════════════════╣
║  Validity periods (change live: PATCH /config)                  ║
║    End-entity   : {config.end_entity_days:<3} days                                       ║
║    Client cert  : {config.client_cert_days:<3} days                                       ║
║    TLS server   : {config.tls_server_days:<3} days                                       ║
║    CA cert      : {config.ca_days:<4} days                                      ║
╠══════════════════════════════════════════════════════════════════╣
║  CMPv2 Endpoint  : POST {scheme}://{args.host}:{args.port}/           ║
║  ACME Directory  : GET  {acme_line:<40}║
║  SCEP Endpoint   : {scep_line:<48}║
║  Config          : GET/PATCH {scheme}://{args.host}:{args.port}/config ║
║  CA Certificate  : GET  {scheme}://{args.host}:{args.port}/ca/cert.pem ║
║  CRL             : GET  {scheme}://{args.host}:{args.port}/ca/crl      ║
║  Health Check    : GET  {scheme}://{args.host}:{args.port}/health      ║
╠══════════════════════════════════════════════════════════════════╣
║  Supported CMPv2 operations:                                    ║
║    ir  - Initialization Request                                 ║
║    cr  - Certification Request                                  ║
║    kur - Key Update Request                                     ║
║    rr  - Revocation Request                                     ║
║    certConf - Certificate Confirmation                          ║
║    genm - General Message (CA Info)                             ║
║    p10cr - PKCS#10 Certificate Request                          ║
╠══════════════════════════════════════════════════════════════════╣
║  Supported ACME operations (RFC 8555):                         ║
║    new-account, new-order, http-01, dns-01, finalize, revoke   ║
╠══════════════════════════════════════════════════════════════════╣
║  Supported SCEP operations (RFC 8894):                          ║
║    GetCACaps, GetCACert, PKCSReq, CertPoll, GetCert, GetCRL    ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if args.tls:
        print("  TLS Quick-start:")
        print(f"     curl --cacert {args.ca_dir}/ca.crt {scheme}://{args.tls_hostname}:{args.port}/health")
        print()

    if args.mtls:
        print("  mTLS Quick-start:")
        print(f"  1. Get a client cert bundle:")
        print(f"     curl http://localhost:{args.bootstrap_port or 8080}/bootstrap?cn=myclient -o bundle.pem")
        print(f"  2. Split bundle: openssl x509 -in bundle.pem -out client.crt")
        print(f"                   openssl pkey -in bundle.pem -out client.key")
        print(f"  3. curl --cert client.crt --key client.key --cacert {args.ca_dir}/ca.crt \\")
        print(f"          {scheme}://{args.tls_hostname}:{args.port}/health")
        print()

    if args.scep_port and HAS_SCEP:
        print("  SCEP Quick-start:")
        print(f"  1. Fetch CA cert:  sscep getca -u http://{args.host}:{args.scep_port}/scep -c ca.crt")
        print(f"  2. Enrol:          sscep enroll -u http://{args.host}:{args.scep_port}/scep \\")
        print(f"                       -c ca.crt -k client.key -r client.csr -l client.crt \\")
        if args.scep_challenge:
            print(f"                       -p '{args.scep_challenge}'")
        print()

    if args.acme_port and HAS_ACME:
        print("  ACME Quick-start:")
        print(f"  1. Fetch directory:    curl {acme_line}")
        print(f"  2. Use any ACME client (certbot, acme.sh, custom) pointed at:")
        print(f"     {acme_line}")
        print(f"  3. For http-01: client must serve the challenge token on port 80.")
        print(f"  4. For dns-01:  client must create a TXT record at _acme-challenge.<domain>.")
        if args.acme_auto_approve_dns:
            print(f"  ⚠ dns-01 auto-approval is ON — do not use in production!")
        print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down PKI server...")
        server.shutdown()
        if bootstrap_srv:
            bootstrap_srv.shutdown()
        if acme_srv:
            acme_srv.shutdown()
        if scep_srv:
            scep_srv.shutdown()

if __name__ == "__main__":
    main()
