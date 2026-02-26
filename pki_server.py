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
  - Certificate profiles (tls_server, tls_client, code_signing, email, ocsp_signing,
    sub_ca, short_lived, default)
  - RFC 9608: id-ce-noRevAvail extension for short-lived certs (CDP/AIA suppressed)
  - RFC 9549/9598: IDNA U-label->A-label for dNSName SANs and domainComponent;
    SmtpUTF8Mailbox otherName for non-ASCII email addresses
  - RFC 5280 §4.2.1.4 / RFC 6818: CertificatePolicies with CPS URI + UserNotice

Dependencies:
    pip install cryptography pyasn1 pyasn1-modules

Usage:
    # Plain HTTP (no mTLS)
    python pki_server.py [--host 0.0.0.0] [--port 8080] [--ca-dir ./ca]

    # mTLS enabled
    python pki_server.py --mtls --port 8443 [--ca-dir ./ca]

    # mTLS + ACME on a second port
    python pki_server.py --mtls --port 8443 --acme-port 8888 [--ca-dir ./ca]

    # ACME with dns-01 auto-approve (testing/internal CA only)
    python pki_server.py --acme-port 8888 --acme-auto-approve-dns
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
import re
import ipaddress
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

# RFC 9608 — No Revocation Available extension OID (id-ce 56)
OID_NO_REV_AVAIL = x509.ObjectIdentifier("2.5.29.56")
NO_REV_AVAIL_THRESHOLD_DAYS = 7  # certs valid <=7 days SHOULD carry noRevAvail

# RFC 8398/9598 — SmtpUTF8Mailbox otherName OID for non-ASCII email in SAN
OID_SMTP_UTF8_MAILBOX = x509.ObjectIdentifier("1.3.6.1.5.5.7.8.9")

# RFC 5280 §4.2.1.14 — Well-known CA/B Forum policy OIDs (for CertificatePolicies)
OID_ANY_POLICY          = x509.ObjectIdentifier("2.5.29.32.0")
OID_POLICY_DV           = x509.ObjectIdentifier("2.23.140.1.2.1")  # CA/B Forum DV
OID_POLICY_OV           = x509.ObjectIdentifier("2.23.140.1.2.2")  # CA/B Forum OV
OID_POLICY_IV           = x509.ObjectIdentifier("2.23.140.1.2.3")  # CA/B Forum IV
OID_POLICY_EV           = x509.ObjectIdentifier("2.23.140.1.1")    # CA/B Forum EV
OID_QT_CPS              = x509.ObjectIdentifier("1.3.6.1.5.5.7.2.1") # id-qt-cps
OID_QT_UNOTICE          = x509.ObjectIdentifier("1.3.6.1.5.5.7.2.2") # id-qt-unotice
from cryptography.hazmat.primitives.serialization import pkcs12
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

# EST server module (optional — loaded if --est-port is specified)
try:
    import est_server as _est_module
    HAS_EST = True
except ImportError:
    HAS_EST = False

# OCSP responder module (optional — loaded if --ocsp-port is specified)
try:
    import ocsp_server as _ocsp_module
    HAS_OCSP = True
except ImportError:
    HAS_OCSP = False

# Web UI module (optional — loaded if --web-port is specified)
try:
    import web_ui as _web_ui_module
    HAS_WEBUI = True
except ImportError:
    HAS_WEBUI = False

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

import copy

logging.basicConfig(    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pki-cmpv2")

# ---------------------------------------------------------------------------
# Feature 10 — OpenTelemetry tracing (optional)
# ---------------------------------------------------------------------------
# If the opentelemetry-sdk package is installed, PyPKI creates spans for every
# certificate issuance, revocation, CRL generation, and HTTP request.
# Without the package, all tracing calls are no-ops (zero overhead).
#
# Install:  pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc
# Configure: set OTEL_EXPORTER_OTLP_ENDPOINT env var (e.g. http://localhost:4317)
# ---------------------------------------------------------------------------

try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.trace import TracerProvider as _OtelTracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor as _BatchSpanProcessor
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter as _OTLPExporter,
        )
        _HAS_OTLP = True
    except ImportError:
        _HAS_OTLP = False
    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False
    _HAS_OTLP = False


def _setup_otel(service_name: str = "pypki") -> None:
    """
    Configure the OpenTelemetry SDK.  Called once at startup if --otel-endpoint
    is provided.  Without the SDK this is a no-op.
    """
    if not _HAS_OTEL:
        logger.debug("opentelemetry-sdk not installed — tracing disabled")
        return

    provider = _OtelTracerProvider()
    if _HAS_OTLP:
        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
        exporter = _OTLPExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(_BatchSpanProcessor(exporter))
        logger.info(f"OpenTelemetry tracing → {endpoint}")
    else:
        # Fallback: log spans to stderr
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        logger.info("OpenTelemetry tracing → console (OTLP exporter not installed)")

    _otel_trace.set_tracer_provider(provider)


def _get_tracer():
    """Return an OpenTelemetry Tracer, or a no-op stub if OTEL is unavailable."""
    if _HAS_OTEL:
        return _otel_trace.get_tracer("pypki")
    # No-op stub
    class _NoopSpan:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def set_attribute(self, *a): pass
        def record_exception(self, *a): pass
        def set_status(self, *a): pass
    class _NoopTracer:
        def start_as_current_span(self, name, **kw):
            return _NoopSpan()
    return _NoopTracer()


_tracer = None  # Set to _get_tracer() after _setup_otel() is called in main()




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


# ---------------------------------------------------------------------------
# RFC 9549 / RFC 8399 — IDNA helpers
# ---------------------------------------------------------------------------

def _idna_encode_label(label: str) -> str:
    """
    Encode a single DNS label using Python's built-in IDNA codec (RFC 3490).

    The built-in codec implicitly applies UseSTD3ASCIIRules (RFC 6818 §7.3):
    labels with invalid characters (spaces, underscores etc.) raise UnicodeError.

    Returns the ACE (A-label) form, e.g. 'münchen' → 'xn--mnchen-3ya'.
    Raises ValueError if the label cannot be IDNA-encoded.
    """
    try:
        return label.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"IDNA encoding failed for label {label!r}: {exc}") from exc


def _idna_encode_domain(domain: str) -> str:
    """
    Convert a fully-qualified domain name to its A-label form per RFC 9549 §4.1.

    Each label is encoded independently so multi-level domains work correctly,
    e.g. 'sub.münchen.de' → 'sub.xn--mnchen-3ya.de'.

    Pure-ASCII domains pass through unchanged.  Raises ValueError on failure.
    """
    if not domain:
        return domain
    # Already pure ASCII — skip encoding (avoids roundtrip issues with wildcards)
    try:
        domain.encode("ascii")
        return domain
    except UnicodeEncodeError:
        pass
    parts = domain.split(".")
    encoded = []
    for part in parts:
        if part == "*":
            encoded.append("*")          # preserve wildcard label
        else:
            encoded.append(_idna_encode_label(part))
    return ".".join(encoded)


def _encode_smtp_utf8_mailbox(mailbox: str) -> bytes:
    """
    Encode a SmtpUTF8Mailbox value per RFC 9598 §3.

    The encoding is a DER UTF8String (tag 0x0C) containing the UTF-8 mailbox.
    This is used as the value of an OtherName with type-id OID_SMTP_UTF8_MAILBOX.
    """
    data = mailbox.encode("utf-8")
    length = len(data)
    if length < 0x80:
        len_bytes = bytes([length])
    elif length < 0x100:
        len_bytes = bytes([0x81, length])
    else:
        len_bytes = bytes([0x82, length >> 8, length & 0xFF])
    return b"\x0c" + len_bytes + data


def _split_email(email: str):
    """Return (local_part, host_part) for an RFC 5321 address, or raise ValueError."""
    if "@" not in email:
        raise ValueError(f"Invalid email address (no @): {email!r}")
    local, _, host = email.partition("@")
    return local, host


def _has_non_ascii(s: str) -> bool:
    """Return True if the string contains any code point > 0x7F."""
    return any(ord(c) > 0x7F for c in s)


# ---------------------------------------------------------------------------
# RFC 5280 §4.2.1.4 — CertificatePolicies helpers
# ---------------------------------------------------------------------------

def _build_policy_information(policy_oid: str,
                               cps_uri: Optional[str] = None,
                               notice_text: Optional[str] = None
                               ) -> "x509.PolicyInformation":
    """
    Build a single PolicyInformation object for use in CertificatePolicies.

    Args:
        policy_oid  : dotted-string OID, e.g. "2.23.140.1.2.1" (CA/B Forum DV)
        cps_uri     : optional CPS URL added as id-qt-cps qualifier
        notice_text : optional human-readable text added as id-qt-unotice UserNotice
                      RFC 6818 §4.2.1.4 requires explicitText to use UTF8String —
                      the cryptography library encodes it as UTF8String automatically.

    Returns a cryptography x509.PolicyInformation instance.
    """
    qualifiers = []
    if cps_uri:
        qualifiers.append(cps_uri)           # library wraps in CPSUri automatically
    if notice_text:
        qualifiers.append(x509.UserNotice(notice_reference=None,
                                           explicit_text=notice_text))
    return x509.PolicyInformation(
        policy_identifier=x509.ObjectIdentifier(policy_oid),
        policy_qualifiers=qualifiers if qualifiers else None,
    )


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
            if der_data[0] != 0x30:
                raise ValueError(f"Expected SEQUENCE (0x30), got 0x{der_data[0]:02x}")

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
# Audit Log
# ---------------------------------------------------------------------------

class AuditLog:
    """
    Structured audit log stored in SQLite.
    Every certificate issuance, revocation, auth event and config change is recorded.
    """

    def __init__(self, ca_dir: Path):
        self._db = ca_dir / "audit.db"
        self._init()

    def _init(self):
        conn = sqlite3.connect(str(self._db))
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts      TEXT NOT NULL,
                    event   TEXT NOT NULL,
                    detail  TEXT,
                    ip      TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def record(self, event: str, detail: str = "", ip: str = ""):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn = sqlite3.connect(str(self._db))
        try:
            conn.execute("INSERT INTO audit(ts,event,detail,ip) VALUES(?,?,?,?)",
                         (ts, event, detail, ip))
            conn.commit()
        finally:
            conn.close()
        logger.info(f"AUDIT [{event}] {detail}")

    def recent(self, n: int = 100) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(str(self._db))
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts,event,detail,ip FROM audit ORDER BY id DESC LIMIT ?", (n,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Token-bucket rate limiter per IP address.
    Applied to all certificate issuance endpoints.
    """

    def __init__(self, max_per_minute: int = 10):
        self._max   = max_per_minute
        self._data: Dict[str, List[float]] = {}   # ip -> list of timestamps
        self._lock  = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.time()
        window = 60.0
        with self._lock:
            timestamps = self._data.get(ip, [])
            # Remove timestamps outside the window
            timestamps = [t for t in timestamps if now - t < window]
            if len(timestamps) >= self._max:
                return False
            timestamps.append(now)
            self._data[ip] = timestamps
        return True

    def status(self, ip: str) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            timestamps = [t for t in self._data.get(ip, []) if now - t < 60]
        return {"ip": ip, "requests_last_minute": len(timestamps), "limit": self._max}


# ---------------------------------------------------------------------------
# Certificate Profiles
# ---------------------------------------------------------------------------

class CertProfile:
    """
    Named certificate profiles that control extensions, key usage, and validity.

    Built-in profiles:
      tls_server   — serverAuth EKU, SAN required, digitalSignature + keyEncipherment
      tls_client   — clientAuth EKU, digitalSignature
      code_signing — codeSigning EKU, digitalSignature + contentCommitment
      email        — emailProtection EKU, digitalSignature + keyEncipherment
      ocsp_signing — OCSPSigning EKU, nocheck extension
      sub_ca       — BasicConstraints cA=True, keyCertSign + cRLSign
      default      — end-entity, all key usages, no EKU restriction
    """

    PROFILES = {
        "tls_server": {
            "key_usage": dict(digital_signature=True, content_commitment=False,
                              key_encipherment=True, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False),
            "eku": [ExtendedKeyUsageOID.SERVER_AUTH],
            "san_required": True,
            "bc_ca": False,
        },
        "tls_client": {
            "key_usage": dict(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False),
            "eku": [ExtendedKeyUsageOID.CLIENT_AUTH],
            "san_required": False,
            "bc_ca": False,
        },
        "code_signing": {
            "key_usage": dict(digital_signature=True, content_commitment=True,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False),
            "eku": [ExtendedKeyUsageOID.CODE_SIGNING],
            "san_required": False,
            "bc_ca": False,
        },
        "email": {
            "key_usage": dict(digital_signature=True, content_commitment=True,
                              key_encipherment=True, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False),
            "eku": [ExtendedKeyUsageOID.EMAIL_PROTECTION],
            "san_required": False,
            "bc_ca": False,
        },
        "ocsp_signing": {
            "key_usage": dict(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False),
            "eku": [ExtendedKeyUsageOID.OCSP_SIGNING],
            "san_required": False,
            "bc_ca": False,
            "ocsp_nocheck": True,
        },
        "sub_ca": {
            "key_usage": dict(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=True,
                              crl_sign=True, encipher_only=False, decipher_only=False),
            "eku": [],
            "san_required": False,
            "bc_ca": True,
            "path_length": 0,
        },
        "default": {
            "key_usage": dict(digital_signature=True, content_commitment=True,
                              key_encipherment=True, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False),
            "eku": [],
            "san_required": False,
            "bc_ca": False,
        },
        # RFC 9608 — Short-lived end-entity cert.
        # id-ce-noRevAvail (2.5.29.56) is added; CDP and AIA-OCSP are suppressed.
        # RFC 9608 §4: MUST NOT be a CA cert; MUST NOT have CDP or OCSP AIA.
        "short_lived": {
            "key_usage": dict(digital_signature=True, content_commitment=False,
                              key_encipherment=True, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False),
            "eku": [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
            "san_required": False,
            "bc_ca": False,
            "no_rev_avail": True,   # triggers id-ce-noRevAvail extension
            "suppress_cdp": True,   # RFC 9608 §4: MUST NOT include CDP
            "suppress_ocsp_aia": True,  # RFC 9608 §4: MUST NOT include AIA OCSP
        },
    }

    @classmethod
    def get(cls, name: str) -> Dict[str, Any]:
        return cls.PROFILES.get(name, cls.PROFILES["default"])


# ---------------------------------------------------------------------------
# Certificate Authority
# ---------------------------------------------------------------------------

class CertificateAuthority:
    """Self-signed CA with certificate issuance and revocation."""

    def __init__(self, ca_dir: str = "./ca", config: Optional["ServerConfig"] = None,
                 ocsp_url: str = "", crl_url: str = "",
                 ca_key_passphrase: Optional[bytes] = None):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.ca_dir / "certificates.db"
        self.config  = config  # may be None (uses hardcoded defaults as fallback)
        self._ocsp_url = ocsp_url   # embedded in every issued cert AIA extension
        self._crl_url  = crl_url    # embedded in every issued cert CDP extension
        self._ca_key_passphrase = ca_key_passphrase
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
                reason      INTEGER,
                profile     TEXT DEFAULT 'default'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS serial_counter (
                id    INTEGER PRIMARY KEY,
                value INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS crl_base (
                id          INTEGER PRIMARY KEY,
                issued_at   TEXT NOT NULL,
                this_update TEXT NOT NULL,
                next_update TEXT NOT NULL,
                der         BLOB NOT NULL
            )
        """)
        conn.execute("INSERT OR IGNORE INTO serial_counter VALUES (1, 1000)")
        # Migrate: add profile column if missing (for existing DBs)
        try:
            conn.execute("ALTER TABLE certificates ADD COLUMN profile TEXT DEFAULT 'default'")
        except Exception:
            pass
        conn.commit()
        conn.close()

    _serial_lock = threading.Lock()

    def _next_serial(self) -> int:
        with self._serial_lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                conn.execute("BEGIN EXCLUSIVE")
                row = conn.execute("SELECT value FROM serial_counter WHERE id=1").fetchone()
                serial = row[0]
                conn.execute("UPDATE serial_counter SET value=? WHERE id=1", (serial + 1,))
                conn.commit()
                return serial
            except Exception:
                conn.rollback()
                raise
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
                self.ca_key = serialization.load_pem_private_key(
                    f.read(), password=self._ca_key_passphrase
                )
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

            now = datetime.datetime.now(datetime.timezone.utc)
            ca_days = self._cfg("ca_days", 3650)
            self.ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(self.ca_key.public_key())
                .serial_number(x509.random_serial_number())
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

            # Encrypt CA key if passphrase provided, otherwise store unencrypted
            if self._ca_key_passphrase:
                key_enc = serialization.BestAvailableEncryption(self._ca_key_passphrase)
                logger.info("CA private key will be encrypted on disk.")
            else:
                key_enc = NoEncryption()
                logger.warning(
                    "CA private key stored WITHOUT encryption. "
                    "Use --ca-key-passphrase for production deployments."
                )
            with open(ca_key_path, "wb") as f:
                f.write(self.ca_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, key_enc))
            # Restrict file permissions (best-effort on platforms that support it)
            try:
                os.chmod(ca_key_path, 0o600)
            except OSError:
                pass
            with open(ca_cert_path, "wb") as f:
                f.write(self.ca_cert.public_bytes(Encoding.PEM))

            logger.info(f"CA certificate written to {ca_cert_path}")

    def issue_certificate(
        self,
        subject_str: str,
        public_key,
        validity_days: Optional[int] = None,
        is_ca: bool = False,
        san_dns: Optional[list] = None,
        san_emails: Optional[list] = None,
        san_ips: Optional[list] = None,
        profile: str = "default",
        ocsp_url: Optional[str] = None,
        crl_url: Optional[str] = None,
        no_rev_avail: Optional[bool] = None,
        certificate_policies: Optional[List[dict]] = None,
        audit: Optional["AuditLog"] = None,
        requester_ip: str = "",
    ) -> x509.Certificate:
        """
        Issue a certificate signed by this CA.

        profile             : one of the CertProfile names (tls_server, tls_client,
                              code_signing, email, ocsp_signing, sub_ca, short_lived, default)
        ocsp_url            : if set, adds an AIA extension with OCSP access description
        crl_url             : if set, adds a CRL Distribution Points extension
        no_rev_avail        : if True, adds the RFC 9608 id-ce-noRevAvail (OID 2.5.29.56)
                              extension and suppresses CDP and AIA-OCSP extensions.
                              If None (default), determined automatically from the profile.
                              RFC 9608 §4: MUST NOT appear in CA certs; MUST NOT coexist
                              with CDP or AIA OCSP AccessDescription.
        certificate_policies: list of policy dicts for RFC 5280 §4.2.1.4 CertificatePolicies.
                              Each dict may contain:
                                "oid"         (str, required) — policy OID, e.g. "2.23.140.1.2.1"
                                "cps_uri"     (str, optional) — CPS URI qualifier
                                "notice_text" (str, optional) — UserNotice explicitText (UTF8String
                                              per RFC 6818 §3)
                              Example:
                                [{"oid": "2.23.140.1.2.1",
                                  "cps_uri": "https://pki.example.com/cps",
                                  "notice_text": "Internal use only"}]
        san_dns             : DNS SANs; U-labels are automatically converted to A-labels
                              per RFC 9549 §4.1 using Python's built-in IDNA codec
                              (IDNA2003, UseSTD3ASCIIRules enforced by the codec).
        san_emails          : email SANs. Routing per RFC 9549 §4.2 / RFC 9598:
                              - ASCII local-part + ASCII-or-IDN host -> rfc822Name
                                (IDN host converted to A-label automatically)
                              - Non-ASCII local-part -> SmtpUTF8Mailbox otherName
                                (OID 1.3.6.1.5.5.7.8.9, UTF8String value)
        """
        prof = CertProfile.get(profile)
        is_ca = is_ca or prof.get("bc_ca", False)

        # RFC 9608 — resolve noRevAvail: explicit parameter wins, else profile default
        # MUST NOT appear in CA certificates (RFC 9608 §4 para 2)
        if no_rev_avail is None:
            no_rev_avail = prof.get("no_rev_avail", False)
        if is_ca:
            no_rev_avail = False  # RFC 9608 §4: MUST NOT be set on CA certs

        # CDP / AIA-OCSP suppression per RFC 9608 §4:
        # "A certificate with noRevAvail MUST NOT include the CDP or AIA OCSP extensions"
        suppress_cdp      = no_rev_avail or prof.get("suppress_cdp", False)
        suppress_ocsp_aia = no_rev_avail or prof.get("suppress_ocsp_aia", False)

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
                "EMAIL": NameOID.EMAIL_ADDRESS,
                # RFC 6818 §5 / RFC 9549 §4: domainComponent
                "DC": NameOID.DOMAIN_COMPONENT,
            }
            k = key.strip().upper()
            if k in oid_map:
                v = val.strip()
                # RFC 6818 §5 / RFC 9549 §4: domainComponent labels MUST be A-labels
                if k == "DC" and v:
                    try:
                        v = _idna_encode_label(v)
                    except ValueError:
                        pass  # non-IDN label (e.g. "com", "org") — store as-is
                attrs.append(x509.NameAttribute(oid_map[k], v))

        if not attrs:
            attrs = [x509.NameAttribute(NameOID.COMMON_NAME, subject_str)]

        subject = x509.Name(attrs)
        serial = self._next_serial()
        now = datetime.datetime.now(datetime.timezone.utc)
        path_len = prof.get("path_length", 0) if is_ca else None

        ku = prof["key_usage"].copy()
        if is_ca:
            ku["key_cert_sign"] = True
            ku["crl_sign"] = True

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=path_len),
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
            .add_extension(x509.KeyUsage(**ku), critical=True)
        )

        # EKU
        if prof.get("eku"):
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(prof["eku"]), critical=False
            )

        # OCSP no-check (for OCSP signing certs)
        if prof.get("ocsp_nocheck"):
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.5"),
                    b"\x05\x00",
                ),
                critical=False,
            )

        # RFC 9608 — id-ce-noRevAvail (OID 2.5.29.56)
        # Signals that the CA will never publish revocation information for this cert.
        # Value is an ASN.1 NULL (0x05 0x00). Extension MUST be non-critical (§4).
        if no_rev_avail:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    OID_NO_REV_AVAIL,
                    b"\x05\x00",  # NULL — the extension has no value per RFC 9608
                ),
                critical=False,
            )

        # SAN — collect DNS names, emails, IPs
        # RFC 9549 §4.1 / RFC 8399 §2.4: dNSName U-labels MUST be converted to A-labels.
        # RFC 9549 §4.2 / RFC 9598: email routing —
        #   ASCII local-part  -> rfc822Name (IDN host encoded as A-label)
        #   Non-ASCII local   -> SmtpUTF8Mailbox otherName (OID 1.3.6.1.5.5.7.8.9)
        san_names = []
        if san_dns:
            for d in san_dns:
                try:
                    san_names.append(x509.DNSName(_idna_encode_domain(d)))
                except ValueError:
                    logger.warning(f"IDNA encoding failed for DNS SAN {d!r}; stored as-is")
                    san_names.append(x509.DNSName(d))
        if san_emails:
            for e in san_emails:
                try:
                    local, host = _split_email(e)
                except ValueError:
                    logger.warning(f"Invalid email SAN {e!r}; skipping")
                    continue
                if _has_non_ascii(local):
                    # RFC 9598 §3: non-ASCII local-part -> SmtpUTF8Mailbox otherName
                    san_names.append(
                        x509.OtherName(OID_SMTP_UTF8_MAILBOX,
                                       _encode_smtp_utf8_mailbox(e))
                    )
                else:
                    # RFC 9549 §4.2: ASCII local-part with IDN host -> rfc822Name (A-label host)
                    try:
                        a_host = _idna_encode_domain(host)
                    except ValueError:
                        a_host = host
                    san_names.append(x509.RFC822Name(f"{local}@{a_host}"))
        if san_ips:
            import ipaddress
            for ip in san_ips:
                try:
                    san_names.append(x509.IPAddress(ipaddress.ip_address(ip)))
                except ValueError:
                    pass

        if san_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_names), critical=False
            )

        # AIA — OCSP URL
        # RFC 9608 §4: MUST NOT include AIA OCSP if noRevAvail is set
        if not suppress_ocsp_aia and (ocsp_url or self._ocsp_url):
            url = ocsp_url or self._ocsp_url
            builder = builder.add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(url),
                    )
                ]),
                critical=False,
            )
        elif no_rev_avail and (ocsp_url or self._ocsp_url):
            logger.debug(
                f"Suppressed AIA-OCSP on serial={self._next_serial.__self__ if False else '?'}: "
                "RFC 9608 §4 prohibits AIA OCSP when noRevAvail is set"
            )

        # CDP — CRL distribution point
        # RFC 9608 §4: MUST NOT include CDP if noRevAvail is set
        if not suppress_cdp and (crl_url or self._crl_url):
            url = crl_url or self._crl_url
            builder = builder.add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]),
                critical=False,
            )
        elif no_rev_avail and (crl_url or self._crl_url):
            logger.debug(
                "Suppressed CDP: RFC 9608 §4 prohibits CRL Distribution Points "
                "when noRevAvail is set"
            )

        # CertificatePolicies (RFC 5280 §4.2.1.4 / RFC 6818 §3)
        # certificate_policies parameter OR profile default
        pol_list = certificate_policies or prof.get("certificate_policies")
        if pol_list:
            policy_infos = []
            for pol in pol_list:
                oid = pol.get("oid")
                if not oid:
                    continue
                policy_infos.append(_build_policy_information(
                    oid,
                    cps_uri=pol.get("cps_uri"),
                    notice_text=pol.get("notice_text"),
                ))
            if policy_infos:
                builder = builder.add_extension(
                    x509.CertificatePolicies(policy_infos),
                    critical=False,
                )

        # Feature 10: OpenTelemetry span for certificate issuance
        _t = _tracer or _get_tracer()
        with _t.start_as_current_span("ca.issue_certificate") as _span:
            _span.set_attribute("cert.serial", serial)
            _span.set_attribute("cert.subject", subject_str)
            _span.set_attribute("cert.profile", profile)
            _span.set_attribute("cert.validity_days", validity_days or 0)
            cert = builder.sign(self.ca_key, SHA256())

        # Store in DB (including profile)
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                "INSERT INTO certificates(serial,subject,not_before,not_after,der,revoked,revoked_at,reason,profile) "
                "VALUES(?,?,?,?,?,0,NULL,NULL,?)",
                (
                    serial,
                    subject_str,
                    now.isoformat(),
                    (now + datetime.timedelta(days=validity_days)).isoformat(),
                    cert.public_bytes(Encoding.DER),
                    profile,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        if audit:
            audit.record("issue", f"serial={serial} subject='{subject_str}' profile={profile}",
                         requester_ip)

        logger.info(f"Issued certificate serial={serial} subject='{subject_str}' profile={profile}")
        return cert

    def generate_ephemeral_key_and_cert(self, subject_str: str) -> Tuple[RSAPrivateKey, x509.Certificate]:
        """Generate a new RSA key pair and issue a certificate (for ir without provided key)."""
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = self.issue_certificate(subject_str, priv_key.public_key())
        return priv_key, cert

    def revoke_certificate(self, serial: int, reason: int = 0) -> bool:
        # Feature 10: tracing
        _t = _tracer or _get_tracer()
        with _t.start_as_current_span("ca.revoke_certificate") as _span:
            _span.set_attribute("cert.serial", serial)
            _span.set_attribute("cert.revocation_reason", reason)
            conn = sqlite3.connect(str(self.db_path))
            try:
                row = conn.execute("SELECT serial FROM certificates WHERE serial=? AND revoked=0", (serial,)).fetchone()
                if not row:
                    return False
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                conn.execute(
                    "UPDATE certificates SET revoked=1, revoked_at=?, reason=? WHERE serial=?",
                    (now, reason, serial),
                )
                conn.commit()
                logger.info(f"Revoked certificate serial={serial} reason={reason}")
                return True
            except Exception as e:
                _span.record_exception(e)
                raise
            finally:
                conn.close()

    def generate_crl(self) -> bytes:
        """Generate a DER-encoded CRL."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            revoked = conn.execute(
                "SELECT serial, revoked_at, reason FROM certificates WHERE revoked=1"
            ).fetchall()
        finally:
            conn.close()

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(datetime.datetime.now(datetime.timezone.utc))
            .next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        )

        for serial, revoked_at, reason in revoked:
            rev_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(
                    datetime.datetime.fromisoformat(revoked_at)
                    if revoked_at
                    else datetime.datetime.now(datetime.timezone.utc)
                )
                .build()
            )
            builder = builder.add_revoked_certificate(rev_cert)

        crl = builder.sign(self.ca_key, SHA256())
        return crl.public_bytes(Encoding.DER)

    def get_cert_by_serial(self, serial: int) -> Optional[bytes]:
        conn = sqlite3.connect(str(self.db_path))
        try:
            row = conn.execute("SELECT der FROM certificates WHERE serial=?", (serial,)).fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def list_certificates(self) -> list:
        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute(
                "SELECT serial, subject, not_before, not_after, revoked, profile FROM certificates"
            ).fetchall()
            return [
                {"serial": r[0], "subject": r[1], "not_before": r[2], "not_after": r[3], "revoked": bool(r[4]), "profile": r[5] or "default"}
                for r in rows
            ]
        finally:
            conn.close()

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

        now = datetime.datetime.now(datetime.timezone.utc)
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
        tls13_only: bool = False,
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
        # TLS 1.3-only mode (--tls13-only) — refuse TLS 1.2 connections
        if tls13_only:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            logger.info("TLS 1.3-only mode active — TLS 1.2 connections will be refused")

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
        now = datetime.datetime.now(datetime.timezone.utc)

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
                "SELECT der FROM certificates WHERE serial=?", (serial,)
            ).fetchone()
            if not row:
                return None
            cert = x509.load_der_x509_certificate(row["der"])
            return cert.public_bytes(Encoding.PEM).decode()
        finally:
            conn.close()

    def generate_crl_der(self) -> bytes:
        """Generate and return the current CRL in DER format.
        Delegates to generate_crl() to avoid duplicated logic.
        """
        return self.generate_crl()

    # ------------------------------------------------------------------
    # Sub-CA issuance
    # ------------------------------------------------------------------

    def issue_sub_ca(
        self,
        cn: str,
        validity_days: int = 1825,
        path_length: int = 0,
        audit: Optional["AuditLog"] = None,
    ):
        """
        Issue a subordinate CA certificate signed by this root CA.
        Returns (private_key, certificate).
        The caller is responsible for securely distributing the private key.
        """
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject_str = f"CN={cn},O=PyPKI Subordinate CA"
        cert = self.issue_certificate(
            subject_str=subject_str,
            public_key=priv_key.public_key(),
            validity_days=validity_days,
            is_ca=True,
            profile="sub_ca",
            audit=audit,
        )
        logger.info(f"Sub-CA issued: CN={cn} serial={cert.serial_number} path_length={path_length}")
        return priv_key, cert

    # ------------------------------------------------------------------
    # PKCS#12 export (cert + CA chain, no private key stored server-side)
    # ------------------------------------------------------------------

    def export_pkcs12(self, serial: int, password: Optional[bytes] = None) -> Optional[bytes]:
        """
        Return a PKCS#12 bundle containing the certificate + CA chain.
        Private key is NOT included (it is never stored server-side).
        """
        der = self.get_cert_by_serial(serial)
        if not der:
            return None
        cert = x509.load_der_x509_certificate(der)
        enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        p12 = pkcs12.serialize_key_and_certificates(
            name=f"cert-{serial}".encode(),
            key=None,
            cert=cert,
            cas=[self.ca_cert],
            encryption_algorithm=enc,
        )
        return p12

    # ------------------------------------------------------------------
    # Delta CRL (RFC 5280 §5.2.4)
    # ------------------------------------------------------------------

    def generate_delta_crl(self, base_crl_number: int = 1) -> bytes:
        """
        Generate a delta CRL containing only revocations since the last base CRL.
        Stores the current CRL as the new base in crl_base table.
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row

        # Fetch the timestamp of the last base CRL
        base_row = conn.execute(
            "SELECT issued_at, this_update FROM crl_base ORDER BY id DESC LIMIT 1"
        ).fetchone()
        base_issued_at = base_row["issued_at"] if base_row else "1970-01-01T00:00:00"

        # Only revocations AFTER the last base
        rows = conn.execute(
            "SELECT serial, revoked_at, reason FROM certificates "
            "WHERE revoked=1 AND revoked_at > ?",
            (base_issued_at,)
        ).fetchall()
        conn.close()

        now = datetime.datetime.now(datetime.timezone.utc)
        next_update = now + datetime.timedelta(hours=6)

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(now)
            .next_update(next_update)
            # Delta CRL indicator extension (id-ce-deltaCRLIndicator)
            .add_extension(
                x509.DeltaCRLIndicator(base_crl_number), critical=True
            )
        )

        for row in rows:
            rev = (
                x509.RevokedCertificateBuilder()
                .serial_number(row["serial"])
                .revocation_date(
                    datetime.datetime.fromisoformat(row["revoked_at"])
                    if row["revoked_at"] else now
                )
                .build()
            )
            builder = builder.add_revoked_certificate(rev)

        crl = builder.sign(self.ca_key, SHA256())
        delta_der = crl.public_bytes(Encoding.DER)

        # Store current full-CRL as new base
        full_crl_der = self.generate_crl()
        conn2 = sqlite3.connect(str(self.db_path))
        conn2.execute(
            "INSERT INTO crl_base(issued_at, this_update, next_update, der) VALUES(?,?,?,?)",
            (now.isoformat(), now.isoformat(), next_update.isoformat(), full_crl_der)
        )
        conn2.commit()
        conn2.close()

        logger.info(f"Delta CRL generated: {len(rows)} new revocations since {base_issued_at}")
        return delta_der

    # ------------------------------------------------------------------
    # CSR validation (naming policy)
    # ------------------------------------------------------------------

    def validate_csr(self, csr: x509.CertificateSigningRequest, profile: str = "default") -> List[str]:
        """
        Validate a CSR against policy rules.
        Returns a list of violation strings (empty = valid).
        """
        violations = []

        if not csr.is_signature_valid:
            violations.append("CSR signature is invalid")

        # Extract CN
        try:
            cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            cn = ""

        if not cn:
            violations.append("CSR must have a Common Name (CN)")

        # Profile-specific checks
        if profile == "tls_server":
            # CN or SAN must be a valid FQDN or IP
            import re
            fqdn_re = re.compile(r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
            if cn and not fqdn_re.match(cn) and cn not in ("localhost",):
                violations.append(f"TLS server CN '{cn}' does not appear to be a valid FQDN")
            # Must have SAN
            try:
                csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            except x509.ExtensionNotFound:
                violations.append("TLS server certificates must include a SubjectAlternativeName extension")

        # Key size check
        try:
            pub = csr.public_key()
            if hasattr(pub, "key_size") and pub.key_size < 2048:
                violations.append(f"RSA key size {pub.key_size} is below minimum 2048 bits")
        except Exception:
            pass

        return violations

    @property
    def ca_cert_der(self) -> bytes:
        return self.ca_cert.public_bytes(Encoding.DER)

    @property
    def ca_cert_pem(self) -> bytes:
        return self.ca_cert.public_bytes(Encoding.PEM)


    # ------------------------------------------------------------------
    # Feature 6 — Key archival / key escrow (RFC 4210 §5.3.4)
    # Encrypts subscriber private key to the CA public key using RSA-OAEP
    # and stores the ciphertext in a dedicated DB table.
    # ------------------------------------------------------------------

    def _init_key_archive_table(self):
        """Create key_archive table if it does not exist."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS key_archive (
                    serial      INTEGER PRIMARY KEY,
                    archived_at TEXT NOT NULL,
                    encrypted   BLOB NOT NULL,
                    subject     TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def archive_private_key(self, serial: int, private_key_pem: bytes) -> bool:
        """
        Encrypt and archive a subscriber private key using RSA-OAEP with the CA public key.
        The plaintext never touches disk.  Returns True on success.

        The CA private key is needed to decrypt — use recover_private_key().
        """
        self._init_key_archive_table()
        from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
        # Chunk-encrypt the PEM with RSA-OAEP + AES-256-GCM (hybrid encryption)
        # Step 1 — generate a random 32-byte AES key
        aes_key = os.urandom(32)
        nonce    = os.urandom(12)
        # Step 2 — encrypt plaintext with AES-256-GCM
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, private_key_pem, None)
        # Step 3 — encrypt AES key with RSA-OAEP (CA public key)
        wrapped_key = self.ca_cert.public_key().encrypt(
            aes_key,
            OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        # Step 4 — pack: 2-byte wrapped_key_len | wrapped_key | 12-byte nonce | ciphertext
        payload = (
            len(wrapped_key).to_bytes(2, "big")
            + wrapped_key
            + nonce
            + ciphertext
        )
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn = sqlite3.connect(str(self.db_path))
        try:
            # Fetch subject from certificates table
            row = conn.execute(
                "SELECT subject FROM certificates WHERE serial=?", (serial,)
            ).fetchone()
            subject = row[0] if row else "unknown"
            conn.execute(
                "INSERT OR REPLACE INTO key_archive(serial,archived_at,encrypted,subject) VALUES(?,?,?,?)",
                (serial, now, payload, subject)
            )
            conn.commit()
        finally:
            conn.close()
        logger.info(f"Key archived for serial={serial}")
        return True

    def recover_private_key(self, serial: int) -> Optional[bytes]:
        """
        Decrypt and return the archived private key PEM for the given serial.
        Returns None if no archive entry exists.
        Requires the CA private key (held in memory, never written in plaintext outside ca.key).
        """
        self._init_key_archive_table()
        from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
        conn = sqlite3.connect(str(self.db_path))
        try:
            row = conn.execute(
                "SELECT encrypted FROM key_archive WHERE serial=?", (serial,)
            ).fetchone()
            if not row:
                return None
            payload = row[0]
        finally:
            conn.close()
        # Unpack
        wk_len = int.from_bytes(payload[:2], "big")
        wrapped_key = payload[2:2 + wk_len]
        nonce = payload[2 + wk_len: 2 + wk_len + 12]
        ciphertext = payload[2 + wk_len + 12:]
        # Decrypt AES key
        from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes_key = self.ca_key.decrypt(
            wrapped_key,
            OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        logger.info(f"Key recovery performed for serial={serial}")
        return plaintext

    # ------------------------------------------------------------------
    # Feature 7 — Name Constraints extension (RFC 5280 §4.2.1.10)
    # ------------------------------------------------------------------

    def issue_certificate_with_name_constraints(
        self,
        subject_str: str,
        public_key,
        permitted_dns: Optional[List[str]] = None,
        excluded_dns: Optional[List[str]] = None,
        permitted_emails: Optional[List[str]] = None,
        excluded_ips: Optional[List[str]] = None,
        **kwargs,
    ) -> x509.Certificate:
        """
        Issue a CA certificate (is_ca=True, profile='sub_ca') with a NameConstraints
        extension per RFC 5280 §4.2.1.10.  NameConstraints MUST only appear in CA certs.

        permitted_dns  : e.g. [".example.com"] — subtree of permitted DNS names
        excluded_dns   : e.g. [".evil.example.com"]
        permitted_emails: e.g. ["@example.com"]
        excluded_ips   : e.g. ["10.0.0.0/8"]
        """
        import ipaddress as _ip
        permitted: List[x509.GeneralName] = []
        excluded:  List[x509.GeneralName] = []

        for dns in (permitted_dns or []):
            permitted.append(x509.DNSName(dns))
        for dns in (excluded_dns or []):
            excluded.append(x509.DNSName(dns))
        for email in (permitted_emails or []):
            permitted.append(x509.RFC822Name(email))
        for cidr in (excluded_ips or []):
            net = _ip.ip_network(cidr, strict=False)
            excluded.append(x509.IPAddress(net))

        nc_ext = x509.NameConstraints(
            permitted_subtrees=permitted if permitted else None,
            excluded_subtrees=excluded  if excluded  else None,
        )

        kwargs.setdefault("is_ca", True)
        kwargs.setdefault("profile", "sub_ca")
        cert = self.issue_certificate(subject_str=subject_str, public_key=public_key, **kwargs)

        # Re-sign with NameConstraints added; we need to rebuild because issue_certificate
        # doesn't expose arbitrary extension injection via keyword args.
        # Build a new cert based on the just-issued cert's fields.
        now = datetime.datetime.now(datetime.timezone.utc)
        nc_cert = (
            x509.CertificateBuilder()
            .subject_name(cert.subject)
            .issuer_name(cert.issuer)
            .public_key(cert.public_key())
            .serial_number(cert.serial_number)
            .not_valid_before(cert.not_valid_before_utc)
            .not_valid_after(cert.not_valid_after_utc)
        )
        for ext in cert.extensions:
            nc_cert = nc_cert.add_extension(ext.value, critical=ext.critical)
        nc_cert = nc_cert.add_extension(nc_ext, critical=True)
        final_cert = nc_cert.sign(self.ca_key, SHA256())

        # Update the DB record so the stored DER matches the returned certificate
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                "UPDATE certificates SET der=? WHERE serial=?",
                (final_cert.public_bytes(Encoding.DER), cert.serial_number),
            )
            conn.commit()
        finally:
            conn.close()
        return final_cert

    # ------------------------------------------------------------------
    # Feature 8 — Expiry monitoring
    # ------------------------------------------------------------------

    def expiring_certificates(self, days_ahead: int = 30) -> List[dict]:
        """
        Return a list of non-revoked certificates expiring within the next
        ``days_ahead`` days.  Each entry has keys: serial, subject, not_after,
        profile, days_remaining.
        """
        cutoff = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_ahead)
        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute(
                "SELECT serial, subject, not_after, profile FROM certificates "
                "WHERE revoked=0 ORDER BY not_after ASC"
            ).fetchall()
        finally:
            conn.close()

        result = []
        for serial, subject, not_after_str, profile in rows:
            try:
                not_after = datetime.datetime.fromisoformat(not_after_str)
                # Make timezone-aware if naive
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                continue
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < not_after <= cutoff:
                days_remaining = (not_after - now).days
                result.append({
                    "serial": serial,
                    "subject": subject,
                    "not_after": not_after.isoformat(),
                    "profile": profile or "default",
                    "days_remaining": days_remaining,
                })
        return result

    def start_expiry_monitor(
        self,
        days_ahead: int = 30,
        check_interval_seconds: int = 86400,
        on_expiring: Optional[callable] = None,
        audit: Optional["AuditLog"] = None,
    ) -> threading.Thread:
        """
        Start a background thread that periodically logs (and optionally calls a
        callback for) certificates approaching expiry.

        on_expiring(cert_info: dict) is called once per certificate per check cycle
        when it enters the warning window.  Use it to send emails, fire webhooks, etc.
        """
        def _monitor():
            logger.info(f"Expiry monitor started: window={days_ahead}d, interval={check_interval_seconds}s")
            while True:
                try:
                    expiring = self.expiring_certificates(days_ahead=days_ahead)
                    if expiring:
                        logger.warning(
                            f"Expiry monitor: {len(expiring)} certificate(s) expiring "
                            f"within {days_ahead} days"
                        )
                        for info in expiring:
                            logger.warning(
                                f"  EXPIRING serial={info['serial']} "
                                f"subject='{info['subject']}' "
                                f"days_remaining={info['days_remaining']} "
                                f"not_after={info['not_after']}"
                            )
                            if on_expiring:
                                try:
                                    on_expiring(info)
                                except Exception as cb_err:
                                    logger.error(f"Expiry callback error: {cb_err}")
                        if audit:
                            audit.record(
                                "expiry_monitor",
                                f"found={len(expiring)} expiring_within={days_ahead}d",
                            )
                    else:
                        logger.debug(f"Expiry monitor: no certificates expiring in {days_ahead} days")
                except Exception as err:
                    logger.error(f"Expiry monitor error: {err}")
                time.sleep(check_interval_seconds)

        t = threading.Thread(target=_monitor, daemon=True, name="expiry-monitor")
        t.start()
        return t

    # ------------------------------------------------------------------
    # Feature 9 — Certificate renewal
    # ------------------------------------------------------------------

    def renew_certificate(
        self,
        serial: int,
        validity_days: Optional[int] = None,
        audit: Optional["AuditLog"] = None,
        requester_ip: str = "",
    ) -> Optional[x509.Certificate]:
        """
        Issue a new certificate with the same subject, SAN, key usage, and profile
        as the certificate identified by ``serial``.  The original certificate is
        not revoked.  Returns the new certificate, or None if serial not found.

        The new cert has a fresh validity window, a new serial number, and keeps
        the same public key (the subscriber reuses their existing key pair).
        This is a lightweight renewal: no new CSR required.
        """
        der = self.get_cert_by_serial(serial)
        if not der:
            return None
        old_cert = x509.load_der_x509_certificate(der)

        # Extract subject
        subject_str = old_cert.subject.rfc4514_string()

        # Extract profile from DB
        conn = sqlite3.connect(str(self.db_path))
        try:
            row = conn.execute(
                "SELECT profile FROM certificates WHERE serial=?", (serial,)
            ).fetchone()
            profile = row[0] if row and row[0] else "default"
        finally:
            conn.close()

        # Extract SANs
        san_dns, san_emails, san_ips = [], [], []
        try:
            san_ext = old_cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            san_dns    = san_ext.get_values_for_type(x509.DNSName)
            san_emails = san_ext.get_values_for_type(x509.RFC822Name)
            san_ips    = [str(ip) for ip in san_ext.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            pass

        # Extract CPS-level policies if present
        cert_policies = None
        try:
            cp = old_cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
            cert_policies = []
            for pi in cp:
                pd: dict = {"oid": pi.policy_identifier.dotted_string}
                for q in (pi.policy_qualifiers or []):
                    if isinstance(q, str):
                        pd["cps_uri"] = q
                    elif isinstance(q, x509.UserNotice):
                        pd["notice_text"] = q.explicit_text
                cert_policies.append(pd)
        except x509.ExtensionNotFound:
            pass

        new_cert = self.issue_certificate(
            subject_str=subject_str,
            public_key=old_cert.public_key(),
            validity_days=validity_days,
            profile=profile,
            san_dns=san_dns if san_dns else None,
            san_emails=san_emails if san_emails else None,
            san_ips=san_ips if san_ips else None,
            certificate_policies=cert_policies,
            audit=audit,
            requester_ip=requester_ip,
        )
        logger.info(
            f"Renewed certificate: old_serial={serial} → new_serial={new_cert.serial_number}"
        )
        return new_cert

    # ------------------------------------------------------------------
    # Feature 11 — Prometheus metrics
    # ------------------------------------------------------------------

    def get_metrics(self) -> dict:
        """
        Return a dictionary of Prometheus-style gauge/counter metrics collected
        from the in-memory CA state and the SQLite database.
        """
        conn = sqlite3.connect(str(self.db_path))
        try:
            total     = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
            revoked   = conn.execute("SELECT COUNT(*) FROM certificates WHERE revoked=1").fetchone()[0]
            valid     = total - revoked
            # Expiring within 30 days
            cutoff = (
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
            ).isoformat()
            now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
            exp30 = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE revoked=0 AND not_after <= ? AND not_after > ?",
                (cutoff, now_str)
            ).fetchone()[0]
            # Expiring within 7 days
            cutoff7 = (
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
            ).isoformat()
            exp7  = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE revoked=0 AND not_after <= ? AND not_after > ?",
                (cutoff7, now_str)
            ).fetchone()[0]
            # Already expired
            expired = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE revoked=0 AND not_after <= ?",
                (now_str,)
            ).fetchone()[0]
            # Per-profile counts
            profile_rows = conn.execute(
                "SELECT profile, COUNT(*) FROM certificates WHERE revoked=0 GROUP BY profile"
            ).fetchall()
        finally:
            conn.close()

        ca_expiry = self.ca_cert.not_valid_after_utc
        ca_days_remaining = (ca_expiry - datetime.datetime.now(datetime.timezone.utc)).days

        return {
            "pypki_certs_issued_total": total,
            "pypki_certs_valid": valid,
            "pypki_certs_revoked_total": revoked,
            "pypki_certs_expiring_30d": exp30,
            "pypki_certs_expiring_7d": exp7,
            "pypki_certs_expired": expired,
            "pypki_ca_days_remaining": ca_days_remaining,
            "pypki_certs_by_profile": dict(profile_rows),
        }

    def metrics_prometheus(self) -> str:
        """
        Return a Prometheus text-format metrics exposition string.
        Suitable for scraping by a Prometheus server or pushing to a Pushgateway.
        """
        m = self.get_metrics()
        lines = [
            "# HELP pypki_certs_issued_total Total number of certificates ever issued",
            "# TYPE pypki_certs_issued_total counter",
            f"pypki_certs_issued_total {m['pypki_certs_issued_total']}",
            "# HELP pypki_certs_valid Number of currently valid (non-revoked, non-expired) certificates",
            "# TYPE pypki_certs_valid gauge",
            f"pypki_certs_valid {m['pypki_certs_valid']}",
            "# HELP pypki_certs_revoked_total Total number of revoked certificates",
            "# TYPE pypki_certs_revoked_total counter",
            f"pypki_certs_revoked_total {m['pypki_certs_revoked_total']}",
            "# HELP pypki_certs_expiring_30d Certificates expiring within 30 days",
            "# TYPE pypki_certs_expiring_30d gauge",
            f"pypki_certs_expiring_30d {m['pypki_certs_expiring_30d']}",
            "# HELP pypki_certs_expiring_7d Certificates expiring within 7 days",
            "# TYPE pypki_certs_expiring_7d gauge",
            f"pypki_certs_expiring_7d {m['pypki_certs_expiring_7d']}",
            "# HELP pypki_certs_expired Certificates that have passed their not_after date (not revoked)",
            "# TYPE pypki_certs_expired gauge",
            f"pypki_certs_expired {m['pypki_certs_expired']}",
            "# HELP pypki_ca_days_remaining Days until the root CA certificate expires",
            "# TYPE pypki_ca_days_remaining gauge",
            f"pypki_ca_days_remaining {m['pypki_ca_days_remaining']}",
            "# HELP pypki_certs_by_profile Certificates per profile (gauge)",
            "# TYPE pypki_certs_by_profile gauge",
        ]
        for profile, count in m["pypki_certs_by_profile"].items():
            safe = profile.replace('"', '\\"')
            lines.append(f'pypki_certs_by_profile{{profile="{safe}"}} {count}')
        lines.append("")  # trailing newline
        return "\n".join(lines) + "\n"


    # ------------------------------------------------------------------
    # Feature 5 — ACME dns-01 real resolver hook
    # ------------------------------------------------------------------
    #
    # For production wildcard certificate issuance the ACME dns-01 challenge
    # requires the server to verify a TXT record at _acme-challenge.<domain>.
    # PyPKI provides two mechanisms:
    #
    #   1. Webhook hook: POST the challenge to an external URL
    #      (your DNS API, DDNS service, Route53 Lambda, etc.)
    #      Configure: --acme-dns-hook-url https://dns-api.internal/challenge
    #
    #   2. RFC 2136 Dynamic DNS (TSIG-authenticated DNS UPDATE)
    #      Configure: --acme-dns-rfc2136-server <IP:PORT>
    #                 --acme-dns-rfc2136-key-name <TSIG key name>
    #                 --acme-dns-rfc2136-key-secret <base64-HMAC-MD5 secret>
    #
    # The hook function is called by the ACME server before challenge validation.
    # ------------------------------------------------------------------

    @staticmethod
    def make_dns01_webhook_hook(hook_url: str, timeout: int = 10):
        """
        Return a dns-01 hook callable that POSTs the challenge to hook_url.

        The hook function signature expected by acme_server.py:
            hook(domain: str, challenge_token: str, key_authorization: str) -> bool

        The webhook receives JSON: {domain, challenge_token, key_authorization}
        and should return HTTP 200 on success.
        """
        import urllib.request as _urllib

        def _hook(domain: str, challenge_token: str, key_authorization: str) -> bool:
            payload = json.dumps({
                "domain": domain,
                "challenge_token": challenge_token,
                "key_authorization": key_authorization,
            }).encode()
            try:
                req = _urllib.Request(
                    hook_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with _urllib.urlopen(req, timeout=timeout) as resp:
                    success = resp.status // 100 == 2
                    if success:
                        logger.info(f"dns-01 webhook OK for {domain}")
                    else:
                        logger.warning(f"dns-01 webhook returned {resp.status} for {domain}")
                    return success
            except Exception as e:
                logger.error(f"dns-01 webhook error for {domain}: {e}")
                return False

        return _hook

    @staticmethod
    def make_dns01_rfc2136_hook(
        nameserver: str,
        key_name: str,
        key_secret: str,
        key_algorithm: str = "hmac-md5",
        ttl: int = 60,
    ):
        """
        Return a dns-01 hook callable that publishes the challenge via
        RFC 2136 Dynamic DNS UPDATE with TSIG authentication.

        Requires the ``dnspython`` package (pip install dnspython).
        ``nameserver`` is "IP" or "IP:PORT" (default port 53).
        ``key_secret`` is the base64-encoded HMAC secret.
        """
        try:
            import dns.update
            import dns.tsigkeyring
            import dns.resolver
            import dns.query
            import dns.rdatatype
        except ImportError:
            logger.error(
                "dnspython not installed — RFC 2136 dns-01 hook unavailable. "
                "Install with: pip install dnspython"
            )
            return None

        host, _, port_str = nameserver.partition(":")
        port = int(port_str) if port_str else 53

        keyring = dns.tsigkeyring.from_text({key_name: key_secret})
        algorithm_map = {
            "hmac-md5": dns.tsig.HMAC_MD5,
            "hmac-sha1": dns.tsig.HMAC_SHA1,
            "hmac-sha256": dns.tsig.HMAC_SHA256,
            "hmac-sha512": dns.tsig.HMAC_SHA512,
        }
        algorithm = algorithm_map.get(key_algorithm.lower(), dns.tsig.HMAC_MD5)

        def _hook(domain: str, _challenge_token: str, key_authorization: str) -> bool:
            """Publish _acme-challenge.<domain> TXT=key_authorization via RFC 2136."""
            # Strip trailing dot, derive zone (last two labels)
            d = domain.rstrip(".")
            labels = d.split(".")
            zone = ".".join(labels[-2:]) + "."
            acme_name = f"_acme-challenge.{d}."
            try:
                update = dns.update.Update(zone, keyring=keyring, keyalgorithm=algorithm)
                update.replace(acme_name, ttl, dns.rdatatype.TXT, f'"{key_authorization}"')
                dns.query.tcp(update, host, port=port, timeout=10)
                logger.info(f"RFC 2136 DNS UPDATE OK for {acme_name}")
                return True
            except Exception as e:
                logger.error(f"RFC 2136 DNS UPDATE failed for {acme_name}: {e}")
                return False

        return _hook


    # ------------------------------------------------------------------
    # Feature 2 — Certificate Transparency (CT) log submission
    # RFC 6962 / RFC 9162 — Signed Certificate Timestamps (SCTs)
    # ------------------------------------------------------------------
    #
    # A CA that issues publicly-trusted TLS certificates MUST embed SCTs
    # from at least two qualified CT logs (Chrome CT Policy, Apple ATS).
    #
    # PyPKI implements the RFC 6962 §4.1 "add-chain" submission: it posts
    # the certificate chain to a CT log's HTTP API and receives a
    # SignedCertificateTimestamp (SCT) in response.  The SCT is then
    # embedded in the TLSFeature / SCT extension (OID 1.3.6.1.4.1.11129.2.4.2).
    #
    # Important: submission to public logs requires a *publically trusted*
    # chain.  For private/internal CAs, configure private log URLs.
    # ------------------------------------------------------------------

    # OID for the embedded SCT list extension (RFC 6962 §3.3)
    OID_SCT_LIST = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")

    # Public Google / Cloudflare test log endpoints (use only if CA is publicly trusted)
    CT_LOG_ARGON_2025 = "https://ct.googleapis.com/logs/us1/argon2025h2/"
    CT_LOG_XENON_2025 = "https://ct.googleapis.com/logs/us1/xenon2025h2/"

    def submit_to_ct_log(
        self,
        cert: x509.Certificate,
        log_url: str,
        timeout: int = 10,
    ) -> Optional[bytes]:
        """
        Submit a certificate to a CT log and return the raw SCT bytes (DER).

        ``log_url`` is the base URL of the CT log (e.g. CT_LOG_ARGON_2025).
        The call uses the RFC 6962 §4.1 "add-chain" endpoint.

        Returns the raw TLS-encoded SCT bytes, or None on failure.
        Requires network access to the CT log.
        """
        import urllib.request as _urllib
        import urllib.error as _urlerr

        # Build chain: [leaf DER, issuer DER]
        chain_ders = [
            cert.public_bytes(Encoding.DER),
            self.ca_cert.public_bytes(Encoding.DER),
        ]
        chain_b64 = [base64.b64encode(der).decode() for der in chain_ders]
        payload = json.dumps({"chain": chain_b64}).encode()

        endpoint = log_url.rstrip("/") + "/ct/v1/add-chain"
        try:
            req = _urllib.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with _urllib.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
        except Exception as e:
            logger.warning(f"CT log submission failed ({endpoint}): {e}")
            return None

        # RFC 6962 §3.2: response contains sct_version, id, timestamp, extensions, signature
        sct_version    = body.get("sct_version", 0)
        log_id         = base64.b64decode(body["id"])
        timestamp_ms   = body["timestamp"]
        extensions     = base64.b64decode(body.get("extensions", ""))
        sig_bytes      = base64.b64decode(body["signature"])

        # Encode as TLS-serialised SCT (RFC 6962 §3.2)
        import struct as _struct
        ext_len = len(extensions)
        sig_len = len(sig_bytes)
        sct = (
            bytes([sct_version])               # version (1 byte)
            + log_id                            # log id (32 bytes)
            + _struct.pack(">Q", timestamp_ms)  # timestamp (8 bytes)
            + _struct.pack(">H", ext_len)       # extensions length (2 bytes)
            + extensions                        # extensions
            + sig_bytes                         # digitally-signed struct
        )
        logger.info(
            f"CT log SCT received from {log_url}: "
            f"serial={cert.serial_number} timestamp_ms={timestamp_ms}"
        )
        return sct

    def embed_scts(
        self,
        cert: x509.Certificate,
        scts: List[bytes],
    ) -> x509.Certificate:
        """
        Return a new certificate with a SignedCertificateTimestampList extension
        (OID 1.3.6.1.4.1.11129.2.4.2) containing ``scts`` (list of raw SCT bytes).

        The extension value is a TLS-encoded SCTList (RFC 6962 §3.3):
            struct { SerializedSCT sct_list<1..2^16-1>; } SignedCertificateTimestampList
        """
        import struct as _struct
        # Build SCTList: each SCT is length-prefixed with 2 bytes
        sct_items = b"".join(_struct.pack(">H", len(s)) + s for s in scts)
        sct_list  = _struct.pack(">H", len(sct_items)) + sct_items
        # Wrap in an OCTET STRING (DER tag 0x04)
        def _der_octet(data: bytes) -> bytes:
            if len(data) < 0x80:
                return bytes([0x04, len(data)]) + data
            elif len(data) < 0x100:
                return bytes([0x04, 0x81, len(data)]) + data
            else:
                return bytes([0x04, 0x82, len(data) >> 8, len(data) & 0xFF]) + data

        ext_value = _der_octet(sct_list)

        # Rebuild the certificate with the SCT extension added
        builder = (
            x509.CertificateBuilder()
            .subject_name(cert.subject)
            .issuer_name(cert.issuer)
            .public_key(cert.public_key())
            .serial_number(cert.serial_number)
            .not_valid_before(cert.not_valid_before_utc)
            .not_valid_after(cert.not_valid_after_utc)
        )
        for ext in cert.extensions:
            builder = builder.add_extension(ext.value, critical=ext.critical)
        builder = builder.add_extension(
            x509.UnrecognizedExtension(self.OID_SCT_LIST, ext_value),
            critical=False,
        )
        return builder.sign(self.ca_key, SHA256())

    def issue_certificate_with_ct(
        self,
        subject_str: str,
        public_key,
        ct_log_urls: Optional[List[str]] = None,
        **kwargs,
    ) -> x509.Certificate:
        """
        Convenience wrapper: issue a certificate, submit it to one or more CT
        logs, embed the resulting SCTs, and return the final certificate.

        ``ct_log_urls`` defaults to [CT_LOG_ARGON_2025, CT_LOG_XENON_2025].
        SCT submission failures are logged as warnings and do not abort issuance.
        """
        cert = self.issue_certificate(subject_str=subject_str, public_key=public_key, **kwargs)

        urls = ct_log_urls or [self.CT_LOG_ARGON_2025, self.CT_LOG_XENON_2025]
        scts = []
        for url in urls:
            sct = self.submit_to_ct_log(cert, url)
            if sct:
                scts.append(sct)

        if scts:
            cert = self.embed_scts(cert, scts)
            logger.info(f"Embedded {len(scts)} SCT(s) into serial={cert.serial_number}")
        else:
            logger.warning("No SCTs obtained; certificate issued without CT transparency")
        return cert


    # ------------------------------------------------------------------
    # Feature 1 — OCSP Stapling (RFC 6961 / RFC 8446)
    # ------------------------------------------------------------------
    #
    # OCSP stapling lets the server proactively fetch its own OCSP response
    # and include it in the TLS handshake, sparing clients a round-trip to
    # the OCSP responder.  Python's ssl module does not expose stapling APIs
    # directly, but we provide the fetch + cache machinery here so that
    # a reverse-proxy (nginx, HAProxy) or a custom TLS wrapper can use it.
    #
    # Usage:
    #   staple = ca.fetch_ocsp_staple(cert_pem, issuer_pem, ocsp_url)
    #   # Then configure your TLS endpoint to include staple in the handshake.
    # ------------------------------------------------------------------

    def _ocsp_cache(self):
        if not hasattr(self, "_ocsp_staple_cache"):
            self._ocsp_staple_cache: Dict[int, Tuple[bytes, float]] = {}
        return self._ocsp_staple_cache

    def fetch_ocsp_staple(
        self,
        cert: Optional[x509.Certificate] = None,
        cert_serial: Optional[int] = None,
        ocsp_url: Optional[str] = None,
        cache_ttl: int = 3600,
    ) -> Optional[bytes]:
        """
        Fetch a DER-encoded OCSP response for ``cert`` (or the cert looked up
        by ``cert_serial``) from ``ocsp_url`` (defaults to self._ocsp_url).

        Responses are cached in memory for ``cache_ttl`` seconds to avoid
        hammering the OCSP responder.  Returns the raw DER bytes suitable
        for passing to an ssl stapling callback, or None on failure.

        Requires: 'cryptography' and standard-library 'urllib.request'.
        """
        import urllib.request as _urllib

        if cert is None and cert_serial is not None:
            der = self.get_cert_by_serial(cert_serial)
            if not der:
                return None
            cert = x509.load_der_x509_certificate(der)
        if cert is None:
            return None

        serial = cert.serial_number
        cache  = self._ocsp_cache()
        now    = time.time()

        # Return cached response if still fresh
        if serial in cache:
            cached_resp, cached_at = cache[serial]
            if now - cached_at < cache_ttl:
                return cached_resp

        url = ocsp_url or self._ocsp_url
        if not url:
            logger.debug("fetch_ocsp_staple: no OCSP URL configured")
            return None

        try:
            # Build an OCSP request (RFC 6960)
            from cryptography.x509.ocsp import OCSPRequestBuilder
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(cert, self.ca_cert, hashes.SHA256())
            req = builder.build()
            req_der = req.public_bytes(Encoding.DER)

            http_req = _urllib.Request(
                url,
                data=req_der,
                headers={"Content-Type": "application/ocsp-request"},
            )
            with _urllib.urlopen(http_req, timeout=5) as resp:
                resp_der = resp.read()

            cache[serial] = (resp_der, now)
            logger.debug(f"OCSP staple fetched and cached for serial={serial}")
            return resp_der
        except Exception as e:
            logger.warning(f"OCSP staple fetch failed for serial={serial}: {e}")
            return None

    def invalidate_ocsp_staple(self, serial: int) -> None:
        """Remove a cached OCSP staple (e.g. after revocation)."""
        self._ocsp_cache().pop(serial, None)


# ---------------------------------------------------------------------------
# CMPv2 Request Handler
# ---------------------------------------------------------------------------

class CMPv2Handler:
    """Process incoming CMPv2 PKIMessages and generate responses."""

    SUPPORTED_BODY_TYPES = {"ir", "cr", "kur", "rr", "certConf", "genm", "p10cr"}

    def __init__(self, ca: CertificateAuthority):
        self.ca = ca
        self._pending_confirmations: Dict[bytes, Tuple[bytes, float]] = {}  # txid -> (cert_der, timestamp)
        self._pending_ttl = 300  # 5 minutes TTL for unconfirmed certs
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
                self._evict_stale_confirmations()
                self._pending_confirmations[txid] = (cert_der, time.time())

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
                self._evict_stale_confirmations()
                self._pending_confirmations[txid] = (cert_der, time.time())

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

        # Extract serial from RevDetails (RFC 4210 §5.3.9)
        # RevDetails ::= SEQUENCE { certDetails CertTemplate, ... }
        # CertTemplate has [1] serialNumber (context tag 1, INTEGER)
        serial = None
        try:
            # RevReqContent ::= SEQUENCE OF RevDetails
            # Each RevDetails: SEQUENCE { certDetails CertTemplate, ... }
            pos = 0
            if body_raw and body_raw[0] == 0x30:
                # Unwrap outer SEQUENCE (RevReqContent)
                _, outer_val, _ = CMPv2ASN1._decode_tlv(body_raw, 0)
                # First RevDetails SEQUENCE
                if outer_val and outer_val[0] == 0x30:
                    _, rd_val, _ = CMPv2ASN1._decode_tlv(outer_val, 0)
                    # certDetails (CertTemplate SEQUENCE)
                    if rd_val and rd_val[0] == 0x30:
                        _, tmpl_val, _ = CMPv2ASN1._decode_tlv(rd_val, 0)
                        # Walk CertTemplate context-tagged fields
                        tpos = 0
                        while tpos < len(tmpl_val):
                            ftag = tmpl_val[tpos]
                            flen, fnext = CMPv2ASN1._decode_length(tmpl_val, tpos + 1)
                            fval = tmpl_val[fnext:fnext + flen]
                            field_num = ftag & 0x1F
                            if field_num == 1:  # [1] serialNumber
                                serial = int.from_bytes(fval, "big")
                                break
                            tpos = fnext + flen
        except Exception as e:
            logger.debug(f"RevDetails parse error: {e}")

        if serial and self.ca.revoke_certificate(serial):
            body = CMPv2ASN1.build_rp_body(0)
        else:
            logger.warning(f"Revocation: serial {serial} not found or already revoked")
            body = CMPv2ASN1.build_rp_body(2)

        return CMPv2ASN1.build_pki_message(12, body, txid, os.urandom(16), snonce)

    def _evict_stale_confirmations(self):
        """Remove pending confirmations older than _pending_ttl seconds (called under lock)."""
        now = time.time()
        stale = [k for k, (_, ts) in self._pending_confirmations.items()
                 if now - ts > self._pending_ttl]
        for k in stale:
            self._pending_confirmations.pop(k, None)
        if stale:
            logger.debug(f"Evicted {len(stale)} stale pending confirmation(s)")

    def _handle_cert_confirm(self, msg: dict, txid: bytes, snonce: bytes) -> bytes:
        """Handle Certificate Confirmation (certConf -> pkiconf)."""
        with self._lock:
            entry = self._pending_confirmations.pop(txid, None)
            cert_der = entry[0] if entry else None

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
            # RFC 9480 §4.3.3 — GetCACerts: return all CA certs (we have one)
            ca_der = self.ca.ca_cert_der
            # CMCPublicationInfo / CACertSeq = SEQUENCE OF Certificate
            ca_seq = _seq(ca_der)
            info_val = _seq(_oid_bytes(OID_IT_GETCACERTS) + _seq(ca_seq))
            logger.info("genm GetCACerts: returning CA certificate")
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
    admin_api_key: Optional[str] = None  # If set, required for sensitive endpoints
    admin_allowed_cns: Optional[List[str]] = None  # mTLS CN allowlist for admin ops

    # Endpoints that require admin authentication
    _ADMIN_ENDPOINTS = {
        "/api/revoke", "/api/sub-ca", "/api/name-constrained-ca",
    }
    _ADMIN_ENDPOINT_PATTERNS = [
        r"^/api/certs/\d+/archive$",
        r"^/api/certs/\d+/recover$",
        r"^/api/certs/\d+/renew$",
    ]

    def _require_admin(self, path: str) -> bool:
        """Check if this path requires admin auth, and if so, verify credentials.
        Returns True if access is allowed, False if denied (and sends 403)."""
        # Determine if this is an admin endpoint
        is_admin = path in self._ADMIN_ENDPOINTS or path == "/config"
        if not is_admin:
            for pattern in self._ADMIN_ENDPOINT_PATTERNS:
                if re.match(pattern, path):
                    is_admin = True
                    break
        if not is_admin:
            return True  # Not an admin endpoint — allow

        # If no admin key is configured, allow (backward compat)
        if not self.admin_api_key and not self.admin_allowed_cns:
            return True

        # Check API key header
        if self.admin_api_key:
            provided = self.headers.get("X-Admin-Key", "")
            if hmac.compare_digest(provided, self.admin_api_key):
                return True

        # Check mTLS client CN allowlist
        if self.admin_allowed_cns:
            client_cn = self._get_client_cn()
            if client_cn and client_cn in self.admin_allowed_cns:
                return True

        self._send_json({"error": "admin authentication required"}, 403)
        if self.audit_log:
            self.audit_log.record("auth_denied", f"path={path}", self.client_address[0])
        return False

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
        if not self._require_admin(path):
            return
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

        if not self._require_admin("/config"):
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
            # Security: enforce rate limiting and optional bootstrap token
            if self.rate_limiter and not self.rate_limiter.allow(self.client_address[0]):
                self._send_json({"error": "rate limit exceeded"}, 429)
                return
            # Check optional bootstrap token
            bootstrap_token = getattr(self, "bootstrap_token", None)
            if bootstrap_token:
                provided_token = self.headers.get("X-Bootstrap-Token", "")
                if "?" in self.path:
                    for param in self.path.split("?")[1].split("&"):
                        if param.startswith("token="):
                            provided_token = param[6:]
                if not hmac.compare_digest(provided_token, bootstrap_token):
                    self._send_json({"error": "invalid or missing bootstrap token"}, 403)
                    return
            cn = self.headers.get("X-Client-CN") or "bootstrap-client"
            # Also accept ?cn= query param
            if "?" in self.path:
                for param in self.path.split("?")[1].split("&"):
                    if param.startswith("cn="):
                        cn = param[3:]
            # Sanitize CN — only allow safe characters
            cn = re.sub(r'[^a-zA-Z0-9._\-]', '_', cn)[:64]
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
            try:
                days = int(params.get("days", 30))
            except ValueError:
                days = 30
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
            # RFC 9811: GET /.well-known/cmp -> return CA certificate
            label = self._extract_cmp_label(path)
            data = self.ca.ca_cert_pem
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

def make_handler(ca: CertificateAuthority, cmp_handler,
                 audit_log: Optional[AuditLog] = None,
                 rate_limiter: Optional[RateLimiter] = None,
                 admin_api_key: Optional[str] = None,
                 admin_allowed_cns: Optional[List[str]] = None,
                 bootstrap_token: Optional[str] = None):
    """Create a bound HTTP handler class with CA and CMP handler attached."""
    class BoundHandler(CMPv2HTTPHandler):
        pass
    BoundHandler.ca = ca
    BoundHandler.cmp_handler = cmp_handler
    BoundHandler.audit_log = audit_log
    BoundHandler.rate_limiter = rate_limiter
    BoundHandler.admin_api_key = admin_api_key
    BoundHandler.admin_allowed_cns = admin_allowed_cns
    BoundHandler.bootstrap_token = bootstrap_token
    return BoundHandler


def make_cmpv3_handler(ca: CertificateAuthority, cmp_handler,
                       audit_log: Optional[AuditLog] = None,
                       rate_limiter: Optional[RateLimiter] = None,
                       admin_api_key: Optional[str] = None,
                       admin_allowed_cns: Optional[List[str]] = None,
                       bootstrap_token: Optional[str] = None):
    """Alias for make_handler (kept for backward compatibility)."""
    return make_handler(ca, cmp_handler, audit_log, rate_limiter,
                        admin_api_key, admin_allowed_cns, bootstrap_token)


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
    tls_group.add_argument(
        "--tls13-only", action="store_true", default=False,
        help="Enforce TLS 1.3 only — refuse TLS 1.2 connections (requires --tls or --mtls)"
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
    acme_group.add_argument(
        "--acme-cert-days", type=int, default=90, metavar="DAYS",
        help="Validity period for ACME-issued certificates in days (default: 90)"
    )
    acme_group.add_argument(
        "--acme-short-lived-threshold", type=int, default=7, metavar="DAYS",
        help="Certs with validity <= this receive RFC 9608 id-ce-noRevAvail and "
             "have CDP/AIA-OCSP suppressed (default: 7)"
    )

    infra_group = parser.add_argument_group(
        "Revocation & PKI infrastructure",
    )
    infra_group.add_argument(
        "--ocsp-port", type=int, default=None, metavar="PORT",
        help="Start OCSP responder on this port (e.g. 8082)"
    )
    infra_group.add_argument(
        "--ocsp-url", default="", metavar="URL",
        help="Public OCSP URL to embed in AIA extension of all issued certs "
             "(e.g. http://pki.internal:8082/ocsp)"
    )
    infra_group.add_argument(
        "--crl-url", default="", metavar="URL",
        help="Public CRL URL to embed in CDP extension of all issued certs "
             "(e.g. http://pki.internal:8080/ca/crl)"
    )
    infra_group.add_argument(
        "--ocsp-cache-seconds", type=int, default=300,
        help="OCSP response cache TTL in seconds (default: 300)"
    )

    ops_group = parser.add_argument_group("Operational options")
    ops_group.add_argument(
        "--web-port", type=int, default=None, metavar="PORT",
        help="Start web dashboard on this port (e.g. 8090)"
    )
    ops_group.add_argument(
        "--rate-limit", type=int, default=0, metavar="N",
        help="Max certificate requests per IP per minute (0 = disabled)"
    )
    ops_group.add_argument(
        "--audit", action="store_true", default=True,
        help="Enable structured audit log in ca/audit.db (default: on)"
    )
    ops_group.add_argument(
        "--no-audit", dest="audit", action="store_false",
        help="Disable audit log"
    )
    ops_group.add_argument(
        "--default-profile", default="default",
        choices=list(CertProfile.PROFILES.keys()),
        help="Default certificate profile for CMPv2 issuance (default: default)"
    )
    ops_group.add_argument(
        "--otel-endpoint", default=None, metavar="URL",
        help="OpenTelemetry OTLP gRPC endpoint for distributed tracing "
             "(e.g. http://localhost:4317). Requires opentelemetry-sdk."
    )
    ops_group.add_argument(
        "--expiry-warn-days", type=int, default=30, metavar="DAYS",
        help="Feature 8: warn about certs expiring within N days (default: 30). "
             "Set to 0 to disable the expiry monitor thread."
    )
    ops_group.add_argument(
        "--acme-dns-hook-url", default=None, metavar="URL",
        help="Feature 5: webhook URL for ACME dns-01 challenge publication "
             "(POST {domain, challenge_token, key_authorization})"
    )
    ops_group.add_argument(
        "--acme-dns-rfc2136-server", default=None, metavar="IP[:PORT]",
        help="Feature 5: RFC 2136 nameserver for dns-01 (e.g. 192.168.1.1:53)"
    )
    ops_group.add_argument(
        "--acme-dns-rfc2136-key-name", default=None, metavar="NAME",
        help="Feature 5: TSIG key name for RFC 2136 DNS UPDATE"
    )
    ops_group.add_argument(
        "--acme-dns-rfc2136-key-secret", default=None, metavar="SECRET",
        help="Feature 5: base64 TSIG HMAC secret for RFC 2136 DNS UPDATE"
    )

    cmpv3_group = parser.add_argument_group(
        "CMPv3 options (RFC 9480)",
        "Enable CMPv3 features (pvno=3, new genm types, extended polling, "
        "well-known URI paths). CMPv3 is auto-negotiated based on client pvno."
    )
    cmpv3_group.add_argument(
        "--cmpv3", action="store_true", default=True,
        help="Enable CMPv3 handler (auto-negotiates pvno=2/3, default: on)"
    )
    cmpv3_group.add_argument(
        "--no-cmpv3", dest="cmpv3", action="store_false",
        help="Force CMPv2 only (no RFC 9480 features)"
    )

    est_group = parser.add_argument_group(
        "EST options (RFC 7030)",
        "Enable Enrollment over Secure Transport. EST MUST run over TLS — "
        "a server cert is auto-issued from the CA if not provided."
    )
    est_group.add_argument(
        "--est-port", type=int, default=None, metavar="PORT",
        help="Start EST server on this port (e.g. 8443)"
    )
    est_group.add_argument(
        "--est-user", action="append", metavar="USER:PASS",
        help="Add an EST Basic auth user (repeat for multiple)"
    )
    est_group.add_argument(
        "--est-require-auth", action="store_true",
        help="Require auth for EST (Basic or TLS client cert)"
    )
    est_group.add_argument(
        "--est-tls-cert", metavar="PATH",
        help="PEM server cert for EST HTTPS (defaults to CA auto-issue)"
    )
    est_group.add_argument(
        "--est-tls-key", metavar="PATH",
        help="PEM private key for --est-tls-cert"
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

    security_group = parser.add_argument_group(
        "Security options",
        "Authentication and key protection settings."
    )
    security_group.add_argument(
        "--ca-key-passphrase", default=None, metavar="PASS",
        help="Passphrase for CA private key encryption on disk. "
             "Can also be set via PYPKI_CA_KEY_PASSPHRASE env var."
    )
    security_group.add_argument(
        "--admin-api-key", default=None, metavar="KEY",
        help="API key required for admin endpoints (revoke, sub-ca, key recovery, config). "
             "Clients must send X-Admin-Key header. Can also be set via PYPKI_ADMIN_API_KEY env var."
    )
    security_group.add_argument(
        "--admin-allowed-cns", default=None, metavar="CN1,CN2",
        help="Comma-separated list of mTLS client CNs allowed to call admin endpoints"
    )
    security_group.add_argument(
        "--bootstrap-token", default=None, metavar="TOKEN",
        help="Shared secret required for bootstrap endpoint. "
             "Clients must send X-Bootstrap-Token header or ?token= query param."
    )

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

    # Audit log
    audit_log = AuditLog(ca_dir) if getattr(args, "audit", True) else None

    # Feature 10: OpenTelemetry tracing
    global _tracer
    if getattr(args, "otel_endpoint", None):
        os.environ.setdefault("OTEL_EXPORTER_OTLP_ENDPOINT", args.otel_endpoint)
        _setup_otel("pypki")
    _tracer = _get_tracer()

    # Rate limiter
    rate_limit_n = getattr(args, "rate_limit", 0)
    rate_limiter = RateLimiter(max_per_minute=rate_limit_n) if rate_limit_n > 0 else None

    # OCSP / CRL URLs to embed in issued certs
    ocsp_url = getattr(args, "ocsp_url", "")
    crl_url  = getattr(args, "crl_url", "")

    # CA key passphrase — CLI arg or env var
    ca_key_passphrase = getattr(args, "ca_key_passphrase", None)
    if ca_key_passphrase is None:
        ca_key_passphrase = os.environ.get("PYPKI_CA_KEY_PASSPHRASE")
    ca_key_passphrase_bytes = ca_key_passphrase.encode() if ca_key_passphrase else None

    ca = CertificateAuthority(ca_dir=args.ca_dir, config=config,
                               ocsp_url=ocsp_url, crl_url=crl_url,
                               ca_key_passphrase=ca_key_passphrase_bytes)

    # Admin API key — CLI arg or env var
    admin_api_key = getattr(args, "admin_api_key", None)
    if admin_api_key is None:
        admin_api_key = os.environ.get("PYPKI_ADMIN_API_KEY")

    # Admin allowed CNs for mTLS
    admin_allowed_cns = None
    if getattr(args, "admin_allowed_cns", None):
        admin_allowed_cns = [cn.strip() for cn in args.admin_allowed_cns.split(",")]

    # Bootstrap token
    bootstrap_token = getattr(args, "bootstrap_token", None)

    # Feature 8: expiry monitor thread
    _expiry_days = getattr(args, "expiry_warn_days", 30)
    if _expiry_days > 0:
        ca.start_expiry_monitor(
            days_ahead=_expiry_days,
            check_interval_seconds=86400,
            audit=audit_log,
        )

    # Feature 5: ACME dns-01 hook configuration
    _dns01_hook = None
    if getattr(args, "acme_dns_hook_url", None):
        _dns01_hook = CertificateAuthority.make_dns01_webhook_hook(
            args.acme_dns_hook_url
        )
        logger.info(f"ACME dns-01 webhook hook: {args.acme_dns_hook_url}")
    elif (getattr(args, "acme_dns_rfc2136_server", None)
          and getattr(args, "acme_dns_rfc2136_key_name", None)
          and getattr(args, "acme_dns_rfc2136_key_secret", None)):
        _dns01_hook = CertificateAuthority.make_dns01_rfc2136_hook(
            nameserver=args.acme_dns_rfc2136_server,
            key_name=args.acme_dns_rfc2136_key_name,
            key_secret=args.acme_dns_rfc2136_key_secret,
        )
        logger.info(f"ACME dns-01 RFC 2136 hook: {args.acme_dns_rfc2136_server}")

    if audit_log:
        audit_log.record("startup", f"port={args.port} tls={'mtls' if args.mtls else 'tls' if args.tls else 'none'}")

    # Use CMPv3Handler (RFC 9480) by default; fall back to CMPv2Handler if --no-cmpv3
    if getattr(args, "cmpv3", True):
        cmp_handler = CMPv3Handler(ca)
        handler_class = make_cmpv3_handler(ca, cmp_handler, audit_log, rate_limiter,
                                            admin_api_key=admin_api_key,
                                            admin_allowed_cns=admin_allowed_cns,
                                            bootstrap_token=bootstrap_token)
        logger.info("CMPv3 handler active (RFC 9480 — pvno auto-negotiation, well-known URI)")
    else:
        cmp_handler = CMPv2Handler(ca)
        handler_class = make_handler(ca, cmp_handler, audit_log, rate_limiter,
                                      admin_api_key=admin_api_key,
                                      admin_allowed_cns=admin_allowed_cns,
                                      bootstrap_token=bootstrap_token)
        logger.info("CMPv2 handler active (--no-cmpv3 specified)")

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
            tls13_only=getattr(args, "tls13_only", False),
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
            print("         Place acme_server.py in the same directory as pki_server.py.")
        else:
            acme_base = args.acme_base_url or f"http://{args.host}:{args.acme_port}"
            acme_srv = _acme_module.start_acme_server(
                host=args.host,
                port=args.acme_port,
                ca=ca,
                ca_dir=ca_dir,
                auto_approve_dns=args.acme_auto_approve_dns,
                base_url=acme_base,
                cert_validity_days=getattr(args, "acme_cert_days", 90),
                short_lived_threshold_days=getattr(args, "acme_short_lived_threshold", 7),
                dns01_hook=_dns01_hook,  # Feature 5: real dns-01 resolver hook
            )

    # Start SCEP server if requested
    scep_srv = None
    if args.scep_port:
        if not HAS_SCEP:
            print("WARNING: scep_server.py not found — SCEP support disabled.")
            print("         Place scep_server.py in the same directory as pki_server.py.")
        else:
            scep_srv = _scep_module.start_scep_server(
                host=args.host,
                port=args.scep_port,
                ca=ca,
                ca_dir=ca_dir,
                challenge=args.scep_challenge,
            )

    # Start EST server if requested
    est_srv = None
    if args.est_port:
        if not HAS_EST:
            print("WARNING: est_server.py not found — EST support disabled.")
            print("         Place est_server.py in the same directory as pki_server.py.")
        else:
            est_users = {}
            for entry in (args.est_user or []):
                u, _, p = entry.partition(":")
                est_users[u] = p
            est_srv = _est_module.start_est_server(
                host=args.host,
                port=args.est_port,
                ca=ca,
                ca_dir=ca_dir,
                users=est_users if est_users else None,
                require_auth=args.est_require_auth,
                tls_cert_path=args.est_tls_cert,
                tls_key_path=args.est_tls_key,
            )

    # Start OCSP responder if requested
    ocsp_srv = None
    if getattr(args, "ocsp_port", None):
        if not HAS_OCSP:
            print("WARNING: ocsp_server.py not found — OCSP support disabled.")
        else:
            ocsp_srv = _ocsp_module.start_ocsp_server(
                host=args.host,
                port=args.ocsp_port,
                ca=ca,
                cache_seconds=getattr(args, "ocsp_cache_seconds", 300),
            )

    # Start Web UI if requested
    web_srv = None
    if getattr(args, "web_port", None):
        if not HAS_WEBUI:
            print("WARNING: web_ui.py not found — Web UI disabled.")
        else:
            _ocsp_base = f"http://{args.host}:{args.ocsp_port}" if getattr(args, "ocsp_port", None) else ""
            _acme_base2 = f"http://{args.host}:{args.acme_port}/acme/directory" if getattr(args, "acme_port", None) else ""
            _scep_base = f"http://{args.host}:{args.scep_port}/scep" if getattr(args, "scep_port", None) else ""
            _est_base  = f"https://{args.host}:{args.est_port}/.well-known/est" if getattr(args, "est_port", None) else ""
            web_srv = _web_ui_module.start_web_ui(
                host=args.host,
                port=args.web_port,
                ca=ca,
                audit_log=audit_log,
                rate_limiter=rate_limiter,
                cmp_base_url=f"{scheme}://{args.host}:{args.port}",
                acme_base_url=_acme_base2,
                scep_base_url=_scep_base,
                est_base_url=_est_base,
                ocsp_base_url=_ocsp_base,
            )

    acme_line = f"http://{args.host}:{args.acme_port}/acme/directory" if (args.acme_port and HAS_ACME) else "disabled"
    scep_line = f"http://{args.host}:{args.scep_port}/scep" if (args.scep_port and HAS_SCEP) else "disabled"
    est_line  = f"https://{args.host}:{args.est_port}/.well-known/est" if (args.est_port and HAS_EST) else "disabled"
    ocsp_line = f"http://{args.host}:{args.ocsp_port}/ocsp" if (getattr(args,"ocsp_port",None) and HAS_OCSP) else "disabled"
    web_line  = f"http://{args.host}:{args.web_port}" if getattr(args,"web_port",None) else "disabled"
    cmp_wk    = f"{scheme}://{args.host}:{args.port}/.well-known/cmp"
    rl_info   = f"{args.rate_limit}/min per IP" if getattr(args,"rate_limit",0) > 0 else "disabled"
    audit_info = "ca/audit.db" if getattr(args,"audit",True) else "disabled"
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
║  Listening (EST)  : {est_line:<47}║
║  Listening (OCSP) : {ocsp_line:<47}║
║  Web Dashboard    : {web_line:<47}║
║  CMP Well-Known   : {cmp_wk:<47}║
║  Rate Limiting    : {rl_info:<47}║
║  Audit Log        : {audit_info:<47}║
║  Metrics          : {scheme}://{args.host}:{args.port}/metrics                      ║
║  Expiry Monitor   : {str(_expiry_days)+"d" if _expiry_days else "disabled":<47}║
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
║  Supported CMPv2/CMPv3 operations:                              ║
║    ir, cr, kur, rr, certConf, genm, p10cr (CMPv2 / RFC 4210)   ║
║    pollReq/pollRep - extended polling (CMPv3 / RFC 9480)        ║
║    genm GetCACerts, GetRootCACertUpdate, GetCertReqTemplate     ║
║    Well-known URI: POST/GET /.well-known/cmp[/p/<label>]        ║
╠══════════════════════════════════════════════════════════════════╣
║  Supported ACME operations (RFC 8555 + RFC 9608):              ║
║    new-account, new-order, http-01, dns-01, finalize, revoke   ║
║    noRevAvail (RFC 9608) auto-applied to short-lived certs     ║
╠══════════════════════════════════════════════════════════════════╣
║  Supported SCEP operations (RFC 8894):                          ║
║    GetCACaps, GetCACert, PKCSReq, CertPoll, GetCert, GetCRL    ║
╠══════════════════════════════════════════════════════════════════╣
║  Supported EST operations (RFC 7030):                           ║
║    cacerts, simpleenroll, simplereenroll, csrattrs, serverkeygen║
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

    if args.est_port and HAS_EST:
        print("  EST Quick-start (RFC 7030):")
        print(f"  1. Get CA chain:  curl --cacert {args.ca_dir}/ca.crt \\")
        print(f"                       https://{args.host}:{args.est_port}/.well-known/est/cacerts | base64 -d > chain.p7")
        print(f"  2. Enrol (openssl):")
        print(f"     openssl req -new -key client.key -out client.csr -subj '/CN=mydevice'")
        print(f"     curl -X POST --cacert {args.ca_dir}/ca.crt \\")
        print(f"          --data-binary @<(base64 client.csr) \\")
        print(f"          -H 'Content-Transfer-Encoding: base64' \\")
        print(f"          https://{args.host}:{args.est_port}/.well-known/est/simpleenroll")
        if args.est_require_auth:
            print(f"     Add: -u 'username:password'")
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
        if est_srv:
            est_srv.shutdown()
        if ocsp_srv:
            ocsp_srv.shutdown()
        if web_srv:
            web_srv.shutdown()
        if audit_log:
            audit_log.record("shutdown", "graceful shutdown via KeyboardInterrupt")

if __name__ == "__main__":
    main()
