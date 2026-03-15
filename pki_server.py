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

# IPsec PKI module (optional — loaded if --ipsec-port is specified)
# RFC 4945 (IPsec cert profile) + RFC 4806 (OCSP hash/IKEv2) + RFC 4809 (requirements)
try:
    import ipsec_server as _ipsec_module
    HAS_IPSEC = True
except ImportError:
    HAS_IPSEC = False

# CMP server module — CMPv2 (RFC 4210) / CMPv3 (RFC 9480) / HTTP (RFC 6712)
# Extracted from pki_server.py into cmp_server.py, consistent with the other
# protocol modules: acme_server.py, scep_server.py, est_server.py, ocsp_server.py.
try:
    import cmp_server as _cmp_module
    HAS_CMP = True
except ImportError:
    HAS_CMP = False
    print("WARNING: cmp_server.py not found — CMPv2/CMPv3 support disabled.")
    print("         Place cmp_server.py in the same directory as pki_server.py.")

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
        conn.close()

    def record(self, event: str, detail: str = "", ip: str = ""):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn = sqlite3.connect(str(self._db))
        conn.execute("INSERT INTO audit(ts,event,detail,ip) VALUES(?,?,?,?)",
                     (ts, event, detail, ip))
        conn.commit()
        conn.close()
        logger.info(f"AUDIT [{event}] {detail}")

    def recent(self, n: int = 100) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(str(self._db))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT ts,event,detail,ip FROM audit ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


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
    """Self-signed CA with certificate issuance and revocation.

    When running as an **intermediate CA** (ca.crt is signed by an external
    root), pass the path to the parent chain PEM as *parent_chain_path* (or
    place it at ``<ca_dir>/ca-chain.pem`` before starting).  The chain PEM
    must contain one or more certificates in order from the immediate issuer
    to the root, *not* including ca.crt itself.

    With a parent chain loaded, the following all return the full chain:
    * :attr:`ca_chain_pem` / :attr:`ca_chain_ders` — all certs root-to-leaf
    * :meth:`provision_tls_server_cert` — appends intermediates to server.crt
    * :meth:`build_tls_context` — loads full chain for mTLS client verification
    * :meth:`export_pkcs12` — includes intermediates in the CA bag
    * EST /cacerts, SCEP GetCACert, CMP GetCACerts — serve the full chain
    """

    def __init__(self, ca_dir: str = "./ca", config: Optional["ServerConfig"] = None,
                 ocsp_url: str = "", crl_url: str = "",
                 parent_chain_path: Optional[str] = None):
        """
        Parameters
        ----------
        ca_dir            : Directory holding ca.key, ca.crt, certificates.db, …
        config            : Optional ServerConfig for live-editable validity periods.
        ocsp_url          : AIA OCSP URL embedded in every issued cert.
        crl_url           : CDP URL embedded in every issued cert.
        parent_chain_path : PEM file with the certificate(s) that signed ca.crt
                            (parent → … → root, *not* including ca.crt itself).
                            If omitted, <ca_dir>/ca-chain.pem is loaded automatically
                            when it exists.  Required for intermediate CA operation.
        """
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.ca_dir / "certificates.db"
        self.config  = config  # may be None (uses hardcoded defaults as fallback)
        self._ocsp_url = ocsp_url   # embedded in every issued cert AIA extension
        self._crl_url  = crl_url    # embedded in every issued cert CDP extension
        self._init_db()
        self._load_or_create_ca()
        self._load_parent_chain(parent_chain_path)

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

            with open(ca_key_path, "wb") as f:
                f.write(self.ca_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
            with open(ca_cert_path, "wb") as f:
                f.write(self.ca_cert.public_bytes(Encoding.PEM))

            logger.info(f"CA certificate written to {ca_cert_path}")

    # ------------------------------------------------------------------
    # Intermediate CA — parent chain loading
    # ------------------------------------------------------------------

    def _load_parent_chain(self, parent_chain_path: Optional[str] = None) -> None:
        """Load the parent certificate chain for intermediate CA operation.

        Sets ``self._parent_chain``: list of x509.Certificate from immediate
        parent to root (empty list when running as a self-signed root CA).

        Search order:
        1. *parent_chain_path* argument (if given)
        2. ``<ca_dir>/ca-chain.pem`` (auto-discovered when present)
        """
        self._parent_chain: List[x509.Certificate] = []

        # Determine which file to load
        candidate: Optional[Path] = None
        if parent_chain_path:
            candidate = Path(parent_chain_path)
        else:
            auto = self.ca_dir / "ca-chain.pem"
            if auto.exists():
                candidate = auto

        if candidate is None:
            # Self-signed root — no parent chain needed
            return

        if not candidate.exists():
            raise FileNotFoundError(
                f"parent_chain_path '{candidate}' not found. "
                "The file must contain the PEM-encoded certificate(s) that signed "
                "ca.crt, in order from the immediate issuer to the root CA."
            )

        pem_data = candidate.read_bytes()
        # Parse all PEM blocks in the file
        import re as _re
        pem_blocks = _re.findall(
            rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            pem_data, _re.DOTALL,
        )
        if not pem_blocks:
            raise ValueError(
                f"parent_chain_path '{candidate}' contains no PEM certificates."
            )

        for block in pem_blocks:
            cert = x509.load_pem_x509_certificate(block)
            self._parent_chain.append(cert)

        # Validate: the first cert in the chain must have signed ca.crt
        try:
            issuer_pub = self._parent_chain[0].public_key()
            issuer_pub.verify(
                self.ca_cert.signature,
                self.ca_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                self.ca_cert.signature_hash_algorithm,
            )
        except Exception as exc:
            raise ValueError(
                f"parent_chain_path '{candidate}': the first certificate did not "
                f"sign ca.crt — {exc}"
            ) from exc

        # Validate continuity: each cert must have signed the one before it
        for i in range(1, len(self._parent_chain)):
            child  = self._parent_chain[i - 1]
            parent = self._parent_chain[i]
            if child.issuer != parent.subject:
                raise ValueError(
                    f"parent_chain_path '{candidate}': chain break between "
                    f"cert[{i-1}] (issuer={child.issuer.rfc4514_string()}) "
                    f"and cert[{i}] (subject={parent.subject.rfc4514_string()})"
                )

        subjects = " → ".join(c.subject.rfc4514_string() for c in self._parent_chain)
        logger.info(
            "Intermediate CA mode — parent chain loaded (%d cert(s)): %s",
            len(self._parent_chain), subjects,
        )

    @property
    def is_intermediate(self) -> bool:
        """True when this CA has a parent chain (i.e. is not a self-signed root)."""
        return bool(self._parent_chain)

    @property
    def ca_chain_ders(self) -> List[bytes]:
        """DER bytes of every cert in the trust chain, ordered leaf → root.

        For a root CA this is ``[ca_cert_der]``.
        For an intermediate CA this is ``[ca_cert_der, parent_der, ..., root_der]``.
        """
        result = [self.ca_cert_der]
        for cert in self._parent_chain:
            result.append(cert.public_bytes(Encoding.DER))
        return result

    @property
    def ca_chain_pem(self) -> bytes:
        """PEM bytes of the full trust chain, ordered leaf → root (concatenated).

        Use this wherever a complete chain is needed: TLS ``load_cert_chain``,
        EST cacerts, SCEP GetCACert (p7c), CMP GetCACerts, PKCS#12 CA bags.
        """
        parts: List[bytes] = [self.ca_cert_pem]
        for cert in self._parent_chain:
            parts.append(cert.public_bytes(Encoding.PEM))
        return b"".join(parts)

    def _write_chain_file(self) -> Path:
        """Write (or refresh) <ca_dir>/server-chain.pem and return its path.

        The file contains: server cert (if present) + intermediate(s) + root.
        Only the intermediate portion (self._parent_chain) is written here;
        callers prepend the leaf cert when needed.
        """
        chain_path = self.ca_dir / "ca-chain.pem"
        if self._parent_chain:
            chain_pem = b"".join(c.public_bytes(Encoding.PEM) for c in self._parent_chain)
            chain_path.write_bytes(chain_pem)
        return chain_path

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
        row = conn.execute("SELECT der FROM certificates WHERE serial=?", (serial,)).fetchone()
        conn.close()
        return row[0] if row else None

    def list_certificates(self) -> list:
        conn = sqlite3.connect(str(self.db_path))
        rows = conn.execute(
            "SELECT serial, subject, not_before, not_after, revoked, profile FROM certificates"
        ).fetchall()
        conn.close()
        return [
            {"serial": r[0], "subject": r[1], "not_before": r[2], "not_after": r[3], "revoked": bool(r[4]), "profile": r[5] or "default"}
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

        # When running as intermediate CA, server.crt must include the full chain
        # (leaf + intermediates) so TLS clients can build the path to their root.
        # ssl.SSLContext.load_cert_chain() reads the chain from the cert file when
        # multiple PEM blocks are present — RFC 5246 / RFC 8446 §4.4.2.
        cert_pem = cert.public_bytes(Encoding.PEM)
        if self._parent_chain:
            chain_suffix = b"".join(c.public_bytes(Encoding.PEM) for c in self._parent_chain)
            cert_pem = cert_pem + chain_suffix
            logger.info(
                "Intermediate CA: appended %d parent cert(s) to server.crt",
                len(self._parent_chain),
            )
        with open(cert_path, "wb") as f:
            f.write(cert_pem)

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
            # For mTLS the trust anchor must include the full chain so Python's ssl
            # module can verify client certs that chain through intermediates.
            # load_verify_locations() accepts a PEM file with multiple concatenated
            # certificates (per OpenSSL convention).
            if self._parent_chain:
                # Write a temporary combined trust-anchor file: this CA + all parents
                import tempfile as _tf, os as _os
                trust_pem = self.ca_chain_pem          # leaf … root
                with _tf.NamedTemporaryFile(delete=False, suffix=".pem") as _f:
                    _f.write(trust_pem)
                    _trust_tmp = _f.name
                ctx.load_verify_locations(_trust_tmp)
                _os.unlink(_trust_tmp)
                logger.info(
                    "TLS mode: mutual — trust anchor is full chain (%d cert(s))",
                    1 + len(self._parent_chain),
                )
            else:
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

        # For intermediate CA, include the full chain in the trust store
        if self._parent_chain:
            import tempfile as _tf, os as _os
            with _tf.NamedTemporaryFile(delete=False, suffix=".pem") as _f:
                _f.write(self.ca_chain_pem)
                _trust_tmp = _f.name
            ctx.load_verify_locations(_trust_tmp)
            _os.unlink(_trust_tmp)
        else:
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
            .last_update(datetime.datetime.now(datetime.timezone.utc))
            .next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7))
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
                        datetime.datetime.fromtimestamp(row["revoked_at"], tz=datetime.timezone.utc)
                        if row["revoked_at"]
                        else datetime.datetime.now(datetime.timezone.utc)
                    )
                    .build()
                )
                builder = builder.add_revoked_certificate(revoked_cert)
        finally:
            conn.close()
        crl = builder.sign(private_key=self.ca_key, algorithm=SHA256())
        return crl.public_bytes(Encoding.DER)

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
        # Include the full CA chain in the PKCS#12 CA bag so that importing
        # applications (browsers, OS key stores) can build the complete path.
        ca_bag = [self.ca_cert] + list(self._parent_chain)
        p12 = pkcs12.serialize_key_and_certificates(
            name=f"cert-{serial}".encode(),
            key=None,
            cert=cert,
            cas=ca_bag,
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
        """Create key_archive table if it does not exist (called from _init_db)."""
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS key_archive (
                serial      INTEGER PRIMARY KEY,
                archived_at TEXT NOT NULL,
                encrypted   BLOB NOT NULL,
                subject     TEXT NOT NULL
            )
        """)
        conn.commit()
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
        return nc_cert.sign(self.ca_key, SHA256())

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
            safe = profile.replace('"', '\"')
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


def main():
    parser = argparse.ArgumentParser(description="PKI Server with CMPv2 Support + mTLS")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument("--ca-dir", default="./ca", help="CA data directory (default: ./ca)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument(
        "--parent-cert", default=None, metavar="PATH",
        help=(
            "PEM file containing the certificate(s) that signed ca.crt, enabling "
            "intermediate CA mode.  List certs from the immediate parent to the root, "
            "one per PEM block.  When present: TLS handshakes include the full chain, "
            "EST /cacerts serves the full chain, SCEP GetCACert returns a p7c, "
            "CMP GetCACerts lists all CA certs, and PKCS#12 bundles include the chain. "
            "You may also place this file at <ca-dir>/ca-chain.pem and omit this flag."
        ),
    )
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
    tls_group.add_argument(
        "--tls-reload-interval", type=int, default=60, metavar="SECS",
        help=(
            "Seconds between certificate-file mtime checks for automatic "
            "zero-downtime TLS reload (default: 60). "
            "Set 0 to disable the file watcher and rely solely on "
            "POST /api/reload-tls (e.g. from a certbot deploy-hook). "
            "Useful with Let's Encrypt: point --tls-cert at the certbot "
            "fullchain.pem — the server will pick up renewals automatically "
            "without any restart or deploy-hook."
        ),
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
        "--web-no-auth", action="store_true", default=False,
        help="Disable PAM authentication on the web dashboard (development only)"
    )
    ops_group.add_argument(
        "--web-pam-service", default="login", metavar="SERVICE",
        help="PAM service name used for web dashboard login (default: login)"
    )
    ops_group.add_argument(
        "--ipsec-port", type=int, default=None, metavar="PORT",
        help="Start IPsec PKI server on this port (RFC 4945/4806/4809, auto-TLS from CA)"
    )
    ops_group.add_argument(
        "--ipsec-tls-cert", default=None, metavar="PATH",
        help="PEM TLS cert for IPsec server (auto-provisioned from CA if omitted)"
    )
    ops_group.add_argument(
        "--ipsec-tls-key", default=None, metavar="PATH",
        help="PEM TLS key for IPsec server (auto-provisioned from CA if omitted)"
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

    ca = CertificateAuthority(
        ca_dir=args.ca_dir,
        config=config,
        ocsp_url=ocsp_url,
        crl_url=crl_url,
        parent_chain_path=getattr(args, "parent_cert", None),
    )
    # Store reload interval on ca so sub-modules (ipsec_server) can read it
    ca._tls_reload_interval = getattr(args, "tls_reload_interval", 60)

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

    if not HAS_CMP:
        print("ERROR: cmp_server.py is required. "
              "Place it in the same directory as pki_server.py.")
        raise SystemExit(1)

    # ── CMP server (delegated to cmp_server.py) ───────────────────────────────
    scheme = "http"
    tls_mode_label = "plain HTTP"
    cmp_tls_cert = cmp_tls_key = None

    if args.tls or args.mtls:
        if args.tls_cert and args.tls_key:
            cmp_tls_cert, cmp_tls_key = args.tls_cert, args.tls_key
            logger.info(f"Using provided TLS certificate: {cmp_tls_cert}")
        else:
            _cp, _kp = ca.provision_tls_server_cert(args.tls_hostname)
            cmp_tls_cert, cmp_tls_key = str(_cp), str(_kp)
        scheme = "https"
        tls_mode_label = (
            "mutual TLS (client cert required)" if args.mtls
            else "TLS (server cert only)"
        )
        if args.mtls:
            logger.info(f"mTLS — clients must present a cert signed by: {ca.ca_dir / 'ca.crt'}")

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

    server = _cmp_module.start_cmp_server(
        host=args.host,
        port=args.port,
        ca=ca,
        audit_log=audit_log,
        rate_limiter=rate_limiter,
        use_cmpv3=getattr(args, "cmpv3", True),
        tls_cert_path=cmp_tls_cert,
        tls_key_path=cmp_tls_key,
        require_client_cert=getattr(args, "mtls", False),
        tls13_only=getattr(args, "tls13_only", False),
        alpn_protocols=alpn_protos,
        tls_reload_interval=getattr(args, "tls_reload_interval", 60),
    )
    proto_label = "CMPv3 (RFC 9480)" if getattr(args, "cmpv3", True) else "CMPv2 (RFC 4210)"
    logger.info(f"{proto_label} active on {scheme}://{args.host}:{args.port}")

    bootstrap_srv = None
    if args.bootstrap_port:
        bootstrap_srv = _cmp_module.start_bootstrap_server(
            args.host, args.bootstrap_port, ca,
            _cmp_module.CMPv2Handler(ca),
        )

    # Start ACME server if requested
    acme_srv = None
    if args.acme_port:
        if not HAS_ACME:
            print("WARNING: acme_server.py not found — ACME support disabled.")
            print("         Place acme_server.py in the same directory as pki_server.py.")
        else:
            # Use tls_hostname (or localhost) instead of 0.0.0.0 for the ACME base URL
            # so directory URLs are reachable by clients (0.0.0.0 is a bind addr, not a hostname)
            _acme_hostname = (
                args.acme_base_url.split("://")[1].split(":")[0]
                if args.acme_base_url
                else (getattr(args, "tls_hostname", None) or "localhost")
                if args.host in ("0.0.0.0", "::")
                else args.host
            )
            acme_base = args.acme_base_url or f"http://{_acme_hostname}:{args.acme_port}"
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
                tls_reload_interval=getattr(args, "tls_reload_interval", 60),
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

    # Start IPsec PKI server if requested (RFC 4945 / RFC 4806 / RFC 4809)
    ipsec_srv = None
    if getattr(args, "ipsec_port", None):
        if not HAS_IPSEC:
            print("WARNING: ipsec_server.py not found — IPsec PKI server disabled.")
        else:
            _ipsec_ocsp_url  = getattr(args, "ocsp_url", None) or None
            _ipsec_crl_url   = getattr(args, "crl_url",  None) or None
            _ipsec_tls_cert  = getattr(args, "ipsec_tls_cert", None) or None
            _ipsec_tls_key   = getattr(args, "ipsec_tls_key",  None) or None
            ipsec_srv = _ipsec_module.start_ipsec_server(
                host=args.host,
                port=args.ipsec_port,
                ca=ca,
                ocsp_url=_ipsec_ocsp_url,
                crl_url=_ipsec_crl_url,
                tls_cert_path=_ipsec_tls_cert,
                tls_key_path=_ipsec_tls_key,
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
                require_auth=not getattr(args, "web_no_auth", False),
                pam_service=getattr(args, "web_pam_service", "login"),
                cmp_base_url=f"{scheme}://{args.host}:{args.port}",
                acme_base_url=_acme_base2,
                scep_base_url=_scep_base,
                est_base_url=_est_base,
                ocsp_base_url=_ocsp_base,
            )

    ca_mode_label = (
        f"intermediate ({len(ca._parent_chain)} parent cert(s))"
        if ca.is_intermediate else "root (self-signed)"
    )
    acme_line = f"http://{args.host}:{args.acme_port}/acme/directory" if (args.acme_port and HAS_ACME) else "disabled"
    scep_line = f"http://{args.host}:{args.scep_port}/scep" if (args.scep_port and HAS_SCEP) else "disabled"
    est_line  = f"https://{args.host}:{args.est_port}/.well-known/est" if (args.est_port and HAS_EST) else "disabled"
    ocsp_line = f"http://{args.host}:{args.ocsp_port}/ocsp" if (getattr(args,"ocsp_port",None) and HAS_OCSP) else "disabled"
    web_line  = f"http://{args.host}:{args.web_port}" if getattr(args,"web_port",None) else "disabled"
    ipsec_line = f"https://{args.host}:{args.ipsec_port}/ipsec" if (getattr(args,"ipsec_port",None) and HAS_IPSEC) else "disabled"
    cmp_wk    = f"{scheme}://{args.host}:{args.port}/.well-known/cmp"
    rl_info   = f"{args.rate_limit}/min per IP" if getattr(args,"rate_limit",0) > 0 else "disabled"
    _tls_reload_interval = getattr(args, "tls_reload_interval", 60)
    tls_reload_info = (f"{_tls_reload_interval}s poll + POST /api/reload-tls"
                       if (args.tls or args.mtls) else "n/a (no TLS)")
    audit_info = "ca/audit.db" if getattr(args,"audit",True) else "disabled"
    boot_line = f"http://{args.host}:{args.bootstrap_port}/bootstrap?cn=<n>" if args.bootstrap_port else "disabled"

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║         PyPKI CMPv2 + ACME Server (RFC 4210 / RFC 8555 + TLS)  ║
╠══════════════════════════════════════════════════════════════════╣
║  Listening (CMPv2): {scheme}://{args.host}:{args.port:<32}║
║  Listening (ACME) : {acme_line:<47}║
║  CA Dir           : {args.ca_dir:<47}║
║  CA Mode          : {ca_mode_label:<47}║
║  TLS Mode         : {tls_mode_label:<47}║
║  Bootstrap        : {boot_line:<47}║
║  Listening (SCEP) : {scep_line:<47}║
║  Listening (EST)  : {est_line:<47}║
║  Listening (OCSP) : {ocsp_line:<47}║
║  Web Dashboard    : {web_line:<47}║
║  IPsec PKI        : {ipsec_line:<47}║
║  CMP Well-Known   : {cmp_wk:<47}║
║  Rate Limiting    : {rl_info:<47}║
║  Audit Log        : {audit_info:<47}║
║  Metrics          : {scheme}://{args.host}:{args.port}/metrics                      ║
║  Expiry Monitor   : {str(_expiry_days)+"d" if _expiry_days else "disabled":<47}║
║  TLS Cert Reload  : {tls_reload_info:<47}║
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

    if 'est_srv' not in dir():
        est_srv = None
    if 'ocsp_srv' not in dir():
        ocsp_srv = None
    if 'web_srv' not in dir():
        web_srv = None

    # Collect all servers that may have a TLS watcher to stop on shutdown
    _tls_servers = [s for s in [server, est_srv, ipsec_srv] if s is not None]

    try:
        # CMP server runs in its own daemon thread (started by start_cmp_server).
        # Block the main thread here so the process stays alive.
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down PKI server...")
        # Stop TLS cert watchers first so they don't log spurious errors
        for _srv in _tls_servers:
            _w = getattr(_srv, "_tls_watcher", None)
            if _w is not None:
                _w.stop()
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
        if ipsec_srv:
            ipsec_srv.shutdown()
        if web_srv:
            web_srv.shutdown()
        if audit_log:
            audit_log.record("shutdown", "graceful shutdown via KeyboardInterrupt")

if __name__ == "__main__":
    main()
