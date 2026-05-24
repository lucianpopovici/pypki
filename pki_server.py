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
    # Plain HTTP (no mTLS) — all services on one port
    python pki_server.py [--host 0.0.0.0] [--port 8080] [--ca-dir ./ca]

    # mTLS enabled
    python pki_server.py --mtls --port 8443 [--ca-dir ./ca]

    # With ACME at /acme, SCEP at /scep
    python pki_server.py --acme-prefix /acme --scep-prefix /scep [--ca-dir ./ca]

    # ACME with dns-01 auto-approve (testing/internal CA only)
    python pki_server.py --acme-prefix /acme --acme-auto-approve-dns
"""

import argparse
import base64
import datetime
import fnmatch
import hashlib
import hmac
import http.server
import json
import logging
import os
import re
import socket
import sqlite3
from db import make_db, Database
import ssl
import struct
import tempfile
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

# Cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding, ec, ed25519, ed448,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# RFC 9608 — No Revocation Available extension OID (id-ce 56)
OID_NO_REV_AVAIL = x509.ObjectIdentifier("2.5.29.56")
NO_REV_AVAIL_THRESHOLD_DAYS = 7  # certs valid <=7 days SHOULD carry noRevAvail

# RFC 8398/9598 — SmtpUTF8Mailbox otherName OID for non-ASCII email in SAN
OID_SMTP_UTF8_MAILBOX = x509.ObjectIdentifier("1.3.6.1.5.5.7.8.9")

# RFC 6962 — CT Pre-certificate Poison extension OID
OID_CT_POISON = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")

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

# ACME server module (optional — loaded if --acme-prefix is specified)
try:
    import acme_server as _acme_module
    HAS_ACME = True
except ImportError:
    HAS_ACME = False

# SCEP server module (optional — loaded if --scep-prefix is specified)
try:
    import scep_server as _scep_module
    HAS_SCEP = True
except ImportError:
    HAS_SCEP = False

# EST server module (optional — loaded if --est-prefix is specified)
try:
    import est_server as _est_module
    HAS_EST = True
except ImportError:
    HAS_EST = False

# OCSP responder module (optional — loaded if --ocsp-prefix is specified)
try:
    import ocsp_server as _ocsp_module
    HAS_OCSP = True
except ImportError:
    HAS_OCSP = False

# TSA server module (optional — loaded if --tsa-prefix is specified)
# RFC 3161 (Time-Stamp Protocol) + RFC 5816 (signingCertificateV2)
try:
    import tsa_server as _tsa_module
    HAS_TSA = True
except ImportError:
    HAS_TSA = False

# Web UI module (optional — loaded if --web-prefix is specified)
try:
    import web_ui as _web_ui_module
    HAS_WEBUI = True
except ImportError:
    HAS_WEBUI = False

# IPsec PKI module (optional — loaded if --ipsec-prefix is specified)
# RFC 4945 (IPsec cert profile) + RFC 4806 (OCSP hash/IKEv2) + RFC 4809 (requirements)
try:
    import ipsec_server as _ipsec_module
    HAS_IPSEC = True
except ImportError:
    HAS_IPSEC = False

# CMP server module import is deferred to after all class definitions to avoid
# circular imports: cmp_server.py does `from pki_server import CertificateAuthority, ...`
# which requires pki_server to be fully loaded first.
# The actual import block appears just before main() at the bottom of this file.
HAS_CMP = False
_cmp_module = None

# §5.9 — Lifecycle hooks / webhooks (optional)
try:
    import hooks as _hooks_module
    HAS_HOOKS = True
except ImportError:
    HAS_HOOKS = False
    _hooks_module = None  # type: ignore[assignment]

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

# ---------------------------------------------------------------------------
# §5.10 — Structured logging + request IDs
# ---------------------------------------------------------------------------

class _RequestIdFilter(logging.Filter):
    """Inject the current request ID (from dispatcher ContextVar) into every record."""
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            from dispatcher_server import request_id_var
            record.req_id = request_id_var.get()
        except Exception:
            record.req_id = ""
        return True


class _JsonFormatter(logging.Formatter):
    """One JSON object per line, suitable for log aggregators."""
    def format(self, record: logging.LogRecord) -> str:
        import json as _json
        d: dict = {
            "ts":      self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
            "req_id":  getattr(record, "req_id", "") or None,
        }
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return _json.dumps(d, separators=(",", ":"))


def configure_logging(level: str = "INFO", log_format: str = "text") -> None:
    """Configure the root logger; called once from main() after arg parsing."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    handler = logging.StreamHandler()
    if log_format == "json":
        fmt: logging.Formatter = _JsonFormatter()
    else:
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(fmt)
    handler.addFilter(_RequestIdFilter())
    root.addHandler(handler)


# Bootstrap with text format so import-time messages are readable; main()
# calls configure_logging() again once CLI args are parsed.
configure_logging("INFO", "text")

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
# §5.11 — In-process Prometheus histogram (no prometheus_client dependency)
# ---------------------------------------------------------------------------

_HIST_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))


class _Histogram:
    """Thread-safe Prometheus-format histogram stored in process memory."""

    def __init__(self, name: str, help_text: str, labels: tuple = (),
                 buckets: tuple = _HIST_BUCKETS) -> None:
        self._name = name
        self._help = help_text
        self._label_names = labels
        self._buckets = buckets
        self._lock = threading.Lock()
        self._data: dict = {}  # label_values_tuple → {"b": [...], "s": float, "c": int}

    def observe(self, value: float, label_values: tuple = ()) -> None:
        with self._lock:
            if label_values not in self._data:
                self._data[label_values] = {
                    "b": [0] * len(self._buckets),
                    "s": 0.0,
                    "c": 0,
                }
            d = self._data[label_values]
            for i, bound in enumerate(self._buckets):
                if value <= bound:
                    d["b"][i] += 1
            d["s"] += value
            d["c"] += 1

    def exposition(self) -> list:
        lines = [
            f"# HELP {self._name} {self._help}",
            f"# TYPE {self._name} histogram",
        ]
        with self._lock:
            snapshot = list(self._data.items())
        for label_vals, d in sorted(snapshot, key=lambda x: str(x[0])):
            if self._label_names:
                label_body = ",".join(
                    f'{k}="{v}"' for k, v in zip(self._label_names, label_vals)
                )
                pfx = f"{{{label_body},"
                sfx = "}"
            else:
                pfx = "{"
                sfx = "}"
            for i, bound in enumerate(self._buckets):
                le = "+Inf" if bound == float("inf") else str(bound)
                lines.append(f'{self._name}_bucket{pfx}le="{le}"{sfx} {d["b"][i]}')
            lines.append(f'{self._name}_sum{{{label_body}}} {d["s"]}' if self._label_names
                         else f'{self._name}_sum {d["s"]}')
            lines.append(f'{self._name}_count{{{label_body}}} {d["c"]}' if self._label_names
                         else f'{self._name}_count {d["c"]}')
        return lines


# Module-level histogram instances — imported by acme_server.py and ocsp_server.py
_hist_issuance = _Histogram(
    "pypki_issuance_duration_seconds",
    "Histogram of certificate issuance duration in seconds",
    labels=("profile", "protocol"),
)
_hist_ocsp = _Histogram(
    "pypki_ocsp_duration_seconds",
    "Histogram of OCSP response generation duration in seconds",
)
_hist_acme_order = _Histogram(
    "pypki_acme_order_duration_seconds",
    "Histogram of ACME order finalization duration in seconds",
    labels=("challenge_type",),
)


# ---------------------------------------------------------------------------
# §5.4 — RA / approval workflow
# ---------------------------------------------------------------------------

def _dns_matches_pattern(name: str, pattern: str) -> bool:
    """Match a DNS name against a glob-style pattern (fnmatch semantics)."""
    return fnmatch.fnmatch(name.lower(), pattern.lower())


class RAPolicy:
    """
    Auto-approval policy engine for the RA workflow.

    Evaluation order (first match wins):
    1. ``auto_approve_all=True`` → always auto-approve.
    2. Profile in ``auto_approve_profiles`` → auto-approve that profile.
    3. JSON policy rules loaded from ``--ra-policy-file``:
       each profile can declare ``auto_approve: true`` or a list of
       ``auto_approve_when`` rules that match on SAN DNS patterns.
    4. Default → require manual review (return None).

    JSON policy file schema::

        {
          "profiles": {
            "tls_server": {
              "auto_approve": false,
              "auto_approve_when": [
                {"san_dns_matches": ["*.cluster.local", "*.svc"]}
              ]
            },
            "default": {"auto_approve": true}
          }
        }
    """

    def __init__(
        self,
        auto_approve_all: bool = True,
        auto_approve_profiles: Optional[List[str]] = None,
        policy_rules: Optional[dict] = None,
    ) -> None:
        self._all = auto_approve_all
        self._profiles: set = set(auto_approve_profiles or [])
        self._rules: dict = policy_rules or {}

    @classmethod
    def from_file(cls, path: str, auto_approve_profiles: Optional[List[str]] = None):
        with open(path) as fh:
            cfg = json.load(fh)
        rules = {}
        for profile, pcfg in cfg.get("profiles", {}).items():
            rules[profile] = {
                "auto_approve": bool(pcfg.get("auto_approve", False)),
                "auto_approve_when": pcfg.get("auto_approve_when", []),
            }
        return cls(
            auto_approve_all=False,
            auto_approve_profiles=auto_approve_profiles,
            policy_rules=rules,
        )

    def should_auto_approve(
        self,
        profile: str,
        san_dns: Optional[List[str]] = None,
        san_ips: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Return a reason string if the request should be auto-approved, else None."""
        if self._all:
            return "auto_approve_all"
        if profile in self._profiles:
            return f"profile '{profile}' in auto-approve list"
        pcfg = self._rules.get(profile, {})
        if pcfg.get("auto_approve"):
            return f"policy: profile '{profile}' auto_approve=true"
        for rule in pcfg.get("auto_approve_when", []):
            patterns = rule.get("san_dns_matches", [])
            for dns in (san_dns or []):
                for pat in patterns:
                    if _dns_matches_pattern(dns, pat):
                        return f"SAN '{dns}' matches pattern '{pat}'"
        return None


class RAWorkflow:
    """
    Registration Authority workflow — submit, approve, and deny certificate requests.

    Backed by the ``pending_requests`` table in the PKI DB.
    Created by ``CertificateAuthority`` when RA is configured; exposed as
    ``ca.ra`` so REST and protocol handlers can call ``ca.ra.submit()``.
    """

    def __init__(self, db: "Database", ca: "CertificateAuthority", policy: RAPolicy) -> None:
        self._db = db
        self._ca = ca
        self._policy = policy

    # ------------------------------------------------------------------
    # Submit a new request
    # ------------------------------------------------------------------

    def submit(
        self,
        protocol: str,
        profile: str,
        subject_dn: str,
        public_key_der: bytes,
        san_dns: Optional[List[str]] = None,
        san_ips: Optional[List[str]] = None,
        san_emails: Optional[List[str]] = None,
        san_uris: Optional[List[str]] = None,
        csr_der: Optional[bytes] = None,
        validity_days: Optional[int] = None,
        requester_ip: str = "",
        protocol_ref: str = "",
        audit: Optional["AuditLog"] = None,
    ) -> tuple:
        """
        Record a certificate request and evaluate auto-approval policy.

        Returns ``(request_id, auto_approved, cert_or_None)``.
        When ``auto_approved`` is True the cert has already been issued and
        ``cert_or_None`` is the ``x509.Certificate``.  When False the request
        is pending and the caller should return an appropriate waiting response.
        """
        request_id = str(uuid.uuid4())
        now = int(time.time())
        self._db.execute(
            "INSERT INTO pending_requests "
            "(request_id, protocol, profile, subject_dn, "
            " san_dns, san_ips, san_emails, san_uris, "
            " public_key_der, csr_der, validity_days, "
            " requester_ip, status, created_at, protocol_ref) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                request_id, protocol, profile, subject_dn,
                json.dumps(san_dns) if san_dns else None,
                json.dumps(san_ips) if san_ips else None,
                json.dumps(san_emails) if san_emails else None,
                json.dumps(san_uris) if san_uris else None,
                public_key_der, csr_der, validity_days,
                requester_ip, "pending", now, protocol_ref,
            ),
        )

        auto_reason = self._policy.should_auto_approve(profile, san_dns, san_ips)
        if auto_reason:
            cert = self._issue_and_finalize(
                request_id, auto_reason, approver=None, audit=audit,
                requester_ip=requester_ip,
            )
            return request_id, True, cert

        if audit:
            audit.record("ra_pending",
                         f"request_id={request_id} protocol={protocol} "
                         f"profile={profile} subject='{subject_dn}'",
                         requester_ip)
        return request_id, False, None

    # ------------------------------------------------------------------
    # Approve / deny
    # ------------------------------------------------------------------

    def approve(
        self,
        request_id: str,
        approver: str = "admin",
        audit: Optional["AuditLog"] = None,
        requester_ip: str = "",
    ) -> Optional["x509.Certificate"]:
        """
        Approve a pending request.  Issues the certificate immediately and
        marks the request as 'issued'.  Returns the issued cert or None if
        the request_id was not found / not pending.
        """
        row = self._db.fetchone(
            "SELECT * FROM pending_requests WHERE request_id=? AND status='pending'",
            (request_id,),
        )
        if not row:
            return None
        return self._issue_and_finalize(
            request_id, None, approver=approver, audit=audit, requester_ip=requester_ip,
        )

    def deny(
        self,
        request_id: str,
        reason: str = "",
        approver: str = "admin",
        audit: Optional["AuditLog"] = None,
        requester_ip: str = "",
    ) -> bool:
        """
        Deny a pending request.  Returns True if the request was found and
        updated, False if it didn't exist or was already decided.
        """
        row = self._db.fetchone(
            "SELECT request_id FROM pending_requests WHERE request_id=? AND status='pending'",
            (request_id,),
        )
        if not row:
            return False
        self._db.execute(
            "UPDATE pending_requests "
            "SET status='denied', approver=?, deny_reason=?, decided_at=? "
            "WHERE request_id=?",
            (approver, reason, int(time.time()), request_id),
        )
        if audit:
            audit.record("ra_denied",
                         f"request_id={request_id} approver={approver} reason='{reason}'",
                         requester_ip)
        return True

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get(self, request_id: str) -> Optional[dict]:
        row = self._db.fetchone(
            "SELECT * FROM pending_requests WHERE request_id=?", (request_id,)
        )
        return self._row_to_dict(row) if row else None

    def list_pending(self) -> List[dict]:
        rows = self._db.fetchall(
            "SELECT * FROM pending_requests WHERE status='pending' ORDER BY created_at"
        )
        return [self._row_to_dict(r) for r in rows]

    def list_recent(self, limit: int = 100) -> List[dict]:
        rows = self._db.fetchall(
            "SELECT * FROM pending_requests ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        return [self._row_to_dict(r) for r in rows]

    def get_by_protocol_ref(self, protocol_ref: str) -> Optional[dict]:
        row = self._db.fetchone(
            "SELECT * FROM pending_requests WHERE protocol_ref=? ORDER BY created_at DESC LIMIT 1",
            (protocol_ref,),
        )
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _issue_and_finalize(
        self,
        request_id: str,
        auto_reason: Optional[str],
        approver: Optional[str],
        audit: Optional["AuditLog"],
        requester_ip: str = "",
    ) -> "x509.Certificate":
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        row = self._db.fetchone(
            "SELECT * FROM pending_requests WHERE request_id=?", (request_id,)
        )
        pub_key = load_der_public_key(bytes(row["public_key_der"]))
        san_dns = json.loads(row["san_dns"]) if row["san_dns"] else None
        san_ips = json.loads(row["san_ips"]) if row["san_ips"] else None
        san_emails = json.loads(row["san_emails"]) if row["san_emails"] else None
        san_uris = json.loads(row["san_uris"]) if row["san_uris"] else None

        cert = self._ca.issue_certificate(
            subject_str=row["subject_dn"],
            public_key=pub_key,
            profile=row["profile"],
            san_dns=san_dns,
            san_ips=san_ips,
            san_emails=san_emails,
            san_uris=san_uris,
            validity_days=row["validity_days"],
            audit=audit,
            requester_ip=requester_ip,
            protocol=f"ra-{row['protocol']}",
        )
        cert_der = cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)

        self._db.execute(
            "UPDATE pending_requests "
            "SET status='issued', cert_der=?, decided_at=?, approver=?, auto_approval_reason=? "
            "WHERE request_id=?",
            (cert_der, int(time.time()), approver, auto_reason, request_id),
        )
        if audit:
            event = "ra_auto_approved" if auto_reason else "ra_approved"
            audit.record(
                event,
                f"request_id={request_id} serial={cert.serial_number} "
                f"subject='{row['subject_dn']}' approver={approver!r} "
                f"reason={auto_reason or 'manual'}",
                requester_ip,
            )
        return cert

    @staticmethod
    def _row_to_dict(row) -> dict:
        d = dict(row)
        for col in ("san_dns", "san_ips", "san_emails", "san_uris"):
            if d.get(col):
                d[col] = json.loads(d[col])
        # Strip binary blobs from the API representation
        d.pop("public_key_der", None)
        d.pop("csr_der", None)
        d.pop("cert_der", None)
        return d


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


# ---------------------------------------------------------------------------
# RFC 7468 — Textual Encodings of PKIX, PKCS, and CMS Structures
# ---------------------------------------------------------------------------

# Labels we accept from external PEM bundles (chain imports, PKCS#7 imports,
# CRL imports). Anything outside this set fails fast.
_RFC7468_DEFAULT_LABELS = frozenset({"CERTIFICATE", "X509 CRL", "PKCS7"})

_RFC7468_BEGIN_RE = re.compile(r"-----BEGIN ([A-Z][A-Z0-9 ]*)-----")
# Case-insensitive scan over every marker-looking sequence; any keyword
# that is not exactly "BEGIN"/"END" or any label that is not uppercase
# fails the strict-case check.
_RFC7468_ANY_MARKER_RE = re.compile(
    r"-----(BEGIN|END)\s+([A-Za-z0-9 ]+?)-----", re.IGNORECASE,
)
_RFC7468_B64_BODY_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def _parse_pem_bundle(
    data,
    allowed_labels=None,
):
    """
    Tokenize a PEM bundle into ``[(label, der_bytes), ...]`` per RFC 7468.

    Strict mode — fails on any deviation from RFC 7468 §3:

      * Boundary markers must be uppercase ASCII (``-----BEGIN <LABEL>-----``,
        ``-----END <LABEL>-----``). Lowercase or mixed-case is rejected.
      * The BEGIN label must equal the matching END label.
      * Only whitespace is permitted outside encapsulation boundaries
        (no explanatory text between or after blocks).
      * The base64 body must use the standard alphabet (``A–Za–z0–9+/`` with
        at most two trailing ``=`` padding chars) and must decode cleanly.

    Both canonical (64-column wrapped) and unwrapped base64 are accepted —
    RFC 7468 §3 explicitly permits either as long as the alphabet is valid.

    Args:
      data: PEM bundle as ``bytes`` or ``str``.
      allowed_labels: optional iterable of permitted labels. When supplied,
        any block whose label is not in the set raises ``ValueError``.
        Defaults to ``None`` (any well-formed label is accepted). For chain
        and CRL imports, pass ``_RFC7468_DEFAULT_LABELS``.

    Returns:
      List of ``(label, der_bytes)`` tuples in file order.

    Raises:
      ValueError: on any framing, alphabet, or label deviation.
    """
    if isinstance(data, bytes):
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"RFC 7468: PEM data contains non-ASCII bytes ({exc})"
            ) from exc
    else:
        text = data

    for m in _RFC7468_ANY_MARKER_RE.finditer(text):
        keyword = m.group(1)
        label = m.group(2)
        if keyword not in ("BEGIN", "END") or label != label.upper():
            raise ValueError(
                "RFC 7468: PEM boundary markers must be uppercase "
                f"(saw '-----{keyword} {label}-----')"
            )

    allowed = frozenset(allowed_labels) if allowed_labels is not None else None

    pos = 0
    blocks = []
    while True:
        m = _RFC7468_BEGIN_RE.search(text, pos)
        if m is None:
            tail = text[pos:]
            if tail.strip():
                raise ValueError(
                    "RFC 7468: trailing non-whitespace data after PEM blocks: "
                    f"{tail.strip()[:60]!r}"
                )
            return blocks

        between = text[pos:m.start()]
        if between.strip():
            raise ValueError(
                "RFC 7468: non-whitespace text outside PEM blocks: "
                f"{between.strip()[:60]!r}"
            )

        label = m.group(1)
        end_marker = f"-----END {label}-----"
        end_idx = text.find(end_marker, m.end())
        if end_idx < 0:
            # If an END marker for a different label appears before the
            # matching one, that's a label mismatch — surface it cleanly.
            stray = re.search(r"-----END ([A-Z][A-Z0-9 ]*)-----", text[m.end():])
            if stray is not None:
                raise ValueError(
                    f"RFC 7468: label mismatch — BEGIN {label!r} "
                    f"vs END {stray.group(1)!r}"
                )
            raise ValueError(
                f"RFC 7468: missing matching END marker for label {label!r}"
            )

        body = text[m.end():end_idx]
        b64 = "".join(body.split())
        if not b64:
            raise ValueError(
                f"RFC 7468: empty body in PEM block {label!r}"
            )
        if not _RFC7468_B64_BODY_RE.fullmatch(b64):
            raise ValueError(
                f"RFC 7468: invalid base64 alphabet in PEM block {label!r}"
            )
        try:
            der = base64.b64decode(b64, validate=True)
        except Exception as exc:
            raise ValueError(
                f"RFC 7468: base64 decode failed for label {label!r}: {exc}"
            ) from exc

        if allowed is not None and label not in allowed:
            raise ValueError(
                f"RFC 7468: PEM label {label!r} is not permitted here "
                f"(allowed: {sorted(allowed)!r})"
            )

        blocks.append((label, der))
        pos = end_idx + len(end_marker)


# ---------------------------------------------------------------------------
# Multi-algorithm CA support — RFC 4055 (RSA-PSS), RFC 5480 + 5758 (ECDSA),
# RFC 8410 (Ed25519/Ed448)
# ---------------------------------------------------------------------------

# Map curve type to its companion hash per RFC 5758 §3.2.
# This is the "matched curve" guidance: SHA-256 for P-256, SHA-384 for P-384,
# SHA-512 for P-521. The cryptography library encodes the right
# ecdsa-with-SHAxxx OID into the signatureAlgorithm field automatically.
_ECDSA_CURVE_TO_HASH = {
    ec.SECP256R1: SHA256,
    ec.SECP384R1: SHA384,
    ec.SECP521R1: SHA512,
}


def _hash_for_key(key):
    """
    Return the hash class appropriate for signing with *key*, or ``None``
    for EdDSA (Ed25519 / Ed448 sign internally without an external hash).

    Raises ``TypeError`` for unsupported key types.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        return SHA256
    if isinstance(key, ec.EllipticCurvePrivateKey):
        for curve_cls, hash_cls in _ECDSA_CURVE_TO_HASH.items():
            if isinstance(key.curve, curve_cls):
                return hash_cls
        # Unknown curve — fall back to SHA-256 but the library may reject
        return SHA256
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None
    raise TypeError(f"Unsupported private-key type for signing: {type(key).__name__}")


def _sign_builder(builder, key, *, rsa_pss: bool = False):
    """
    Sign an X.509 builder with the correct (hash, padding) for the key type.

    Supports:
      * RSA — defaults to PKCS#1 v1.5 (RFC 8017). Pass ``rsa_pss=True`` to
        sign with RSASSA-PSS (RFC 4055), MGF1+SHA-256, salt length 32.
      * ECDSA — matched-curve hash per RFC 5758 §3.2 (P-256/SHA-256,
        P-384/SHA-384, P-521/SHA-512). The cryptography library writes
        the right ecdsa-with-SHAxxx OID into ``signatureAlgorithm``.
      * Ed25519 / Ed448 — no external hash (RFC 8032 / RFC 8410).

    ``builder`` may be any of ``CertificateBuilder``,
    ``CertificateRevocationListBuilder``, etc.; they share the same
    ``sign(key, algorithm[, rsa_padding=...])`` shape.
    """
    hash_cls = _hash_for_key(key)
    algorithm = hash_cls() if hash_cls is not None else None
    if isinstance(key, rsa.RSAPrivateKey) and rsa_pss:
        pss = padding.PSS(
            mgf=padding.MGF1(hash_cls()),
            salt_length=hash_cls.digest_size,
        )
        return builder.sign(key, algorithm, rsa_padding=pss)
    return builder.sign(key, algorithm)


def _sign_data(key, data: bytes, *, rsa_pss: bool = False) -> bytes:
    """
    Sign raw bytes with the correct (padding, hash) for the key type.

    Used by CMS-building code (SCEP, CMP protection) where the signature
    is computed over canonical ASN.1 bytes rather than a builder object.

    Returns the raw signature bytes. For Ed25519/Ed448 callers, the SCEP /
    CMS protocols cannot accept the signature directly (CMS requires a
    named digest algorithm); callers that rely on CMS MUST gate on
    :func:`_eddsa_compatible_with_cms` first.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        if rsa_pss:
            return key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(SHA256()),
                    salt_length=SHA256.digest_size,
                ),
                SHA256(),
            )
        return key.sign(data, padding.PKCS1v15(), SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        hash_cls = _hash_for_key(key)
        return key.sign(data, ec.ECDSA(hash_cls()))
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return key.sign(data)
    raise TypeError(f"Unsupported private-key type for signing: {type(key).__name__}")


# CA key-type catalog. Maps the operator-facing CLI string to a generator
# closure. Default remains RSA-4096 to preserve out-of-the-box behaviour.
_CA_KEY_FACTORIES = {
    "rsa-2048":  lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "rsa-3072":  lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072),
    "rsa-4096":  lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096),
    "ec-p256":   lambda: ec.generate_private_key(ec.SECP256R1()),
    "ec-p384":   lambda: ec.generate_private_key(ec.SECP384R1()),
    "ec-p521":   lambda: ec.generate_private_key(ec.SECP521R1()),
    "ed25519":   lambda: ed25519.Ed25519PrivateKey.generate(),
    "ed448":     lambda: ed448.Ed448PrivateKey.generate(),
}


def _generate_ca_key(key_type: str):
    """
    Generate a CA private key for the given catalog name.

    Raises ``ValueError`` for unknown types — surfaced cleanly to the
    operator at startup, before the CA dir is touched.
    """
    factory = _CA_KEY_FACTORIES.get(key_type)
    if factory is None:
        raise ValueError(
            f"Unsupported --ca-key-type {key_type!r}; "
            f"valid choices: {sorted(_CA_KEY_FACTORIES)}"
        )
    return factory()


def _eddsa_compatible_with_cms(key) -> bool:
    """
    Return False when *key* cannot be used to sign CMS SignedData (RFC 5652).

    CMS requires a named digest algorithm in ``SignerInfo`` (``digestAlgorithm``
    + ``signatureAlgorithm``); Ed25519 / Ed448 sign their input internally
    and have no separate hash to advertise, so SCEP (which is CMS-based)
    cannot interoperate with EdDSA CAs.
    """
    return not isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))


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
        """Merge: defaults ← CLI overrides ← file / in-memory edits.
        _data (loaded from file + live PATCH calls) wins over _cli so that
        the Config-UI PATCH endpoint can persistently override CLI defaults."""
        import copy
        result = copy.deepcopy(DEFAULT_CONFIG)
        self._deep_merge(result, self._cli)
        self._deep_merge(result, self._data)
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
    Structured audit log stored via the DAL (db.py).

    Every certificate issuance, revocation, auth event and config change
    is recorded. Backend selection is per-instance via ``db_url``; default
    is SQLite at ``<ca_dir>/audit.db`` for full backward compatibility.

    For multi-node deployments, pass an explicit ``db_url`` pointing at
    Postgres so all nodes write to the same audit log.

    Public surface preserved against the previous inline-sqlite3 version:
        - record(event, detail="", ip="")     — append a row + emit log line
        - recent(n=100)                       — list of {timestamp,event,detail,ip}

    Note on timestamps: the ``ts`` column remains a TEXT ISO-8601 string
    matching the legacy schema. CLAUDE.md's INTEGER unix-seconds direction
    applies to future tables and to a future modernization migration on
    this one — this wiring is behavior-preserving.
    """

    def __init__(self, ca_dir: Path, db_url: Optional[str] = None):
        from db import make_db
        from migrations import MigrationRunner

        # Default URL preserves the historical file location.
        if db_url is None:
            db_url = f"sqlite:///{ca_dir / 'audit.db'}"
        self._db_url = db_url
        self._db = make_db(db_url)

        # Apply pending migrations. Locating the migration directory:
        # use the one shipped alongside this module. Tests override by
        # constructing AuditLog with their own db_url against a pre-migrated
        # database, or by setting the env var below.
        import os
        mig_root = os.environ.get(
            "PYPKI_MIGRATIONS_ROOT",
            str(Path(__file__).resolve().parent / "db_migrations"),
        )
        runner = MigrationRunner(
            self._db,
            Path(mig_root) / "audit",
            namespace="audit",
        )
        runner.apply_pending()

    def record(self, event: str, detail: str = "", ip: str = "") -> None:
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._db.execute(
            "INSERT INTO audit(ts, event, detail, ip) VALUES (?, ?, ?, ?)",
            (ts, event, detail, ip),
        )
        logger.info(f"AUDIT [{event}] {detail}")

    def recent(self, n: int = 100) -> List[Dict[str, Any]]:
        rows = self._db.fetchall(
            "SELECT ts AS timestamp, event, detail, ip "
            "FROM audit ORDER BY id DESC LIMIT ?",
            (n,),
        )
        # Row is a dict subclass; dict(r) yields the plain shape callers expect.
        return [dict(r) for r in rows]

    def close(self) -> None:
        """Release DB resources. Idempotent. Safe to call from shutdown hooks."""
        try:
            self._db.close()
        except Exception:
            logger.exception("AuditLog: error closing db")


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
        # RFC 3161 §2.3: id-kp-timeStamping EKU MUST be critical; cert MUST
        # contain only this EKU.  eku_critical=True triggers critical=True below.
        "tsa_signing": {
            "key_usage": dict(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False),
            "eku": [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.8")],  # id-kp-timeStamping
            "eku_critical": True,  # RFC 3161 §2.3 MUST
            "san_required": False,
            "bc_ca": False,
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
                 parent_chain_path: Optional[str] = None,
                 ca_key_type: str = "rsa-4096",
                 sig_algorithm: str = "rsa-pkcs1v15",
                 pki_db_url: str = "",
                 hsm_cfg=None):
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
        ca_key_type       : Key algorithm for first-run CA bootstrap. One of
                            ``rsa-2048``/``rsa-3072``/``rsa-4096`` (default),
                            ``ec-p256``/``ec-p384``/``ec-p521`` (RFC 5480),
                            ``ed25519``/``ed448`` (RFC 8410). Ignored once
                            ``ca.key`` exists on disk.
        sig_algorithm     : Signature padding for RSA CA keys — one of
                            ``rsa-pkcs1v15`` (default) or ``rsa-pss`` (RFC 4055).
                            No-op for ECDSA / EdDSA keys.
        pki_db_url        : Database URL for the PKI certificate store.
                            Defaults to ``sqlite:///<ca_dir>/certificates.db``.
                            Use ``postgresql://user:pass@host/db`` for HA deployments.
        hsm_cfg           : Optional HSMConfig for PKCS#11 / HSM key backing (§5.1).
                            When set, the CA signing key is loaded from the HSM
                            token instead of ca.key on disk. The public cert is
                            still stored in ca.crt.
        """
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.ca_dir / "certificates.db"
        # §5.2 — Database Abstraction Layer (SQLite default; Postgres via --pki-db-url)
        _pki_url = pki_db_url or f"sqlite:///{self.db_path}"
        self._pki_db: Database = make_db(_pki_url)
        self.config  = config  # may be None (uses hardcoded defaults as fallback)
        self._ocsp_url = ocsp_url   # embedded in every issued cert AIA extension
        self._crl_url  = crl_url    # embedded in every issued cert CDP extension
        self._ca_key_type = ca_key_type
        # Normalize the signature-algorithm choice once at init so every
        # _sign_builder call can read self._rsa_pss as a plain bool.
        if sig_algorithm not in ("rsa-pkcs1v15", "rsa-pss"):
            raise ValueError(
                f"Unsupported sig_algorithm {sig_algorithm!r}; "
                "valid: rsa-pkcs1v15, rsa-pss"
            )
        self._sig_algorithm = sig_algorithm
        self._rsa_pss = (sig_algorithm == "rsa-pss")
        # §5.1 — optional PKCS#11 HSM config; None = file-backed key (default)
        self._hsm_cfg = hsm_cfg
        # RFC 7292 hardening: reject unencrypted PKCS#12 export unless explicitly allowed.
        # Set to True via --p12-allow-unencrypted CLI flag.
        self._p12_allow_unencrypted: bool = False
        # RFC 6962 CT configuration: populated by CLI flags --ct-log-url /
        # --ct-log-pubkey / --ct-require-n.  Empty by default (CT opt-in).
        self._ct_log_urls: List[str] = []
        self._ct_log_pubkeys: List[bytes] = []   # PEM-encoded ECDSA pubkeys, aligned to _ct_log_urls
        self._ct_require_n: int = 0              # min SCTs required; 0 = best-effort
        # §5.9 — Lifecycle webhooks: set by main() after CLI arg parsing.
        self._webhook: Optional["_hooks_module.WebhookDispatcher"] = None  # type: ignore[name-defined]
        # §5.4 — RA workflow: set by configure_ra() after CLI arg parsing;
        # defaults to auto-approve-all (backwards-compatible behaviour).
        self.ra: Optional[RAWorkflow] = None
        self._init_db()
        self._load_or_create_ca()
        self._load_parent_chain(parent_chain_path)

    def configure_ra(self, policy: RAPolicy) -> None:
        """Attach an RAWorkflow to this CA with the given approval policy."""
        self.ra = RAWorkflow(self._pki_db, self, policy)

    def _init_db(self):
        # Bootstrap the core schema directly via the DAL (idempotent).
        self._pki_db.execute("""
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
        self._pki_db.execute("""
            CREATE TABLE IF NOT EXISTS serial_counter (
                id    INTEGER PRIMARY KEY,
                value INTEGER NOT NULL
            )
        """)
        self._pki_db.execute("""
            CREATE TABLE IF NOT EXISTS crl_base (
                id          INTEGER PRIMARY KEY,
                issued_at   TEXT NOT NULL,
                this_update TEXT NOT NULL,
                next_update TEXT NOT NULL,
                der         BLOB NOT NULL
            )
        """)
        self._pki_db.execute("INSERT OR IGNORE INTO serial_counter VALUES (1, 1000)")
        # Migrate: add profile column if missing (for existing DBs)
        try:
            self._pki_db.execute(
                "ALTER TABLE certificates ADD COLUMN profile TEXT DEFAULT 'default'"
            )
        except Exception:
            pass

        # Apply pending pki-namespace migrations (versioned schema files
        # under db_migrations/pki/). The 001 file is a no-op against an
        # existing DB because all CREATE TABLEs use IF NOT EXISTS;
        # subsequent migrations (e.g. 002_crl_number.sql for RFC 5280
        # §5.2.3 compliance) are applied here.
        try:
            from migrations import MigrationRunner
            mig_root = os.environ.get(
                "PYPKI_MIGRATIONS_ROOT",
                str(Path(__file__).resolve().parent / "db_migrations"),
            )
            mig_dir = Path(mig_root) / "pki"
            if mig_dir.is_dir():
                MigrationRunner(self._pki_db, mig_dir, namespace="pki").apply_pending()
        except Exception as e:
            logger.warning(f"pki-namespace migrations skipped: {e}")

    def _next_serial(self) -> int:
        with self._pki_db.advisory_lock("serial-allocation"):
            row = self._pki_db.fetchone("SELECT value FROM serial_counter WHERE id=1")
            serial = row[0]
            self._pki_db.execute(
                "UPDATE serial_counter SET value=? WHERE id=1", (serial + 1,)
            )
        return serial

    def _next_crl_number(self) -> int:
        """
        Atomically allocate the next CRL number (RFC 5280 §5.2.3).

        Both base and delta CRLs share this counter. advisory_lock serializes
        concurrent CRL generation across all processes/nodes so the same number
        is never assigned twice. Falls back to 1 if the table is missing.
        """
        try:
            with self._pki_db.advisory_lock("crl-allocation"):
                row = self._pki_db.fetchone("SELECT value FROM crl_number WHERE id=1")
                if row is None:
                    self._pki_db.execute(
                        "INSERT OR IGNORE INTO crl_number(id, value) VALUES (1, 0)"
                    )
                    current = 0
                else:
                    current = row[0]
                next_num = current + 1
                self._pki_db.execute(
                    "UPDATE crl_number SET value=? WHERE id=1", (next_num,)
                )
            return next_num
        except Exception as e:
            logger.warning(
                f"crl_number table missing; CRL will use number 1 "
                f"(reapply migrations to fix): {e}"
            )
            return 1

    def _cfg(self, attr: str, default: int) -> int:
        """Read a validity value from config, falling back to default."""
        if self.config:
            return getattr(self.config, attr, default)
        return default

    def _load_or_create_ca(self):
        ca_key_path = self.ca_dir / "ca.key"
        ca_cert_path = self.ca_dir / "ca.crt"

        if self._hsm_cfg is not None:
            self._load_or_create_ca_hsm(ca_cert_path)
            return

        if ca_key_path.exists() and ca_cert_path.exists():
            logger.info("Loading existing CA key and certificate.")
            with open(ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
        else:
            logger.info(
                "Generating new CA key (%s) and self-signed certificate...",
                self._ca_key_type,
            )
            self.ca_key = _generate_ca_key(self._ca_key_type)

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyPKI CMPv2"),
                x509.NameAttribute(NameOID.COMMON_NAME, "PyPKI Root CA"),
            ])

            now = datetime.datetime.now(datetime.timezone.utc)
            ca_days = self._cfg("ca_days", 3650)
            builder = (
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
            )
            self.ca_cert = _sign_builder(builder, self.ca_key, rsa_pss=self._rsa_pss)

            # RFC 5958: persist as PKCS#8 PrivateKeyInfo so EC / EdDSA keys
            # also round-trip cleanly. RSA keys remain readable everywhere.
            with open(ca_key_path, "wb") as f:
                f.write(self.ca_key.private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption(),
                ))
            with open(ca_cert_path, "wb") as f:
                f.write(self.ca_cert.public_bytes(Encoding.PEM))

            logger.info(f"CA certificate written to {ca_cert_path}")

    def _load_or_create_ca_hsm(self, ca_cert_path: Path):
        """
        §5.1 — HSM-backed CA key initialisation.

        The signing key lives on the PKCS#11 token and never touches disk.
        Only the self-signed CA certificate is written to ca.crt on first boot.
        On subsequent boots the cert is read from disk and the key is re-loaded
        from the token.
        """
        from hsm_backend import load_hsm_signing_key

        self.ca_key = load_hsm_signing_key(self._hsm_cfg)

        if ca_cert_path.exists():
            logger.info("Loading existing CA certificate (HSM key mode).")
            with open(ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            return

        logger.info("Generating self-signed CA certificate using HSM key...")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyPKI CMPv2"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PyPKI Root CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_days = self._cfg("ca_days", 3650)
        builder = (
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
        )
        self.ca_cert = _sign_builder(builder, self.ca_key, rsa_pss=self._rsa_pss)
        with open(ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(Encoding.PEM))
        logger.info(f"CA certificate written to {ca_cert_path} (HSM-signed)")

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
        # RFC 7468 strict parse — chain files may carry only CERTIFICATE blocks.
        try:
            blocks = _parse_pem_bundle(pem_data, allowed_labels={"CERTIFICATE"})
        except ValueError as exc:
            raise ValueError(
                f"parent_chain_path '{candidate}': {exc}"
            ) from exc

        if not blocks:
            raise ValueError(
                f"parent_chain_path '{candidate}' contains no PEM certificates."
            )

        for _label, der in blocks:
            cert = x509.load_der_x509_certificate(der)
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
        san_uris: Optional[list] = None,
        profile: str = "default",
        ct_poison: bool = False,
        forced_serial: Optional[int] = None,
        forced_time: Optional[datetime.datetime] = None,
        ocsp_url: Optional[str] = None,
        crl_url: Optional[str] = None,
        no_rev_avail: Optional[bool] = None,
        certificate_policies: Optional[List[dict]] = None,
        audit: Optional["AuditLog"] = None,
        requester_ip: str = "",
        path_length: Optional[int] = None,
        protocol: str = "",
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

        if not attrs and not (san_dns or san_emails or san_ips or san_uris):
            attrs = [x509.NameAttribute(NameOID.COMMON_NAME, subject_str or "PyPKI Entity")]

        subject = x509.Name(attrs)
        serial = forced_serial if forced_serial is not None else self._next_serial()
        now = forced_time if forced_time is not None else datetime.datetime.now(datetime.timezone.utc)
        path_len = (
            path_length if path_length is not None
            else (prof.get("path_length", 0) if is_ca else None)
        )
        if not is_ca:
            path_len = None  # non-CA certs MUST NOT carry a pathLenConstraint

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

        # EKU — RFC 3161 §2.3 requires critical=True for tsa_signing profile
        if prof.get("eku"):
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(prof["eku"]),
                critical=prof.get("eku_critical", False),
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

        # RFC 6962 — CT Pre-certificate Poison extension
        # OID 1.3.6.1.4.1.11129.2.4.3. MUST be critical.
        if ct_poison:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(OID_CT_POISON, b"\x05\x00"), # NULL
                critical=True,
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
        if san_uris:
            for uri in san_uris:
                san_names.append(x509.UniformResourceIdentifier(uri))

        if san_names:
            # RFC 5280 §4.2.1.6: "If the subject field is empty... the
            # subjectAltName extension MUST be present and MUST be marked critical."
            # Also RFC 4945 §5.1.3 for IPsec.
            san_critical = len(list(subject)) == 0
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_names), critical=san_critical
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
        # certificate_policies parameter OR profile default OR deployment-wide
        # default (set via --cps-uri / --cps-policy-oid on the command line,
        # or via 'certificate_policies_default' in config.json).
        pol_list = (
            certificate_policies
            or prof.get("certificate_policies")
            or (self.config.get("certificate_policies_default") if self.config else None)
        )
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
        _t0 = time.perf_counter()
        with _t.start_as_current_span("ca.issue_certificate") as _span:
            _span.set_attribute("cert.serial", serial)
            _span.set_attribute("cert.subject", subject_str)
            _span.set_attribute("cert.profile", profile)
            _span.set_attribute("cert.validity_days", validity_days or 0)
            cert = _sign_builder(builder, self.ca_key, rsa_pss=self._rsa_pss)
        _hist_issuance.observe(time.perf_counter() - _t0, (profile, protocol))

        # Store in DB (including profile)
        self._pki_db.execute(
            "INSERT OR REPLACE INTO certificates"
            "(serial,subject,not_before,not_after,der,revoked,revoked_at,reason,profile) "
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

        if audit:
            audit.record("issue", f"serial={serial} subject='{subject_str}' profile={profile}",
                         requester_ip)

        if self._webhook:
            event = "subca.issued" if profile in ("sub_ca", "cross_signed") else "cert.issued"
            self._webhook.emit(event, {
                "serial": serial,
                "subject": subject_str,
                "profile": profile,
                "not_after": cert.not_valid_after_utc.isoformat(),
                "requester_ip": requester_ip,
            })

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
        row = self._pki_db.fetchone(
            "SELECT serial FROM certificates WHERE serial=? AND revoked=0", (serial,)
        )
        if not row:
            return False
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._pki_db.execute(
            "UPDATE certificates SET revoked=1, revoked_at=?, reason=? WHERE serial=?",
            (now, reason, serial),
        )
        logger.info(f"Revoked certificate serial={serial} reason={reason}")
        if self._webhook:
            self._webhook.emit("cert.revoked", {
                "serial": serial,
                "reason": reason,
            })
        return True

    def generate_crl(self) -> bytes:
        """
        Generate a DER-encoded CRL.

        Per RFC 5280 §5.2.1 + §5.2.3 / RFC 6818, the CRL carries:
          - cRLNumber                 (monotonically increasing serial)
          - authorityKeyIdentifier    (matches the CA cert's SKI)
        Both are non-critical.
        """
        revoked = self._pki_db.fetchall(
            "SELECT serial, revoked_at, reason FROM certificates WHERE revoked=1"
        )
        crl_number = self._next_crl_number()

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(datetime.datetime.now(datetime.timezone.utc))
            .next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            # RFC 5280 §5.2.3 — cRLNumber MUST be present.
            .add_extension(x509.CRLNumber(crl_number), critical=False)
            # RFC 5280 §5.2.1 — authorityKeyIdentifier MUST be present.
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_cert.public_key()
                ),
                critical=False,
            )
        )

        for r in revoked:
            rev_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(r["serial"]))
                .revocation_date(
                    datetime.datetime.fromisoformat(r["revoked_at"])
                    if r["revoked_at"]
                    else datetime.datetime.now(datetime.timezone.utc)
                )
                .build()
            )
            builder = builder.add_revoked_certificate(rev_cert)

        crl = _sign_builder(builder, self.ca_key, rsa_pss=self._rsa_pss)
        return crl.public_bytes(Encoding.DER)

    def get_cert_by_serial(self, serial: int) -> Optional[bytes]:
        row = self._pki_db.fetchone(
            "SELECT der FROM certificates WHERE serial=?", (serial,)
        )
        return row["der"] if row else None

    def list_certificates(self) -> list:
        rows = self._pki_db.fetchall(
            "SELECT serial, subject, not_before, not_after, revoked, profile FROM certificates"
        )
        return [
            {
                "serial": r["serial"],
                "subject": r["subject"],
                "not_before": r["not_before"],
                "not_after": r["not_after"],
                "revoked": bool(r["revoked"]),
                "profile": r["profile"] or "default",
            }
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
            f.write(priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

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

        client_builder = (
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
        )
        cert = _sign_builder(client_builder, self.ca_key, rsa_pss=self._rsa_pss)

        # Persist in DB
        self._pki_db.execute(
            "INSERT INTO certificates VALUES (?,?,?,?,?,0,NULL,NULL)",
            (
                serial, subject_str, now.isoformat(),
                (now + datetime.timedelta(days=validity_days)).isoformat(),
                cert.public_bytes(Encoding.DER),
            ),
        )

        logger.info(f"Issued client certificate serial={serial} CN={common_name}")
        cert_pem = cert.public_bytes(Encoding.PEM)
        key_pem = priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
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
                Encoding.PEM, serialization.PrivateFormat.PKCS8, NoEncryption()
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
        row = self._pki_db.fetchone(
            "SELECT der FROM certificates WHERE serial=?", (serial,)
        )
        if not row:
            return None
        cert = x509.load_der_x509_certificate(row["der"])
        return cert.public_bytes(Encoding.PEM).decode("ascii")

    def generate_crl_der(self) -> bytes:
        """
        Generate and return the current CRL in DER format.

        Per RFC 5280 §5.2.1 + §5.2.3 / RFC 6818 the CRL carries cRLNumber
        and authorityKeyIdentifier extensions.
        """
        crl_number = self._next_crl_number()
        # Build a real CRL from the revoked serials in the DB
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(datetime.datetime.now(datetime.timezone.utc))
            .next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7))
            .add_extension(x509.CRLNumber(crl_number), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_cert.public_key()
                ),
                critical=False,
            )
        )
        rows = self._pki_db.fetchall(
            "SELECT serial, revoked_at FROM certificates WHERE revoked=1"
        )
        for row in rows:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(row["serial"])
                .revocation_date(
                    datetime.datetime.fromisoformat(row["revoked_at"])
                    if row["revoked_at"]
                    else datetime.datetime.now(datetime.timezone.utc)
                )
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)
        crl = _sign_builder(builder, self.ca_key, rsa_pss=self._rsa_pss)
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

        ``path_length`` constrains how many further intermediates may sit
        below the issued sub-CA (RFC 5280 §4.2.1.9):
            0 = issued sub-CA may only sign end-entity certs (default)
            1 = issued sub-CA may sign one further tier (e.g., a service-mesh
                intermediate) which in turn signs end-entity certs
            None = no constraint (not recommended)
        """
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject_str = f"CN={cn},O=PyPKI Subordinate CA"
        cert = self.issue_certificate(
            subject_str=subject_str,
            public_key=priv_key.public_key(),
            validity_days=validity_days,
            is_ca=True,
            profile="sub_ca",
            path_length=path_length,
            audit=audit,
        )
        logger.info(f"Sub-CA issued: CN={cn} serial={cert.serial_number} path_length={path_length}")
        return priv_key, cert

    # ------------------------------------------------------------------
    # Cross-signing (§5.6)
    # ------------------------------------------------------------------

    def cross_sign(
        self,
        other_cert: x509.Certificate,
        validity_days: int,
        audit: Optional["AuditLog"] = None,
        requester_ip: str = "",
    ) -> x509.Certificate:
        """
        Cross-sign an existing certificate: same subject + same SPKI, signed by this CA.

        The resulting certificate has a fresh serial number, new validity window,
        and is signed by this CA's key. The source certificate is unmodified.
        Trust anchors on both old and new CA can verify each other's intermediates.

        Useful for CA algorithm migrations (RSA → ECC → ML-DSA): clients that
        only trust the old root can still follow the old-signed copy while clients
        that have the new root prefer the new-signed copy.

        Extensions copied from source: BasicConstraints, KeyUsage, SubjectAlternativeName.
        Extensions generated fresh: SKI, AKI (from this CA's key), AIA, CDP.
        ExtendedKeyUsage is intentionally NOT copied for EE certs — cross-signing
        an EE cert is unusual; CA profile extensions are carried as-is.
        """
        from cryptography.hazmat.primitives import hashes as _hashes
        public_key = other_cert.public_key()
        subject = other_cert.subject
        serial = self._next_serial()
        now = datetime.datetime.now(datetime.timezone.utc)
        subject_str = subject.rfc4514_string()

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False,
            )
        )

        # Copy structural extensions verbatim from the source cert
        for ext_cls in (x509.BasicConstraints, x509.KeyUsage, x509.SubjectAlternativeName):
            try:
                ext = other_cert.extensions.get_extension_for_class(ext_cls)
                builder = builder.add_extension(ext.value, critical=ext.critical)
            except x509.ExtensionNotFound:
                if ext_cls is x509.BasicConstraints:
                    # BasicConstraints is required; default to non-CA EE cert
                    builder = builder.add_extension(
                        x509.BasicConstraints(ca=False, path_length=None), critical=True
                    )

        # AIA (OCSP) from this CA's configuration
        if self._ocsp_url:
            builder = builder.add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(self._ocsp_url),
                    )
                ]),
                critical=False,
            )

        # CDP from this CA's configuration
        if self._crl_url:
            builder = builder.add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(self._crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]),
                critical=False,
            )

        cert = _sign_builder(builder, self.ca_key, rsa_pss=self._rsa_pss)

        # Store in DB
        self._pki_db.execute(
            "INSERT OR REPLACE INTO certificates"
            "(serial,subject,not_before,not_after,der,revoked,revoked_at,reason,profile) "
            "VALUES(?,?,?,?,?,0,NULL,NULL,?)",
            (
                serial,
                subject_str,
                now.isoformat(),
                (now + datetime.timedelta(days=validity_days)).isoformat(),
                cert.public_bytes(Encoding.DER),
                "cross_signed",
            ),
        )

        src_fp = other_cert.fingerprint(_hashes.SHA256()).hex()
        dst_fp = cert.fingerprint(_hashes.SHA256()).hex()

        if audit:
            audit.record(
                "cross_sign",
                f"serial={serial} subject='{subject_str}' "
                f"src_fp={src_fp[:16]} dst_fp={dst_fp[:16]}",
                requester_ip,
            )

        logger.info(
            f"Cross-signed cert serial={serial} subject='{subject_str}' "
            f"src_fp={src_fp[:16]} dst_fp={dst_fp[:16]}"
        )
        if self._webhook:
            self._webhook.emit("cross.signed", {
                "serial": serial,
                "subject": subject_str,
                "src_fingerprint": src_fp[:16],
                "dst_fingerprint": dst_fp[:16],
                "requester_ip": requester_ip,
            })
        return cert

    # ------------------------------------------------------------------
    # PKCS#12 export (cert + CA chain, no private key stored server-side)
    # ------------------------------------------------------------------

    def export_pkcs12(self, serial: int, password: Optional[bytes] = None) -> Optional[bytes]:
        """
        Return a PKCS#12 bundle containing the certificate + CA chain.
        Private key is NOT included (it is never stored server-side).

        RFC 7292 hardening: unencrypted (passwordless) export is rejected unless
        ``self._p12_allow_unencrypted`` is True (set via --p12-allow-unencrypted).
        """
        der = self.get_cert_by_serial(serial)
        if not der:
            return None
        if password is None and not self._p12_allow_unencrypted:
            raise ValueError(
                "Unencrypted PKCS#12 export is disabled (RFC 7292 hardening). "
                "Provide a password or start the server with --p12-allow-unencrypted."
            )
        cert = x509.load_der_x509_certificate(der)
        enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()

        # RFC 7292: set friendlyName attribute for better UX in OS key stores
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            friendly_name = cn_attrs[0].value.encode() if cn_attrs else f"cert-{serial}".encode()
        except Exception:
            friendly_name = f"cert-{serial}".encode()

        # Include the full CA chain in the PKCS#12 CA bag so that importing
        # applications (browsers, OS key stores) can build the complete path.
        ca_bag = [self.ca_cert] + list(self._parent_chain)
        p12 = pkcs12.serialize_key_and_certificates(
            name=friendly_name,
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
        # Fetch the timestamp of the last base CRL
        base_row = self._pki_db.fetchone(
            "SELECT issued_at, this_update FROM crl_base ORDER BY id DESC LIMIT 1"
        )
        base_issued_at = base_row["issued_at"] if base_row else "1970-01-01T00:00:00"

        # Only revocations AFTER the last base
        rows = self._pki_db.fetchall(
            "SELECT serial, revoked_at, reason FROM certificates "
            "WHERE revoked=1 AND revoked_at > ?",
            (base_issued_at,)
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        next_update = now + datetime.timedelta(hours=6)
        crl_number = self._next_crl_number()

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(now)
            .next_update(next_update)
            # RFC 5280 §5.2.3 — cRLNumber. For a delta CRL this MUST be
            # greater than the cRLNumber of the base CRL it supplements;
            # the monotonic counter trivially satisfies that.
            .add_extension(x509.CRLNumber(crl_number), critical=False)
            # RFC 5280 §5.2.1 — authorityKeyIdentifier.
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_cert.public_key()
                ),
                critical=False,
            )
            # RFC 5280 §5.2.4 — deltaCRLIndicator points at the base.
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

        crl = _sign_builder(builder, self.ca_key, rsa_pss=self._rsa_pss)
        delta_der = crl.public_bytes(Encoding.DER)

        # Store current full-CRL as new base
        full_crl_der = self.generate_crl()
        self._pki_db.execute(
            "INSERT INTO crl_base(issued_at, this_update, next_update, der) VALUES(?,?,?,?)",
            (now.isoformat(), now.isoformat(), next_update.isoformat(), full_crl_der)
        )

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
        self._pki_db.execute("""
            CREATE TABLE IF NOT EXISTS key_archive (
                serial      INTEGER PRIMARY KEY,
                archived_at TEXT NOT NULL,
                encrypted   BLOB NOT NULL,
                subject     TEXT NOT NULL
            )
        """)

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
        row = self._pki_db.fetchone(
            "SELECT subject FROM certificates WHERE serial=?", (serial,)
        )
        subject = row["subject"] if row else "unknown"
        self._pki_db.execute(
            "INSERT OR REPLACE INTO key_archive(serial,archived_at,encrypted,subject) VALUES(?,?,?,?)",
            (serial, now, payload, subject)
        )
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
        row = self._pki_db.fetchone(
            "SELECT encrypted FROM key_archive WHERE serial=?", (serial,)
        )
        if not row:
            return None
        payload = row["encrypted"]
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
        return _sign_builder(nc_cert, self.ca_key, rsa_pss=self._rsa_pss)

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
        rows = self._pki_db.fetchall(
            "SELECT serial, subject, not_after, profile FROM certificates "
            "WHERE revoked=0 ORDER BY not_after ASC"
        )

        result = []
        for r in rows:
            try:
                not_after = datetime.datetime.fromisoformat(r["not_after"])
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                continue
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < not_after <= cutoff:
                days_remaining = (not_after - now).days
                result.append({
                    "serial": r["serial"],
                    "subject": r["subject"],
                    "not_after": not_after.isoformat(),
                    "profile": r["profile"] or "default",
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
                            if self._webhook:
                                self._webhook.emit("cert.expiring", dict(info))
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
        row = self._pki_db.fetchone(
            "SELECT profile FROM certificates WHERE serial=?", (serial,)
        )
        profile = row["profile"] if row and row["profile"] else "default"

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
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cutoff  = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).isoformat()
        cutoff7 = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).isoformat()

        total    = self._pki_db.fetchone("SELECT COUNT(*) FROM certificates")[0]
        revoked  = self._pki_db.fetchone("SELECT COUNT(*) FROM certificates WHERE revoked=1")[0]
        valid    = total - revoked
        exp30    = self._pki_db.fetchone(
            "SELECT COUNT(*) FROM certificates WHERE revoked=0 AND not_after <= ? AND not_after > ?",
            (cutoff, now_str)
        )[0]
        exp7     = self._pki_db.fetchone(
            "SELECT COUNT(*) FROM certificates WHERE revoked=0 AND not_after <= ? AND not_after > ?",
            (cutoff7, now_str)
        )[0]
        expired  = self._pki_db.fetchone(
            "SELECT COUNT(*) FROM certificates WHERE revoked=0 AND not_after <= ?",
            (now_str,)
        )[0]
        profile_rows = self._pki_db.fetchall(
            "SELECT profile, COUNT(*) FROM certificates WHERE revoked=0 GROUP BY profile"
        )

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
            "pypki_certs_by_profile": {r[0]: r[1] for r in profile_rows},
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
        # §5.11 — histogram metrics (issuance, OCSP, ACME order)
        for hist in (_hist_issuance, _hist_ocsp, _hist_acme_order):
            lines.extend(hist.exposition())
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

    def submit_pre_cert_to_ct_log(
        self,
        pre_cert: x509.Certificate,
        log_url: str,
        timeout: int = 10,
        log_pubkey_pem: Optional[bytes] = None,
    ) -> Optional[bytes]:
        """
        Submit a Pre-certificate to a CT log and return the raw SCT bytes.

        The call uses the RFC 6962 §4.2 "add-pre-chain" endpoint.
        Returns the raw TLS-encoded SCT bytes, or None on failure.

        If ``log_pubkey_pem`` is given (PEM ECDSA public key), the returned
        SCT's DigitallySigned is verified against that key before returning.
        Returns None if verification fails (logs a warning).
        """
        import urllib.request as _urllib

        # Build chain: [pre-cert DER, issuer DER]
        chain_ders = [
            pre_cert.public_bytes(Encoding.DER),
            self.ca_cert.public_bytes(Encoding.DER),
        ]
        chain_b64 = [base64.b64encode(der).decode() for der in chain_ders]
        payload = json.dumps({"chain": chain_b64}).encode()

        endpoint = log_url.rstrip("/") + "/ct/v1/add-pre-chain"
        try:
            req = _urllib.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with _urllib.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
        except Exception as e:
            logger.warning(f"CT log pre-cert submission failed ({endpoint}): {e}")
            return None

        # RFC 6962 §3.2: response structure is the same as add-chain
        sct_version    = body.get("sct_version", 0)
        log_id         = base64.b64decode(body["id"])
        timestamp_ms   = body["timestamp"]
        extensions     = base64.b64decode(body.get("extensions", ""))
        sig_bytes      = base64.b64decode(body["signature"])

        if log_pubkey_pem:
            pre_cert_der = pre_cert.public_bytes(Encoding.DER)
            if not self.verify_sct_signature(
                sct_version, timestamp_ms, extensions, sig_bytes,
                pre_cert_der, log_pubkey_pem, entry_type=1,
                issuer_pubkey=self.ca_key.public_key(),
            ):
                logger.warning(
                    f"CT log SCT signature verification FAILED for {log_url}; discarding SCT"
                )
                return None

        import struct as _struct
        sct = (
            bytes([sct_version])
            + log_id
            + _struct.pack(">Q", timestamp_ms)
            + _struct.pack(">H", len(extensions))
            + extensions
            + sig_bytes
        )
        return sct

    @staticmethod
    def verify_sct_signature(
        sct_version: int,
        timestamp_ms: int,
        extensions: bytes,
        dig_signed: bytes,
        cert_der: bytes,
        log_pubkey_pem: bytes,
        *,
        entry_type: int = 0,
        issuer_pubkey=None,
    ) -> bool:
        """
        Verify a CT log SCT DigitallySigned structure (RFC 6962 §3.2).

        ``dig_signed`` is the raw bytes of the TLS DigitallySigned struct:
          [hash_alg(1)] [sig_alg(1)] [sig_len(2)] [signature(sig_len)]

        The signed data (TreeLeafMessage) is reconstructed from the other args:
          version(1) sig_type(1) timestamp(8) entry_type(2) signed_entry extensions

        ``entry_type``: 0 = x509_entry (leaf cert), 1 = precert_entry.
        For precert_entry, ``issuer_pubkey`` must be provided (used for
        issuer_key_hash = SHA-256(SubjectPublicKeyInfo)).

        Returns True if the signature is valid, False otherwise.
        """
        import struct as _struct
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        try:
            pubkey = load_pem_public_key(log_pubkey_pem)
        except Exception as e:
            logger.warning(f"CT pubkey load failed: {e}")
            return False

        # Parse DigitallySigned: hash_alg(1) sig_alg(1) sig_len(2) signature
        if len(dig_signed) < 4:
            return False
        hash_alg_byte = dig_signed[0]
        sig_len = _struct.unpack_from(">H", dig_signed, 2)[0]
        if len(dig_signed) < 4 + sig_len:
            return False
        signature = dig_signed[4:4 + sig_len]

        # Choose hash algorithm from TLS hash_alg byte (RFC 5246 §7.4.1.4.1):
        # 4=SHA256, 5=SHA384, 6=SHA512
        hash_map = {4: SHA256, 5: SHA384, 6: SHA512}
        HashClass = hash_map.get(hash_alg_byte, SHA256)

        # Build the TreeLeafMessage signed data:
        # version(1=v1=0) sig_type(1=cert_ts=0) timestamp(8) entry_type(2) signed_entry extensions
        if entry_type == 0:
            # x509_entry: 3-byte length + cert DER
            signed_entry = len(cert_der).to_bytes(3, "big") + cert_der
        else:
            # precert_entry: issuer_key_hash(32) + 3-byte-len + TBSCertificate
            import hashlib
            if issuer_pubkey is None:
                return False
            spki_der = issuer_pubkey.public_bytes(
                Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            issuer_key_hash = hashlib.sha256(spki_der).digest()
            tbs = cert_der  # we pass TBS bytes directly from the pre-cert
            signed_entry = issuer_key_hash + len(tbs).to_bytes(3, "big") + tbs

        signed_data = (
            bytes([sct_version, 0])            # version, signature_type=certificate_timestamp
            + _struct.pack(">Q", timestamp_ms)  # timestamp
            + _struct.pack(">H", entry_type)    # entry_type (uint16)
            + signed_entry
            + _struct.pack(">H", len(extensions))
            + extensions
        )

        try:
            pubkey.verify(signature, signed_data, ECDSA(HashClass()))
            return True
        except Exception:
            return False

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
        return _sign_builder(builder, self.ca_key, rsa_pss=self._rsa_pss)

    def issue_certificate_with_ct(
        self,
        subject_str: str,
        public_key,
        ct_log_urls: Optional[List[str]] = None,
        ct_log_pubkeys: Optional[List[bytes]] = None,
        ct_require_n: Optional[int] = None,
        **kwargs,
    ) -> x509.Certificate:
        """
        Issue a certificate using the RFC 6962 Pre-certificate flow:
        1. Issue a Pre-certificate with a critical Poison extension.
        2. Submit it to CT logs via 'add-pre-chain' to obtain SCTs.
        3. Issue the final certificate with the SCTs embedded and Poison removed.

        This flow ensures that the SCTs embedded in the final certificate
        are valid for that specific certificate structure.

        Parameters
        ----------
        ct_log_urls     : CT log base URLs; defaults to ``self._ct_log_urls`` (from CLI).
        ct_log_pubkeys  : PEM ECDSA public keys for each log (for SCT sig verification);
                          defaults to ``self._ct_log_pubkeys`` (from CLI).
        ct_require_n    : Minimum number of verified SCTs required before issuance;
                          defaults to ``self._ct_require_n``.  If fewer SCTs are
                          obtained, raises ``RuntimeError``.  Set 0 to disable check.

        SCT submission failures are logged as warnings and do not abort issuance
        (unless ct_require_n is not met).
        """
        # Resolve defaults from CA-level config (set by CLI flags).
        urls     = ct_log_urls    or self._ct_log_urls    or [self.CT_LOG_ARGON_2025, self.CT_LOG_XENON_2025]
        pubkeys  = ct_log_pubkeys or self._ct_log_pubkeys or []
        req_n    = ct_require_n   if ct_require_n is not None else self._ct_require_n

        # 1. Issue Pre-certificate
        # Capture the serial and time so the final cert matches exactly.
        forced_time = datetime.datetime.now(datetime.timezone.utc)
        pre_cert = self.issue_certificate(
            subject_str=subject_str,
            public_key=public_key,
            ct_poison=True,
            forced_time=forced_time,
            **kwargs
        )
        serial = pre_cert.serial_number

        scts = []
        for i, url in enumerate(urls):
            pubkey_pem = pubkeys[i] if i < len(pubkeys) else None
            sct = self.submit_pre_cert_to_ct_log(pre_cert, url, log_pubkey_pem=pubkey_pem)
            if sct:
                scts.append(sct)

        if req_n > 0 and len(scts) < req_n:
            raise RuntimeError(
                f"CT transparency requirement not met: got {len(scts)} verified SCT(s), "
                f"need {req_n} (--ct-require-n). Certificate NOT issued."
            )

        # 2. Issue final certificate with same serial/time but NO poison.
        final_cert = self.issue_certificate(
            subject_str=subject_str,
            public_key=public_key,
            ct_poison=False,
            forced_serial=serial,
            forced_time=forced_time,
            **kwargs
        )

        if scts:
            final_cert = self.embed_scts(final_cert, scts)
            logger.info(f"Embedded {len(scts)} SCT(s) into serial={final_cert.serial_number} (Pre-cert flow)")
        else:
            logger.warning("No SCTs obtained; certificate issued without CT transparency")
        
        return final_cert


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
# CMP server module — CMPv2 (RFC 4210) / CMPv3 (RFC 9480) / HTTP (RFC 6712)
# Extracted from pki_server.py into cmp_server.py, consistent with the other
# protocol modules: acme_server.py, scep_server.py, est_server.py, ocsp_server.py.
# Imported HERE (after all class definitions) to avoid the circular import:
#   cmp_server.py does `from pki_server import CertificateAuthority, ...`
#   which requires pki_server to be fully loaded first.
# ---------------------------------------------------------------------------
try:
    import cmp_server as _cmp_module
    HAS_CMP = True
    # Re-export CMP symbols so callers can do `import pki_server as pki; pki.CMPv3Handler`
    CMP_WELL_KNOWN_PATH    = _cmp_module.CMP_WELL_KNOWN_PATH
    CMPv2ASN1              = _cmp_module.CMPv2ASN1
    CMPv2Handler           = _cmp_module.CMPv2Handler
    CMPv3Handler           = _cmp_module.CMPv3Handler
    CMPv2HTTPHandler       = _cmp_module.CMPv2HTTPHandler
    ThreadedHTTPServer     = _cmp_module.ThreadedHTTPServer
    TLSServer              = _cmp_module.TLSServer
    make_handler           = _cmp_module.make_handler
    make_cmpv3_handler     = _cmp_module.make_cmpv3_handler
    start_bootstrap_server = _cmp_module.start_bootstrap_server
except ImportError:
    HAS_CMP = False
    print("WARNING: cmp_server.py not found — CMPv2/CMPv3 support disabled.")
    print("         Place cmp_server.py in the same directory as pki_server.py.")


def _build_hsm_cfg(args):
    """Return an HSMConfig from parsed CLI args, or None if --hsm-module was not supplied."""
    try:
        from hsm_backend import HSMConfig
    except ImportError:
        return None
    return HSMConfig.from_args(args)


def main():
    parser = argparse.ArgumentParser(description="PKI Server with CMPv2 Support + mTLS")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument("--cmp-prefix", default="/cmp", metavar="PREFIX",
                        help="Path prefix for CMP handler (default: /cmp)")
    parser.add_argument("--ca-dir", default="./ca", help="CA data directory (default: ./ca)")
    parser.add_argument(
        "--pki-db-url", default=None, metavar="URL",
        help=(
            "DAL connection URL for the certificate store. Defaults to "
            "sqlite:///<ca-dir>/certificates.db. Use postgresql://user:pass@host/db "
            "for HA / multi-node deployments. "
            "Requires psycopg[binary] installed for postgresql:// URLs."
        ),
    )
    parser.add_argument(
        "--acme-db-url", default=None, metavar="URL",
        help="DAL connection URL for ACME state. Defaults to sqlite:///<ca-dir>/acme.db.",
    )
    parser.add_argument(
        "--scep-db-url", default=None, metavar="URL",
        help="DAL connection URL for SCEP state. Defaults to sqlite:///<ca-dir>/scep.db.",
    )
    parser.add_argument(
        "--audit-db-url", default=None, metavar="URL",
        help=(
            "DAL connection URL for the audit log. Defaults to "
            "sqlite:///<ca-dir>/audit.db. Use postgresql://user:pass@host/db "
            "for multi-node deployments with a shared audit log. "
            "Requires psycopg installed for postgresql:// URLs."
        ),
    )
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument(
        "--log-format", default="text", choices=["text", "json"],
        help="Log output format: 'text' (default) for human-readable, "
             "'json' for structured one-object-per-line output (§5.10)."
    )
    parser.add_argument(
        "--cps-uri", default=None, metavar="URL",
        help=(
            "URL where this CA's Certification Practice Statement is "
            "published. When set, every issued certificate gets a "
            "CertificatePolicies extension carrying this URI as a "
            "CPS qualifier (RFC 5280 §4.2.1.4 / id-qt-cps). PyPKI "
            "ships a CPS template at docs/CPS.md — host that on a "
            "URL of your choosing and point this flag at it. "
            "Default: omit the CertificatePolicies extension entirely."
        ),
    )
    parser.add_argument(
        "--cps-policy-oid", default=None, metavar="OID",
        help=(
            "Policy OID asserted by issued certificates' "
            "CertificatePolicies extension. Required if --cps-uri is "
            "set. Use a sub-arc of your IANA Private Enterprise Number "
            "(e.g. 1.3.6.1.4.1.<PEN>.1.1). Free PEN registration: "
            "https://pen.iana.org/pen/PenApplication.page"
        ),
    )
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
    parser.add_argument(
        "--ca-key-type", default="rsa-4096",
        choices=["rsa-2048", "rsa-3072", "rsa-4096",
                 "ec-p256", "ec-p384", "ec-p521",
                 "ed25519", "ed448"],
        help=(
            "Algorithm and parameters for the CA private key on first-run "
            "bootstrap. Ignored once ca.key exists on disk. "
            "RSA = PKCS#1 v1.5 / PSS (RFC 4055), ECDSA = matched-curve "
            "SHA-2 (RFC 5480/5758), EdDSA = Ed25519 / Ed448 (RFC 8410). "
            "SCEP requires an RSA CA key. Default: rsa-4096."
        ),
    )
    parser.add_argument(
        "--sig-algorithm", default="rsa-pkcs1v15",
        choices=["rsa-pkcs1v15", "rsa-pss"],
        help=(
            "Signature padding for RSA CA keys: PKCS#1 v1.5 (default) or "
            "RSASSA-PSS per RFC 4055 §3.1 (MGF1+SHA-256, salt length 32). "
            "No-op for ECDSA / EdDSA keys, which have a single signature scheme."
        ),
    )
    hsm_group = parser.add_argument_group(
        "HSM / PKCS#11 options (§5.1)",
        "Delegate CA signing to a hardware security module via PKCS#11. "
        "Requires python-pkcs11 (pip install python-pkcs11) and a PKCS#11 "
        "module (.so / .dll) such as SoftHSM2, YubiHSM, or a vendor module. "
        "The private key never leaves the token."
    )
    hsm_group.add_argument(
        "--hsm-module", metavar="PATH",
        help="Path to the PKCS#11 shared library (e.g. /usr/lib/softhsm/libsofthsm2.so)"
    )
    hsm_group.add_argument(
        "--hsm-slot", type=int, default=0, metavar="N",
        help="PKCS#11 slot index (default: 0)"
    )
    hsm_group.add_argument(
        "--hsm-pin-env", default="PYPKI_HSM_PIN", metavar="VAR",
        help="Environment variable holding the HSM user PIN (default: PYPKI_HSM_PIN). "
             "Never supply the PIN as a command-line argument."
    )
    hsm_group.add_argument(
        "--hsm-key-label", default="pypki-ca", metavar="LABEL",
        help="CKA_LABEL of the CA signing key on the token (default: pypki-ca)"
    )
    hsm_group.add_argument(
        "--hsm-init-if-missing", action="store_true", default=False,
        help="Generate a 4096-bit RSA key on the token if the label is absent. "
             "The generated key has CKA_EXTRACTABLE=False — it can never be exported."
    )
    ra_group = parser.add_argument_group(
        "RA / approval workflow (§5.4)",
        "Registration Authority controls. By default all requests are auto-approved "
        "(backwards-compatible). Use --ra-policy-file or --ra-require-approval to "
        "gate issuance on human review."
    )
    ra_group.add_argument(
        "--ra-auto-approve", action="store_true", default=False,
        help="Auto-approve all certificate requests regardless of profile (default when "
             "no --ra-policy-file or --ra-require-approval is given)"
    )
    ra_group.add_argument(
        "--ra-require-approval", action="store_true", default=False,
        help="Require manual approval for every certificate request. "
             "Overrides --ra-auto-approve."
    )
    ra_group.add_argument(
        "--ra-auto-approve-profiles", default="", metavar="PROFILES",
        help="Comma-separated list of certificate profiles that are auto-approved "
             "even when --ra-require-approval is set. Example: default,tls_server"
    )
    ra_group.add_argument(
        "--ra-policy-file", default="", metavar="PATH",
        help="Path to a JSON RA policy file. Overrides --ra-auto-approve-profiles for "
             "the profiles it mentions."
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
        "--acme-prefix", default=None, metavar="PREFIX",
        help="Mount ACME server at this path prefix (e.g. /acme)"
    )
    acme_group.add_argument(
        "--acme-base-url", default=None, metavar="URL",
        help="Public base URL for ACME (default: http://<host>:<port><acme-prefix>)"
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
    acme_group.add_argument(
        "--acme-allow-private-ip", action="store_true",
        help="RFC 8738: permit private, loopback, link-local, multicast, "
             "reserved, and unspecified IP addresses as `ip` identifiers in "
             "ACME orders. OFF by default to mirror public-CA practice; "
             "enable for homelab and internal-only deployments."
    )
    acme_group.add_argument(
        "--acme-require-eab", action="store_true", default=False,
        help="RFC 8555 §7.3.4: Require External Account Binding for all new accounts"
    )
    acme_group.add_argument(
        "--acme-eab-file", default=None, metavar="PATH",
        help="JSON file containing EAB KID to HMAC key mappings (e.g. {\"kid1\": \"key1_b64\"})"
    )
    acme_group.add_argument(
        "--acme-per-account-cert-limit", type=int, default=0, metavar="N",
        help="Maximum certificates an ACME account may obtain per window (0 = unlimited, default). "
             "Works with --acme-per-account-window-days."
    )
    acme_group.add_argument(
        "--acme-per-account-window-days", type=int, default=7, metavar="N",
        help="Rolling window in days for --acme-per-account-cert-limit (default: 7)"
    )
    acme_group.add_argument(
        "--acme-star-enabled", action="store_true", default=False,
        help="Enable RFC 8739 ACME STAR (short-term auto-renewed certificates)"
    )
    acme_group.add_argument(
        "--acme-star-min-lifetime", type=int, default=86400, metavar="SECONDS",
        help="Minimum STAR certificate lifetime in seconds (default: 86400 = 1 day)"
    )
    acme_group.add_argument(
        "--acme-star-max-duration", type=int, default=7776000, metavar="SECONDS",
        help="Maximum STAR auto-renewal window in seconds (default: 7776000 = 90 days)"
    )

    ct_group = parser.add_argument_group(
        "Certificate Transparency (RFC 6962 / RFC 9162)",
        "Opt-in CT log submission and SCT embedding. All flags are optional; "
        "CT is disabled by default. Only enable for publicly-trusted CAs — "
        "private / homelab CAs should leave CT off."
    )
    ct_group.add_argument(
        "--ct-log-url", action="append", metavar="URL", dest="ct_log_urls",
        help="RFC 6962 CT log base URL (e.g. https://ct.googleapis.com/logs/us1/argon2025h2/). "
             "Repeat for multiple logs. When set, every issuance uses the Pre-cert flow and "
             "embeds SCTs from each reachable log."
    )
    ct_group.add_argument(
        "--ct-log-pubkey", action="append", metavar="PATH", dest="ct_log_pubkeys",
        help="Path to PEM ECDSA public key for the corresponding --ct-log-url (by index). "
             "When provided, each received SCT's DigitallySigned is verified against this "
             "key before embedding. Discards the SCT silently on verification failure."
    )
    ct_group.add_argument(
        "--ct-require-n", type=int, default=0, metavar="N",
        help="Minimum number of verified SCTs required for issuance to succeed "
             "(default: 0 = best-effort, do not abort on SCT failure). "
             "Set to 2 to require at least two qualifying SCTs (Chrome policy)."
    )

    infra_group = parser.add_argument_group(
        "Revocation & PKI infrastructure",
    )
    infra_group.add_argument(
        "--ocsp-prefix", default=None, metavar="PREFIX",
        help="Mount OCSP responder at this path prefix (e.g. /ocsp)"
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
    infra_group.add_argument(
        "--ocsp-require-nonce", action="store_true", default=False,
        help="RFC 8954 strict mode: reject OCSP requests that lack a "
             "nonce extension with status 'unauthorized'. Prevents replay "
             "of cached responses by a man-in-the-middle. Default: off "
             "(nonceless requests are accepted, matching RFC 6960 default)."
    )
    infra_group.add_argument(
        "--tsa-prefix", default=None, metavar="PREFIX",
        help="Mount RFC 3161 / RFC 5816 TSA at this path prefix (e.g. /tsa)"
    )
    infra_group.add_argument(
        "--tsa-policy-oid", default="1.3.6.1.4.1.99999.1", metavar="OID",
        help="TSA policy OID embedded in every TimeStampToken (default: placeholder; "
             "assign a real OID from your PEN arc for production use)"
    )
    infra_group.add_argument(
        "--tsa-accuracy-seconds", type=int, default=1, metavar="N",
        help="Declared clock accuracy in seconds embedded in TSTInfo (default: 1)"
    )
    infra_group.add_argument(
        "--tsa-cert", default=None, metavar="PATH",
        help="PEM TSA signing cert (auto-provisioned from CA if omitted)"
    )
    infra_group.add_argument(
        "--tsa-key", default=None, metavar="PATH",
        help="PEM TSA signing key (auto-provisioned from CA if omitted)"
    )

    ops_group = parser.add_argument_group("Operational options")
    ops_group.add_argument(
        "--web-prefix", default=None, metavar="PREFIX",
        help="Mount web dashboard at this path prefix (e.g. /)"
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
        "--ipsec-prefix", default=None, metavar="PREFIX",
        help="Mount IPsec PKI server at this path prefix (e.g. /ipsec)"
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
        "--est-prefix", default=None, metavar="PREFIX",
        help="Mount EST server at this path prefix (e.g. /est)"
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

    pkcs12_group = parser.add_argument_group("PKCS#12 options (RFC 7292)")
    pkcs12_group.add_argument(
        "--p12-allow-unencrypted", action="store_true", default=False,
        help="RFC 7292 hardening: allow passwordless PKCS#12 export via the web UI and "
             "REST API. OFF by default — unencrypted P12 bundles are rejected to prevent "
             "accidental key exposure. Enable only on trusted internal networks."
    )

    scep_group = parser.add_argument_group(
        "SCEP options (RFC 8894)",
        "Enable the SCEP protocol for network device certificate enrolment. "
        "Requires scep_server.py in the same directory."
    )
    scep_group.add_argument(
        "--scep-prefix", default=None, metavar="PREFIX",
        help="Mount SCEP server at this path prefix (e.g. /scep)"
    )
    scep_group.add_argument(
        "--scep-challenge", default="", metavar="SECRET",
        help="Challenge password for SCEP enrolment (empty = no challenge required)"
    )
    scep_group.add_argument(
        "--scep-use-otp", action="store_true", default=False,
        help="Enable single-use OTP challenges for SCEP enrolment (minted via /api/scep/otp)"
    )

    webhook_group = parser.add_argument_group(
        "lifecycle hooks (§5.9)",
        "HTTP POST webhooks fired on cert.issued, cert.revoked, cert.expiring, subca.issued, cross.signed."
    )
    webhook_group.add_argument(
        "--webhook-url", action="append", default=[], dest="webhook_urls", metavar="URL",
        help="Webhook endpoint URL (repeatable; all URLs receive every enabled event)"
    )
    webhook_group.add_argument(
        "--webhook-secret", default="", metavar="SECRET",
        help="HMAC-SHA256 signing secret; sets X-PyPKI-Signature header on every delivery"
    )
    webhook_group.add_argument(
        "--webhook-events", default="", metavar="EVENT,...",
        help=(
            "Comma-separated list of events to deliver "
            "(default: all). Example: cert.issued,cert.revoked"
        )
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

    configure_logging(args.log_level, getattr(args, "log_format", "text"))

    # Build CLI overrides dict (only keys the user explicitly set)
    cli_validity = {}
    if args.end_entity_days:  cli_validity["end_entity_days"]  = args.end_entity_days
    if args.client_cert_days: cli_validity["client_cert_days"] = args.client_cert_days
    if args.tls_server_days:  cli_validity["tls_server_days"]  = args.tls_server_days
    if args.ca_days:          cli_validity["ca_days"]          = args.ca_days
    cli_overrides = {"validity": cli_validity} if cli_validity else {}

    # CPS / certificate policy wiring (RFC 5280 §4.2.1.4):
    # When the operator sets --cps-uri, every issued cert carries a
    # CertificatePolicies extension with that URI as a CPS qualifier.
    # Requires a paired --cps-policy-oid so the policy actually has an
    # identifier — the URI alone is just a qualifier.
    if getattr(args, "cps_uri", None):
        if not getattr(args, "cps_policy_oid", None):
            raise SystemExit(
                "--cps-uri requires --cps-policy-oid (the policy needs an "
                "identifier — the URI is just a qualifier per RFC 5280 §4.2.1.4)"
            )
        cli_overrides.setdefault("certificate_policies_default", []).append({
            "oid":     args.cps_policy_oid,
            "cps_uri": args.cps_uri,
        })

    ca_dir = Path(args.ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    config = ServerConfig(ca_dir=ca_dir, cli_overrides=cli_overrides)

    # Audit log — defaults to sqlite at <ca_dir>/audit.db; overridable via
    # --audit-db-url for multi-node deployments writing to shared Postgres.
    audit_log = (
        AuditLog(ca_dir, db_url=getattr(args, "audit_db_url", None))
        if getattr(args, "audit", True) else None
    )

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
        ca_key_type=getattr(args, "ca_key_type", "rsa-4096"),
        sig_algorithm=getattr(args, "sig_algorithm", "rsa-pkcs1v15"),
        pki_db_url=getattr(args, "pki_db_url", None) or "",
        hsm_cfg=_build_hsm_cfg(args),
    )
    # Store reload interval on ca so sub-modules (ipsec_server) can read it
    ca._tls_reload_interval = getattr(args, "tls_reload_interval", 60)

    # RFC 7292 hardening: allow/reject unencrypted PKCS#12 export
    ca._p12_allow_unencrypted = getattr(args, "p12_allow_unencrypted", False)

    # RFC 6962 CT configuration: load log URLs and pubkeys from CLI
    _ct_urls = getattr(args, "ct_log_urls", None) or []
    ca._ct_log_urls = _ct_urls
    ca._ct_require_n = getattr(args, "ct_require_n", 0)
    _ct_pubkey_paths = getattr(args, "ct_log_pubkeys", None) or []
    _ct_pubkeys = []
    for path in _ct_pubkey_paths:
        try:
            _ct_pubkeys.append(Path(path).read_bytes())
        except Exception as e:
            logger.warning(f"--ct-log-pubkey {path}: {e}; SCT verification for that log disabled")
    ca._ct_log_pubkeys = _ct_pubkeys
    if _ct_urls:
        logger.info(
            f"CT transparency: {len(_ct_urls)} log(s) configured, "
            f"require_n={ca._ct_require_n}, "
            f"pubkeys={len(_ct_pubkeys)}"
        )

    # Feature 8: expiry monitor thread
    _expiry_days = getattr(args, "expiry_warn_days", 30)
    if _expiry_days > 0:
        ca.start_expiry_monitor(
            days_ahead=_expiry_days,
            check_interval_seconds=86400,
            audit=audit_log,
        )

    # §5.9 — Lifecycle webhook dispatcher
    _wh_urls = getattr(args, "webhook_urls", []) or []
    if _wh_urls and HAS_HOOKS:
        _wh_events_str = getattr(args, "webhook_events", "") or ""
        _wh_events = (
            {e.strip() for e in _wh_events_str.split(",") if e.strip()}
            if _wh_events_str else None
        )
        ca._webhook = _hooks_module.WebhookDispatcher(
            urls=_wh_urls,
            secret=getattr(args, "webhook_secret", "") or "",
            enabled_events=_wh_events,
            audit_fn=audit_log.record if audit_log else None,
        )
        ca._webhook.start()
        logger.info(
            "Lifecycle webhooks: %d URL(s), events=%s",
            len(_wh_urls),
            ",".join(sorted(_wh_events)) if _wh_events else "all",
        )
    elif _wh_urls and not HAS_HOOKS:
        logger.warning("--webhook-url provided but hooks.py not found; webhooks disabled")

    # §5.4 — RA / approval workflow
    _ra_policy_file = getattr(args, "ra_policy_file", "") or ""
    _ra_require = getattr(args, "ra_require_approval", False)
    _ra_auto = getattr(args, "ra_auto_approve", False)
    _ra_profiles_raw = getattr(args, "ra_auto_approve_profiles", "") or ""
    _ra_auto_profiles = [p.strip() for p in _ra_profiles_raw.split(",") if p.strip()]
    if _ra_policy_file:
        try:
            _ra_policy = RAPolicy.from_file(_ra_policy_file, _ra_auto_profiles or None)
            logger.info(f"RA policy loaded from {_ra_policy_file}")
        except Exception as _e:
            logger.warning(f"RA policy file load failed ({_e}); falling back to auto-approve-all")
            _ra_policy = RAPolicy(auto_approve_all=True)
    elif _ra_require:
        _ra_policy = RAPolicy(
            auto_approve_all=False,
            auto_approve_profiles=_ra_auto_profiles or None,
        )
        logger.info(f"RA manual-approval mode; auto-approve profiles: {_ra_auto_profiles or 'none'}")
    else:
        # Default / --ra-auto-approve: backwards-compatible auto-approve-all
        _ra_policy = RAPolicy(auto_approve_all=True)
    ca.configure_ra(_ra_policy)

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

    import dispatcher_server as _dispatcher_module
    route_table = _dispatcher_module.RouteTable()

    # Start the single shared dispatcher server (all services share this port)
    server = _dispatcher_module.start_dispatcher_server(
        host=args.host,
        port=args.port,
        route_table=route_table,
        tls_cert_path=cmp_tls_cert,
        tls_key_path=cmp_tls_key,
        require_client_cert=getattr(args, "mtls", False),
        tls13_only=getattr(args, "tls13_only", False),
        alpn_protocols=alpn_protos,
        tls_reload_interval=getattr(args, "tls_reload_interval", 60),
        ca=ca,
    )

    _cmp_proxy = _cmp_module.start_cmp_server(
        route_table=route_table,
        prefix=getattr(args, "cmp_prefix", "/cmp"),
        ca=ca,
        audit_log=audit_log,
        rate_limiter=rate_limiter,
        use_cmpv3=getattr(args, "cmpv3", True),
    )
    proto_label = "CMPv3 (RFC 9480)" if getattr(args, "cmpv3", True) else "CMPv2 (RFC 4210)"
    logger.info(f"{proto_label} active on {scheme}://{args.host}:{args.port}{getattr(args, 'cmp_prefix', '/cmp')}")

    bootstrap_srv = None
    if args.bootstrap_port:
        bootstrap_srv = _cmp_module.start_bootstrap_server(
            args.host, args.bootstrap_port, ca,
            _cmp_module.CMPv2Handler(ca),
        )

    # Start ACME server if requested
    acme_srv = None
    if getattr(args, "acme_prefix", None):
        if not HAS_ACME:
            print("WARNING: acme_server.py not found — ACME support disabled.")
            print("         Place acme_server.py in the same directory as pki_server.py.")
        else:
            _acme_prefix = args.acme_prefix
            # Use tls_hostname (or localhost) instead of 0.0.0.0 for the ACME base URL
            # so directory URLs are reachable by clients (0.0.0.0 is a bind addr, not a hostname)
            _acme_hostname = (
                args.acme_base_url.split("://")[1].split(":")[0]
                if args.acme_base_url
                else (getattr(args, "tls_hostname", None) or "localhost")
                if args.host in ("0.0.0.0", "::")
                else args.host
            )
            acme_base = args.acme_base_url or f"{scheme}://{_acme_hostname}:{args.port}{_acme_prefix}"
            acme_srv = _acme_module.start_acme_server(
                route_table=route_table,
                prefix=_acme_prefix,
                ca=ca,
                ca_dir=ca_dir,
                auto_approve_dns=args.acme_auto_approve_dns,
                base_url=acme_base,
                cert_validity_days=getattr(args, "acme_cert_days", 90),
                short_lived_threshold_days=getattr(args, "acme_short_lived_threshold", 7),
                dns01_hook=_dns01_hook,  # Feature 5: real dns-01 resolver hook
                allow_private_ip=getattr(args, "acme_allow_private_ip", False),
                require_eab=getattr(args, "acme_require_eab", False),
                eab_file=getattr(args, "acme_eab_file", None),
                per_account_cert_limit=getattr(args, "acme_per_account_cert_limit", 0),
                per_account_window_days=getattr(args, "acme_per_account_window_days", 7),
                db_url=getattr(args, "acme_db_url", None) or "",
                star_enabled=getattr(args, "acme_star_enabled", False),
                star_min_lifetime=getattr(args, "acme_star_min_lifetime", 86400),
                star_max_duration=getattr(args, "acme_star_max_duration", 7776000),
            )

    # Start SCEP server if requested
    scep_srv = None
    if getattr(args, "scep_prefix", None):
        if not HAS_SCEP:
            print("WARNING: scep_server.py not found — SCEP support disabled.")
            print("         Place scep_server.py in the same directory as pki_server.py.")
        else:
            scep_srv = _scep_module.start_scep_server(
                route_table=route_table,
                prefix=args.scep_prefix,
                ca=ca,
                ca_dir=ca_dir,
                challenge=args.scep_challenge,
                use_otp=getattr(args, "scep_use_otp", False),
                db_url=getattr(args, "scep_db_url", None) or "",
            )

    # Start EST server if requested
    est_srv = None
    if getattr(args, "est_prefix", None):
        if not HAS_EST:
            print("WARNING: est_server.py not found — EST support disabled.")
            print("         Place est_server.py in the same directory as pki_server.py.")
        else:
            est_users = {}
            for entry in (args.est_user or []):
                u, _, p = entry.partition(":")
                est_users[u] = p
            est_srv = _est_module.start_est_server(
                route_table=route_table,
                prefix=args.est_prefix,
                ca=ca,
                ca_dir=ca_dir,
                users=est_users if est_users else None,
                require_auth=args.est_require_auth,
            )

    # Start OCSP responder if requested
    ocsp_srv = None
    if getattr(args, "ocsp_prefix", None):
        if not HAS_OCSP:
            print("WARNING: ocsp_server.py not found — OCSP support disabled.")
        else:
            ocsp_srv = _ocsp_module.start_ocsp_server(
                route_table=route_table,
                prefix=args.ocsp_prefix,
                ca=ca,
                cache_seconds=getattr(args, "ocsp_cache_seconds", 300),
                require_nonce=getattr(args, "ocsp_require_nonce", False),
            )

    # Start TSA server if requested (RFC 3161 + RFC 5816)
    tsa_srv = None
    if getattr(args, "tsa_prefix", None):
        if not HAS_TSA:
            print("WARNING: tsa_server.py not found — TSA disabled.")
        else:
            tsa_srv = _tsa_module.start_tsa_server(
                route_table=route_table,
                prefix=args.tsa_prefix,
                ca=ca,
                policy_oid=getattr(args, "tsa_policy_oid", "1.3.6.1.4.1.99999.1"),
                accuracy_seconds=getattr(args, "tsa_accuracy_seconds", 1),
                tsa_cert_path=getattr(args, "tsa_cert", None),
                tsa_key_path=getattr(args, "tsa_key", None),
                audit_log=audit_log,
            )

    # Start IPsec PKI server if requested (RFC 4945 / RFC 4806 / RFC 4809)
    ipsec_srv = None
    if getattr(args, "ipsec_prefix", None):
        if not HAS_IPSEC:
            print("WARNING: ipsec_server.py not found — IPsec PKI server disabled.")
        else:
            _ipsec_ocsp_url = getattr(args, "ocsp_url", None) or None
            _ipsec_crl_url  = getattr(args, "crl_url",  None) or None
            ipsec_srv = _ipsec_module.start_ipsec_server(
                route_table=route_table,
                prefix=args.ipsec_prefix,
                ca=ca,
                ocsp_url=_ipsec_ocsp_url,
                crl_url=_ipsec_crl_url,
            )

    # Start Web UI if requested
    web_srv = None
    if getattr(args, "web_prefix", None):
        if not HAS_WEBUI:
            print("WARNING: web_ui.py not found — Web UI disabled.")
        else:
            _dispatcher_base = f"{scheme}://{args.host}:{args.port}"
            _ocsp_base  = f"{_dispatcher_base}{args.ocsp_prefix}"  if getattr(args, "ocsp_prefix",  None) else ""
            _acme_base2 = f"{_dispatcher_base}{args.acme_prefix}/directory" if getattr(args, "acme_prefix", None) else ""
            _scep_base  = f"{_dispatcher_base}{args.scep_prefix}"  if getattr(args, "scep_prefix",  None) else ""
            _est_base   = f"{_dispatcher_base}{args.est_prefix}/.well-known/est" if getattr(args, "est_prefix",  None) else ""
            web_srv = _web_ui_module.start_web_ui(
                route_table=route_table,
                prefix=args.web_prefix,
                ca=ca,
                audit_log=audit_log,
                rate_limiter=rate_limiter,
                require_auth=not getattr(args, "web_no_auth", False),
                pam_service=getattr(args, "web_pam_service", "login"),
                dispatcher_base_url=_dispatcher_base,
                cmp_base_url=f"{_dispatcher_base}{getattr(args, 'cmp_prefix', '/cmp')}",
                acme_base_url=_acme_base2,
                scep_base_url=_scep_base,
                est_base_url=_est_base,
                ocsp_base_url=_ocsp_base,
                # Running server objects — let the UI reflect current state
                cmp_server=_cmp_proxy,
                acme_server=acme_srv,
                scep_server=scep_srv,
                est_server=est_srv,
                ocsp_server=ocsp_srv,
                ipsec_server=ipsec_srv,
                # Module references — required for start/stop from the Services page
                cmp_module=_cmp_module     if HAS_CMP   else None,
                acme_module=_acme_module   if HAS_ACME  else None,
                scep_module=_scep_module   if HAS_SCEP  else None,
                est_module=_est_module     if HAS_EST   else None,
                ocsp_module=_ocsp_module   if HAS_OCSP  else None,
                ipsec_module=_ipsec_module if HAS_IPSEC else None,
            )

    ca_mode_label = (
        f"intermediate ({len(ca._parent_chain)} parent cert(s))"
        if ca.is_intermediate else "root (self-signed)"
    )
    _base     = f"{scheme}://{args.host}:{args.port}"
    _cmp_pfx  = getattr(args, "cmp_prefix", "/cmp")
    acme_line = f"{_base}{args.acme_prefix}/directory" if (getattr(args,"acme_prefix",None) and HAS_ACME) else "disabled"
    scep_line = f"{_base}{args.scep_prefix}" if (getattr(args,"scep_prefix",None) and HAS_SCEP) else "disabled"
    est_line  = f"{_base}{args.est_prefix}/.well-known/est" if (getattr(args,"est_prefix",None) and HAS_EST) else "disabled"
    ocsp_line = f"{_base}{args.ocsp_prefix}" if (getattr(args,"ocsp_prefix",None) and HAS_OCSP) else "disabled"
    tsa_line  = f"{_base}{args.tsa_prefix}"  if (getattr(args,"tsa_prefix",None)  and HAS_TSA)  else "disabled"
    web_line  = f"{_base}{args.web_prefix}" if getattr(args,"web_prefix",None) else "disabled"
    ipsec_line = f"{_base}{args.ipsec_prefix}" if (getattr(args,"ipsec_prefix",None) and HAS_IPSEC) else "disabled"
    cmp_wk    = f"{_base}/.well-known/cmp"
    rl_info   = f"{args.rate_limit}/min per IP" if getattr(args,"rate_limit",0) > 0 else "disabled"
    _tls_reload_interval = getattr(args, "tls_reload_interval", 60)
    tls_reload_info = (f"{_tls_reload_interval}s poll + POST /api/reload-tls"
                       if (args.tls or args.mtls) else "n/a (no TLS)")
    audit_info = "ca/audit.db" if getattr(args,"audit",True) else "disabled"
    boot_line = f"http://{args.host}:{args.bootstrap_port}/bootstrap?cn=<n>" if args.bootstrap_port else "disabled"

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║         PyPKI — Single-Port PKI Server (path-prefix routing)   ║
╠══════════════════════════════════════════════════════════════════╣
║  Listening on     : {scheme}://{args.host}:{args.port:<32}║
║  CA Dir           : {args.ca_dir:<47}║
║  CA Mode          : {ca_mode_label:<47}║
║  TLS Mode         : {tls_mode_label:<47}║
║  Bootstrap        : {boot_line:<47}║
╠══════════════════════════════════════════════════════════════════╣
║  CMP ({proto_label:<10}): {_base}{_cmp_pfx:<{27-len(_cmp_pfx)}}║
║  ACME             : {acme_line:<47}║
║  SCEP             : {scep_line:<47}║
║  EST              : {est_line:<47}║
║  OCSP             : {ocsp_line:<47}║
║  TSA              : {tsa_line:<47}║
║  IPsec PKI        : {ipsec_line:<47}║
║  Web Dashboard    : {web_line:<47}║
╠══════════════════════════════════════════════════════════════════╣
║  CMP Well-Known   : {cmp_wk:<47}║
║  Config           : GET/PATCH {_base}{_cmp_pfx}/api/config      ║
║  CA Certificate   : GET  {_base}{_cmp_pfx}/ca/cert.pem          ║
║  CRL              : GET  {_base}{_cmp_pfx}/ca/crl               ║
║  Health Check     : GET  {_base}{_cmp_pfx}/health               ║
║  Metrics          : GET  {_base}{_cmp_pfx}/metrics              ║
╠══════════════════════════════════════════════════════════════════╣
║  Rate Limiting    : {rl_info:<47}║
║  Audit Log        : {audit_info:<47}║
║  Expiry Monitor   : {str(_expiry_days)+"d" if _expiry_days else "disabled":<47}║
║  TLS Cert Reload  : {tls_reload_info:<47}║
╠══════════════════════════════════════════════════════════════════╣
║  Validity periods (change live: PATCH {_cmp_pfx}/api/config)    ║
║    End-entity   : {config.end_entity_days:<3} days                                       ║
║    Client cert  : {config.client_cert_days:<3} days                                       ║
║    TLS server   : {config.tls_server_days:<3} days                                       ║
║    CA cert      : {config.ca_days:<4} days                                      ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if args.tls:
        print("  TLS Quick-start:")
        print(f"     curl --cacert {args.ca_dir}/ca.crt {scheme}://{args.tls_hostname}:{args.port}{_cmp_pfx}/health")
        print()

    if args.mtls:
        print("  mTLS Quick-start:")
        print(f"  1. Get a client cert bundle:")
        print(f"     curl http://localhost:{args.bootstrap_port or 8080}/bootstrap?cn=myclient -o bundle.pem")
        print(f"  2. Split bundle: openssl x509 -in bundle.pem -out client.crt")
        print(f"                   openssl pkey -in bundle.pem -out client.key")
        print(f"  3. curl --cert client.crt --key client.key --cacert {args.ca_dir}/ca.crt \\")
        print(f"          {scheme}://{args.tls_hostname}:{args.port}{_cmp_pfx}/health")
        print()

    if getattr(args, "est_prefix", None) and HAS_EST:
        print("  EST Quick-start (RFC 7030):")
        print(f"  1. Get CA chain:  curl --cacert {args.ca_dir}/ca.crt \\")
        print(f"                       {_base}{args.est_prefix}/.well-known/est/cacerts | base64 -d > chain.p7")
        print(f"  2. Enrol (openssl):")
        print(f"     openssl req -new -key client.key -out client.csr -subj '/CN=mydevice'")
        print(f"     curl -X POST --cacert {args.ca_dir}/ca.crt \\")
        print(f"          --data-binary @<(base64 client.csr) \\")
        print(f"          -H 'Content-Transfer-Encoding: base64' \\")
        print(f"          {_base}{args.est_prefix}/.well-known/est/simpleenroll")
        if args.est_require_auth:
            print(f"     Add: -u 'username:password'")
        print()

    if getattr(args, "scep_prefix", None) and HAS_SCEP:
        print("  SCEP Quick-start:")
        print(f"  1. Fetch CA cert:  sscep getca -u {_base}{args.scep_prefix} -c ca.crt")
        print(f"  2. Enrol:          sscep enroll -u {_base}{args.scep_prefix} \\")
        print(f"                       -c ca.crt -k client.key -r client.csr -l client.crt \\")
        if args.scep_challenge:
            print(f"                       -p '{args.scep_challenge}'")
        print()

    if getattr(args, "acme_prefix", None) and HAS_ACME:
        print("  ACME Quick-start:")
        print(f"  1. Fetch directory:    curl {acme_line}")
        print(f"  2. Use any ACME client (certbot, acme.sh, custom) pointed at:")
        print(f"     {acme_line}")
        print(f"  3. For http-01: client must serve the challenge token on port 80.")
        print(f"  4. For dns-01:  client must create a TXT record at _acme-challenge.<domain>.")
        if args.acme_auto_approve_dns:
            print(f"  ⚠ dns-01 auto-approval is ON — do not use in production!")
        print()

    if 'bootstrap_srv' not in dir():
        bootstrap_srv = None

    try:
        # Dispatcher server runs in its own daemon thread.
        # Block the main thread here so the process stays alive.
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down PKI server...")
        # Stop TLS cert watcher on the dispatcher server
        _w = getattr(server, "_tls_watcher", None)
        if _w is not None:
            _w.stop()
        server.shutdown()
        if bootstrap_srv:
            bootstrap_srv.shutdown()
        if audit_log:
            audit_log.record("shutdown", "graceful shutdown via KeyboardInterrupt")

if __name__ == "__main__":
    main()
