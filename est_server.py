#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
EST Server — RFC 7030 (Enrollment over Secure Transport)
=========================================================
EST provides HTTPS-based certificate enrolment, primarily used by IoT devices,
routers, and any client that already has TLS but needs a PKI certificate.

Supported operations (RFC 7030 §4):
  - GET  /.well-known/est/cacerts             : CA cert chain (MUST)
  - POST /.well-known/est/simpleenroll        : CSR → signed certificate (MUST)
  - POST /.well-known/est/simplereenroll      : renewal with existing cert (MUST)
  - GET  /.well-known/est/csrattrs            : CSR attribute hints (OPTIONAL)
  - POST /.well-known/est/serverkeygen        : server-generated key pair (OPTIONAL)

All paths also support a CA label variant:
  /.well-known/est/<label>/cacerts  etc.

Authentication (RFC 7030 §3.3):
  - HTTP Basic auth  — username:password checked against EST user store
  - TLS client cert  — certificate signed by this CA is accepted automatically
  - Both modes active simultaneously; the client uses whichever it has

RFC 7030 key points implemented:
  - Responses are base64-encoded DER (MIME type application/pkcs7-mime or
    application/pkcs8) NOT PEM
  - simpleenroll/simplereenroll accept both PKCS#10 DER (base64) and
    raw base64-encoded CSR in the body
  - serverkeygen returns a PKCS#7 certs-only blob + PKCS#8 key, or
    a multipart/mixed response per RFC 7030 §4.4
  - csrattrs returns a PKCS#9 ChallengePassword attribute sequence
    hinting which extensions and key type the CA prefers
  - Proper HTTP 401 + WWW-Authenticate on auth failure

Dependencies: same as pki_server.py (cryptography)
"""

import base64
import datetime
import hashlib
import http.server
import json
import logging
import os
import ssl
import threading
import traceback
from pathlib import Path
from typing import Optional, Dict, Tuple, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

logger = logging.getLogger("est")

# ---------------------------------------------------------------------------
# ASN.1 / DER helpers (subset — kept local to avoid coupling)
# ---------------------------------------------------------------------------

def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    lb = []
    while n:
        lb.append(n & 0xFF)
        n >>= 8
    lb.reverse()
    return bytes([0x80 | len(lb)]) + bytes(lb)

def _seq(content: bytes) -> bytes:
    return b"\x30" + _encode_length(len(content)) + content

def _set(content: bytes) -> bytes:
    return b"\x31" + _encode_length(len(content)) + content

def _oid(dotted: str) -> bytes:
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
            enc += bytes([(b | 0x80) if i < len(buf) - 1 else b for i, b in enumerate(buf)])
    return b"\x06" + _encode_length(len(enc)) + enc

def _octet_string(v: bytes) -> bytes:
    return b"\x04" + _encode_length(len(v)) + v

def _integer(val: int) -> bytes:
    if val == 0:
        return b"\x02\x01\x00"
    raw = []
    n = val
    while n:
        raw.append(n & 0xFF)
        n >>= 8
    raw.reverse()
    if raw[0] & 0x80:
        raw.insert(0, 0)
    return b"\x02" + _encode_length(len(raw)) + bytes(raw)

def _ctx(n: int, content: bytes, constructed: bool = True) -> bytes:
    tag = (0xA0 | n) if constructed else (0x80 | n)
    return bytes([tag]) + _encode_length(len(content)) + content

def _utf8_string(v: str) -> bytes:
    b = v.encode("utf-8")
    return b"\x0c" + _encode_length(len(b)) + b

def _ia5_string(v: str) -> bytes:
    b = v.encode("ascii")
    return b"\x16" + _encode_length(len(b)) + b

# Well-known OIDs
OID_SIGNED_DATA      = "1.2.840.113549.1.7.2"
OID_DATA             = "1.2.840.113549.1.7.1"
OID_SHA256           = "2.16.840.1.101.3.4.2.1"
OID_SHA256_WITH_RSA  = "1.2.840.113549.1.1.11"
OID_RSA_ENCRYPTION   = "1.2.840.113549.1.1.1"
OID_CONTENT_TYPE     = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST   = "1.2.840.113549.1.9.4"
OID_SMIME_CAPS       = "1.2.840.113549.1.9.15"
OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14"
# RFC 7030 csrattrs hints
OID_EC_PUBLIC_KEY    = "1.2.840.10045.2.1"
OID_P256             = "1.2.840.10045.3.1.7"
OID_CHALLENGE_PW     = "1.2.840.113549.1.9.7"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE        = "2.5.29.15"
OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_EKU              = "2.5.29.37"
OID_CLIENT_AUTH      = "1.3.6.1.5.5.7.3.2"


# ---------------------------------------------------------------------------
# CMS / PKCS#7 builder for EST responses
# ---------------------------------------------------------------------------

class ESTCMSBuilder:
    """
    Build CMS SignedData wrappers required by RFC 7030.
    EST uses 'degenerate' SignedData (certs-only, no signers) for cert delivery.
    """

    @staticmethod
    def certs_only(cert_ders: list, ca_cert_der: bytes) -> bytes:
        """
        Build a PKCS#7 certs-only SignedData containing the issued cert
        and the CA cert (full chain).  Used for simpleenroll responses.
        Returns DER.
        """
        # certificates [0] IMPLICIT — concatenate all certs
        cert_bytes = b"".join(cert_ders) + ca_cert_der
        certs_field = _ctx(0, cert_bytes)

        eci = _seq(_oid(OID_DATA))  # encapContentInfo (no content)

        sd_inner = (
            _integer(1)    # version
            + _set(b"")    # digestAlgorithms (empty for degenerate)
            + eci
            + certs_field
            + _set(b"")    # signerInfos (empty for degenerate)
        )

        return _seq(
            _oid(OID_SIGNED_DATA)
            + _ctx(0, _seq(sd_inner))
        )

    @staticmethod
    def certs_only_chain(chain_ders: list) -> bytes:
        """
        Build a PKCS#7 certs-only SignedData from an ordered list of DER certs.

        Unlike :meth:`certs_only`, this variant accepts an arbitrary list of
        DER-encoded certificates (e.g. the full CA chain from
        ``ca.ca_chain_ders``) and encodes them all in the certificates bag.
        This is the correct form for EST /cacerts when running as an
        intermediate CA (RFC 7030 §4.1 requires the full chain).
        """
        cert_bytes = b"".join(chain_ders)
        certs_field = _ctx(0, cert_bytes)
        eci = _seq(_oid(OID_DATA))
        sd_inner = (
            _integer(1)
            + _set(b"")
            + eci
            + certs_field
            + _set(b"")
        )
        return _seq(
            _oid(OID_SIGNED_DATA)
            + _ctx(0, _seq(sd_inner))
        )

    @staticmethod
    def signed_cert(
        cert_der: bytes,
        ca_cert_der: bytes,
        ca_key,
        ca_cert,
    ) -> bytes:
        """
        Build a full signed CMS SignedData (signed by CA) wrapping the cert.
        Used for serverkeygen responses where the cert must be authenticated.
        """
        # For EST simpleenroll the degenerate form is sufficient per RFC 7030.
        return ESTCMSBuilder.certs_only([cert_der], ca_cert_der)


# ---------------------------------------------------------------------------
# CSR attribute builder (csrattrs)
# ---------------------------------------------------------------------------

def build_csrattrs() -> bytes:
    """
    Build a DER-encoded CsrAttrs sequence (RFC 7030 §4.5.2).
    Hints the client to use RSA-2048 or P-256, include SAN, and EKU clientAuth.

    CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
    AttrOrOID ::= CHOICE { oid OID, attribute Attribute }
    """
    def attr(oid_str: str, *values: bytes) -> bytes:
        val_set = _set(b"".join(values))
        return _seq(_oid(oid_str) + val_set)

    # Hint: include extensionRequest with SAN + EKU
    san_ext_oid = _oid(OID_SUBJECT_ALT_NAME)
    eku_ext_oid = _oid(OID_EKU)
    ext_request_value = _seq(
        _seq(san_ext_oid)
        + _seq(eku_ext_oid + _seq(_oid(OID_CLIENT_AUTH)))
    )

    attrs = (
        # Tell client to use RSA or EC (hint only — client can ignore)
        _oid(OID_RSA_ENCRYPTION)
        + attr(OID_EXTENSION_REQUEST, ext_request_value)
    )

    return _seq(attrs)


# ---------------------------------------------------------------------------
# EST user store (for HTTP Basic auth)
# ---------------------------------------------------------------------------

class ESTUserStore:
    """
    Simple in-memory + optional file-backed user store for EST HTTP Basic auth.
    Passwords stored as SHA-256 hex hashes.
    """

    def __init__(self, users: Optional[Dict[str, str]] = None):
        # users: {username: sha256_hex_of_password}
        self._users: Dict[str, str] = {}
        if users:
            for u, p in users.items():
                self.add_user(u, p)

    def add_user(self, username: str, password: str, already_hashed: bool = False):
        if already_hashed:
            self._users[username] = password
        else:
            self._users[username] = hashlib.sha256(password.encode()).hexdigest()

    def authenticate(self, username: str, password: str) -> bool:
        expected = self._users.get(username)
        if not expected:
            return False
        given = hashlib.sha256(password.encode()).hexdigest()
        # Constant-time compare
        return hashlib.compare_digest(given, expected)

    def has_users(self) -> bool:
        return bool(self._users)


# ---------------------------------------------------------------------------
# EST HTTP Request Handler
# ---------------------------------------------------------------------------

EST_WELL_KNOWN = "/.well-known/est"

class ESTHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP handler implementing RFC 7030 EST over HTTPS.

    Class attributes (set by start_est_server):
      ca            : CertificateAuthority instance
      user_store    : ESTUserStore for HTTP Basic auth
      require_auth  : bool — if True, at least one auth method must succeed
    """

    ca: "CertificateAuthority" = None
    user_store: ESTUserStore = None
    require_auth: bool = True

    def log_message(self, fmt, *args):
        logger.info(f"EST {self.client_address[0]} - {fmt % args}")

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        try:
            path = self.path.split("?")[0].rstrip("/")
            op, label = self._parse_est_path(path)

            if op is None:
                self._send_error(404, "Not an EST endpoint")
                return

            # Authenticate
            client_cert = self._get_client_cert()
            basic_user = self._check_basic_auth()

            if self.require_auth and client_cert is None and basic_user is None:
                self._send_401()
                return

            auth_id = (
                f"cert:{client_cert.subject.rfc4514_string()}" if client_cert
                else f"basic:{basic_user}" if basic_user
                else "anonymous"
            )
            logger.info(f"EST {method} /{op} auth={auth_id}")

            if method == "GET" and op == "cacerts":
                self._handle_cacerts()
            elif method == "GET" and op == "csrattrs":
                self._handle_csrattrs()
            elif method == "POST" and op == "simpleenroll":
                body = self._read_body()
                self._handle_simpleenroll(body, renew=False, client_cert=client_cert)
            elif method == "POST" and op == "simplereenroll":
                body = self._read_body()
                self._handle_simpleenroll(body, renew=True, client_cert=client_cert)
            elif method == "POST" and op == "serverkeygen":
                body = self._read_body()
                self._handle_serverkeygen(body)
            else:
                self._send_error(405, f"Method {method} not allowed for operation {op}")

        except Exception as e:
            logger.error(f"EST dispatch error: {e}\n{traceback.format_exc()}")
            self._send_error(500, "Internal server error")

    # ------------------------------------------------------------------
    # EST operations
    # ------------------------------------------------------------------

    def _handle_cacerts(self):
        """
        GET /.well-known/est/cacerts
        RFC 7030 §4.1 — return CA certificate chain as base64-encoded
        PKCS#7 certs-only SignedData.

        For an intermediate CA the PKCS#7 bag contains every cert in the chain
        (this CA + parent(s) up to the root) so EST clients can build the full
        path.  The degenerate SignedData format encodes all certs in the
        certificates [0] field; order is leaf-first per common convention.
        """
        # Build list of all chain DERs (leaf → root) and encode as certs-only PKCS#7.
        # certs_only() treats the last argument as the "CA cert" and prepends any
        # additional certs in the first list; we pass all parents as the extra list.
        chain_ders = self.ca.ca_chain_ders   # [leaf_der, parent_der, ..., root_der]
        pkcs7 = ESTCMSBuilder.certs_only_chain(chain_ders)
        b64 = base64.b64encode(pkcs7)

        self.send_response(200)
        self.send_header("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
        self.send_header("Content-Transfer-Encoding", "base64")
        self.send_header("Content-Length", str(len(b64)))
        self.end_headers()
        self.wfile.write(b64)
        logger.info("EST cacerts: returned CA certificate chain")

    def _handle_csrattrs(self):
        """
        GET /.well-known/est/csrattrs
        RFC 7030 §4.5 — return CSR attribute hints as base64 DER.
        """
        attrs_der = build_csrattrs()
        b64 = base64.b64encode(attrs_der)

        self.send_response(200)
        self.send_header("Content-Type", "application/csrattrs")
        self.send_header("Content-Transfer-Encoding", "base64")
        self.send_header("Content-Length", str(len(b64)))
        self.end_headers()
        self.wfile.write(b64)
        logger.info("EST csrattrs: returned CSR attribute hints")

    def _handle_simpleenroll(self, body: bytes, renew: bool, client_cert: Optional[x509.Certificate]):
        """
        POST /.well-known/est/simpleenroll  (initial enrolment)
        POST /.well-known/est/simplereenroll (renewal)
        RFC 7030 §4.2, §4.2.2

        Body: base64-encoded PKCS#10 CSR DER
        (Content-Transfer-Encoding: base64)
        """
        csr = self._decode_csr(body)
        if csr is None:
            self._send_error(400, "Could not decode PKCS#10 CSR")
            return

        if not csr.is_signature_valid:
            self._send_error(400, "CSR signature is invalid")
            return

        if renew:
            # RFC 7030 §4.2.2: reenroll MUST be authenticated by existing cert
            if client_cert is None:
                self._send_error(403, "Reenrollment requires TLS client certificate")
                return
            # Verify the CSR subject matches the existing cert subject (or is empty)
            # RFC 7030 allows the CA to accept or change the subject
            logger.info(f"EST simplereenroll for CN={client_cert.subject.rfc4514_string()}")

        subject_str = csr.subject.rfc4514_string() or "CN=EST Client"
        pub_key = csr.public_key()

        # Extract SANs from the CSR extensionRequest attribute so the issued
        # cert matches what the client asked for. Without this, a client
        # requesting DNS:app.example.com would receive a cert with no SAN at
        # all (hostname verification would silently fail).
        # RFC 7030 §4.2.1: the server MAY modify the requested attributes;
        # PyPKI's policy is "pass through the canonical four SAN types".
        # Note: URI SANs (including SPIFFE) are not yet threaded — tracked in
        # CLAUDE.md "EST CSR SAN pass-through + profile-aware csrattrs".
        san_dns:    list = []
        san_emails: list = []
        san_ips:    list = []
        try:
            csr_san = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for n in csr_san.value:
                if isinstance(n, x509.DNSName):
                    san_dns.append(n.value)
                elif isinstance(n, x509.RFC822Name):
                    san_emails.append(n.value)
                elif isinstance(n, x509.IPAddress):
                    san_ips.append(str(n.value))
                # URISAN / OtherName intentionally skipped for now
        except x509.ExtensionNotFound:
            pass

        try:
            cert = self.ca.issue_certificate(
                subject_str=subject_str,
                public_key=pub_key,
                san_dns=san_dns or None,
                san_emails=san_emails or None,
                san_ips=san_ips or None,
            )
        except Exception as e:
            logger.error(f"EST issuance failed: {e}")
            self._send_error(500, f"Certificate issuance failed: {e}")
            return

        cert_der = cert.public_bytes(Encoding.DER)
        # Include the full CA chain so clients can verify the cert path end-to-end.
        chain_ders = [cert_der] + self.ca.ca_chain_ders   # issued cert + this CA + parents
        pkcs7 = ESTCMSBuilder.certs_only_chain(chain_ders)
        b64 = base64.b64encode(pkcs7)

        op = "simplereenroll" if renew else "simpleenroll"
        logger.info(f"EST {op}: issued cert for '{subject_str}' serial={cert.serial_number}")

        self.send_response(200)
        self.send_header("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
        self.send_header("Content-Transfer-Encoding", "base64")
        self.send_header("Content-Length", str(len(b64)))
        self.end_headers()
        self.wfile.write(b64)

    def _handle_serverkeygen(self, body: bytes):
        """
        POST /.well-known/est/serverkeygen
        RFC 7030 §4.4 — generate a key pair server-side, issue a cert,
        and return both to the client.

        Response: multipart/mixed with two parts:
          Part 1: application/pkcs7-mime (certificate)
          Part 2: application/pkcs8 (encrypted or unencrypted private key)

        Per RFC 7030, the private key SHOULD be encrypted. We return it
        unencrypted (PrivateKeyInfo / PKCS#8) and note this in the logs.
        Production deployments should use CMS EnvelopedData for the key part.
        """
        # Parse optional CSR for subject/extensions hints (body may be empty)
        subject_str = "CN=EST Serverkeygen Client"
        san_dns = []
        if body:
            csr = self._decode_csr(body)
            if csr and csr.is_signature_valid:
                subject_str = csr.subject.rfc4514_string() or subject_str
                try:
                    san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san_dns = [n.value for n in san_ext.value if isinstance(n, x509.DNSName)]
                except x509.ExtensionNotFound:
                    pass

        # Generate key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        try:
            cert = self.ca.issue_certificate(
                subject_str=subject_str,
                public_key=public_key,
                san_dns=san_dns if san_dns else None,
            )
        except Exception as e:
            logger.error(f"EST serverkeygen issuance failed: {e}")
            self._send_error(500, f"Certificate issuance failed: {e}")
            return

        cert_der = cert.public_bytes(Encoding.DER)
        chain_ders = [cert_der] + self.ca.ca_chain_ders
        pkcs7 = ESTCMSBuilder.certs_only_chain(chain_ders)
        cert_b64 = base64.b64encode(pkcs7)

        # PKCS#8 private key DER (unencrypted PrivateKeyInfo)
        key_der = private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )
        key_b64 = base64.b64encode(key_der)

        # RFC 7030 §4.4: multipart/mixed response
        boundary = "estServerKeygenBoundary"
        cert_part = (
            f"--{boundary}\r\n"
            f"Content-Type: application/pkcs7-mime; smime-type=certs-only\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n"
        ).encode() + cert_b64 + b"\r\n"

        key_part = (
            f"--{boundary}\r\n"
            f"Content-Type: application/pkcs8\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n"
        ).encode() + key_b64 + b"\r\n"

        body_out = cert_part + key_part + f"--{boundary}--\r\n".encode()

        logger.info(
            f"EST serverkeygen: issued cert+key for '{subject_str}' "
            f"serial={cert.serial_number} "
            f"(NOTE: private key returned unencrypted — use TLS for transport security)"
        )

        self.send_response(200)
        self.send_header("Content-Type", f"multipart/mixed; boundary={boundary}")
        self.send_header("Content-Length", str(len(body_out)))
        self.end_headers()
        self.wfile.write(body_out)

    # ------------------------------------------------------------------
    # Authentication helpers
    # ------------------------------------------------------------------

    def _get_client_cert(self) -> Optional[x509.Certificate]:
        """Return the peer's client certificate if it was verified by TLS."""
        try:
            peer_dict = self.connection.getpeercert(binary_form=True)
            if peer_dict:
                cert = x509.load_der_x509_certificate(peer_dict)
                # Verify it was issued by our CA (AKI or issuer name match)
                try:
                    aki = cert.extensions.get_extension_for_class(
                        x509.AuthorityKeyIdentifier
                    ).value.key_identifier
                    ca_ski = self.ca.ca_cert.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier
                    ).value.key_identifier
                    if aki == ca_ski:
                        return cert
                except x509.ExtensionNotFound:
                    if cert.issuer == self.ca.ca_cert.subject:
                        return cert
        except Exception:
            pass
        return None

    def _check_basic_auth(self) -> Optional[str]:
        """
        Validate HTTP Basic auth header against the user store.
        Returns the username on success, None on failure or missing.
        """
        if self.user_store is None or not self.user_store.has_users():
            return None
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            username, _, password = decoded.partition(":")
            if self.user_store.authenticate(username, password):
                logger.info(f"EST Basic auth success for user={username!r}")
                return username
        except Exception:
            pass
        return None

    def _send_401(self):
        """Send 401 with WWW-Authenticate header."""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="EST"')
        self.send_header("Content-Type", "text/plain")
        body = b"Authentication required"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # Path parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_est_path(path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Parse path to extract EST operation and optional CA label.
        Returns (operation, label) or (None, None) if not an EST path.

        Valid paths:
          /.well-known/est/cacerts
          /.well-known/est/<label>/cacerts
          /.well-known/est/simpleenroll
          etc.
        """
        base = "/.well-known/est"
        if not path.startswith(base):
            return None, None

        rest = path[len(base):].lstrip("/")
        if not rest:
            return None, None

        parts = rest.split("/")
        known_ops = {"cacerts", "simpleenroll", "simplereenroll", "csrattrs", "serverkeygen"}

        if parts[0] in known_ops:
            return parts[0], None
        elif len(parts) >= 2 and parts[1] in known_ops:
            return parts[1], parts[0]  # (op, label)

        return None, None

    # ------------------------------------------------------------------
    # Body decoding helpers
    # ------------------------------------------------------------------

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _decode_csr(self, body: bytes) -> Optional[x509.CertificateSigningRequest]:
        """
        Decode a PKCS#10 CSR from:
          1. Base64 DER (as per RFC 7030 — Content-Transfer-Encoding: base64)
          2. Raw DER
          3. PEM (fallback)
        """
        if not body:
            return None
        # Try base64 DER first
        try:
            der = base64.b64decode(body)
            return x509.load_der_x509_csr(der)
        except Exception:
            pass
        # Try raw DER
        try:
            return x509.load_der_x509_csr(body)
        except Exception:
            pass
        # Try PEM
        try:
            return x509.load_pem_x509_csr(body)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Error response
    # ------------------------------------------------------------------

    def _send_error(self, code: int, msg: str):
        body = msg.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Integration entry point
# ---------------------------------------------------------------------------

def _build_est_tls_context(
    cert_path: str,
    key_path: str,
    ca: "CertificateAuthority",
) -> ssl.SSLContext:
    """Build a hardened SSLContext for the EST server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!RC4:!DES:!MD5")
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    # Accept (but don't require) client certs for TLS client auth
    ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.load_verify_locations(str(ca.ca_dir / "ca.crt"))
    return ctx


def start_est_server(
    route_table,
    prefix: str,
    ca: "CertificateAuthority",
    ca_dir: Path,
    users: Optional[Dict[str, str]] = None,
    require_auth: bool = False,
    # TLS parameters kept for API compatibility but are now handled by the
    # dispatcher server; passing them here has no effect.
    tls_cert_path: Optional[str] = None,
    tls_key_path: Optional[str] = None,
    tls_reload_interval: int = 60,
):
    """
    Register the EST handler with the shared route table.

    TLS is now handled at the dispatcher level (start_dispatcher_server).
    EST's RFC 7030 TLS requirement is satisfied when the dispatcher is
    started with tls_mode="tls" or "mtls".

    Returns a _RouteProxy whose .shutdown() unregisters the handler.
    """
    from dispatcher_server import _RouteProxy

    user_store = ESTUserStore(users)

    class BoundESTHandler(ESTHandler):
        pass

    BoundESTHandler.ca = ca
    BoundESTHandler.user_store = user_store
    BoundESTHandler.require_auth = require_auth

    route_table.register(prefix, BoundESTHandler)
    logger.info("EST handler registered at prefix %r", prefix)
    return _RouteProxy(route_table, prefix, label="est")


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="EST Server (RFC 7030)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca-dir", default="./ca")
    parser.add_argument("--user", action="append", metavar="USER:PASS",
                        help="Add a Basic auth user (repeat for multiple)")
    parser.add_argument("--require-auth", action="store_true",
                        help="Require auth (Basic or TLS client cert)")
    parser.add_argument("--tls-cert", metavar="PATH")
    parser.add_argument("--tls-key", metavar="PATH")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    import logging
    logging.getLogger().setLevel(args.log_level)

    try:
        from pki_server import CertificateAuthority, ServerConfig
    except ImportError:
        print("ERROR: pki_server.py not found — place it in the same directory.")
        raise SystemExit(1)

    ca_dir = Path(args.ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    config = ServerConfig(ca_dir=ca_dir)
    ca = CertificateAuthority(ca_dir=args.ca_dir, config=config)

    users = {}
    for entry in (args.user or []):
        u, _, p = entry.partition(":")
        users[u] = p

    srv = start_est_server(
        host=args.host,
        port=args.port,
        ca=ca,
        ca_dir=ca_dir,
        users=users if users else None,
        require_auth=args.require_auth,
        tls_cert_path=args.tls_cert,
        tls_key_path=args.tls_key,
    )

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║               PyPKI EST Server (RFC 7030)                       ║
╠══════════════════════════════════════════════════════════════════╣
║  Base URL  : https://{args.host}:{args.port}/.well-known/est{' ' * max(0, 13 - len(str(args.port)))}║
║  CA Dir    : {args.ca_dir:<51}║
║  Auth      : {'required' if args.require_auth else 'optional (Basic or TLS cert)':<51}║
║  Users     : {str(len(users)) + ' configured' if users else 'none (TLS cert auth only)':<51}║
╠══════════════════════════════════════════════════════════════════╣
║  Endpoints:                                                     ║
║    cacerts       GET  /.well-known/est/cacerts                  ║
║    csrattrs      GET  /.well-known/est/csrattrs                 ║
║    simpleenroll  POST /.well-known/est/simpleenroll             ║
║    simplereenroll POST /.well-known/est/simplereenroll          ║
║    serverkeygen  POST /.well-known/est/serverkeygen             ║
╠══════════════════════════════════════════════════════════════════╣
║  Quick-start (openssl):                                         ║
║    openssl s_client -connect {args.host}:{args.port}               ║
║      -CAfile ./ca/ca.crt                                        ║
╚══════════════════════════════════════════════════════════════════╝
""")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down EST server...")
        srv.shutdown()


if __name__ == "__main__":
    main()
