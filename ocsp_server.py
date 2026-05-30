#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
OCSP Responder — RFC 6960 + RFC 5019 (Lightweight OCSP)
=========================================================
Online Certificate Status Protocol responder for the PyPKI CA.

Features:
  - POST /ocsp            : RFC 6960 §A.1 HTTP POST binding
  - GET  /ocsp/<b64req>   : RFC 5019 §5 GET binding (cacheable by CDN/proxy)
  - GET  /ocsp/           : Redirect hint (returns 400 with usage note)
  - Signed responses using the CA key or a dedicated OCSP signing certificate
  - Response pre-caching: responses are cached in-memory for `cache_seconds`
    (default 300 s) to reduce DB load — safe because status rarely changes
  - good / revoked / unknown responses with proper CertStatus encoding
  - Revocation reason code included in revoked responses
  - OCSP signing cert with id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2)

RFC 6960 response structure (DER):
  OCSPResponse ::= SEQUENCE {
    responseStatus         OCSPResponseStatus,
    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }

  ResponseBytes ::= SEQUENCE {
    responseType           OBJECT IDENTIFIER,
    response               OCTET STRING }

  BasicOCSPResponse ::= SEQUENCE {
    tbsResponseData        ResponseData,
    signatureAlgorithm     AlgorithmIdentifier,
    signature              BIT STRING,
    certs                  [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

Dependencies: cryptography (same as pki_server.py)
"""

import base64
import datetime
from datetime import timezone as _tz
import hashlib
import http.server
import logging
import os
import threading
import time
import traceback
from pathlib import Path
from typing import Optional, Dict, Tuple, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

logger = logging.getLogger("ocsp")

# §5.11 — import histogram lazily to avoid circular import at module load
def _get_hist_ocsp():
    from pki_server import _hist_ocsp  # noqa: PLC0415
    return _hist_ocsp

from der_codec import (
    encode_length as _enc_len, decode_length as _dec_len, decode_tlv as _dec_tlv,
    seq as _seq, set_ as _set, ctx as _ctx, oid as _oid,
    integer as _int, octet_string as _oct, bit_string as _bit,
    null as _null, generalized_time as _generalized_time, ia5_string as _ia5,
    decode_oid_bytes as _decode_oid_bytes,
    OID_SHA1, OID_SHA256, OID_RSA_ENCRYPTION, OID_SHA256_WITH_RSA,
    OID_BASIC_OCSP_RESP, OID_OCSP_NONCE, OID_OCSP_NOCHECK, OID_ID_PKIX_OCSP,
    OID_EXTENDED_KEY_USAGE, OID_EKU_OCSP_SIGNING,
)

# OCSP response status codes
RESP_SUCCESSFUL        = 0
RESP_MALFORMED_REQUEST = 1
RESP_INTERNAL_ERROR    = 2
RESP_TRY_LATER         = 3
RESP_SIG_REQUIRED      = 5
RESP_UNAUTHORIZED      = 6

# CertStatus
STATUS_GOOD     = 0
STATUS_REVOKED  = 1
STATUS_UNKNOWN  = 2


# ---------------------------------------------------------------------------
# OCSP request parser
# ---------------------------------------------------------------------------

class OCSPRequestParser:
    """Parse a DER-encoded OCSPRequest per RFC 6960 §4.1."""

    @staticmethod
    def parse(der: bytes) -> Optional[Dict[str, Any]]:
        """
        Returns dict with:
          serial         : int
          issuer_name_hash : bytes  (SHA-1 of issuer Name DER)
          issuer_key_hash  : bytes  (SHA-1 of issuer public key BIT STRING value)
          hash_alg         : str   ("sha1" or "sha256")
          nonce            : bytes or None
        """
        try:
            result: Dict[str, Any] = {}

            # OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, [0] signature OPTIONAL }
            tag, outer, _ = _dec_tlv(der, 0)

            # TBSRequest ::= SEQUENCE { [0] version, [1] requestorName, requestList, [2] requestExtensions }
            pos = 0
            tag, tbs_val, pos = _dec_tlv(outer, pos)

            # requestList SEQUENCE OF Request
            tbs_pos = 0
            # skip optional version [0]
            if tbs_pos < len(tbs_val) and tbs_val[tbs_pos] == 0xA0:
                _, _, tbs_pos = _dec_tlv(tbs_val, tbs_pos)
            # skip optional requestorName [1]
            if tbs_pos < len(tbs_val) and tbs_val[tbs_pos] == 0xA1:
                _, _, tbs_pos = _dec_tlv(tbs_val, tbs_pos)

            # requestList
            tag, req_list, tbs_pos = _dec_tlv(tbs_val, tbs_pos)

            # First Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0] OPTIONAL }
            tag, req_val, _ = _dec_tlv(req_list, 0)

            # CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
            tag, certid_val, _ = _dec_tlv(req_val, 0)

            cid_pos = 0
            # hashAlgorithm AlgorithmIdentifier
            tag, alg_seq, cid_pos = _dec_tlv(certid_val, cid_pos)
            tag, alg_oid_val, _ = _dec_tlv(alg_seq, 0)
            alg_oid = _decode_oid_bytes(alg_oid_val)
            result["hash_alg"] = "sha256" if alg_oid == OID_SHA256 else "sha1"

            # issuerNameHash OCTET STRING
            tag, result["issuer_name_hash"], cid_pos = _dec_tlv(certid_val, cid_pos)

            # issuerKeyHash OCTET STRING
            tag, result["issuer_key_hash"], cid_pos = _dec_tlv(certid_val, cid_pos)

            # serialNumber INTEGER
            tag, serial_bytes, cid_pos = _dec_tlv(certid_val, cid_pos)
            result["serial"] = int.from_bytes(serial_bytes, "big")

            # requestExtensions [2] — look for nonce
            result["nonce"] = None
            result["nonce_length_violation"] = False  # RFC 8954 enforcement signal
            if tbs_pos < len(tbs_val) and tbs_val[tbs_pos] == 0xA2:
                _, ext_seq, _ = _dec_tlv(tbs_val, tbs_pos)
                tag2, exts_val, _ = _dec_tlv(ext_seq, 0)
                epos = 0
                while epos < len(exts_val):
                    tag3, ext_val, epos = _dec_tlv(exts_val, epos)
                    try:
                        einner = 0
                        tag4, oid_val, einner = _dec_tlv(ext_val, einner)
                        oid_str = _decode_oid_bytes(oid_val)
                        if oid_str == OID_OCSP_NONCE:
                            _, nonce_oct, _ = _dec_tlv(ext_val, einner)
                            _, nonce_value, _ = _dec_tlv(nonce_oct, 0)
                            # RFC 8954 §2.1: the Nonce extension value MUST
                            # be at minimum 1 byte and at maximum 32 bytes.
                            # An out-of-bounds nonce is a malformed request.
                            if not (1 <= len(nonce_value) <= 32):
                                result["nonce_length_violation"] = True
                                result["nonce"] = nonce_value  # keep for logging
                            else:
                                result["nonce"] = nonce_value
                    except Exception:
                        pass

            return result

        except Exception as e:
            logger.debug(f"OCSP parse error: {e}")
            return None


# ---------------------------------------------------------------------------
# OCSP response builder
# ---------------------------------------------------------------------------

class OCSPResponseBuilder:
    """Build DER-encoded OCSP responses per RFC 6960."""

    @staticmethod
    def error(status_code: int) -> bytes:
        """Build an OCSPResponse with a non-successful status (no responseBytes)."""
        return _seq(_ctx(0, bytes([status_code]), constructed=False))

    @staticmethod
    def build(
        serial: int,
        cert_status: int,          # STATUS_GOOD / STATUS_REVOKED / STATUS_UNKNOWN
        revoked_at: Optional[datetime.datetime],
        revocation_reason: int,
        ca: "CertificateAuthority",
        ocsp_key,                  # signing key (CA key or dedicated OCSP key)
        ocsp_cert: x509.Certificate,  # cert of the signing key
        this_update: datetime.datetime,
        next_update: datetime.datetime,
        nonce: Optional[bytes] = None,
    ) -> bytes:
        """Build a signed BasicOCSPResponse wrapped in OCSPResponse."""

        # ---- CertStatus ----
        if cert_status == STATUS_GOOD:
            cert_status_der = _ctx(0, b"", constructed=False)   # [0] IMPLICIT NULL
        elif cert_status == STATUS_REVOKED:
            rev_time = _generalized_time(revoked_at or datetime.datetime.now(_tz.utc))
            reason_enc = _ctx(0, _seq(_int(revocation_reason)), constructed=True)
            revoked_info = rev_time + reason_enc
            cert_status_der = _ctx(1, revoked_info)              # [1] RevokedInfo
        else:
            cert_status_der = _ctx(2, b"", constructed=False)    # [2] IMPLICIT NULL

        # ---- CertID (SHA-256 based) ----
        ca_name_der = ca.ca_cert.subject.public_bytes()
        issuer_name_hash = hashlib.sha256(ca_name_der).digest()
        # Public key bit string value (strip tag+len+unused-bits byte)
        pub_der = ca.ca_key.public_key().public_bytes(Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        # Extract BIT STRING value from SPKI
        try:
            _, spki_inner, _ = _dec_tlv(pub_der, 0)
            spki_pos = 0
            _, _, spki_pos = _dec_tlv(spki_inner, spki_pos)  # skip algorithm
            _, bit_string_val, _ = _dec_tlv(spki_inner, spki_pos)
            issuer_key_hash = hashlib.sha256(bit_string_val[1:]).digest()  # skip unused bits byte
        except Exception:
            issuer_key_hash = hashlib.sha256(pub_der).digest()

        hash_alg = _seq(_oid(OID_SHA256) + _null())
        cert_id = _seq(
            hash_alg
            + _oct(issuer_name_hash)
            + _oct(issuer_key_hash)
            + _int(serial)
        )

        # ---- SingleResponse ----
        single_resp = _seq(
            cert_id
            + cert_status_der
            + _generalized_time(this_update)
            + _ctx(0, _generalized_time(next_update))  # [0] nextUpdate
        )

        # ---- ResponseData ----
        # responderID CHOICE [2] byKey (SubjectKeyIdentifier)
        try:
            ski = ocsp_cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value.key_identifier
            responder_id = _ctx(2, _oct(ski))  # [2] byKey
        except Exception:
            # Fall back to [1] byName
            responder_id = _ctx(1, ocsp_cert.subject.public_bytes())

        extensions_der = b""
        if nonce is not None:
            nonce_ext = _seq(
                _oid(OID_OCSP_NONCE)
                + _oct(_oct(nonce))   # double-wrapped per RFC 6960
            )
            extensions_der = _ctx(1, _seq(nonce_ext))

        tbs_response_data = _seq(
            responder_id
            + _generalized_time(this_update)   # producedAt
            + _seq(single_resp)                # responses
            + extensions_der
        )

        # ---- Sign ----
        signature_bytes = ocsp_key.sign(
            tbs_response_data,
            asym_padding.PKCS1v15(),
            SHA256(),
        )

        sig_alg = _seq(_oid(OID_SHA256_WITH_RSA) + _null())
        sig_bit = _bit(signature_bytes)

        # Include signing cert in [0] certs
        certs_field = _ctx(0, _seq(ocsp_cert.public_bytes(Encoding.DER)))

        basic_ocsp_resp = _seq(tbs_response_data + sig_alg + sig_bit + certs_field)

        # ---- Wrap in ResponseBytes ----
        response_bytes = _seq(_oid(OID_BASIC_OCSP_RESP) + _oct(basic_ocsp_resp))

        # ---- OCSPResponse ----
        return _seq(
            _ctx(0, bytes([RESP_SUCCESSFUL]), constructed=False)  # responseStatus
            + _ctx(0, response_bytes)                             # responseBytes [0]
        )


# ---------------------------------------------------------------------------
# OCSP signing certificate provisioner
# ---------------------------------------------------------------------------

def provision_ocsp_signing_cert(ca: "CertificateAuthority") -> Tuple[Any, x509.Certificate]:
    """
    Issue (or reuse) a dedicated OCSP signing certificate.
    The OCSP signing cert has:
      - EKU: OCSPSigning
      - id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2) — tells clients
        not to check the revocation status of this cert itself
      - Short validity (30 days, auto-renewed)
    Returns (private_key, certificate).
    """
    ocsp_key_path  = ca.ca_dir / "ocsp.key"
    ocsp_cert_path = ca.ca_dir / "ocsp.crt"

    # Reuse if valid for at least 7 more days
    if ocsp_key_path.exists() and ocsp_cert_path.exists():
        try:
            with open(ocsp_key_path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            with open(ocsp_cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            if cert.not_valid_after_utc > (
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
            ):
                logger.info("Reusing existing OCSP signing certificate")
                return key, cert
        except Exception as e:
            logger.warning(f"OCSP cert reload failed: {e}, re-issuing")

    logger.info("Generating OCSP signing key and certificate...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(_tz.utc)

    # id-pkix-ocsp-nocheck OID
    ocsp_nocheck_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")

    ocsp_builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "PyPKI OCSP Responder"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyPKI"),
        ]))
        .issuer_name(ca.ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(ca._next_serial())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.ca_key.public_key()),
            critical=False,
        )
        # id-pkix-ocsp-nocheck: clients MUST NOT check revocation status of this cert
        .add_extension(
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.5"),
                value=b"\x05\x00",  # NULL value
            ),
            critical=False,
        )
    )
    # Signed via pki_server._sign_builder so the right (hash, padding) is
    # picked for RSA / ECDSA / EdDSA CAs (RFC 5758, RFC 8410, RFC 4055).
    try:
        from pki_server import _sign_builder as _pki_sign_builder
        cert = _pki_sign_builder(
            ocsp_builder, ca.ca_key,
            rsa_pss=getattr(ca, "_rsa_pss", False),
        )
    except ImportError:
        cert = ocsp_builder.sign(ca.ca_key, SHA256())

    # RFC 5958 PKCS#8 — works for RSA, EC, and EdDSA OCSP signer keys.
    with open(ocsp_key_path, "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    with open(ocsp_cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

    logger.info(f"OCSP signing cert issued, valid until {cert.not_valid_after_utc.date()}")
    return key, cert


# ---------------------------------------------------------------------------
# Response cache
# ---------------------------------------------------------------------------

class OCSPResponseCache:
    """Simple TTL cache for pre-built OCSP responses."""

    def __init__(self, ttl_seconds: int = 300):
        self._cache: Dict[int, Tuple[bytes, float]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def get(self, serial: int) -> Optional[bytes]:
        with self._lock:
            entry = self._cache.get(serial)
            if entry and time.time() < entry[1]:
                return entry[0]
        return None

    def put(self, serial: int, response: bytes):
        with self._lock:
            self._cache[serial] = (response, time.time() + self._ttl)

    def invalidate(self, serial: int):
        with self._lock:
            self._cache.pop(serial, None)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class OCSPHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP handler for the OCSP responder.
    Supports:
      POST /ocsp             RFC 6960 §A.1
      GET  /ocsp/<base64>    RFC 5019 §5 (CDN-cacheable)
    """

    ca: "CertificateAuthority" = None
    ocsp_key = None
    ocsp_cert: x509.Certificate = None
    cache: OCSPResponseCache = None
    cache_max_age: int = 300   # seconds for Cache-Control header
    require_nonce: bool = False  # RFC 8954 strict-mode toggle (--ocsp-require-nonce)

    def log_message(self, fmt, *args):
        logger.debug(f"OCSP {self.client_address[0]} - {fmt % args}")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        response = self._handle_request(body)
        self._send_raw(200, response, "application/ocsp-response")

    def do_GET(self):
        path = self.path.split("?")[0]
        # Accept both "/" (root, no b64) and "/<b64>" (GET binding per RFC 5019)
        b64_part = path.lstrip("/")
        if not b64_part:
            self._send_raw(400, OCSPResponseBuilder.error(RESP_MALFORMED_REQUEST),
                           "application/ocsp-response")
            return

        try:
            # RFC 5019: URL-safe base64, may or may not have padding
            b64_padded = b64_part + "=" * (-len(b64_part) % 4)
            req_der = base64.urlsafe_b64decode(b64_padded)
        except Exception:
            self._send_raw(400, OCSPResponseBuilder.error(RESP_MALFORMED_REQUEST),
                           "application/ocsp-response")
            return

        response = self._handle_request(req_der, cacheable=True)
        self._send_raw(200, response, "application/ocsp-response", cacheable=True)

    def _handle_request(self, req_der: bytes, cacheable: bool = False) -> bytes:
        parsed = OCSPRequestParser.parse(req_der)
        if parsed is None:
            return OCSPResponseBuilder.error(RESP_MALFORMED_REQUEST)

        # RFC 8954 §2.1 enforcement: a nonce extension whose value is not
        # 1..32 bytes MUST cause the request to be treated as malformed.
        if parsed.get("nonce_length_violation"):
            bad_len = len(parsed.get("nonce") or b"")
            logger.info(
                f"OCSP nonce length violation: {bad_len} bytes "
                f"(RFC 8954 §2.1 requires 1..32)"
            )
            return OCSPResponseBuilder.error(RESP_MALFORMED_REQUEST)

        serial = parsed["serial"]
        nonce  = parsed.get("nonce")

        # RFC 8954 strict-mode: reject nonceless requests with `unauthorized`
        # so a man-in-the-middle cannot replay cached responses.
        if self.require_nonce and nonce is None:
            logger.info(
                "OCSP request rejected: nonce required by --ocsp-require-nonce"
            )
            return OCSPResponseBuilder.error(RESP_UNAUTHORIZED)

        # Check cache (only for GET / no nonce — nonce responses can't be cached)
        if cacheable and nonce is None:
            cached = self.cache.get(serial) if self.cache else None
            if cached:
                return cached

        try:
            row = self.ca._pki_db.fetchone(
                "SELECT serial, revoked, revoked_at, reason FROM certificates WHERE serial=?",
                (serial,)
            )
        except Exception as e:
            logger.error(f"OCSP DB error: {e}")
            return OCSPResponseBuilder.error(RESP_INTERNAL_ERROR)

        now = datetime.datetime.now(_tz.utc)
        next_update = now + datetime.timedelta(seconds=self.cache_max_age)

        if row is None:
            status = STATUS_UNKNOWN
            revoked_at = None
            reason = 0
        elif row["revoked"]:
            status = STATUS_REVOKED
            try:
                revoked_at = datetime.datetime.fromisoformat(row["revoked_at"])
            except Exception:
                revoked_at = now
            reason = row["reason"] or 0
        else:
            status = STATUS_GOOD
            revoked_at = None
            reason = 0

        _t0 = time.perf_counter()
        response = OCSPResponseBuilder.build(
            serial=serial,
            cert_status=status,
            revoked_at=revoked_at,
            revocation_reason=reason,
            ca=self.ca,
            ocsp_key=self.ocsp_key,
            ocsp_cert=self.ocsp_cert,
            this_update=now,
            next_update=next_update,
            nonce=nonce,
        )
        _get_hist_ocsp().observe(time.perf_counter() - _t0)

        logger.info(
            f"OCSP serial={serial} "
            f"status={'good' if status==STATUS_GOOD else 'revoked' if status==STATUS_REVOKED else 'unknown'}"
        )

        if cacheable and nonce is None and self.cache:
            self.cache.put(serial, response)

        return response

    def _send_raw(self, code: int, body: bytes, content_type: str, cacheable: bool = False):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cacheable and body:
            self.send_header("Cache-Control", f"max-age={self.cache_max_age}, public")
        else:
            self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Integration entry point
# ---------------------------------------------------------------------------

def start_ocsp_server(
    route_table,
    prefix: str,
    ca: "CertificateAuthority",
    cache_seconds: int = 300,
    require_nonce: bool = False,
):
    """
    Register the OCSP handler with *route_table* under *prefix*.

    Returns a _RouteProxy whose .shutdown() unregisters the OCSP routes.

    Backwards-compatible standalone mode: when *route_table* is a ``str``
    (host address) and *prefix* is an ``int`` (port), a real
    ``ThreadingHTTPServer`` is started and returned directly.

    ``require_nonce`` enables RFC 8954 strict mode: requests without a
    nonce extension are rejected with status 'unauthorized'. Default is
    off, matching RFC 6960 default behavior.
    """
    # Backwards-compat: start_ocsp_server(host, port, ca, cache_seconds=N)
    if isinstance(route_table, str) and isinstance(prefix, int):
        return _start_ocsp_standalone(route_table, prefix, ca, cache_seconds, require_nonce)

    from dispatcher_server import _RouteProxy

    ocsp_key, ocsp_cert = provision_ocsp_signing_cert(ca)
    cache = OCSPResponseCache(ttl_seconds=cache_seconds)

    class BoundOCSPHandler(OCSPHandler):
        pass

    BoundOCSPHandler.ca = ca
    BoundOCSPHandler.ocsp_key = ocsp_key
    BoundOCSPHandler.ocsp_cert = ocsp_cert
    BoundOCSPHandler.cache = cache
    BoundOCSPHandler.cache_max_age = cache_seconds
    BoundOCSPHandler.require_nonce = require_nonce

    route_table.register(prefix, BoundOCSPHandler)
    logger.info(
        f"OCSP handler registered at prefix {prefix!r} "
        f"(require_nonce={require_nonce})"
    )
    return _RouteProxy(route_table, prefix, label="ocsp")


def _start_ocsp_standalone(
    host: str,
    port: int,
    ca: "CertificateAuthority",
    cache_seconds: int = 300,
    require_nonce: bool = False,
):
    """Start a real standalone HTTP OCSP server on host:port (backwards-compat mode)."""
    import http.server
    import threading

    ocsp_key, ocsp_cert = provision_ocsp_signing_cert(ca)
    cache = OCSPResponseCache(ttl_seconds=cache_seconds)

    class _StandaloneOCSPHandler(OCSPHandler):
        pass

    _StandaloneOCSPHandler.ca = ca
    _StandaloneOCSPHandler.ocsp_key = ocsp_key
    _StandaloneOCSPHandler.ocsp_cert = ocsp_cert
    _StandaloneOCSPHandler.cache = cache
    _StandaloneOCSPHandler.cache_max_age = cache_seconds
    _StandaloneOCSPHandler.require_nonce = require_nonce

    server = http.server.ThreadingHTTPServer((host, port), _StandaloneOCSPHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    logger.info("OCSP standalone server started on %s:%d", host, port)
    return server


# ---------------------------------------------------------------------------
# Pre-generated OCSP response builder (RFC 5019 §6)
# ---------------------------------------------------------------------------

def generate_static_responses(
    ca: "CertificateAuthority",
    output_dir,
    validity_hours: int = 24,
) -> int:
    """
    Pre-generate one signed OCSP response file per certificate in *ca*.

    Files are written under:
      <output_dir>/<sha1-issuer-key>/<sha1-issuer-name>/<serial>.ocsp

    This path layout is compatible with nginx ``proxy_cache``, Apache
    ``mod_ssl_ct``, and static file serving for OCSP stapling.

    Each response has ``thisUpdate=now`` and ``nextUpdate=now+validity_hours``.
    No nonce is embedded (static files cannot be nonce-bound).

    Returns the count of files written.
    """
    from pathlib import Path as _Path
    import hashlib as _hashlib

    output_dir = _Path(output_dir)
    ocsp_key, ocsp_cert = provision_ocsp_signing_cert(ca)

    now = datetime.datetime.now(_tz.utc)
    next_update = now + datetime.timedelta(hours=validity_hours)

    # Path components: SHA-1 hex of the raw DER bytes fed into the CertID
    ca_name_der = ca.ca_cert.subject.public_bytes()
    issuer_name_hash = _hashlib.sha1(ca_name_der).hexdigest()

    pub_der = ca.ca_key.public_key().public_bytes(
        Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        _, spki_inner, _ = _dec_tlv(pub_der, 0)
        spki_pos = 0
        _, _, spki_pos = _dec_tlv(spki_inner, spki_pos)  # skip AlgorithmIdentifier
        _, bit_string_val, _ = _dec_tlv(spki_inner, spki_pos)
        key_bytes = bit_string_val[1:]  # strip the leading unused-bits byte
    except Exception:
        key_bytes = pub_der
    issuer_key_hash = _hashlib.sha1(key_bytes).hexdigest()

    cert_dir = output_dir / issuer_key_hash / issuer_name_hash
    cert_dir.mkdir(parents=True, exist_ok=True)

    rows = ca._pki_db.fetchall(
        "SELECT serial, revoked, revoked_at, reason FROM certificates"
    )

    count = 0
    for row in rows:
        serial = row["serial"]
        if row["revoked"]:
            status = STATUS_REVOKED
            try:
                revoked_at = datetime.datetime.fromisoformat(row["revoked_at"])
            except Exception:
                revoked_at = now
            reason = row["reason"] or 0
        else:
            status = STATUS_GOOD
            revoked_at = None
            reason = 0

        resp = OCSPResponseBuilder.build(
            serial=serial,
            cert_status=status,
            revoked_at=revoked_at,
            revocation_reason=reason,
            ca=ca,
            ocsp_key=ocsp_key,
            ocsp_cert=ocsp_cert,
            this_update=now,
            next_update=next_update,
            nonce=None,
        )

        (cert_dir / f"{serial}.ocsp").write_bytes(resp)
        count += 1

    logger.info(
        f"Pre-generated {count} OCSP responses in {cert_dir} "
        f"(validity={validity_hours}h)"
    )
    return count


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="OCSP Responder (RFC 6960 / RFC 5019)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--ca-dir", default="./ca")
    parser.add_argument("--cache-seconds", type=int, default=300)
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    import logging as _log
    _log.getLogger().setLevel(args.log_level)

    try:
        from pki_server import CertificateAuthority, ServerConfig
    except ImportError:
        print("ERROR: pki_server.py not found.")
        raise SystemExit(1)

    ca_dir = Path(args.ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    config = ServerConfig(ca_dir=ca_dir)
    ca = CertificateAuthority(ca_dir=args.ca_dir, config=config)

    srv = start_ocsp_server(
        host=args.host,
        port=args.port,
        ca=ca,
        cache_seconds=args.cache_seconds,
    )

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║            PyPKI OCSP Responder (RFC 6960 / RFC 5019)          ║
╠══════════════════════════════════════════════════════════════════╣
║  POST http://{args.host}:{args.port}/ocsp                              ║
║  GET  http://{args.host}:{args.port}/ocsp/<base64-req>                 ║
║  Cache TTL : {args.cache_seconds} seconds                                     ║
╠══════════════════════════════════════════════════════════════════╣
║  Test:                                                          ║
║    openssl ocsp -issuer ca/ca.crt -cert <cert.pem>              ║
║      -url http://{args.host}:{args.port}/ocsp -resp_text          ║
╚══════════════════════════════════════════════════════════════════╝
""")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down OCSP responder...")
        srv.shutdown()


if __name__ == "__main__":
    main()
