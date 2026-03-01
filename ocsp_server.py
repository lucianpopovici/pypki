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

# ---------------------------------------------------------------------------
# DER / ASN.1 helpers
# ---------------------------------------------------------------------------

def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    lb = []
    while n:
        lb.append(n & 0xFF)
        n >>= 8
    lb.reverse()
    return bytes([0x80 | len(lb)]) + bytes(lb)

def _dec_len(data: bytes, pos: int) -> Tuple[int, int]:
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    nb = b & 0x7F
    return int.from_bytes(data[pos+1:pos+1+nb], "big"), pos + 1 + nb

def _dec_tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
    tag = data[pos]
    l, vstart = _dec_len(data, pos + 1)
    return tag, data[vstart:vstart+l], vstart + l

def _seq(c: bytes) -> bytes:
    return b"\x30" + _enc_len(len(c)) + c

def _set(c: bytes) -> bytes:
    return b"\x31" + _enc_len(len(c)) + c

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
            enc += bytes([(b | 0x80) if i < len(buf)-1 else b for i, b in enumerate(buf)])
    return b"\x06" + _enc_len(len(enc)) + enc

def _int(v: int) -> bytes:
    if v == 0:
        return b"\x02\x01\x00"
    raw = []
    n = v
    while n:
        raw.append(n & 0xFF)
        n >>= 8
    raw.reverse()
    if raw[0] & 0x80:
        raw.insert(0, 0)
    return b"\x02" + _enc_len(len(raw)) + bytes(raw)

def _oct(v: bytes) -> bytes:
    return b"\x04" + _enc_len(len(v)) + v

def _bit(v: bytes, unused: int = 0) -> bytes:
    return b"\x03" + _enc_len(len(v) + 1) + bytes([unused]) + v

def _ctx(n: int, c: bytes, constructed: bool = True) -> bytes:
    tag = (0xA0 | n) if constructed else (0x80 | n)
    return bytes([tag]) + _enc_len(len(c)) + c

def _null() -> bytes:
    return b"\x05\x00"

def _generalized_time(dt: datetime.datetime) -> bytes:
    s = dt.strftime("%Y%m%d%H%M%SZ").encode()
    return b"\x18" + _enc_len(len(s)) + s

def _ia5(v: str) -> bytes:
    b = v.encode("ascii")
    return b"\x16" + _enc_len(len(b)) + b

# OID constants
OID_SHA1               = "1.3.14.3.2.26"
OID_SHA256             = "2.16.840.1.101.3.4.2.1"
OID_RSA_ENCRYPTION     = "1.2.840.113549.1.1.1"
OID_SHA256_WITH_RSA    = "1.2.840.113549.1.1.11"
OID_BASIC_OCSP_RESP    = "1.3.6.1.5.5.7.48.1.1"
OID_OCSP_NONCE         = "1.3.6.1.5.5.7.48.1.2"
OID_OCSP_NOCHECK       = "1.3.6.1.5.5.7.48.1.5"
OID_ID_PKIX_OCSP       = "1.3.6.1.5.5.7.48.1"
OID_EXTENDED_KEY_USAGE = "2.5.29.37"
OID_EKU_OCSP_SIGNING   = "1.3.6.1.5.5.7.3.9"

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
                            _, result["nonce"], _ = _dec_tlv(nonce_oct, 0)
                    except Exception:
                        pass

            return result

        except Exception as e:
            logger.debug(f"OCSP parse error: {e}")
            return None


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

    cert = (
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
        .sign(ca.ca_key, SHA256())
    )

    with open(ocsp_key_path, "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
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

    def log_message(self, fmt, *args):
        logger.debug(f"OCSP {self.client_address[0]} - {fmt % args}")

    def do_POST(self):
        if not self.path.rstrip("/").startswith("/ocsp"):
            self._send_raw(400, b"", "application/ocsp-response")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        response = self._handle_request(body)
        self._send_raw(200, response, "application/ocsp-response")

    def do_GET(self):
        path = self.path.split("?")[0]
        if not path.startswith("/ocsp/"):
            self._send_raw(400, OCSPResponseBuilder.error(RESP_MALFORMED_REQUEST),
                           "application/ocsp-response")
            return

        b64_part = path[len("/ocsp/"):]
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

        serial = parsed["serial"]
        nonce  = parsed.get("nonce")

        # Check cache (only for GET / no nonce — nonce responses can't be cached)
        if cacheable and nonce is None:
            cached = self.cache.get(serial) if self.cache else None
            if cached:
                return cached

        try:
            import sqlite3
            conn = sqlite3.connect(str(self.ca.db_path))
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT serial, revoked, revoked_at, reason FROM certificates WHERE serial=?",
                (serial,)
            ).fetchone()
            conn.close()
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
    host: str,
    port: int,
    ca: "CertificateAuthority",
    cache_seconds: int = 300,
) -> http.server.HTTPServer:
    """Start OCSP responder in a background thread. Returns HTTPServer."""

    ocsp_key, ocsp_cert = provision_ocsp_signing_cert(ca)
    cache = OCSPResponseCache(ttl_seconds=cache_seconds)

    class BoundOCSPHandler(OCSPHandler):
        pass

    BoundOCSPHandler.ca = ca
    BoundOCSPHandler.ocsp_key = ocsp_key
    BoundOCSPHandler.ocsp_cert = ocsp_cert
    BoundOCSPHandler.cache = cache
    BoundOCSPHandler.cache_max_age = cache_seconds

    import http.server as _hs

    class _ThreadedServer(_hs.ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = _ThreadedServer((host, port), BoundOCSPHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info(f"OCSP responder listening on http://{host}:{port}/ocsp")
    return srv


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="OCSP Responder (RFC 6960 / RFC 5019)")
    parser.add_argument("--host", default="localhost")
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
