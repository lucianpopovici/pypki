#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
TSA Server — RFC 3161 + RFC 5816
==================================
Time-Stamp Authority (TSA) server for the PyPKI CA.

Features:
  - POST /tsa             : RFC 3161 §2.4 HTTP transport
  - TimeStampReq parser   : version, messageImprint, nonce, certReq
  - TimeStampResp builder : CMS SignedData wrapping TSTInfo
  - RFC 5816              : signingCertificateV2 (ESSCertIDv2 with SHA-256)
  - TSA signing cert auto-issued from CA (EKU id-kp-timeStamping, CRITICAL)
  - SHA-256/384/512 accepted; MD5/SHA-1 rejected per policy
  - Audit log integration

RFC 3161 TimeStampReq/Resp (DER):
  TimeStampReq ::= SEQUENCE {
    version         INTEGER  { v1(1) },
    messageImprint  MessageImprint,
    reqPolicy       TSAPolicyId          OPTIONAL,
    nonce           INTEGER              OPTIONAL,
    certReq         BOOLEAN  DEFAULT FALSE,
    extensions  [0] IMPLICIT Extensions OPTIONAL
  }
  MessageImprint ::= SEQUENCE {
    hashAlgorithm  AlgorithmIdentifier,
    hashedMessage  OCTET STRING
  }
  TimeStampResp ::= SEQUENCE {
    status          PKIStatusInfo,
    timeStampToken  TimeStampToken OPTIONAL   -- ContentInfo/SignedData
  }
  TSTInfo ::= SEQUENCE {
    version         INTEGER  { v1(1) },
    policy          TSAPolicyId,
    messageImprint  MessageImprint,
    serialNumber    INTEGER,
    genTime         GeneralizedTime,
    accuracy        Accuracy             OPTIONAL,
    ordering        BOOLEAN  DEFAULT FALSE,
    nonce           INTEGER              OPTIONAL,
    tsa         [0] GeneralName          OPTIONAL,
    extensions  [1] IMPLICIT Extensions OPTIONAL
  }

Dependencies: cryptography (same as pki_server.py)
"""

import datetime
from datetime import timezone as _tz
import hashlib
import http.server
import logging
import threading
from pathlib import Path
from typing import Optional, Dict, Tuple, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID

logger = logging.getLogger("tsa")

from der_codec import (
    encode_length as _enc_len, decode_length as _dec_len, decode_tlv as _dec_tlv,
    seq as _seq, set_ as _set, ctx as _ctx, oid as _oid,
    integer as _int_der, octet_string as _oct, bit_string as _bit,
    null as _null, utf8_string as _utf8str, generalized_time as _generalized_time,
    decode_oid_bytes as _decode_oid_bytes,
    OID_SHA1, OID_SHA256, OID_SHA384, OID_SHA512,
    OID_SHA256_WITH_RSA, OID_SHA384_WITH_RSA, OID_SHA512_WITH_RSA,
    OID_ECDSA_SHA256, OID_ECDSA_SHA384, OID_ECDSA_SHA512,
    OID_SIGNED_DATA, OID_TST_INFO, OID_CONTENT_TYPE, OID_MESSAGE_DIGEST,
    OID_SIGNING_CERT_V2, OID_EKU_TIMESTAMPING,
    OID_RSA_ENCRYPTION as OID_RSA_ENC,
)

# Placeholder policy OID — operators SHOULD supply a real PEN-based OID via
# --tsa-policy-oid (see docs/CPS.md §7.2 for guidance on policy OID assignment)
TSA_DEFAULT_POLICY_OID = "1.3.6.1.4.1.99999.1"

# Accepted hash algorithm OIDs for message imprint.
# MD5 (1.2.840.113549.2.5) and SHA-1 (1.3.14.3.2.26) are explicitly rejected
# per current CA/Browser Forum guidance and NIST SP 800-131A.
_ALLOWED_HASH_OIDS = {OID_SHA256, OID_SHA384, OID_SHA512}

_HASH_OID_TO_NAME = {
    OID_SHA256: "sha256",
    OID_SHA384: "sha384",
    OID_SHA512: "sha512",
}

_HASH_OID_TO_FN = {
    OID_SHA256: hashlib.sha256,
    OID_SHA384: hashlib.sha384,
    OID_SHA512: hashlib.sha512,
}

# PKIStatus codes (RFC 3161 §2.4.2 / RFC 3280)
TSA_STATUS_GRANTED    = 0
TSA_STATUS_REJECTION  = 2

# PKIFailureInfo bit positions (RFC 3161 §2.4.2)
FAIL_BAD_ALG          = 0   # unrecognised or unsupported algorithm identifier
FAIL_BAD_REQUEST      = 2   # request contains data not allowed by the policy
FAIL_BAD_DATA_FORMAT  = 5   # data submitted has wrong format


# ---------------------------------------------------------------------------
# TSA request parser
# ---------------------------------------------------------------------------

class TSARequestParser:
    """Parse a DER-encoded TimeStampReq per RFC 3161 §2.4.1."""

    @staticmethod
    def parse(der: bytes) -> Optional[Dict[str, Any]]:
        """
        Returns dict with:
          version    : int    (must be 1)
          hash_oid   : str    (dotted OID of hash algorithm)
          hash_alg   : str    ("sha256", "sha384", "sha512") or None if unrecognised
          imprint    : bytes  (the hashed message bytes)
          policy     : str or None (requested TSA policy OID)
          nonce      : int or None
          cert_req   : bool   (client wants TSA cert included in response)
        Returns None on parse failure.
        """
        try:
            result: Dict[str, Any] = {}

            tag, outer, _ = _dec_tlv(der, 0)
            if tag != 0x30:
                return None

            pos = 0

            # version INTEGER  { v1(1) }
            tag, ver_bytes, pos = _dec_tlv(outer, pos)
            if tag != 0x02:
                return None
            result["version"] = int.from_bytes(ver_bytes, "big")

            # messageImprint  MessageImprint
            tag, imprint_seq, pos = _dec_tlv(outer, pos)
            if tag != 0x30:
                return None

            ipos = 0
            tag, alg_seq, ipos = _dec_tlv(imprint_seq, ipos)
            if tag != 0x30:
                return None
            tag, alg_oid_val, _ = _dec_tlv(alg_seq, 0)
            result["hash_oid"]  = _decode_oid_bytes(alg_oid_val)
            result["hash_alg"]  = _HASH_OID_TO_NAME.get(result["hash_oid"])

            tag, result["imprint"], ipos = _dec_tlv(imprint_seq, ipos)
            if tag != 0x04:
                return None

            # Optional fields
            result["policy"]   = None
            result["nonce"]    = None
            result["cert_req"] = False

            while pos < len(outer):
                tag, val, pos = _dec_tlv(outer, pos)
                if tag == 0x06:     # OID — reqPolicy TSAPolicyId
                    result["policy"] = _decode_oid_bytes(val)
                elif tag == 0x02:   # INTEGER — nonce
                    result["nonce"] = int.from_bytes(val, "big")
                elif tag == 0x01:   # BOOLEAN — certReq
                    result["cert_req"] = bool(val[0])
                # [0] extensions — ignored

            return result

        except Exception as e:
            logger.debug("TSA request parse error: %s", e)
            return None


# ---------------------------------------------------------------------------
# TSA response builder
# ---------------------------------------------------------------------------

class TSAResponseBuilder:
    """Build DER-encoded TimeStampResp per RFC 3161 + RFC 5816."""

    # ---- error responses ----

    @staticmethod
    def error(
        status: int = TSA_STATUS_REJECTION,
        fail_bit: Optional[int] = None,
        status_text: str = "",
    ) -> bytes:
        """Build a TimeStampResp with only a PKIStatusInfo (rejection)."""
        status_str_der = b""
        if status_text:
            status_str_der = _seq(_utf8str(status_text))

        fail_info_der = b""
        if fail_bit is not None:
            byte_idx = fail_bit // 8
            bit_mask = 0x80 >> (fail_bit % 8)
            buf = bytearray(byte_idx + 1)
            buf[byte_idx] |= bit_mask
            unused = 7 - (fail_bit % 8)
            fail_info_der = _bit(bytes(buf), unused)

        pki_status_info = _seq(_int_der(status) + status_str_der + fail_info_der)
        return _seq(pki_status_info)

    # ---- successful timestamp response ----

    @staticmethod
    def build(
        parsed_req: Dict[str, Any],
        tsa_key,
        tsa_cert: x509.Certificate,
        policy_oid: str,
        serial: int,
        accuracy_seconds: int = 1,
    ) -> bytes:
        """
        Build a granted TimeStampResp containing a CMS-signed TimeStampToken.

        The token is a CMS SignedData (v3) whose encapContentInfo carries a
        TSTInfo (id-ct-TSTInfo) as the eContent OCTET STRING.  The signer
        info uses sha256WithRSAEncryption (or the matched-curve ECDSA OID)
        and includes the signingCertificateV2 signed attribute per RFC 5816.
        """
        now = datetime.datetime.now(_tz.utc)

        # ---- TSTInfo DER ----
        tst_body = (
            _int_der(1)                         # version v1
            + _oid(policy_oid)                  # policy
            + _build_message_imprint(           # messageImprint echoed from request
                parsed_req["hash_oid"],
                parsed_req["imprint"],
            )
            + _int_der(serial)                  # serialNumber
            + _generalized_time(now)            # genTime
            + _seq(_int_der(accuracy_seconds))  # accuracy SEQUENCE { seconds }
        )
        if parsed_req.get("nonce") is not None:
            tst_body += _int_der(parsed_req["nonce"])

        tst_info = _seq(tst_body)

        # ---- CMS signed attributes ----
        # messageDigest = SHA-256 of the TSTInfo DER (the eContent value)
        tst_info_digest = hashlib.sha256(tst_info).digest()

        # signingCertificateV2 (RFC 5816): ESSCertIDv2 using SHA-256 of TSA cert
        tsa_cert_der = tsa_cert.public_bytes(Encoding.DER)
        cert_hash = hashlib.sha256(tsa_cert_der).digest()
        # ESSCertIDv2: hashAlgorithm is DEFAULT sha256 and MAY be omitted (RFC 5816 §3)
        ess_cert_id_v2 = _seq(_oct(cert_hash))
        signing_cert_v2_attr_val = _seq(_seq(ess_cert_id_v2))  # SigningCertificateV2 value

        # Three mandatory signed attributes
        attr_content_type = _seq(
            _oid(OID_CONTENT_TYPE) + _set(_oid(OID_TST_INFO))
        )
        attr_message_digest = _seq(
            _oid(OID_MESSAGE_DIGEST) + _set(_oct(tst_info_digest))
        )
        attr_signing_cert_v2 = _seq(
            _oid(OID_SIGNING_CERT_V2) + _set(signing_cert_v2_attr_val)
        )

        # DER SET OF: elements sorted in lexicographic byte order (DER canonical)
        sorted_attrs = sorted(
            [attr_content_type, attr_message_digest, attr_signing_cert_v2]
        )
        signed_attrs_body = b"".join(sorted_attrs)

        # The signature is computed over the SET-tagged encoding
        signed_attrs_for_sig = b"\x31" + _enc_len(len(signed_attrs_body)) + signed_attrs_body

        # The SignerInfo encodes signedAttrs with [0] IMPLICIT (replaces SET tag)
        signed_attrs_implicit = (
            b"\xa0" + _enc_len(len(signed_attrs_body)) + signed_attrs_body
        )

        # ---- Sign ----
        sig_bytes = _tsa_sign(tsa_key, signed_attrs_for_sig)
        sig_alg_der = _sig_alg_for_key(tsa_key)

        # ---- SignerInfo (v1 with issuerAndSerialNumber) ----
        issuer_and_serial = _seq(
            tsa_cert.issuer.public_bytes()   # issuer Name DER
            + _int_der(tsa_cert.serial_number)
        )
        digest_alg = _seq(_oid(OID_SHA256) + _null())

        signer_info = _seq(
            _int_der(1)            # version v1 (issuerAndSerialNumber)
            + issuer_and_serial    # sid: issuerAndSerialNumber
            + digest_alg           # digestAlgorithm: SHA-256
            + signed_attrs_implicit
            + sig_alg_der          # signatureAlgorithm
            + _oct(sig_bytes)      # signature OCTET STRING
        )

        # ---- EncapsulatedContentInfo ----
        encap_content_info = _seq(
            _oid(OID_TST_INFO)
            + _ctx(0, _oct(tst_info))   # eContent [0] EXPLICIT OCTET STRING
        )

        # ---- Certificates ----
        certs_field = b""
        if parsed_req.get("cert_req"):
            certs_field = _ctx(0, tsa_cert_der)

        # ---- SignedData (v3: encapContentInfo not id-data) ----
        signed_data = _seq(
            _int_der(3)                          # version v3
            + _set(_seq(_oid(OID_SHA256) + _null()))  # digestAlgorithms
            + encap_content_info
            + certs_field
            + _set(signer_info)                  # signerInfos
        )

        # ---- ContentInfo ----
        content_info = _seq(
            _oid(OID_SIGNED_DATA)
            + _ctx(0, signed_data)
        )

        # ---- TimeStampResp ----
        pki_status_info = _seq(_int_der(TSA_STATUS_GRANTED))
        return _seq(pki_status_info + content_info)


def _build_message_imprint(hash_oid: str, imprint: bytes) -> bytes:
    """Encode MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }."""
    return _seq(
        _seq(_oid(hash_oid) + _null())
        + _oct(imprint)
    )


def _tsa_sign(key, data: bytes) -> bytes:
    """Sign data with the appropriate algorithm for the key type."""
    try:
        from pki_server import _sign_data
        return _sign_data(key, data)
    except ImportError:
        pass
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, asym_padding.PKCS1v15(), SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        hash_cls = _ec_hash(key)
        return key.sign(data, ec.ECDSA(hash_cls()))
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return key.sign(data)
    raise TypeError(f"Unsupported TSA key type: {type(key).__name__}")


def _ec_hash(key: ec.EllipticCurvePrivateKey):
    """Return the matched-curve hash class for an ECDSA key (RFC 5758 §3.2)."""
    if isinstance(key.curve, ec.SECP384R1):
        return SHA384
    if isinstance(key.curve, ec.SECP521R1):
        return SHA512
    return SHA256


def _sig_alg_for_key(key) -> bytes:
    """Return DER AlgorithmIdentifier for the signing algorithm of *key*."""
    if isinstance(key, rsa.RSAPrivateKey):
        return _seq(_oid(OID_SHA256_WITH_RSA) + _null())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP384R1):
            return _seq(_oid(OID_ECDSA_SHA384))   # RFC 5758: no NULL params for ECDSA
        if isinstance(key.curve, ec.SECP521R1):
            return _seq(_oid(OID_ECDSA_SHA512))
        return _seq(_oid(OID_ECDSA_SHA256))
    return _seq(_oid(OID_SHA256_WITH_RSA) + _null())


# ---------------------------------------------------------------------------
# TSA signing certificate provisioner
# ---------------------------------------------------------------------------

def provision_tsa_signing_cert(ca: "CertificateAuthority") -> Tuple[Any, x509.Certificate]:
    """
    Issue (or reuse) a dedicated TSA signing certificate.

    RFC 3161 §2.3 requirements:
      - EKU id-kp-timeStamping MUST be present and MUST be marked critical.
      - The TSA signing cert MUST NOT be used for any other purpose (no other EKU).
      - KU: digitalSignature only.

    Returns (private_key, certificate).
    """
    tsa_key_path  = ca.ca_dir / "tsa.key"
    tsa_cert_path = ca.ca_dir / "tsa.crt"

    if tsa_key_path.exists() and tsa_cert_path.exists():
        try:
            with open(tsa_key_path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            with open(tsa_cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            if cert.not_valid_after_utc > (
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
            ):
                logger.info("Reusing existing TSA signing certificate")
                return key, cert
        except Exception as e:
            logger.warning("TSA cert reload failed: %s, re-issuing", e)

    logger.info("Generating TSA signing key and certificate...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(_tz.utc)

    tsa_eku_oid = x509.ObjectIdentifier(OID_EKU_TIMESTAMPING)

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "PyPKI TSA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyPKI"),
        ]))
        .issuer_name(ca.ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(ca._next_serial())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
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
        # RFC 3161 §2.3: EKU MUST be critical; MUST contain only id-kp-timeStamping
        .add_extension(
            x509.ExtendedKeyUsage([tsa_eku_oid]),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.ca_key.public_key()),
            critical=False,
        )
    )

    try:
        from pki_server import _sign_builder as _pki_sign
        cert = _pki_sign(builder, ca.ca_key, rsa_pss=getattr(ca, "_rsa_pss", False))
    except ImportError:
        cert = builder.sign(ca.ca_key, SHA256())

    with open(tsa_key_path, "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    with open(tsa_cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

    logger.info("TSA signing cert issued, valid until %s", cert.not_valid_after_utc.date())
    return key, cert


# ---------------------------------------------------------------------------
# Serial number counter for timestamps
# ---------------------------------------------------------------------------

class TSASerialCounter:
    """Thread-safe monotonic serial number counter stored in a flat text file."""

    def __init__(self, counter_path: Path):
        self._path  = counter_path
        self._lock  = threading.Lock()
        self._value = self._load()

    def _load(self) -> int:
        try:
            return int(self._path.read_text().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def next(self) -> int:
        with self._lock:
            self._value += 1
            try:
                self._path.write_text(str(self._value))
            except OSError:
                pass
            return self._value


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class TSAHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP handler for the RFC 3161 TSA.

    Endpoint:
      POST /tsa   Content-Type: application/timestamp-query
                  → 200  Content-Type: application/timestamp-reply
    """

    ca:               "CertificateAuthority" = None
    tsa_key                                  = None
    tsa_cert:         x509.Certificate       = None
    policy_oid:       str                    = TSA_DEFAULT_POLICY_OID
    accuracy_seconds: int                    = 1
    serial_counter:   TSASerialCounter       = None
    audit_log                                = None

    def log_message(self, fmt, *args):
        logger.debug("TSA %s - %s", self.client_address[0], fmt % args)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        response = self._handle_request(body)
        self._send_raw(200, response, "application/timestamp-reply")

    def _handle_request(self, req_der: bytes) -> bytes:
        parsed = TSARequestParser.parse(req_der)
        if parsed is None:
            logger.info("TSA: malformed request (parse failure)")
            return TSAResponseBuilder.error(
                TSA_STATUS_REJECTION, FAIL_BAD_DATA_FORMAT, "malformed TimeStampReq"
            )

        if parsed["version"] != 1:
            return TSAResponseBuilder.error(
                TSA_STATUS_REJECTION, FAIL_BAD_REQUEST,
                f"unsupported version {parsed['version']}"
            )

        if parsed["hash_oid"] not in _ALLOWED_HASH_OIDS:
            logger.info(
                "TSA: rejected hash OID %s (SHA-256/384/512 only)",
                parsed["hash_oid"],
            )
            return TSAResponseBuilder.error(
                TSA_STATUS_REJECTION, FAIL_BAD_ALG,
                f"hash {parsed['hash_oid']} not accepted; use SHA-256, SHA-384, or SHA-512",
            )

        if parsed["policy"] and parsed["policy"] != self.policy_oid:
            return TSAResponseBuilder.error(
                TSA_STATUS_REJECTION, FAIL_BAD_REQUEST,
                f"policy {parsed['policy']} not supported",
            )

        serial = self.serial_counter.next()

        try:
            response = TSAResponseBuilder.build(
                parsed_req=parsed,
                tsa_key=self.tsa_key,
                tsa_cert=self.tsa_cert,
                policy_oid=self.policy_oid,
                serial=serial,
                accuracy_seconds=self.accuracy_seconds,
            )
        except Exception as e:
            logger.error("TSA build error: %s", e, exc_info=True)
            return TSAResponseBuilder.error(
                TSA_STATUS_REJECTION, FAIL_BAD_REQUEST, "internal error"
            )

        if self.audit_log:
            try:
                self.audit_log.record(
                    "tsa_timestamp",
                    f"serial={serial} hash={parsed['hash_alg']} "
                    f"nonce={parsed.get('nonce')} policy={self.policy_oid}",
                    requester_ip=self.client_address[0],
                )
            except Exception:
                pass

        logger.info(
            "TSA timestamp serial=%d hash=%s nonce=%s",
            serial, parsed["hash_alg"], parsed.get("nonce"),
        )
        return response

    def _send_raw(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Integration entry point
# ---------------------------------------------------------------------------

def start_tsa_server(
    route_table,
    prefix: str,
    ca: "CertificateAuthority",
    policy_oid: str = TSA_DEFAULT_POLICY_OID,
    accuracy_seconds: int = 1,
    tsa_cert_path: Optional[str] = None,
    tsa_key_path: Optional[str] = None,
    audit_log=None,
):
    """
    Register the TSA handler with *route_table* under *prefix*.

    When *tsa_cert_path* / *tsa_key_path* are provided, the supplied cert and
    key are used instead of auto-provisioning.  If absent, a new TSA signing
    cert is issued from the CA (RFC 3161 §2.3: critical id-kp-timeStamping EKU,
    KU=digitalSignature only, 365-day validity).

    Returns a _RouteProxy whose .shutdown() unregisters the TSA routes.
    """
    from dispatcher_server import _RouteProxy

    if tsa_cert_path and tsa_key_path:
        with open(tsa_key_path, "rb") as f:
            tsa_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(tsa_cert_path, "rb") as f:
            tsa_cert = x509.load_pem_x509_certificate(f.read())
        logger.info("TSA using pre-provisioned cert from %s", tsa_cert_path)
    else:
        tsa_key, tsa_cert = provision_tsa_signing_cert(ca)

    serial_counter = TSASerialCounter(ca.ca_dir / "tsa_serial.txt")

    class BoundTSAHandler(TSAHandler):
        pass

    BoundTSAHandler.ca               = ca
    BoundTSAHandler.tsa_key          = tsa_key
    BoundTSAHandler.tsa_cert         = tsa_cert
    BoundTSAHandler.policy_oid       = policy_oid
    BoundTSAHandler.accuracy_seconds = accuracy_seconds
    BoundTSAHandler.serial_counter   = serial_counter
    BoundTSAHandler.audit_log        = audit_log

    route_table.register(prefix, BoundTSAHandler)
    logger.info(
        "TSA handler registered at %r (policy=%s, accuracy=%ds)",
        prefix, policy_oid, accuracy_seconds,
    )
    return _RouteProxy(route_table, prefix, label="tsa")
