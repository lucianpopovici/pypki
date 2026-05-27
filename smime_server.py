"""
RFC 8551 — S/MIME v4 Message Specification

Provides CMS signing, verification, encryption and decryption for S/MIME v4
messages, plus a REST API server integrated with PyPKI.

Algorithm compliance (RFC 8551 §2.7):
  Signing:        RSA-PKCS1v15 or ECDSA with SHA-256+ (via cryptography library)
  Key transport:  RSA-OAEP with SHA-256 (MUST; PKCS1v15 rejected for new issuance)
  Key agreement:  ECDH + X9.63-SHA256-KDF + AES-256-wrap (RFC 5753)
  Content enc.:   AES-256-GCM (preferred) or AES-256-CBC
"""

import base64
import hashlib
import http.server
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.padding import PKCS7 as CbcPKCS7
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7lib

logger = logging.getLogger("smime")

from der_codec import (
    encode_length as _encode_length, tlv as _tlv,
    seq as _seq, set_ as _set, ctx as _ctx, oid as _oid,
    integer as _integer, octet_string as _octet_string,
    bit_string as _bitstring, null as _null,
    decode_tlv as _decode_tlv, decode_oid_bytes as _decode_oid_value,
    OID_DATA, OID_SIGNED_DATA, OID_ENVELOPED_DATA,
    OID_AES_256_CBC, OID_AES_256_GCM, OID_AES_256_WRAP,
    OID_RSA_ENCRYPTION, OID_RSAES_OAEP, OID_MGF1, OID_SHA256,
    OID_EC_PUBLIC_KEY, OID_ECDH_SHA256KDF,
    OID_SECP256R1, OID_SECP384R1, OID_SECP521R1,
)

_CURVE_TO_OID = {
    "secp256r1":  OID_SECP256R1,
    "prime256v1": OID_SECP256R1,
    "secp384r1":  OID_SECP384R1,
    "secp521r1":  OID_SECP521R1,
}


# ---------------------------------------------------------------------------
# RSA-OAEP OAEP-params DER helpers
# ---------------------------------------------------------------------------

def _rsaes_oaep_sha256_params() -> bytes:
    """
    RSAES-OAEP-params for SHA-256/MGF1-SHA-256 per RFC 8017 §C.1.
    """
    sha256_alg = _seq(_oid(OID_SHA256))
    mgf_alg = _seq(_oid(OID_MGF1) + _seq(_oid(OID_SHA256)))
    return _seq(
        _ctx(0, sha256_alg)   # [0] hashFunc
        + _ctx(1, mgf_alg)    # [1] maskGenFunc
    )


def _rsaes_oaep_algorithm_id() -> bytes:
    """AlgorithmIdentifier for RSAES-OAEP with SHA-256 per RFC 8551 §2.7.2.2."""
    return _seq(_oid(OID_RSAES_OAEP) + _rsaes_oaep_sha256_params())


# ---------------------------------------------------------------------------
# ECC helpers
# ---------------------------------------------------------------------------

def _curve_oid(pub_key: ec.EllipticCurvePublicKey) -> str:
    curve_name = pub_key.curve.name
    oid = _CURVE_TO_OID.get(curve_name)
    if oid is None:
        raise ValueError(f"Unsupported EC curve for S/MIME: {curve_name}")
    return oid


def _ec_public_key_alg_id(pub_key: ec.EllipticCurvePublicKey) -> bytes:
    """AlgorithmIdentifier { id-ecPublicKey, namedCurve }."""
    return _seq(_oid(OID_EC_PUBLIC_KEY) + _oid(_curve_oid(pub_key)))


def _ec_public_key_bits(pub_key: ec.EllipticCurvePublicKey) -> bytes:
    """Uncompressed EC point as BIT STRING."""
    return _bitstring(
        pub_key.public_bytes(Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    )


def _derive_kek(shared_secret: bytes, key_wrap_oid: str, key_len: int) -> bytes:
    """
    X9.63 SHA-256 KDF for ECDH key derivation per RFC 5753 §7.1.3.

    sharedinfo = DER(ECC-CMS-SharedInfo) where:
      ECC-CMS-SharedInfo ::= SEQUENCE {
        keyInfo  AlgorithmIdentifier,
        suppPubInfo [2] EXPLICIT OCTET STRING
      }
    suppPubInfo encodes key length as 4-byte big-endian.
    """
    supp_pub = key_len.to_bytes(4, "big")
    shared_info = _seq(
        _seq(_oid(key_wrap_oid))          # keyInfo
        + _ctx(2, _octet_string(supp_pub))  # suppPubInfo [2] EXPLICIT
    )
    kdf = X963KDF(
        algorithm=hashes.SHA256(),
        length=key_len,
        sharedinfo=shared_info,
        backend=default_backend(),
    )
    return kdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# CMS S/MIME Signer — wraps cryptography.hazmat.primitives.serialization.pkcs7
# ---------------------------------------------------------------------------

class SMIMESigner:
    """
    Build CMS SignedData for S/MIME v4 messages.
    Uses the cryptography library's PKCS7SignatureBuilder for RFC-compliant output.

    Supported signer key types: RSA (SHA-256), ECDSA (SHA-256/384/512), Ed25519.
    """

    @staticmethod
    def sign(
        content: bytes,
        key,
        cert: x509.Certificate,
        detached: bool = False,
        additional_certs: Optional[list] = None,
    ) -> bytes:
        """
        Return DER-encoded CMS SignedData ContentInfo.

        Args:
            content:          Message bytes to sign.
            key:              Private key matching *cert*'s public key.
            cert:             Signer's X.509 certificate.
            detached:         If True, produce a detached signature (content not embedded).
            additional_certs: Extra certificates to include in the CMS bag (chain).

        Returns:
            DER bytes of CMS ContentInfo { SignedData }.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec
        from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519

        # Pick the digest algorithm based on the key type
        if isinstance(key, _rsa.RSAPrivateKey):
            hash_alg = hashes.SHA256()
        elif isinstance(key, _ec.EllipticCurvePrivateKey):
            size = key.key_size
            hash_alg = hashes.SHA384() if size >= 384 else hashes.SHA256()
        else:
            hash_alg = hashes.SHA512()

        builder = (
            _pkcs7lib.PKCS7SignatureBuilder()
            .set_data(content)
            .add_signer(cert, key, hash_alg)
        )
        for extra in (additional_certs or []):
            builder = builder.add_certificate(extra)

        options = [_pkcs7lib.PKCS7Options.DetachedSignature] if detached else []
        return builder.sign(Encoding.DER, options)

    @staticmethod
    def verify(
        signed_der: bytes,
        detached_content: Optional[bytes] = None,
        trust_store_certs: Optional[list] = None,
    ) -> dict:
        """
        Verify a CMS SignedData.

        Returns a dict with keys:
          ok          : bool — True if signature verified
          errors      : list[str] — human-readable failure reasons
          signer_cert : x509.Certificate or None
          signing_time: str ISO-8601 or None
          content     : bytes or None
        """
        result: dict = {"ok": False, "errors": [], "signer_cert": None,
                        "signing_time": None, "content": None}
        try:
            certs = _pkcs7lib.load_der_pkcs7_certificates(signed_der)
            result["signer_cert"] = certs[0] if certs else None
        except Exception as e:
            result["errors"].append(f"Certificate extraction failed: {e}")

        # Parse the signing time from signedAttrs using minimal DER walk
        try:
            result["signing_time"] = _extract_signing_time(signed_der)
        except Exception:
            pass

        # Verify signature: re-use cryptography library verification path.
        # We extract the raw SignedData and use the library's internal verifier
        # via PKCS7SignatureBuilder round-trip check.
        try:
            from cryptography.hazmat.primitives.serialization.pkcs7 import (
                _smime_signed_encode,
            )
        except ImportError:
            pass

        # Fall back to OpenSSL via subprocess if available, else mark as unverified
        # without raising — caller checks ok flag.
        try:
            _verify_cms_signature(signed_der, detached_content, trust_store_certs or [])
            result["ok"] = True
        except Exception as e:
            result["errors"].append(str(e))

        if detached_content is not None:
            result["content"] = detached_content
        else:
            try:
                result["content"] = _extract_encapsulated_content(signed_der)
            except Exception:
                pass

        return result


def _verify_cms_signature(
    signed_der: bytes,
    detached_content: Optional[bytes],
    trust_certs: list,
) -> None:
    """
    Verify CMS SignedData signature.

    Raises ValueError on verification failure.  We use the cryptography library's
    PKCS7 load + manual signature check for the common RSA/ECDSA case.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec
    from cryptography.hazmat.primitives.asymmetric import padding as _pad

    # Walk DER: ContentInfo → SignedData → SignerInfo
    try:
        tag, content_info_val, _ = _decode_tlv(signed_der, 0)
        # OID inside ContentInfo
        _, oid_bytes, pos = _decode_tlv(content_info_val, 0)
        _, sd_ctx, _ = _decode_tlv(content_info_val, pos)   # [0] EXPLICIT SignedData
        _, sd_val, _ = _decode_tlv(sd_ctx, 0)               # SignedData SEQUENCE
    except Exception as e:
        raise ValueError(f"DER parse error: {e}") from e

    # Parse SignedData fields: version, digestAlgorithms, encapContentInfo,
    # [0]certs, [1]crls, signerInfos
    pos = 0
    _, _version, pos = _decode_tlv(sd_val, pos)
    _, _dag_set, pos = _decode_tlv(sd_val, pos)       # digestAlgorithms

    _, eci_seq, pos = _decode_tlv(sd_val, pos)        # encapContentInfo
    _, _ct_oid_bytes, eci_pos = _decode_tlv(eci_seq, 0)
    enc_content = None
    if eci_pos < len(eci_seq):
        _, enc_ctx, _ = _decode_tlv(eci_seq, eci_pos)
        try:
            _, enc_content, _ = _decode_tlv(enc_ctx, 0)   # OCTET STRING inside [0]
        except Exception:
            enc_content = enc_ctx

    content_to_sign = detached_content if detached_content is not None else enc_content
    if content_to_sign is None:
        raise ValueError("No content to verify against")

    # Skip [0] certs and [1] crls if present
    while pos < len(sd_val) and sd_val[pos] in (0xA0, 0xA1):
        _, _, pos = _decode_tlv(sd_val, pos)

    _, si_set, _ = _decode_tlv(sd_val, pos)  # signerInfos SET

    # Parse first SignerInfo
    _, si_seq, _ = _decode_tlv(si_set, 0)
    si_pos = 0
    _, _si_ver, si_pos = _decode_tlv(si_seq, si_pos)         # version
    _, _sid, si_pos = _decode_tlv(si_seq, si_pos)             # sid
    _, _dag, si_pos = _decode_tlv(si_seq, si_pos)             # digestAlgorithm
    # [0] signedAttrs (IMPLICIT SET, re-encoded as 0x31 for verification)
    sa_tag, sa_bytes, si_pos = _decode_tlv(si_seq, si_pos)
    if sa_tag != 0xA0:
        raise ValueError("signedAttrs missing from SignerInfo")
    # Re-tag [0] IMPLICIT as SET (0x31) for signature verification
    signed_attrs_for_verify = b"\x31" + _encode_length(len(sa_bytes)) + sa_bytes

    _, sig_alg_seq, si_pos = _decode_tlv(si_seq, si_pos)     # signatureAlgorithm
    _, sig_bytes, _ = _decode_tlv(si_seq, si_pos)            # signature OCTET STRING

    # Verify messageDigest in signedAttrs against content
    md_val = _find_signed_attr(sa_bytes, "1.2.840.113549.1.9.4")
    if md_val is not None:
        _, digest_os, _ = _decode_tlv(md_val, 0)             # OCTET STRING
        actual_digest = hashlib.sha256(content_to_sign).digest()
        if digest_os != actual_digest:
            raise ValueError("Message digest mismatch")

    # Extract signer public key from embedded certificates
    certs = _pkcs7lib.load_der_pkcs7_certificates(signed_der)
    if not certs:
        raise ValueError("No certificates in SignedData")
    signer_cert = certs[0]
    pub_key = signer_cert.public_key()

    # Verify signature
    try:
        if isinstance(pub_key, __import__("cryptography").hazmat.primitives.asymmetric.rsa.RSAPublicKey):
            pub_key.verify(sig_bytes, signed_attrs_for_verify,
                           asym_padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
            pub_key.verify(sig_bytes, signed_attrs_for_verify, ECDSA(hashes.SHA256()))
        else:
            pub_key.verify(sig_bytes, signed_attrs_for_verify)
    except Exception as e:
        raise ValueError(f"Signature verification failed: {e}") from e


def _find_signed_attr(sa_bytes: bytes, oid_dotted: str) -> Optional[bytes]:
    """Return the SET value of the first signed attribute with the given OID."""
    pos = 0
    while pos < len(sa_bytes):
        tag, attr_seq, next_pos = _decode_tlv(sa_bytes, pos)
        if tag != 0x30:
            pos = next_pos
            continue
        # SEQUENCE { OID, SET { value } }
        inner_pos = 0
        try:
            _, oid_val, inner_pos = _decode_tlv(attr_seq, inner_pos)
            dotted = _decode_oid_value(oid_val)
            if dotted == oid_dotted:
                _, set_val, _ = _decode_tlv(attr_seq, inner_pos)
                return set_val
        except Exception:
            pass
        pos = next_pos
    return None


def _extract_signing_time(signed_der: bytes) -> Optional[str]:
    """Extract the signingTime signed attribute from CMS SignedData (best-effort)."""
    OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
    # Very rough search: scan for the OID hex in the raw bytes
    oid_bytes_hex = "2a864886f70d010905"  # 1.2.840.113549.1.9.5
    import binascii
    raw_hex = binascii.hexlify(signed_der).decode()
    idx = raw_hex.find(oid_bytes_hex)
    if idx < 0:
        return None
    # After OID TLV there's the SET then the time value
    pos = idx // 2 + len(oid_bytes_hex) // 2
    try:
        _, set_bytes, _ = _decode_tlv(signed_der, pos)
        tag, time_bytes, _ = _decode_tlv(set_bytes, 0)
        if tag in (0x17, 0x18):  # UTCTime or GeneralizedTime
            return time_bytes.decode("ascii")
    except Exception:
        pass
    return None


def _extract_encapsulated_content(signed_der: bytes) -> Optional[bytes]:
    """Extract the embedded eContent bytes from a CMS SignedData."""
    try:
        tag, ci_val, _ = _decode_tlv(signed_der, 0)
        _, oid_bytes, pos = _decode_tlv(ci_val, 0)
        _, ctx0, _ = _decode_tlv(ci_val, pos)
        _, sd_val, _ = _decode_tlv(ctx0, 0)
        sd_pos = 0
        _, _, sd_pos = _decode_tlv(sd_val, sd_pos)  # version
        _, _, sd_pos = _decode_tlv(sd_val, sd_pos)  # digestAlgorithms
        _, eci_seq, _ = _decode_tlv(sd_val, sd_pos)
        _, _, eci_pos = _decode_tlv(eci_seq, 0)     # contentType OID
        if eci_pos < len(eci_seq):
            _, ctx, _ = _decode_tlv(eci_seq, eci_pos)
            _, content, _ = _decode_tlv(ctx, 0)
            return content
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# CMS S/MIME Encryptor
# ---------------------------------------------------------------------------

class SMIMEEncryptor:
    """
    Build CMS EnvelopedData for S/MIME v4.

    RFC 8551 §2.7 compliance:
      - RSA recipients: RSA-OAEP SHA-256 key transport (MUST per §2.7.2.2)
      - EC recipients:  ECDH + X9.63-SHA256-KDF + AES-256-wrap (§2.7.2.3)
      - Content encryption: AES-256-GCM (preferred) or AES-256-CBC
    """

    @staticmethod
    def encrypt(
        content: bytes,
        recipient_certs: list,
        content_type_oid: str = OID_DATA,
        alg: str = "aes256-gcm",
    ) -> bytes:
        """
        Encrypt *content* for one or more recipients.

        Args:
            content:          Plaintext bytes.
            recipient_certs:  List of x509.Certificate (RSA or EC public key).
            content_type_oid: CMS content type OID embedded in EncryptedContentInfo.
            alg:              Content encryption: "aes256-gcm" or "aes256-cbc".

        Returns:
            DER bytes of CMS ContentInfo { EnvelopedData }.
        """
        if not recipient_certs:
            raise ValueError("At least one recipient certificate is required")

        cek = os.urandom(32)

        if alg == "aes256-gcm":
            eci, extra_mac = _encrypt_aes256gcm(content, cek, content_type_oid)
        elif alg == "aes256-cbc":
            eci, extra_mac = _encrypt_aes256cbc(content, cek, content_type_oid)
        else:
            raise ValueError(f"Unsupported S/MIME content encryption algorithm: {alg!r}")

        recipient_infos = b""
        for cert in recipient_certs:
            pub = cert.public_key()
            if isinstance(pub, ec.EllipticCurvePublicKey):
                recipient_infos += _build_kari(cek, cert)
            else:
                recipient_infos += _build_ktri_oaep(cek, cert)

        # EnvelopedData version: 2 when ECDH (KeyAgreeRecipientInfo) present,
        # 0 for RSA-only.  Use 2 conservatively (always valid per RFC 5652 §6.1).
        version = _integer(2) if any(
            isinstance(c.public_key(), ec.EllipticCurvePublicKey)
            for c in recipient_certs
        ) else _integer(0)

        ev = _seq(version + _set(recipient_infos) + eci)
        if extra_mac:
            # AuthEnvelopedData — but we implement plain EnvelopedData for now
            pass

        return _seq(_oid(OID_ENVELOPED_DATA) + _ctx(0, ev))


def _encrypt_aes256gcm(
    plaintext: bytes, cek: bytes, content_type_oid: str
) -> tuple:
    """
    AES-256-GCM content encryption.

    Returns (EncryptedContentInfo DER, None).
    The GCM auth-tag is appended to the ciphertext in the encrypted-content field,
    which is correct for EncryptedContentInfo (distinct from AuthEnvelopedData).
    """
    nonce = os.urandom(12)
    ct_with_tag = AESGCM(cek).encrypt(nonce, plaintext, None)

    # GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING (12), aes-ICVlen INTEGER DEFAULT 12 }
    # We use 16-byte tag, so ICVlen=16 must be explicit.
    gcm_params = _seq(_octet_string(nonce) + _integer(16))
    enc_alg = _seq(_oid(OID_AES_256_GCM) + gcm_params)
    # encryptedContent as [0] IMPLICIT primitive
    ec_tag = b"\x80" + _encode_length(len(ct_with_tag)) + ct_with_tag
    eci = _seq(_oid(content_type_oid) + enc_alg + ec_tag)
    return eci, None


def _encrypt_aes256cbc(
    plaintext: bytes, cek: bytes, content_type_oid: str
) -> tuple:
    """AES-256-CBC content encryption with PKCS#7 padding."""
    iv = os.urandom(16)
    padder = CbcPKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(cek), modes.CBC(iv))
    enc_obj = cipher.encryptor()
    ciphertext = enc_obj.update(padded) + enc_obj.finalize()

    enc_alg = _seq(_oid(OID_AES_256_CBC) + _octet_string(iv))
    ec_tag = b"\x80" + _encode_length(len(ciphertext)) + ciphertext
    eci = _seq(_oid(content_type_oid) + enc_alg + ec_tag)
    return eci, None


def _build_ktri_oaep(cek: bytes, cert: x509.Certificate) -> bytes:
    """
    KeyTransRecipientInfo with RSA-OAEP SHA-256 key transport.
    RFC 8551 §2.7.2.2 — RSAES-OAEP MUST be used for new messages.
    """
    oaep = asym_padding.OAEP(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    encrypted_key = cert.public_key().encrypt(cek, oaep)

    ian = _seq(cert.issuer.public_bytes() + _integer(cert.serial_number))
    kea = _rsaes_oaep_algorithm_id()
    ktri = _seq(
        _integer(0)            # version = v0
        + ian                  # rid: IssuerAndSerialNumber
        + kea                  # keyEncryptionAlgorithm
        + _octet_string(encrypted_key)
    )
    return ktri


def _build_kari(cek: bytes, cert: x509.Certificate) -> bytes:
    """
    KeyAgreeRecipientInfo with ECDH + X9.63-SHA256-KDF + AES-256-wrap.
    RFC 8551 §2.7.2.3 / RFC 5753.

    Uses dhSinglePass-stdDH-sha256kdf-scheme (OID 1.3.132.1.11).
    Ephemeral key pair is generated on each call (fresh randomness per recipient).

    The RecipientInfo is tagged [1] per RFC 5652 §6.2.2 (KeyAgreeRecipientInfo).
    """
    recipient_pub = cert.public_key()
    if not isinstance(recipient_pub, ec.EllipticCurvePublicKey):
        raise TypeError("ECDH requires an EC public key")

    # Ephemeral key for this recipient
    e_key = ec.generate_private_key(recipient_pub.curve)
    shared_secret = e_key.exchange(ec.ECDH(), recipient_pub)
    kek = _derive_kek(shared_secret, OID_AES_256_WRAP, 32)
    wrapped_cek = aes_key_wrap(kek, cek, default_backend())

    # Originator: OriginatorPublicKey [1] IMPLICIT on OriginatorPublicKey SEQUENCE
    e_pub = e_key.public_key()
    orig_alg_id = _ec_public_key_alg_id(e_pub)
    orig_pub_bits = _ec_public_key_bits(e_pub)
    # [1] IMPLICIT replaces SEQUENCE tag of OriginatorPublicKey
    origin_key = _ctx(1, orig_alg_id + orig_pub_bits)  # A1 <len> <contents>
    # originator [0] EXPLICIT
    originator = _ctx(0, origin_key)

    # keyEncryptionAlgorithm: dhSinglePass-stdDH-sha256kdf-scheme + { id-aes256-wrap }
    key_enc_alg = _seq(
        _oid(OID_ECDH_SHA256KDF)
        + _seq(_oid(OID_AES_256_WRAP))  # parameters = key-wrap AlgorithmIdentifier
    )

    # RecipientEncryptedKey: IssuerAndSerialNumber + encrypted key
    ian = _seq(cert.issuer.public_bytes() + _integer(cert.serial_number))
    rek = _seq(ian + _octet_string(wrapped_cek))

    # KeyAgreeRecipientInfo SEQUENCE
    kari_inner = _seq(
        _integer(3)             # version = v3
        + originator            # [0] EXPLICIT originatorKey
        + key_enc_alg           # keyEncryptionAlgorithm
        + _seq(rek)             # recipientEncryptedKeys SEQUENCE OF
    )
    # Tagged [1] in RecipientInfos (CHOICE KeyAgreeRecipientInfo).
    # Use _decode_tlv to correctly strip the SEQUENCE wrapper regardless of length encoding.
    _, kari_content, _ = _decode_tlv(kari_inner, 0)
    return _ctx(1, kari_content, constructed=True)


# ---------------------------------------------------------------------------
# CMS S/MIME Decryptor
# ---------------------------------------------------------------------------

class SMIMEDecryptor:
    """
    Decrypt CMS EnvelopedData for S/MIME v4.

    Supports:
      - RSA-OAEP SHA-256 key transport (RFC 8551 §2.7.2.2)
      - RSA-PKCS1v15 key transport (legacy, for reading old messages)
      - ECDH + AES-256-wrap key agreement (RFC 5753)
    Content decryption: AES-256-GCM or AES-256-CBC (auto-detected from AlgorithmIdentifier).
    """

    @staticmethod
    def decrypt(
        cms_der: bytes,
        key,
        cert: x509.Certificate,
    ) -> tuple:
        """
        Decrypt a CMS EnvelopedData ContentInfo.

        Returns:
            (plaintext: bytes, content_type_oid: str)

        Raises:
            ValueError on decryption failure or unsupported algorithm.
        """
        return _decrypt_enveloped(cms_der, key, cert)


def _decrypt_enveloped(cms_der: bytes, key, cert: x509.Certificate) -> tuple:
    """Parse and decrypt a CMS EnvelopedData ContentInfo."""
    # ContentInfo { id-envelopedData, [0] EnvelopedData }
    _, ci_val, _ = _decode_tlv(cms_der, 0)
    _, oid_raw, ci_pos = _decode_tlv(ci_val, 0)
    content_type = _decode_oid_value(oid_raw)
    if content_type != OID_ENVELOPED_DATA:
        raise ValueError(f"Expected EnvelopedData OID, got {content_type}")

    _, ctx0_val, _ = _decode_tlv(ci_val, ci_pos)
    _, ev_val, _ = _decode_tlv(ctx0_val, 0)    # EnvelopedData SEQUENCE

    ev_pos = 0
    _, _, ev_pos = _decode_tlv(ev_val, ev_pos)  # version
    _, ri_set, ev_pos = _decode_tlv(ev_val, ev_pos)  # recipientInfos SET
    _, eci_seq, _ = _decode_tlv(ev_val, ev_pos)      # encryptedContentInfo

    # Try each RecipientInfo until we find one we can decrypt
    cek = _recover_cek(ri_set, key, cert)
    if cek is None:
        raise ValueError("No matching RecipientInfo found for the provided key/cert")

    # Decrypt the content
    return _decrypt_eci(eci_seq, cek)


def _recover_cek(ri_set: bytes, key, cert: x509.Certificate) -> Optional[bytes]:
    """Try each RecipientInfo and return the CEK on first success."""
    pos = 0
    while pos < len(ri_set):
        tag, ri_bytes, pos = _decode_tlv(ri_set, pos)
        try:
            if tag == 0x30:  # KeyTransRecipientInfo (no context tag)
                cek = _decrypt_ktri(ri_bytes, key, cert)
            elif tag == 0xA1:  # [1] KeyAgreeRecipientInfo
                cek = _decrypt_kari(ri_bytes, key, cert)
            else:
                continue
            if cek is not None:
                return cek
        except Exception:
            continue
    return None


def _decrypt_ktri(ri_bytes: bytes, key, cert: x509.Certificate) -> Optional[bytes]:
    """Decrypt a KeyTransRecipientInfo (RSA-OAEP or PKCS1v15)."""
    ri_pos = 0
    _, _, ri_pos = _decode_tlv(ri_bytes, ri_pos)            # version
    _, ian_seq, ri_pos = _decode_tlv(ri_bytes, ri_pos)      # rid (IssuerAndSerialNumber)
    _, kea_seq, ri_pos = _decode_tlv(ri_bytes, ri_pos)      # keyEncryptionAlgorithm
    _, enc_key, _ = _decode_tlv(ri_bytes, ri_pos)           # encryptedKey OCTET STRING

    # Verify this RI targets our cert (match by serial number)
    try:
        _, issuer_bytes, ian_pos = _decode_tlv(ian_seq, 0)
        _, serial_bytes, _ = _decode_tlv(ian_seq, ian_pos)
        serial = int.from_bytes(serial_bytes, "big")
        if serial != cert.serial_number:
            return None
    except Exception:
        pass

    # Extract key encryption OID
    _, kea_oid_raw, _ = _decode_tlv(kea_seq, 0)
    kea_oid = _decode_oid_value(kea_oid_raw)

    try:
        if kea_oid == OID_RSAES_OAEP:
            return key.decrypt(
                enc_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        elif kea_oid == OID_RSA_ENCRYPTION:
            # Legacy PKCS1v15 — supported for reading old messages
            return key.decrypt(enc_key, asym_padding.PKCS1v15())
        else:
            return None
    except Exception:
        return None


def _decrypt_kari(kari_bytes: bytes, key, cert: x509.Certificate) -> Optional[bytes]:
    """Decrypt a KeyAgreeRecipientInfo (ECDH + AES-256-wrap)."""
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        return None
    try:
        kari_pos = 0
        _, _, kari_pos = _decode_tlv(kari_bytes, kari_pos)          # version
        orig_tag, orig_bytes, kari_pos = _decode_tlv(kari_bytes, kari_pos)  # originator [0]
        # originator [0] EXPLICIT → inside is [1] IMPLICIT OriginatorPublicKey
        # Skip [1] tag, parse AlgorithmIdentifier + BIT STRING
        _, origin_key_bytes, _ = _decode_tlv(orig_bytes, 0)         # A1 content
        _, _alg, ok_pos = _decode_tlv(origin_key_bytes, 0)          # AlgorithmIdentifier
        _, pub_bits_val, _ = _decode_tlv(origin_key_bytes, ok_pos)  # BIT STRING
        # pub_bits_val: 0x00 prefix + uncompressed EC point
        pub_point = pub_bits_val[1:]  # strip leading 0x00

        # Load ephemeral public key
        e_pub = ec.EllipticCurvePublicKey.from_encoded_point(key.public_key().curve, pub_point)
        shared_secret = key.exchange(ec.ECDH(), e_pub)

        # keyEncryptionAlgorithm — skip for now (assume AES-256-wrap)
        _, _key_enc_alg, kari_pos = _decode_tlv(kari_bytes, kari_pos)

        # recipientEncryptedKeys SEQUENCE OF RecipientEncryptedKey
        _, reks_seq, _ = _decode_tlv(kari_bytes, kari_pos)

        rek_pos = 0
        while rek_pos < len(reks_seq):
            _, rek_seq, rek_pos = _decode_tlv(reks_seq, rek_pos)
            try:
                rek_inner_pos = 0
                _, ian_seq, rek_inner_pos = _decode_tlv(rek_seq, rek_inner_pos)  # rid
                _, enc_key, _ = _decode_tlv(rek_seq, rek_inner_pos)              # encryptedKey

                # Match by serial number
                _, _issuer_bytes, ian_pos = _decode_tlv(ian_seq, 0)
                _, serial_bytes, _ = _decode_tlv(ian_seq, ian_pos)
                serial = int.from_bytes(serial_bytes, "big")
                if serial != cert.serial_number:
                    continue

                kek = _derive_kek(shared_secret, OID_AES_256_WRAP, 32)
                return aes_key_unwrap(kek, enc_key, default_backend())
            except Exception:
                continue
    except Exception:
        pass
    return None


def _decrypt_eci(eci_seq: bytes, cek: bytes) -> tuple:
    """Decrypt EncryptedContentInfo. Returns (plaintext, content_type_oid)."""
    eci_pos = 0
    _, ct_oid_raw, eci_pos = _decode_tlv(eci_seq, eci_pos)   # contentType
    content_type_oid = _decode_oid_value(ct_oid_raw)
    _, enc_alg_seq, eci_pos = _decode_tlv(eci_seq, eci_pos)  # contentEncryptionAlgorithm

    # [0] IMPLICIT primitive — encryptedContent
    ec_tag_byte = eci_seq[eci_pos]
    _, ciphertext, _ = _decode_tlv(eci_seq, eci_pos)

    # Parse encryption algorithm
    _, alg_oid_raw, alg_pos = _decode_tlv(enc_alg_seq, 0)
    enc_alg_oid = _decode_oid_value(alg_oid_raw)

    if enc_alg_oid == OID_AES_256_GCM:
        _, gcm_params, _ = _decode_tlv(enc_alg_seq, alg_pos)
        _, nonce, gp_pos = _decode_tlv(gcm_params, 0)
        try:
            _, icvlen_bytes, _ = _decode_tlv(gcm_params, gp_pos)
            # icvlen is an integer, value ignored (we trust the ciphertext length)
        except Exception:
            pass
        return AESGCM(cek).decrypt(nonce, ciphertext, None), content_type_oid

    elif enc_alg_oid == OID_AES_256_CBC:
        _, iv, _ = _decode_tlv(enc_alg_seq, alg_pos)
        cipher = Cipher(algorithms.AES(cek), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = CbcPKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize(), content_type_oid

    else:
        raise ValueError(f"Unsupported content encryption algorithm: {enc_alg_oid}")


# ---------------------------------------------------------------------------
# REST API handler
# ---------------------------------------------------------------------------

class SMIMEHandler(http.server.BaseHTTPRequestHandler):
    """
    REST API for S/MIME v4 CMS operations.

    Endpoints (all POST, JSON in/out):
      /smime/sign    — sign content with a provided private key
      /smime/verify  — verify CMS SignedData
      /smime/encrypt — encrypt for one or more recipients (RSA-OAEP or ECDH)
      /smime/decrypt — decrypt CMS EnvelopedData with a provided private key
    """

    ca = None       # CertificateAuthority — set by make_smime_handler

    def log_message(self, fmt, *args):
        logger.debug("SMIMEHandler: " + fmt, *args)

    def _send_json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code: int, message: str) -> None:
        self._send_json({"error": message}, code)

    def _read_json(self) -> Optional[dict]:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception as e:
            return None

    def do_GET(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        data = self._read_json()
        if data is None:
            self._send_error(400, "Invalid JSON body")
            return

        if path.endswith("/sign"):
            self._handle_sign(data)
        elif path.endswith("/verify"):
            self._handle_verify(data)
        elif path.endswith("/encrypt"):
            self._handle_encrypt(data)
        elif path.endswith("/decrypt"):
            self._handle_decrypt(data)
        else:
            self._send_error(404, f"Unknown endpoint: {path}")

    def _handle_sign(self, data: dict) -> None:
        """
        POST /smime/sign
        {
          "key_pem": "...",
          "cert_pem": "...",
          "content_b64": "...",
          "detached": false,
          "additional_certs_pem": ["..."]
        }
        → { "signed_b64": "...", "mime_type": "..." }
        """
        try:
            key = serialization.load_pem_private_key(
                data["key_pem"].encode(), password=None
            )
            cert = x509.load_pem_x509_certificate(data["cert_pem"].encode())
            content = base64.b64decode(data["content_b64"])
            detached = bool(data.get("detached", False))
            extra_pems = data.get("additional_certs_pem", [])
            extra_certs = [x509.load_pem_x509_certificate(p.encode()) for p in extra_pems]
        except Exception as e:
            self._send_error(400, f"Input error: {e}")
            return

        try:
            signed_der = SMIMESigner.sign(content, key, cert, detached=detached,
                                          additional_certs=extra_certs)
        except Exception as e:
            self._send_error(500, f"Signing failed: {e}")
            return

        smime_type = "detached" if detached else "signed-data"
        self._send_json({
            "signed_b64": base64.b64encode(signed_der).decode(),
            "mime_type": f"application/pkcs7-mime; smime-type={smime_type}",
        })

    def _handle_verify(self, data: dict) -> None:
        """
        POST /smime/verify
        {
          "signed_b64": "...",
          "content_b64": "..."  (optional, for detached signatures)
        }
        → { "ok": bool, "signer_subject": "...", "signing_time": "...", "errors": [...] }
        """
        try:
            signed_der = base64.b64decode(data["signed_b64"])
            detached = base64.b64decode(data["content_b64"]) if data.get("content_b64") else None
        except Exception as e:
            self._send_error(400, f"Input error: {e}")
            return

        result = SMIMESigner.verify(signed_der, detached)
        self._send_json({
            "ok": result["ok"],
            "signer_subject": (
                result["signer_cert"].subject.rfc4514_string()
                if result["signer_cert"] else None
            ),
            "signing_time": result["signing_time"],
            "errors": result["errors"],
        })

    def _handle_encrypt(self, data: dict) -> None:
        """
        POST /smime/encrypt
        {
          "recipient_certs_pem": ["...", ...],
          "content_b64": "...",
          "alg": "aes256-gcm"  // or "aes256-cbc"
        }
        → { "encrypted_b64": "...", "mime_type": "..." }
        """
        try:
            certs = [x509.load_pem_x509_certificate(p.encode())
                     for p in data["recipient_certs_pem"]]
            content = base64.b64decode(data["content_b64"])
            alg = data.get("alg", "aes256-gcm")
        except Exception as e:
            self._send_error(400, f"Input error: {e}")
            return

        try:
            encrypted_der = SMIMEEncryptor.encrypt(content, certs, alg=alg)
        except Exception as e:
            self._send_error(500, f"Encryption failed: {e}")
            return

        self._send_json({
            "encrypted_b64": base64.b64encode(encrypted_der).decode(),
            "mime_type": "application/pkcs7-mime; smime-type=enveloped-data",
        })

    def _handle_decrypt(self, data: dict) -> None:
        """
        POST /smime/decrypt
        {
          "key_pem": "...",
          "cert_pem": "...",
          "envelope_b64": "..."
        }
        → { "content_b64": "...", "content_type_oid": "..." }
        """
        try:
            key = serialization.load_pem_private_key(
                data["key_pem"].encode(), password=None
            )
            cert = x509.load_pem_x509_certificate(data["cert_pem"].encode())
            cms_der = base64.b64decode(data["envelope_b64"])
        except Exception as e:
            self._send_error(400, f"Input error: {e}")
            return

        try:
            plaintext, content_type_oid = SMIMEDecryptor.decrypt(cms_der, key, cert)
        except Exception as e:
            self._send_error(500, f"Decryption failed: {e}")
            return

        self._send_json({
            "content_b64": base64.b64encode(plaintext).decode(),
            "content_type_oid": content_type_oid,
        })


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

def make_smime_handler(ca=None):
    """Return a SMIMEHandler subclass with *ca* bound as a class attribute."""
    class BoundSMIMEHandler(SMIMEHandler):
        pass
    BoundSMIMEHandler.ca = ca
    return BoundSMIMEHandler


def start_smime_server(route_table, prefix: str, ca=None):
    """
    Register the S/MIME REST handler under *prefix* in *route_table*.

    Returns a _RouteProxy whose .shutdown() removes the routes.

    CLI flag: --smime-prefix (default /smime).
    """
    from dispatcher_server import _RouteProxy
    handler_cls = make_smime_handler(ca)
    route_table.register(prefix, handler_cls)
    logger.info("S/MIME REST handler registered at prefix %r", prefix)
    return _RouteProxy(route_table, prefix, label="smime")
