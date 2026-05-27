"""
composite.py — Composite ML-DSA + classical signature support.

Implements draft-ietf-lamps-pq-composite-sigs (targeting revision -18, April 2026).
Gated behind --enable-composite-mldsa in pki_server; default off until the
RFC number is assigned and OIDs confirmed stable.

Wire format (draft §4 / §5):
  SubjectPublicKeyInfo.subjectPublicKey BIT STRING:
      ML-DSA_raw_bytes || classical_raw_bytes  (concatenation, no extra wrapper)

  Signature BIT STRING value is DER of:
      CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
      [0] ML-DSA signature, [1] classical signature

Signing combiner (draft §4.2, -13 HPKE-style domain separators):
  M' = "CompositeAlgorithmSignatures2025" || domain_label || H(M)
  domain_label = ASCII algorithm name string  (NOT OID DER bytes; -13 fix)
  H            = SHA-256 for *-SHA256 variants, SHA-512 for *-SHA512 variants

Re-verify OIDs at https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/
before each release.  OIDs live in the 2.16.840.1.114027.80.8.1 Entrust arc.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    load_der_public_key,
)

from der_codec import (
    seq, bit_string, oid as _oid_der, integer as _int_der,
    octet_string, null as _null, decode_tlv,
)

# ---------------------------------------------------------------------------
# Algorithm catalog (draft-ietf-lamps-pq-composite-sigs §6.1)
# Re-verify OIDs before each release — stable since -13 per sidecar.
# ---------------------------------------------------------------------------

COMPOSITE_OIDS: dict[str, dict] = {
    "composite-mldsa44-rsa2048-pss": {
        "oid":         "2.16.840.1.114027.80.8.1.13",
        "mldsa_level": 44,
        "classical":   "rsa2048-pss",
        "hash":        "sha256",
        "domain":      "id-MLDSA44-RSA2048-PSS-SHA256",
    },
    "composite-mldsa44-ecdsa-p256": {
        "oid":         "2.16.840.1.114027.80.8.1.16",
        "mldsa_level": 44,
        "classical":   "ecdsa-p256",
        "hash":        "sha256",
        "domain":      "id-MLDSA44-ECDSA-P256-SHA256",
    },
    "composite-mldsa65-ecdsa-p384": {
        "oid":         "2.16.840.1.114027.80.8.1.21",
        "mldsa_level": 65,
        "classical":   "ecdsa-p384",
        "hash":        "sha512",
        "domain":      "id-MLDSA65-ECDSA-P384-SHA512",
    },
    "composite-mldsa87-ecdsa-p521": {
        "oid":         "2.16.840.1.114027.80.8.1.27",
        "mldsa_level": 87,
        "classical":   "ecdsa-p521",
        "hash":        "sha512",
        "domain":      "id-MLDSA87-ECDSA-P521-SHA512",
    },
}

# ML-DSA public key byte lengths per FIPS 204 §5
_MLDSA_PUB_LEN = {44: 1312, 65: 1952, 87: 2592}

# ML-DSA algorithm OIDs (draft-ietf-lamps-dilithium-certificates)
_MLDSA_OIDS = {
    44: "2.16.840.1.101.3.4.3.17",
    65: "2.16.840.1.101.3.4.3.18",
    87: "2.16.840.1.101.3.4.3.19",
}

# ECDSA curve OIDs
_EC_CURVE_OIDS = {
    "ecdsa-p256": "1.2.840.10045.3.1.7",
    "ecdsa-p384": "1.3.132.0.34",
    "ecdsa-p521": "1.3.132.0.35",
}

# Domain-separator prefix per draft §4.2 (-12 onward; no randomizer)
_PREFIX = b"CompositeAlgorithmSignatures2025"


# ---------------------------------------------------------------------------
# Key container
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class CompositeKey:
    name: str          # key in COMPOSITE_OIDS
    mldsa: object      # MLDSA{44,65,87}PrivateKey
    classical: object  # RSAPrivateKey | EllipticCurvePrivateKey


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_composite_key(name: str) -> CompositeKey:
    """Generate a fresh composite key pair for the named algorithm combination."""
    if name not in COMPOSITE_OIDS:
        raise ValueError(f"Unknown composite algorithm: {name!r}. Valid: {list(COMPOSITE_OIDS)}")
    entry = COMPOSITE_OIDS[name]
    return CompositeKey(
        name=name,
        mldsa=_gen_mldsa(entry["mldsa_level"]),
        classical=_gen_classical(entry["classical"]),
    )


def _gen_mldsa(level: int):
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
    except ImportError:
        raise RuntimeError("cryptography ≥ 44.0.0 required for ML-DSA / composite support")
    generators = {44: _mldsa.MLDSA44PrivateKey, 65: _mldsa.MLDSA65PrivateKey, 87: _mldsa.MLDSA87PrivateKey}
    return generators[level].generate()


def _gen_classical(name: str):
    if name == "rsa2048-pss":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if name == "ecdsa-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if name == "ecdsa-p384":
        return ec.generate_private_key(ec.SECP384R1())
    if name == "ecdsa-p521":
        return ec.generate_private_key(ec.SECP521R1())
    raise ValueError(f"Unknown classical component: {name!r}")


# ---------------------------------------------------------------------------
# Public key serialization
# ---------------------------------------------------------------------------

def composite_spki_der(key: CompositeKey) -> bytes:
    """
    Build SubjectPublicKeyInfo DER for a composite key pair.

    BIT STRING value = ML-DSA_raw || classical_raw  (draft §5.1).
    AlgorithmIdentifier parameters absent (not NULL) per draft §5.1.
    """
    entry = COMPOSITE_OIDS[key.name]
    mldsa_raw = _mldsa_pub_raw(key.mldsa.public_key())
    classical_raw = _classical_pub_raw(key.classical.public_key())
    alg_id = seq(_oid_der(entry["oid"]))  # absent parameters per draft §5.1
    return seq(alg_id + bit_string(mldsa_raw + classical_raw))


def _mldsa_pub_raw(pub) -> bytes:
    """Extract raw ML-DSA public key bytes from a public key object."""
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    _, body, _ = decode_tlv(spki, 0)
    _, _, alg_end = decode_tlv(body, 0)   # skip AlgorithmIdentifier
    _, bs_val, _ = decode_tlv(body, alg_end)
    return bs_val[1:]  # strip unused-bits prefix byte


def _classical_pub_raw(pub) -> bytes:
    """Serialize classical public key to its raw form (no SPKI wrapper)."""
    if isinstance(pub, rsa.RSAPublicKey):
        # RFC 8017 A.1.1 RSAPublicKey DER (PKCS1)
        return pub.public_bytes(Encoding.DER, PublicFormat.PKCS1)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        # X9.62 uncompressed point (04 || x || y); no OCTET STRING per draft -13
        return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    raise TypeError(f"Unsupported classical key type: {type(pub).__name__}")


# ---------------------------------------------------------------------------
# Private key serialization  (RFC 5958 / PKCS#8)
# ---------------------------------------------------------------------------

def composite_private_key_der(key: CompositeKey) -> bytes:
    """
    Serialize composite private key to OneAsymmetricKey DER (RFC 5958).

    privateKey OCTET STRING wraps:
        CompositePrivateKey ::= SEQUENCE SIZE(2) OF OneAsymmetricKey
    [0] = ML-DSA, [1] = classical  (draft §6.2)
    """
    entry = COMPOSITE_OIDS[key.name]
    mldsa_p8 = key.mldsa.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    classical_p8 = key.classical.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    alg_id = seq(_oid_der(entry["oid"]))
    return seq(_int_der(0) + alg_id + octet_string(seq(mldsa_p8 + classical_p8)))


# ---------------------------------------------------------------------------
# Signing combiner (draft §4.2)
# ---------------------------------------------------------------------------

def composite_sign(key: CompositeKey, message: bytes) -> bytes:
    """
    Sign message with the composite combiner.

    Returns CompositeSignatureValue DER:
        SEQUENCE { BIT STRING(mldsa_sig), BIT STRING(classical_sig) }
    """
    entry = COMPOSITE_OIDS[key.name]
    m_prime = _m_prime(entry, message)
    sig_mldsa = key.mldsa.sign(m_prime)
    sig_classical = _classical_sign(key.classical, m_prime, entry)
    return seq(bit_string(sig_mldsa) + bit_string(sig_classical))


def _m_prime(entry: dict, message: bytes) -> bytes:
    """Construct M' = Prefix || domain_label || H(message)."""
    domain = entry["domain"].encode("ascii")
    h = hashlib.sha256(message) if entry["hash"] == "sha256" else hashlib.sha512(message)
    return _PREFIX + domain + h.digest()


def _classical_sign(key, m_prime: bytes, entry: dict) -> bytes:
    if entry["classical"] == "rsa2048-pss":
        return key.sign(
            m_prime,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
    hash_alg = hashes.SHA256() if entry["hash"] == "sha256" else hashes.SHA512()
    return key.sign(m_prime, ec.ECDSA(hash_alg))


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def composite_verify(spki_der: bytes, name: str, message: bytes, sig_der: bytes) -> bool:
    """
    Verify a composite signature against a composite SubjectPublicKeyInfo.
    Returns True only when both ML-DSA and classical components verify.
    """
    entry = COMPOSITE_OIDS[name]
    m_prime = _m_prime(entry, message)

    _, seq_val, _ = decode_tlv(sig_der, 0)
    _, mldsa_bs, pos = decode_tlv(seq_val, 0)
    _, classical_bs, _ = decode_tlv(seq_val, pos)
    sig_mldsa = mldsa_bs[1:]       # strip unused-bits prefix byte
    sig_classical = classical_bs[1:]

    mldsa_pub, classical_pub = _parse_composite_spki(spki_der, entry)

    try:
        mldsa_pub.verify(sig_mldsa, m_prime)
    except Exception:
        return False
    try:
        _classical_verify(classical_pub, m_prime, sig_classical, entry)
    except Exception:
        return False
    return True


def _parse_composite_spki(spki_der: bytes, entry: dict):
    """Extract ML-DSA and classical public keys from a composite SPKI DER."""
    _, body, _ = decode_tlv(spki_der, 0)
    _, _, alg_end = decode_tlv(body, 0)
    _, bs_val, _ = decode_tlv(body, alg_end)
    pub_raw = bs_val[1:]  # strip unused-bits byte

    mldsa_len = _MLDSA_PUB_LEN[entry["mldsa_level"]]
    mldsa_raw = pub_raw[:mldsa_len]
    classical_raw = pub_raw[mldsa_len:]

    mldsa_pub = _load_mldsa_pub(mldsa_raw, entry["mldsa_level"])
    classical_pub = _load_classical_pub(classical_raw, entry["classical"])
    return mldsa_pub, classical_pub


def _load_mldsa_pub(raw: bytes, level: int):
    alg_id = seq(_oid_der(_MLDSA_OIDS[level]))
    return load_der_public_key(seq(alg_id + bit_string(raw)))


def _load_classical_pub(raw: bytes, classical_name: str):
    if "rsa" in classical_name:
        alg_id = seq(_oid_der("1.2.840.113549.1.1.1") + _null())
        return load_der_public_key(seq(alg_id + bit_string(raw)))
    alg_id = seq(_oid_der("1.2.840.10045.2.1") + _oid_der(_EC_CURVE_OIDS[classical_name]))
    return load_der_public_key(seq(alg_id + bit_string(raw)))


def _classical_verify(pub, m_prime: bytes, sig: bytes, entry: dict) -> None:
    if entry["classical"] == "rsa2048-pss":
        pub.verify(
            sig, m_prime,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
        return
    hash_alg = hashes.SHA256() if entry["hash"] == "sha256" else hashes.SHA512()
    pub.verify(sig, m_prime, ec.ECDSA(hash_alg))
