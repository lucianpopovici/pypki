"""
hsm_backend.py — PKCS#11 / HSM signing key support for PyPKI (§5.1)
=====================================================================

Provides HSM-backed private key objects that implement cryptography's
RSAPrivateKey / EllipticCurvePrivateKey ABCs so they can be passed
directly to CertificateBuilder.sign() without any changes to existing
signing paths (``_sign_builder`` in pki_server.py continues to work
unchanged).

Initialisation path
-------------------
1. ``HSMConfig.from_args(args)`` parses ``--hsm-*`` CLI flags.
2. ``load_hsm_signing_key(cfg)`` opens the PKCS#11 session and returns
   an ``HSMRSAPrivateKey`` or ``HSMECPrivateKey``.
3. ``CertificateAuthority._load_or_create_ca()`` receives the HSM key as
   ``self.ca_key`` — all downstream callers remain unchanged.

Security properties
-------------------
* Private key material **never leaves the HSM token** — only the public
  key modulus/point is exported (read-only attribute access).
* ``private_bytes()`` and ``private_numbers()`` raise ``NotImplementedError``
  so accidental serialisation fails fast rather than leaking material.
* ``EXTRACTABLE=False`` is enforced during key generation (``--hsm-init-if-missing``).

Supported mechanisms
--------------------
RSA PKCS#1 v1.5:  CKM_SHA256_RSA_PKCS / CKM_SHA384_RSA_PKCS / CKM_SHA512_RSA_PKCS
RSA PSS:          CKM_SHA256_RSA_PKCS_PSS / CKM_SHA384_RSA_PKCS_PSS / CKM_SHA512_RSA_PKCS_PSS
ECDSA:            CKM_ECDSA_SHA256 / CKM_ECDSA_SHA384 / CKM_ECDSA_SHA512

Optional dependency
-------------------
``python-pkcs11`` is only imported when an ``--hsm-module`` flag is supplied.
PyPKI starts normally without it; a clear error is raised if HSM is requested
but the driver is not installed.

    pip install python-pkcs11          # driver
    apt install softhsm2               # soft token for testing / CI
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Optional, TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

if TYPE_CHECKING:
    pass

logger = logging.getLogger("pypki.hsm")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class HSMConfig:
    """Parsed HSM CLI flags — all fields except ``module`` have safe defaults."""

    module: str
    slot: int = 0
    pin_env: str = "PYPKI_HSM_PIN"
    key_label: str = "pypki-ca"
    init_if_missing: bool = False

    @classmethod
    def from_args(cls, args: Any) -> Optional["HSMConfig"]:
        """Return an HSMConfig if --hsm-module was set, else None."""
        module = getattr(args, "hsm_module", None)
        if not module:
            return None
        return cls(
            module=module,
            slot=getattr(args, "hsm_slot", 0),
            pin_env=getattr(args, "hsm_pin_env", "PYPKI_HSM_PIN"),
            key_label=getattr(args, "hsm_key_label", "pypki-ca"),
            init_if_missing=getattr(args, "hsm_init_if_missing", False),
        )


# ---------------------------------------------------------------------------
# PKCS#11 key wrappers — used only in the real HSM path
# ---------------------------------------------------------------------------

class _PKCS11RSAKeyWrapper:
    """
    Wraps a python-pkcs11 RSA PrivateKey and exposes a sign(data, padding, hash_alg)
    interface so ``HSMRSAPrivateKey.sign()`` can delegate without importing pkcs11.
    """

    def __init__(self, pkcs11_key: Any) -> None:
        self._key = pkcs11_key

    def sign(self, data: bytes,
             padding_obj: asym_padding.AsymmetricPadding,
             hash_alg: hashes.HashAlgorithm) -> bytes:
        import pkcs11

        hash_name = type(hash_alg).__name__.lower()

        if isinstance(padding_obj, asym_padding.PKCS1v15):
            _mechs = {
                "sha256": pkcs11.Mechanism.SHA256_RSA_PKCS,
                "sha384": pkcs11.Mechanism.SHA384_RSA_PKCS,
                "sha512": pkcs11.Mechanism.SHA512_RSA_PKCS,
            }
            mech = _mechs.get(hash_name)
            if mech is None:
                raise ValueError(f"Unsupported hash for RSA PKCS#1v15 HSM: {hash_name}")
            return bytes(self._key.sign(data, mechanism=mech))

        if isinstance(padding_obj, asym_padding.PSS):
            _mechs = {
                "sha256": pkcs11.Mechanism.SHA256_RSA_PKCS_PSS,
                "sha384": pkcs11.Mechanism.SHA384_RSA_PKCS_PSS,
                "sha512": pkcs11.Mechanism.SHA512_RSA_PKCS_PSS,
            }
            _hash_mechs = {
                "sha256": pkcs11.Mechanism.SHA256,
                "sha384": pkcs11.Mechanism.SHA384,
                "sha512": pkcs11.Mechanism.SHA512,
            }
            mech = _mechs.get(hash_name)
            hash_mech = _hash_mechs.get(hash_name)
            if mech is None:
                raise ValueError(f"Unsupported hash for RSA PSS HSM: {hash_name}")
            salt = padding_obj._salt_length
            if not isinstance(salt, int):
                salt = hash_alg.digest_size
            try:
                from pkcs11.mechanisms import RSAPSSMechanism
                params = RSAPSSMechanism(hash_mech, pkcs11.MGF.SHA256, salt)
                return bytes(self._key.sign(data, mechanism=mech, mechanism_param=params))
            except (ImportError, AttributeError):
                return bytes(self._key.sign(data, mechanism=mech))

        raise ValueError(f"Unsupported RSA padding for HSM: {type(padding_obj).__name__}")


class _PKCS11ECKeyWrapper:
    """
    Wraps a python-pkcs11 EC PrivateKey and exposes a sign(data, ecdsa_alg)
    interface so ``HSMECPrivateKey.sign()`` can delegate without importing pkcs11.
    """

    def __init__(self, pkcs11_key: Any) -> None:
        self._key = pkcs11_key

    def sign(self, data: bytes, signature_algorithm: ec.ECDSA) -> bytes:
        import pkcs11
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        hash_name = type(signature_algorithm.algorithm).__name__.lower()
        _mechs = {
            "sha256": pkcs11.Mechanism.ECDSA_SHA256,
            "sha384": pkcs11.Mechanism.ECDSA_SHA384,
            "sha512": pkcs11.Mechanism.ECDSA_SHA512,
        }
        mech = _mechs.get(hash_name)
        if mech is None:
            raise ValueError(f"Unsupported hash for ECDSA HSM: {hash_name}")
        raw = bytes(self._key.sign(data, mechanism=mech))
        half = len(raw) // 2
        r = int.from_bytes(raw[:half], "big")
        s = int.from_bytes(raw[half:], "big")
        return encode_dss_signature(r, s)


_NO_PKCS11_MSG = (
    "python-pkcs11 is required for HSM support. "
    "Install with: pip install python-pkcs11\n"
    "For testing with a software token: apt install softhsm2"
)


# ---------------------------------------------------------------------------
# HSM-backed RSA private key
# ---------------------------------------------------------------------------

class HSMRSAPrivateKey(rsa.RSAPrivateKey):
    """
    RSA signing key backed by a PKCS#11 token.

    Subclasses cryptography's ``RSAPrivateKey`` ABC so that isinstance()
    checks in CertificateBuilder.sign() / CRL / OCSP builders succeed and
    the Rust layer dispatches back into our Python sign() method.

    The private key **never leaves the token**. private_bytes() and
    private_numbers() raise NotImplementedError intentionally.
    """

    def __init__(self, priv_key: Any, public_key: rsa.RSAPublicKey) -> None:
        """
        Parameters
        ----------
        priv_key   : pkcs11.PrivateKey handle from python-pkcs11
        public_key : cryptography RSAPublicKey loaded from the token's public key attributes
        """
        self._priv = priv_key
        self._pub = public_key

    # --- Required ABC methods ---

    def sign(self, data: bytes, padding_obj: asym_padding.AsymmetricPadding,
             algorithm: hashes.HashAlgorithm) -> bytes:
        # Delegates to _priv.sign(data, padding, hash_alg).
        # For real HSM: _priv is _PKCS11RSAKeyWrapper (imports pkcs11 lazily).
        # For tests:    _priv is _MockPKCS11Key (no pkcs11 import needed).
        return bytes(self._priv.sign(data, padding_obj, algorithm))

    @property
    def key_size(self) -> int:
        return self._pub.key_size

    def public_key(self) -> rsa.RSAPublicKey:
        return self._pub

    def decrypt(self, ciphertext: bytes, padding_obj: asym_padding.AsymmetricPadding) -> bytes:
        raise NotImplementedError("HSM key decrypt not implemented (signing keys only)")

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        raise NotImplementedError("Private key material cannot be exported from HSM")

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError("Private key material cannot be exported from HSM")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


# ---------------------------------------------------------------------------
# HSM-backed ECDSA private key
# ---------------------------------------------------------------------------

class HSMECPrivateKey(ec.EllipticCurvePrivateKey):
    """
    ECDSA signing key backed by a PKCS#11 token.

    PKCS#11 ECDSA_SHA* mechanisms return raw r||s (2*coord_bytes); this
    class converts to DER-encoded ASN.1 SEQUENCE { INTEGER r, INTEGER s }
    as required by the cryptography library.
    """

    def __init__(self, priv_key: Any, public_key: ec.EllipticCurvePublicKey) -> None:
        self._priv = priv_key
        self._pub = public_key

    def sign(self, data: bytes, signature_algorithm: ec.ECDSA) -> bytes:
        if not isinstance(signature_algorithm, ec.ECDSA):
            raise TypeError(f"Expected ECDSA signature algorithm, got {type(signature_algorithm).__name__}")
        # Delegates to _priv.sign(data, ecdsa_alg).
        # For real HSM: _priv is _PKCS11ECKeyWrapper.
        # For tests:    _priv is _MockPKCS11Key.
        return bytes(self._priv.sign(data, signature_algorithm))

    @property
    def key_size(self) -> int:
        return self._pub.key_size

    @property
    def curve(self) -> ec.EllipticCurve:
        return self._pub.curve

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._pub

    def exchange(self, algorithm: Any, peer_public_key: Any) -> bytes:
        raise NotImplementedError("ECDH exchange not supported for HSM CA signing keys")

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        raise NotImplementedError("Private key material cannot be exported from HSM")

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError("Private key material cannot be exported from HSM")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


# ---------------------------------------------------------------------------
# Key loading + generation
# ---------------------------------------------------------------------------

def load_hsm_signing_key(cfg: HSMConfig):
    """
    Open a PKCS#11 session with *cfg*, locate the CA signing key by label,
    and return an ``HSMRSAPrivateKey`` or ``HSMECPrivateKey``.

    If the key is absent and ``cfg.init_if_missing`` is True, a 4096-bit RSA
    key pair is generated on the token with ``CKA_EXTRACTABLE = False``.

    Raises
    ------
    RuntimeError   if python-pkcs11 is not installed
    RuntimeError   if the PIN env var is not set
    RuntimeError   if the key label is not found and init_if_missing is False
    """
    try:
        import pkcs11
        from pkcs11 import KeyType, ObjectClass, Attribute
    except ImportError:
        raise RuntimeError(_NO_PKCS11_MSG)

    pin = os.environ.get(cfg.pin_env)
    if not pin:
        raise RuntimeError(
            f"HSM PIN not set. Export environment variable {cfg.pin_env!r} "
            "before starting PyPKI."
        )

    lib = pkcs11.lib(cfg.module)
    token = lib.get_token(slot_id=cfg.slot)
    # Open read-write so key generation (if needed) and signing both work.
    session = token.open(user_pin=pin, rw=True)

    # Locate private key by label.
    priv_iter = session.get_objects({
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.LABEL: cfg.key_label,
    })
    try:
        priv = next(priv_iter)
    except StopIteration:
        if cfg.init_if_missing:
            priv = _generate_rsa_on_token(session, cfg.key_label)
            logger.info(
                f"Generated RSA-4096 key on HSM slot={cfg.slot} label={cfg.key_label!r}"
            )
        else:
            raise RuntimeError(
                f"Key label {cfg.key_label!r} not found on HSM slot {cfg.slot}. "
                f"Use --hsm-init-if-missing to generate it automatically."
            )

    pub = _export_public_key(session, cfg.key_label)

    if isinstance(pub, rsa.RSAPublicKey):
        logger.info(f"Loaded RSA-{pub.key_size} key from HSM (slot={cfg.slot} label={cfg.key_label!r})")
        return HSMRSAPrivateKey(_PKCS11RSAKeyWrapper(priv), pub)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        logger.info(
            f"Loaded EC-{pub.curve.name} key from HSM (slot={cfg.slot} label={cfg.key_label!r})"
        )
        return HSMECPrivateKey(_PKCS11ECKeyWrapper(priv), pub)
    else:
        raise RuntimeError(f"Unsupported HSM key type: {type(pub).__name__}")


def _generate_rsa_on_token(session: Any, label: str) -> Any:
    """Generate a non-extractable RSA-4096 key pair on the token."""
    try:
        import pkcs11
        from pkcs11 import KeyType, Attribute
    except ImportError:
        raise RuntimeError(_NO_PKCS11_MSG)

    pub_template = {
        Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
        Attribute.KEY_TYPE: KeyType.RSA,
        Attribute.LABEL: label,
        Attribute.MODULUS_BITS: 4096,
        Attribute.PUBLIC_EXPONENT: b"\x01\x00\x01",  # 65537
        Attribute.TOKEN: True,
        Attribute.VERIFY: True,
    }
    priv_template = {
        Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
        Attribute.KEY_TYPE: KeyType.RSA,
        Attribute.LABEL: label,
        Attribute.TOKEN: True,
        Attribute.SENSITIVE: True,
        Attribute.PRIVATE: True,
        Attribute.EXTRACTABLE: False,
        Attribute.SIGN: True,
    }
    _pub, priv = session.generate_keypair(
        KeyType.RSA, 4096,
        public_template=pub_template,
        private_template=priv_template,
    )
    return priv


def _export_public_key(session: Any, label: str):
    """
    Export the public key for *label* from the token as a cryptography
    RSAPublicKey or EllipticCurvePublicKey.
    """
    try:
        import pkcs11
        from pkcs11 import KeyType, ObjectClass, Attribute
    except ImportError:
        raise RuntimeError(_NO_PKCS11_MSG)

    pub_iter = session.get_objects({
        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
        Attribute.LABEL: label,
    })
    try:
        pub_obj = next(pub_iter)
    except StopIteration:
        raise RuntimeError(f"Public key with label {label!r} not found on token")

    key_type = pub_obj[Attribute.KEY_TYPE]

    if key_type == KeyType.RSA:
        modulus = int.from_bytes(pub_obj[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_obj[Attribute.PUBLIC_EXPONENT], "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    if key_type == KeyType.EC:
        # CKA_EC_POINT is an OCTET STRING containing the uncompressed point
        # (possibly DER-wrapped as another OCTET STRING by some tokens).
        # CKA_EC_PARAMS is the DER-encoded curve OID (namedCurve form).
        ec_params: bytes = pub_obj[Attribute.EC_PARAMS]
        ec_point: bytes = pub_obj[Attribute.EC_POINT]

        # Some tokens wrap EC_POINT in a DER OCTET STRING (tag 0x04 len body)
        # — strip the wrapper if present.
        if ec_point and ec_point[0] == 0x04 and len(ec_point) > 2:
            # Could be DER OCTET STRING tag 0x04 <len> <point>
            # Check if outer byte 0x04 is OCTET STRING or uncompressed point marker
            # An uncompressed EC point also starts with 0x04 but is followed by coords.
            # Heuristic: if the length byte(s) decode as DER and the inner content
            # starts with 0x04 (uncompressed marker), strip the outer wrapper.
            inner_len, hdr_len = _decode_ber_len(ec_point, 1)
            if hdr_len + inner_len == len(ec_point) and ec_point[hdr_len] == 0x04:
                ec_point = ec_point[hdr_len:]

        # Build a SubjectPublicKeyInfo DER from ec_params + ec_point and let
        # the cryptography library parse it — avoids hand-mapping OID → curve.
        spki = _build_ec_spki(ec_params, ec_point)
        return serialization.load_der_public_key(spki)

    raise RuntimeError(f"Unsupported PKCS#11 key type for export: {key_type}")


def _decode_ber_len(data: bytes, offset: int) -> tuple[int, int]:
    """Return (length_value, total_header_bytes_consumed) from BER length at offset."""
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    n = b & 0x7F
    val = int.from_bytes(data[offset + 1: offset + 1 + n], "big")
    return val, offset + 1 + n


def _encode_der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def _build_ec_spki(ec_params_der: bytes, ec_point_bytes: bytes) -> bytes:
    """
    Build a DER SubjectPublicKeyInfo from:
      ec_params_der  — DER OID of the curve (CKA_EC_PARAMS)
      ec_point_bytes — Uncompressed point (0x04 || x || y)
    """
    # id-ecPublicKey OID bytes: 1.2.840.10045.2.1
    oid_ec_pubkey = bytes.fromhex("2a 86 48 ce 3d 02 01".replace(" ", ""))
    alg_id_content = (
        b"\x06" + _encode_der_len(len(oid_ec_pubkey)) + oid_ec_pubkey
        + ec_params_der  # the named-curve OID as an OID DER sequence
    )
    alg_id = b"\x30" + _encode_der_len(len(alg_id_content)) + alg_id_content
    bit_string = b"\x03" + _encode_der_len(len(ec_point_bytes) + 1) + b"\x00" + ec_point_bytes
    body = alg_id + bit_string
    return b"\x30" + _encode_der_len(len(body)) + body
