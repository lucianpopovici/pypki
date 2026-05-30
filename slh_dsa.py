"""
SLH-DSA (FIPS 205) support for PyPKI.

Provides key generation, signing, SPKI and PKCS#8 DER encoding for all twelve
SLH-DSA parameter sets defined in draft-ietf-lamps-x509-slhdsa-09.

Backed by the 'slhdsa' pip package (import name 'slhdsa').  Only the
sign/verify/keygen primitives are delegated to slhdsa; all DER encoding is
hand-rolled so we control the wire format precisely.
"""
from __future__ import annotations

import base64
import hashlib

try:
    import slhdsa as _slhdsa
    HAS_SLHDSA = True
except ImportError:
    _slhdsa = None  # type: ignore[assignment]
    HAS_SLHDSA = False

# ---------------------------------------------------------------------------
# OID table — draft-ietf-lamps-x509-slhdsa-09 §6
# 2.16.840.1.101.3.4.3.{20..31}
# ---------------------------------------------------------------------------

SLH_DSA_OIDS: dict[str, str] = {
    "slh-dsa-sha2-128s":  "2.16.840.1.101.3.4.3.20",
    "slh-dsa-sha2-128f":  "2.16.840.1.101.3.4.3.21",
    "slh-dsa-sha2-192s":  "2.16.840.1.101.3.4.3.22",
    "slh-dsa-sha2-192f":  "2.16.840.1.101.3.4.3.23",
    "slh-dsa-sha2-256s":  "2.16.840.1.101.3.4.3.24",
    "slh-dsa-sha2-256f":  "2.16.840.1.101.3.4.3.25",
    "slh-dsa-shake-128s": "2.16.840.1.101.3.4.3.26",
    "slh-dsa-shake-128f": "2.16.840.1.101.3.4.3.27",
    "slh-dsa-shake-192s": "2.16.840.1.101.3.4.3.28",
    "slh-dsa-shake-192f": "2.16.840.1.101.3.4.3.29",
    "slh-dsa-shake-256s": "2.16.840.1.101.3.4.3.30",
    "slh-dsa-shake-256f": "2.16.840.1.101.3.4.3.31",
}

# Reverse: dotted OID string → parameter name
_OID_TO_NAME: dict[str, str] = {v: k for k, v in SLH_DSA_OIDS.items()}

# Public key size (2*n bytes), private key size (4*n bytes) per FIPS 205
PK_SIZE: dict[str, int] = {
    "slh-dsa-sha2-128s": 32,  "slh-dsa-sha2-128f": 32,
    "slh-dsa-sha2-192s": 48,  "slh-dsa-sha2-192f": 48,
    "slh-dsa-sha2-256s": 64,  "slh-dsa-sha2-256f": 64,
    "slh-dsa-shake-128s": 32, "slh-dsa-shake-128f": 32,
    "slh-dsa-shake-192s": 48, "slh-dsa-shake-192f": 48,
    "slh-dsa-shake-256s": 64, "slh-dsa-shake-256f": 64,
}
SK_SIZE: dict[str, int] = {k: v * 2 for k, v in PK_SIZE.items()}

# Approximate signature sizes (bytes) — see CLAUDE-slh-dsa.md
SIG_SIZE: dict[str, int] = {
    "slh-dsa-sha2-128s":   7856, "slh-dsa-sha2-128f":  17088,
    "slh-dsa-sha2-192s":  16224, "slh-dsa-sha2-192f":  35664,
    "slh-dsa-sha2-256s":  29792, "slh-dsa-sha2-256f":  49856,
    "slh-dsa-shake-128s":  7856, "slh-dsa-shake-128f": 17088,
    "slh-dsa-shake-192s": 16224, "slh-dsa-shake-192f": 35664,
    "slh-dsa-shake-256s": 29792, "slh-dsa-shake-256f": 49856,
}

# Map from parameter name to slhdsa Parameter object (populated when available)
_PARAMS: dict[str, object] = {}
if HAS_SLHDSA:
    _PARAMS = {
        "slh-dsa-sha2-128s":  _slhdsa.sha2_128s,
        "slh-dsa-sha2-128f":  _slhdsa.sha2_128f,
        "slh-dsa-sha2-192s":  _slhdsa.sha2_192s,
        "slh-dsa-sha2-192f":  _slhdsa.sha2_192f,
        "slh-dsa-sha2-256s":  _slhdsa.sha2_256s,
        "slh-dsa-sha2-256f":  _slhdsa.sha2_256f,
        "slh-dsa-shake-128s": _slhdsa.shake_128s,
        "slh-dsa-shake-128f": _slhdsa.shake_128f,
        "slh-dsa-shake-192s": _slhdsa.shake_192s,
        "slh-dsa-shake-192f": _slhdsa.shake_192f,
        "slh-dsa-shake-256s": _slhdsa.shake_256s,
        "slh-dsa-shake-256f": _slhdsa.shake_256f,
    }


# ---------------------------------------------------------------------------
# Minimal DER helpers (self-contained; do not import from der_codec to keep
# this module dependency-free for potential standalone use)
# ---------------------------------------------------------------------------

def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(body)) + body


def _der_seq(*items: bytes) -> bytes:
    body = b"".join(items)
    return _tlv(0x30, body)


def _der_oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for v in parts[2:]:
        if v == 0:
            body += b"\x00"
        else:
            acc: list[int] = []
            while v:
                acc.append(v & 0x7F)
                v >>= 7
            acc.reverse()
            body += bytes([b | (0x80 if i < len(acc) - 1 else 0) for i, b in enumerate(acc)])
    return _tlv(0x06, body)


def _der_int(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return _tlv(0x02, raw)


def _der_os(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _der_bs(data: bytes) -> bytes:
    """BIT STRING with 0 unused bits prefix."""
    return _tlv(0x03, b"\x00" + data)


def _alg_id(param_name: str) -> bytes:
    """AlgorithmIdentifier SEQUENCE { OID } — no parameters for SLH-DSA."""
    return _der_seq(_der_oid(SLH_DSA_OIDS[param_name]))


# ---------------------------------------------------------------------------
# SPKI and PKCS#8 encoding
# Per draft-ietf-lamps-x509-slhdsa-09:
#   SubjectPublicKeyInfo.subjectPublicKey BIT STRING = raw pk bytes
#   OneAsymmetricKey.privateKey OCTET STRING = raw sk bytes
# ---------------------------------------------------------------------------

def spki_der(param_name: str, pk_raw: bytes) -> bytes:
    """SubjectPublicKeyInfo DER for an SLH-DSA public key."""
    return _der_seq(_alg_id(param_name) + _der_bs(pk_raw))


def pkcs8_der(param_name: str, sk_raw: bytes) -> bytes:
    """OneAsymmetricKey (PKCS#8) DER for an SLH-DSA private key."""
    return _der_seq(_der_int(0) + _alg_id(param_name) + _der_os(sk_raw))


def pkcs8_pem(param_name: str, sk_raw: bytes) -> bytes:
    """PEM-wrapped OneAsymmetricKey for an SLH-DSA private key."""
    der = pkcs8_der(param_name, sk_raw)
    b64 = base64.b64encode(der).decode("ascii")
    lines = ["-----BEGIN PRIVATE KEY-----"]
    for i in range(0, len(b64), 64):
        lines.append(b64[i : i + 64])
    lines += ["-----END PRIVATE KEY-----", ""]
    return "\n".join(lines).encode()


# ---------------------------------------------------------------------------
# PKCS#8 loader — minimal DER parser; returns (param_name, sk_raw)
# ---------------------------------------------------------------------------

def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    offset += 1
    if data[offset] & 0x80:
        nb = data[offset] & 0x7F
        length = int.from_bytes(data[offset + 1 : offset + 1 + nb], "big")
        offset += 1 + nb
    else:
        length = data[offset]
        offset += 1
    return tag, data[offset : offset + length], offset + length


def _decode_oid(body: bytes) -> str:
    parts = [body[0] // 40, body[0] % 40]
    i = 1
    while i < len(body):
        val = 0
        while True:
            b = body[i]; i += 1
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        parts.append(val)
    return ".".join(str(p) for p in parts)


def load_der_private_key(der: bytes) -> "SLHDSAPrivateKey":
    """Parse a PKCS#8 DER blob and return an SLHDSAPrivateKey."""
    try:
        _, outer, _ = _read_tlv(der, 0)           # SEQUENCE (OneAsymmetricKey)
        off = 0
        _, _, off  = _read_tlv(outer, off)         # INTEGER version
        _, alg_body, off = _read_tlv(outer, off)   # SEQUENCE (AlgorithmIdentifier)
        _, oid_body, _   = _read_tlv(alg_body, 0)  # OID
        oid_str = _decode_oid(oid_body)

        _, sk_raw, _ = _read_tlv(outer, off)       # OCTET STRING (privateKey)
    except Exception as exc:
        raise ValueError(f"Cannot parse PKCS#8 DER: {exc}") from exc

    param_name = _OID_TO_NAME.get(oid_str)
    if param_name is None:
        raise ValueError(f"Not an SLH-DSA PKCS#8 key (OID {oid_str!r})")
    return SLHDSAPrivateKey(param_name, sk_raw)


def load_pem_private_key(pem_data: bytes) -> "SLHDSAPrivateKey":
    """Load an SLH-DSA private key from PEM-encoded PKCS#8."""
    lines = pem_data.decode("ascii", errors="replace").splitlines()
    b64_lines: list[str] = []
    in_block = False
    for line in lines:
        if line.startswith("-----BEGIN "):
            in_block = True
        elif line.startswith("-----END "):
            in_block = False
        elif in_block:
            b64_lines.append(line)
    der = base64.b64decode("".join(b64_lines))
    return load_der_private_key(der)


def peek_pem_oid(pem_data: bytes) -> str | None:
    """Return the algorithm OID dotted string from a PKCS#8 PEM, or None on error."""
    try:
        return load_pem_private_key(pem_data).param_name
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Key classes
# ---------------------------------------------------------------------------

class SLHDSAPublicKey:
    """SLH-DSA public key."""

    def __init__(self, param_name: str, pk_raw: bytes) -> None:
        if param_name not in SLH_DSA_OIDS:
            raise ValueError(f"Unknown SLH-DSA parameter set: {param_name!r}")
        self.param_name = param_name
        self._pk_raw = pk_raw

    def raw_bytes(self) -> bytes:
        return self._pk_raw

    def to_spki_der(self) -> bytes:
        return spki_der(self.param_name, self._pk_raw)

    def key_identifier(self) -> bytes:
        """SHA-1 of the raw public key bytes (SubjectKeyIdentifier value)."""
        return hashlib.sha1(self._pk_raw).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Return True if signature is valid; raise ValueError on bad signature."""
        if not HAS_SLHDSA:
            raise RuntimeError("slhdsa package not installed")
        par = _PARAMS[self.param_name]
        pub = _slhdsa.PublicKey.from_digest(self._pk_raw, par)
        return bool(pub.verify(data, signature))


class SLHDSAPrivateKey:
    """SLH-DSA private key (wraps slhdsa.SecretKey)."""

    def __init__(self, param_name: str, sk_raw: bytes) -> None:
        if param_name not in SLH_DSA_OIDS:
            raise ValueError(f"Unknown SLH-DSA parameter set: {param_name!r}")
        self.param_name = param_name
        self._sk_raw = sk_raw

    def sign(self, data: bytes) -> bytes:
        if not HAS_SLHDSA:
            raise RuntimeError("slhdsa package not installed")
        par = _PARAMS[self.param_name]
        sk = _slhdsa.SecretKey.from_digest(self._sk_raw, par)
        return sk.sign(data)

    def public_key(self) -> SLHDSAPublicKey:
        if not HAS_SLHDSA:
            raise RuntimeError("slhdsa package not installed")
        par = _PARAMS[self.param_name]
        sk = _slhdsa.SecretKey.from_digest(self._sk_raw, par)
        pk_raw = sk.pubkey.digest()
        return SLHDSAPublicKey(self.param_name, pk_raw)

    def to_pkcs8_der(self) -> bytes:
        return pkcs8_der(self.param_name, self._sk_raw)

    def to_pkcs8_pem(self) -> bytes:
        return pkcs8_pem(self.param_name, self._sk_raw)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate(param_name: str) -> SLHDSAPrivateKey:
    """Generate a new SLH-DSA private key for the given parameter set."""
    if not HAS_SLHDSA:
        raise RuntimeError(
            "slhdsa package not installed — run: pip install slh-dsa"
        )
    if param_name not in SLH_DSA_OIDS:
        raise ValueError(
            f"Unknown SLH-DSA parameter set {param_name!r}; "
            f"valid choices: {sorted(SLH_DSA_OIDS)}"
        )
    par = _PARAMS[param_name]
    kp = _slhdsa.KeyPair.gen(par)
    sk_raw = kp.sec.digest()
    return SLHDSAPrivateKey(param_name, sk_raw)
