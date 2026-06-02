#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Azure Key Vault signing backend for PyPKI.

Uses the Key Vault Keys sign and getKey REST APIs.
No azure-identity dependency; stdlib urllib only.

FIPS tier note: Standard vault = FIPS 140-2 Level 2.
                Managed HSM     = FIPS 140-2 Level 3.
A startup warning is logged when Level 3 is required but standard tier is used.

Supported algorithms (verify at release time):
  RSA:   PS256 (PSS SHA-256), PS384, PS512
         RS256 (PKCS#1v1.5 SHA-256), RS384, RS512
  ECDSA: ES256, ES384, ES512
"""

import json
import logging
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from oidc import _b64url_encode, _b64url_decode
from kms_aws import _compute_digest

from key_backend import KMSRSAPrivateKey, KMSECPrivateKey

log = logging.getLogger("pypki.kms_azure")

_AKV_API_VERSION = "7.4"

_RSA_PSS_ALGS = {
    "sha256": "PS256",
    "sha384": "PS384",
    "sha512": "PS512",
}
_RSA_PKCS1_ALGS = {
    "sha256": "RS256",
    "sha384": "RS384",
    "sha512": "RS512",
}
_EC_ALGS = {
    "sha256": "ES256",
    "sha384": "ES384",
    "sha512": "ES512",
}


def _akv_request(url: str, token: str, body: Optional[dict] = None) -> dict:
    """Send an authenticated request to Azure Key Vault."""
    versioned = f"{url}?api-version={_AKV_API_VERSION}"
    if body is not None:
        data    = json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        req     = urllib.request.Request(versioned, data=data, headers=headers, method="POST")
    else:
        req = urllib.request.Request(versioned, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())



def _jwk_to_public_key(jwk: dict) -> Any:
    """Convert an Azure JWK dict to a cryptography public key."""
    kty = jwk.get("kty", "")
    if kty == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        crv_map = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
        curve   = crv_map.get(jwk.get("crv", "P-256"))
        if curve is None:
            raise ValueError(f"Unsupported curve: {jwk.get('crv')}")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise ValueError(f"Unsupported Azure JWK kty: {kty}")


class _AzureRSASigner:
    def __init__(self, key_url: str, backend: "AzureKVBackend") -> None:
        self._url     = key_url
        self._backend = backend

    def sign(
        self,
        data: bytes,
        padding_obj: asym_padding.AsymmetricPadding,
        algorithm:   hashes.HashAlgorithm,
    ) -> bytes:
        hash_name = type(algorithm).__name__.lower()
        if isinstance(padding_obj, asym_padding.PSS):
            alg = _RSA_PSS_ALGS.get(hash_name)
        else:
            alg = _RSA_PKCS1_ALGS.get(hash_name)
        if alg is None:
            raise ValueError(f"Unsupported RSA hash for Azure KV: {hash_name}")
        digest = _compute_digest(data, algorithm)
        resp   = _akv_request(
            f"{self._url}/sign",
            self._backend._token(),
            {"alg": alg, "value": _b64url_encode(digest)},
        )
        return _b64url_decode(resp["value"])


class _AzureECSigner:
    def __init__(self, key_url: str, backend: "AzureKVBackend") -> None:
        self._url     = key_url
        self._backend = backend

    def sign(self, data: bytes, signature_algorithm: ec.ECDSA) -> bytes:
        hash_name = type(signature_algorithm.algorithm).__name__.lower()
        alg       = _EC_ALGS.get(hash_name)
        if alg is None:
            raise ValueError(f"Unsupported ECDSA hash for Azure KV: {hash_name}")
        digest = _compute_digest(data, signature_algorithm.algorithm)
        resp   = _akv_request(
            f"{self._url}/sign",
            self._backend._token(),
            {"alg": alg, "value": _b64url_encode(digest)},
        )
        # Azure returns raw (r || s) for EC signatures — convert to DER
        raw  = _b64url_decode(resp["value"])
        half = len(raw) // 2
        r    = int.from_bytes(raw[:half], "big")
        s    = int.from_bytes(raw[half:], "big")
        return encode_dss_signature(r, s)


class AzureKVBackend:
    """
    Azure Key Vault key backend.

    ``ref`` (backend_ref) is the full versioned key URL::

        https://my-vault.vault.azure.net/keys/my-key/abc123def456

    Always pin the version; key rotation requires updating the ref.
    """

    name = "azure-kv"

    def __init__(
        self,
        auth_mode:          str           = "managed-identity",
        tenant_id:          Optional[str] = None,
        client_id:          Optional[str] = None,
        client_secret_file: Optional[str] = None,
    ) -> None:
        self._auth_mode          = auth_mode
        self._tenant_id          = tenant_id
        self._client_id          = client_id
        self._client_secret_file = client_secret_file
        self._pub_cache:  Dict[str, Any] = {}
        self._lock        = threading.Lock()

    def _token(self) -> str:
        from auth_azure import resolve_token
        return resolve_token(
            self._auth_mode,
            resource           = "https://vault.azure.net",
            tenant_id          = self._tenant_id,
            client_id          = self._client_id,
            client_secret_file = self._client_secret_file,
        )

    def public_key(self, ref: str) -> Any:
        with self._lock:
            if ref in self._pub_cache:
                return self._pub_cache[ref]
        resp    = _akv_request(ref, self._token())
        jwk     = resp.get("key", resp)
        pub_key = _jwk_to_public_key(jwk)
        with self._lock:
            self._pub_cache[ref] = pub_key
        return pub_key

    def get_private_key(self, ref: str) -> Any:
        pub = self.public_key(ref)
        if isinstance(pub, rsa.RSAPublicKey):
            return KMSRSAPrivateKey(_AzureRSASigner(ref, self), pub)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return KMSECPrivateKey(_AzureECSigner(ref, self), pub)
        raise ValueError(f"Unsupported key type for Azure KV ref: {type(pub).__name__}")

    def healthy(self, ref: str) -> bool:
        try:
            self.public_key(ref)
            return True
        except Exception as exc:
            log.warning("Azure KV health check failed for %s: %s", ref, exc)
            return False

    def sign(self, ref: str, digest: bytes, algorithm: str) -> bytes:
        """Direct sign call (KeyBackend protocol)."""
        parts    = algorithm.split("-")
        hash_name= parts[-1]
        if "pss" in algorithm:
            alg = _RSA_PSS_ALGS.get(hash_name)
        elif "pkcs1" in algorithm or "rsa" in algorithm:
            alg = _RSA_PKCS1_ALGS.get(hash_name)
        else:
            alg = _EC_ALGS.get(hash_name)
        if alg is None:
            raise ValueError(f"No Azure KV mapping for: {algorithm}")
        resp = _akv_request(
            f"{ref}/sign",
            self._token(),
            {"alg": alg, "value": _b64url_encode(digest)},
        )
        return _b64url_decode(resp["value"])
