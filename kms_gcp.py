#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
GCP Cloud KMS signing backend for PyPKI.

Uses the Cloud KMS asymmetricSign and getPublicKey REST APIs.
No google-cloud-kms dependency; stdlib urllib only.

Supported algorithms (verify at release time):
  RSA:   RSA_SIGN_PKCS1_{2048,3072,4096}_SHA{256,384,512}
         RSA_SIGN_PSS_{2048,3072,4096}_SHA{256,384,512}
  ECDSA: EC_SIGN_P256_SHA256, EC_SIGN_P384_SHA384
  Ed25519: EC_SIGN_ED25519 (regional; verify availability)
"""

import base64
import json
import logging
import threading
import time
import urllib.request
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding

from key_backend import KMSRSAPrivateKey, KMSECPrivateKey

log = logging.getLogger("pypki.kms_gcp")

_GCP_KMS_BASE = "https://cloudkms.googleapis.com/v1"

# Algorithm string → GCP signing algorithm name component
_RSA_PKCS1 = {"sha256": "PKCS1", "sha384": "PKCS1", "sha512": "PKCS1"}
_RSA_PSS   = {"sha256": "PSS",   "sha384": "PSS",   "sha512": "PSS"}


def _gcp_request(url: str, token: str, body: Optional[dict] = None) -> dict:
    """Send an authenticated request to Cloud KMS."""
    if body is not None:
        data    = json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        req     = urllib.request.Request(url, data=data, headers=headers, method="POST")
    else:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def _digest_payload(data: bytes, algorithm: hashes.HashAlgorithm) -> dict:
    """Build the GCP digest payload dict."""
    from cryptography.hazmat.backends import default_backend
    h = hashes.Hash(algorithm, default_backend())
    h.update(data)
    digest = h.finalize()
    hash_name = type(algorithm).__name__.lower()   # 'sha256', 'sha384', etc.
    return {hash_name: base64.b64encode(digest).decode()}


class _GCPRSASigner:
    def __init__(self, ref: str, backend: "GCPKMSBackend") -> None:
        self._ref     = ref
        self._backend = backend

    def sign(
        self,
        data: bytes,
        padding_obj: asym_padding.AsymmetricPadding,
        algorithm:   hashes.HashAlgorithm,
    ) -> bytes:
        digest_dict = _digest_payload(data, algorithm)
        resp = _gcp_request(
            f"{_GCP_KMS_BASE}/{self._ref}:asymmetricSign",
            self._backend._token(),
            {"digest": digest_dict},
        )
        return base64.b64decode(resp["signature"])


class _GCPECSigner:
    def __init__(self, ref: str, backend: "GCPKMSBackend") -> None:
        self._ref     = ref
        self._backend = backend

    def sign(self, data: bytes, signature_algorithm: ec.ECDSA) -> bytes:
        digest_dict = _digest_payload(data, signature_algorithm.algorithm)
        resp = _gcp_request(
            f"{_GCP_KMS_BASE}/{self._ref}:asymmetricSign",
            self._backend._token(),
            {"digest": digest_dict},
        )
        # GCP returns DER-encoded signature for ECDSA
        return base64.b64decode(resp["signature"])


class GCPKMSBackend:
    """
    GCP Cloud KMS key backend.

    ``ref`` (backend_ref) is the full CryptoKeyVersion resource path::

        projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1

    Pin the version explicitly; never use ``cryptoKeyVersions/latest``.
    """

    name = "gcp-kms"

    def __init__(
        self,
        auth_mode: str           = "metadata-server",
        sa_file:   Optional[str] = None,
    ) -> None:
        self._auth_mode   = auth_mode
        self._sa_file     = sa_file
        self._pub_cache:  Dict[str, Any] = {}
        self._lock        = threading.Lock()

    def _token(self) -> str:
        from auth_gcp import resolve_token
        return resolve_token(self._auth_mode, self._sa_file)

    def public_key(self, ref: str) -> Any:
        with self._lock:
            if ref in self._pub_cache:
                return self._pub_cache[ref]
        resp    = _gcp_request(f"{_GCP_KMS_BASE}/{ref}/publicKey", self._token())
        pem     = resp.get("pem", "")
        pub_key = serialization.load_pem_public_key(pem.encode())
        with self._lock:
            self._pub_cache[ref] = pub_key
        return pub_key

    def get_private_key(self, ref: str) -> Any:
        pub = self.public_key(ref)
        if isinstance(pub, rsa.RSAPublicKey):
            return KMSRSAPrivateKey(_GCPRSASigner(ref, self), pub)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return KMSECPrivateKey(_GCPECSigner(ref, self), pub)
        raise ValueError(f"Unsupported key type for GCP KMS ref: {type(pub).__name__}")

    def healthy(self, ref: str) -> bool:
        try:
            self.public_key(ref)
            return True
        except Exception as exc:
            log.warning("GCP KMS health check failed for %s: %s", ref, exc)
            return False

    def sign(self, ref: str, digest: bytes, algorithm: str) -> bytes:
        """Direct sign call (KeyBackend protocol)."""
        from cryptography.hazmat.backends import default_backend
        hash_cls = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
        parts = algorithm.split("-")
        hcls  = hash_cls.get(parts[-1])
        if hcls is None:
            raise ValueError(f"Unsupported hash in algorithm: {algorithm}")
        hash_name = parts[-1]
        digest_payload = {hash_name: base64.b64encode(digest).decode()}
        resp = _gcp_request(
            f"{_GCP_KMS_BASE}/{ref}:asymmetricSign",
            self._token(),
            {"digest": digest_payload},
        )
        return base64.b64decode(resp["signature"])
