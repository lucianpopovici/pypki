#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
AWS KMS signing backend for PyPKI.

Uses the KMS Sign and GetPublicKey APIs over HTTPS with SigV4 auth.
No boto3 dependency; stdlib urllib only.

Supported algorithms (verify at release time):
  RSA:   RSASSA_PKCS1_V1_5_SHA_{256,384,512}
         RSASSA_PSS_SHA_{256,384,512}
  ECDSA: ECDSA_SHA_{256,384,512}
  Note:  Ed25519 NOT yet available on AWS KMS as of mid-2025.
"""

import base64
import json
import logging
import ssl
import threading
import time
import urllib.request
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from key_backend import KMSRSAPrivateKey, KMSECPrivateKey

log = logging.getLogger("pypki.kms_aws")

# Algorithm mapping: (key_type, hash_name, padding_type) → AWS signing algorithm
_RSA_PKCS1_ALGS = {
    "sha256": "RSASSA_PKCS1_V1_5_SHA_256",
    "sha384": "RSASSA_PKCS1_V1_5_SHA_384",
    "sha512": "RSASSA_PKCS1_V1_5_SHA_512",
}
_RSA_PSS_ALGS = {
    "sha256": "RSASSA_PSS_SHA_256",
    "sha384": "RSASSA_PSS_SHA_384",
    "sha512": "RSASSA_PSS_SHA_512",
}
_EC_ALGS = {
    "sha256": "ECDSA_SHA_256",
    "sha384": "ECDSA_SHA_384",
    "sha512": "ECDSA_SHA_512",
}

_MAX_RETRIES     = 3
_BACKOFF_BASE_S  = 0.5
_THROTTLE_CODE   = "ThrottlingException"
_ACCESS_DENIED   = "AccessDeniedException"


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _kms_request(
    region: str,
    target: str,
    payload: dict,
    access_key: str,
    secret_key: str,
    session_token: str = "",
) -> dict:
    """Sign and send a KMS API request; return the decoded JSON response."""
    from auth_aws import sigv4_headers

    url  = f"https://kms.{region}.amazonaws.com/"
    body = json.dumps(payload).encode()
    hdrs = sigv4_headers(
        method="POST",
        url=url,
        body=body,
        service="kms",
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        extra_headers={"X-Amz-Target": target},
    )

    for attempt in range(_MAX_RETRIES):
        req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode(errors="replace")
            try:
                err = json.loads(body_err)
            except Exception:
                err = {"__type": "UnknownError", "message": body_err}

            err_code = err.get("__type", "").split(".")[-1]
            if err_code == _ACCESS_DENIED:
                raise PermissionError(
                    f"AWS KMS AccessDenied for target={target}: {err.get('message', '')}"
                ) from exc
            if err_code == _THROTTLE_CODE and attempt < _MAX_RETRIES - 1:
                wait = _BACKOFF_BASE_S * (2 ** attempt)
                log.warning("AWS KMS throttled; retrying in %.1fs (attempt %d)", wait, attempt + 1)
                time.sleep(wait)
                continue
            raise RuntimeError(f"AWS KMS error {err_code}: {err.get('message', body_err)}") from exc

    raise RuntimeError("AWS KMS request failed after retries")


# ---------------------------------------------------------------------------
# Signer objects (passed to KMSRSAPrivateKey / KMSECPrivateKey)
# ---------------------------------------------------------------------------

class _AWSRSASigner:
    def __init__(self, key_id: str, backend: "AWSKMSBackend") -> None:
        self._key_id  = key_id
        self._backend = backend

    def sign(
        self,
        data: bytes,
        padding_obj: asym_padding.AsymmetricPadding,
        algorithm:   hashes.HashAlgorithm,
    ) -> bytes:
        hash_name = type(algorithm).__name__.lower()
        if isinstance(padding_obj, asym_padding.PSS):
            aws_alg = _RSA_PSS_ALGS.get(hash_name)
        else:
            aws_alg = _RSA_PKCS1_ALGS.get(hash_name)
        if aws_alg is None:
            raise ValueError(f"Unsupported RSA hash for AWS KMS: {hash_name}")

        # AWS KMS Sign takes a pre-computed digest when MessageType=DIGEST
        digest = _compute_digest(data, algorithm)
        resp   = self._backend._sign(self._key_id, digest, aws_alg)
        return base64.b64decode(resp["Signature"])


class _AWSSigner:
    def __init__(self, key_id: str, backend: "AWSKMSBackend") -> None:
        self._key_id  = key_id
        self._backend = backend

    def sign(self, data: bytes, signature_algorithm: ec.ECDSA) -> bytes:
        hash_name = type(signature_algorithm.algorithm).__name__.lower()
        aws_alg   = _EC_ALGS.get(hash_name)
        if aws_alg is None:
            raise ValueError(f"Unsupported ECDSA hash for AWS KMS: {hash_name}")

        digest  = _compute_digest(data, signature_algorithm.algorithm)
        resp    = self._backend._sign(self._key_id, digest, aws_alg)
        raw_sig = base64.b64decode(resp["Signature"])
        # AWS KMS returns DER-encoded ECDSA signature already
        return raw_sig


def _compute_digest(data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    """Hash data with the given algorithm."""
    from cryptography.hazmat.backends import default_backend
    h = hashes.Hash(algorithm, default_backend())
    h.update(data)
    return h.finalize()


# ---------------------------------------------------------------------------
# AWSKMSBackend
# ---------------------------------------------------------------------------

class AWSKMSBackend:
    """
    AWS KMS key backend.

    ``ref`` (backend_ref) is an AWS KMS key ARN or alias, e.g.:
      arn:aws:kms:us-east-1:123456789:key/mrk-xxx
      alias/pypki-root-2026
    """

    name = "aws-kms"

    def __init__(
        self,
        region:      str            = "us-east-1",
        auth_mode:   str            = "imdsv2",
        static_file: Optional[str]  = None,
    ) -> None:
        self._region      = region
        self._auth_mode   = auth_mode
        self._static_file = static_file
        self._pub_cache:  Dict[str, Any] = {}
        self._lock        = threading.Lock()

    def _creds(self) -> Tuple[str, str, str]:
        from auth_aws import resolve_credentials
        return resolve_credentials(self._auth_mode, self._static_file)

    def _sign(self, key_id: str, digest: bytes, aws_alg: str) -> dict:
        ak, sk, tok = self._creds()
        return _kms_request(
            self._region, "TrentService.Sign",
            {"KeyId": key_id, "Message": base64.b64encode(digest).decode(),
             "MessageType": "DIGEST", "SigningAlgorithm": aws_alg},
            ak, sk, tok,
        )

    def public_key(self, ref: str) -> Any:
        with self._lock:
            if ref in self._pub_cache:
                return self._pub_cache[ref]
        ak, sk, tok = self._creds()
        resp = _kms_request(
            self._region, "TrentService.GetPublicKey",
            {"KeyId": ref}, ak, sk, tok,
        )
        der     = base64.b64decode(resp["PublicKey"])
        pub_key = serialization.load_der_public_key(der)
        with self._lock:
            self._pub_cache[ref] = pub_key
        return pub_key

    def get_private_key(self, ref: str) -> Any:
        """Return a cryptography-compatible private-key shim for *ref*."""
        pub = self.public_key(ref)
        if isinstance(pub, rsa.RSAPublicKey):
            return KMSRSAPrivateKey(_AWSRSASigner(ref, self), pub)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return KMSECPrivateKey(_AWSSigner(ref, self), pub)
        raise ValueError(f"Unsupported key type for AWS KMS ref: {type(pub).__name__}")

    def healthy(self, ref: str) -> bool:
        try:
            self.public_key(ref)
            return True
        except Exception as exc:
            log.warning("AWS KMS health check failed for %s: %s", ref, exc)
            return False

    def sign(self, ref: str, digest: bytes, algorithm: str) -> bytes:
        """Direct sign call (KeyBackend protocol)."""
        parts = algorithm.split("-")
        if parts[0] == "rsa":
            pss  = "pss" in algorithm
            algs = _RSA_PSS_ALGS if pss else _RSA_PKCS1_ALGS
            hash_name = parts[-1].replace("sha", "sha")  # 'sha256' etc.
            aws_alg   = algs.get(hash_name)
        elif parts[0] == "ecdsa":
            hash_name = parts[-1]
            aws_alg   = _EC_ALGS.get(hash_name)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if aws_alg is None:
            raise ValueError(f"No AWS KMS mapping for: {algorithm}")
        resp = self._sign(ref, digest, aws_alg)
        return base64.b64decode(resp["Signature"])
