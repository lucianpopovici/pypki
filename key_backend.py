#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
KeyBackend protocol and shim classes for cloud KMS signing.

Follows the same pattern as hsm_backend.py: expose cryptography ABC-compatible
private key objects so CertificateBuilder.sign() works unchanged regardless of
where the key lives (file, PKCS#11, AWS KMS, GCP Cloud KMS, Azure Key Vault).

The private key material never leaves the cloud provider.
private_bytes() / private_numbers() raise NotImplementedError.

Usage:

    backend = build_backend("aws-kms", ref="arn:aws:kms:...", cfg={...})
    ca_key  = backend.get_private_key()
    # ca_key is now a KMSRSAPrivateKey or KMSECPrivateKey
    # pass it to CertificateAuthority(ca_key=ca_key, ...)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding

log = logging.getLogger("pypki.key_backend")


# ---------------------------------------------------------------------------
# Protocol definition
# ---------------------------------------------------------------------------

@runtime_checkable
class KeyBackend(Protocol):
    """
    Abstract key backend. Implementations sign with a remote/hardware key.

    ``ref`` is an opaque backend-specific key reference:
      - file:    filesystem path to the PEM private key
      - pkcs11:  key label on the token
      - aws-kms: ARN or alias/name
      - gcp-kms: full resource path including version
      - azure-kv: full URL including key version
    """

    name: str   # 'file' | 'pkcs11' | 'aws-kms' | 'gcp-kms' | 'azure-kv'

    def sign(self, ref: str, digest: bytes, algorithm: str) -> bytes:
        """Sign a pre-computed digest. algorithm: 'rsa-pkcs1-sha256', 'ecdsa-sha256', …"""
        ...

    def public_key(self, ref: str) -> Any:
        """Return the cryptography public key for *ref*."""
        ...

    def healthy(self, ref: str) -> bool:
        """Return True if the backend can reach the key."""
        ...


# ---------------------------------------------------------------------------
# KMS RSA private-key shim
# ---------------------------------------------------------------------------

class KMSRSAPrivateKey(rsa.RSAPrivateKey):
    """
    RSA signing key backed by a cloud KMS provider.

    Subclasses cryptography's RSAPrivateKey ABC so that isinstance() checks in
    CertificateBuilder.sign() succeed and the Rust dispatcher calls our sign().
    """

    def __init__(self, signer: Any, public_key: rsa.RSAPublicKey) -> None:
        self._signer = signer
        self._pub    = public_key

    def sign(
        self,
        data: bytes,
        padding_obj: asym_padding.AsymmetricPadding,
        algorithm:   hashes.HashAlgorithm,
    ) -> bytes:
        return self._signer.sign(data, padding_obj, algorithm)

    @property
    def key_size(self) -> int:
        return self._pub.key_size

    def public_key(self) -> rsa.RSAPublicKey:
        return self._pub

    def decrypt(self, ciphertext: bytes, padding_obj: asym_padding.AsymmetricPadding) -> bytes:
        raise NotImplementedError("KMS key decrypt not supported (signing keys only)")

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        raise NotImplementedError("Private key material cannot be exported from KMS")

    def private_bytes(self, encoding, fmt, encryption_algorithm) -> bytes:
        raise NotImplementedError("Private key material cannot be exported from KMS")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


# ---------------------------------------------------------------------------
# KMS EC private-key shim
# ---------------------------------------------------------------------------

class KMSECPrivateKey(ec.EllipticCurvePrivateKey):
    """
    ECDSA signing key backed by a cloud KMS provider.
    """

    def __init__(self, signer: Any, public_key: ec.EllipticCurvePublicKey) -> None:
        self._signer = signer
        self._pub    = public_key

    def sign(self, data: bytes, signature_algorithm: ec.ECDSA) -> bytes:
        return self._signer.sign(data, signature_algorithm)

    @property
    def curve(self) -> ec.EllipticCurve:
        return self._pub.curve

    @property
    def key_size(self) -> int:
        return self._pub.key_size

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._pub

    def exchange(self, algorithm, peer_public_key) -> bytes:
        raise NotImplementedError("KMS key exchange not supported (signing keys only)")

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        raise NotImplementedError("Private key material cannot be exported from KMS")

    def private_bytes(self, encoding, fmt, encryption_algorithm) -> bytes:
        raise NotImplementedError("Private key material cannot be exported from KMS")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


# ---------------------------------------------------------------------------
# Backend factory
# ---------------------------------------------------------------------------

def build_backend(
    backend_name: str,
    ref: str,
    cfg: Optional[Dict[str, Any]] = None,
) -> "KeyBackend":
    """
    Return a KeyBackend instance for the given provider.

    backend_name : 'aws-kms' | 'gcp-kms' | 'azure-kv'
    ref          : provider-specific key reference
    cfg          : optional provider configuration dict (region, auth_mode, etc.)
    """
    cfg = cfg or {}
    if backend_name == "aws-kms":
        from kms_aws import AWSKMSBackend
        return AWSKMSBackend(
            region       = cfg.get("region", _aws_region_from_ref(ref)),
            auth_mode    = cfg.get("auth_mode", "imdsv2"),
            static_file  = cfg.get("static_credentials_file"),
        )
    if backend_name == "gcp-kms":
        from kms_gcp import GCPKMSBackend
        return GCPKMSBackend(
            auth_mode    = cfg.get("auth_mode", "metadata-server"),
            sa_file      = cfg.get("service_account_file"),
        )
    if backend_name == "azure-kv":
        from kms_azure import AzureKVBackend
        return AzureKVBackend(
            auth_mode           = cfg.get("auth_mode", "managed-identity"),
            tenant_id           = cfg.get("tenant_id"),
            client_id           = cfg.get("client_id"),
            client_secret_file  = cfg.get("client_secret_file"),
        )
    raise ValueError(f"Unknown key backend: {backend_name!r}. "
                     f"Supported: aws-kms, gcp-kms, azure-kv")


def _aws_region_from_ref(ref: str) -> str:
    """Extract region from an ARN like 'arn:aws:kms:us-east-1:...' """
    parts = ref.split(":")
    if len(parts) >= 4 and parts[0] == "arn":
        return parts[3]
    import os
    return os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
