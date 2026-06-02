#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
GCP authentication helpers — metadata server and service-account JWT auth.

Stdlib only; no google-cloud-auth dependency.
"""

import hashlib
import hmac
import json
import logging
import os
import time
import urllib.request
from typing import Dict, Optional, Tuple

from oidc import _b64url_encode

log = logging.getLogger("pypki.auth_gcp")

_METADATA_SERVER     = "http://metadata.google.internal"
_METADATA_FLAVOR_HDR = {"Metadata-Flavor": "Google"}

from auth import _CachedToken


# ---------------------------------------------------------------------------
# Metadata server token retrieval
# ---------------------------------------------------------------------------

class GCPMetadataToken(_CachedToken):
    """Thread-safe GCP access-token cache backed by the metadata server."""

    def __init__(self, service_account: str = "default") -> None:
        super().__init__()
        self._sa = service_account

    def _fetch(self) -> tuple:
        return _fetch_metadata_token(self._sa)


def _fetch_metadata_token(service_account: str = "default") -> Tuple[str, int]:
    """Fetch an OAuth2 access token from the GCP metadata server."""
    url = (
        f"{_METADATA_SERVER}/computeMetadata/v1/instance/"
        f"service-accounts/{service_account}/token"
    )
    req = urllib.request.Request(url, headers=_METADATA_FLAVOR_HDR)
    with urllib.request.urlopen(req, timeout=3) as r:
        data = json.loads(r.read())
    return data["access_token"], int(data.get("expires_in", 3600))


# ---------------------------------------------------------------------------
# Service-account JSON key (offline, static credentials)
# ---------------------------------------------------------------------------

def _sa_jwt(sa_info: dict, scopes: str = "https://www.googleapis.com/auth/cloudkms") -> str:
    """
    Create a self-signed JWT for a GCP service account.

    sa_info is the parsed contents of a service-account JSON key file.
    """
    import datetime
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    header  = _b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT", "kid": sa_info["private_key_id"]}).encode())
    payload = _b64url_encode(json.dumps({
        "iss": sa_info["client_email"],
        "scope": scopes,
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    }).encode())
    signing_input = f"{header}.{payload}".encode()
    priv_key = load_pem_private_key(sa_info["private_key"].encode(), password=None)
    sig = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url_encode(sig)}"


def _exchange_sa_jwt(sa_info: dict) -> Tuple[str, int]:
    """Exchange a service-account JWT for an access token."""
    jwt = _sa_jwt(sa_info)
    body = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion":  jwt,
    }).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    import urllib.parse
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read())
    return data["access_token"], int(data.get("expires_in", 3600))


class GCPServiceAccountToken(_CachedToken):
    """Thread-safe token cache for service-account JSON key files."""

    def __init__(self, sa_file: str) -> None:
        super().__init__()
        self._sa_info = json.loads(open(sa_file).read())

    def _fetch(self) -> tuple:
        return _exchange_sa_jwt(self._sa_info)


def resolve_token(
    auth_mode: str = "metadata-server",
    sa_file: Optional[str] = None,
) -> str:
    """
    Return a valid GCP access token.

    auth_mode:
      'metadata-server'     — GCE/GKE metadata server (preferred in cloud)
      'service-account-file' — sa_file path to JSON key file
      'workload-identity'   — alias for 'metadata-server' (IRSA equivalent)
    """
    if auth_mode in ("metadata-server", "workload-identity"):
        tok, _ = _fetch_metadata_token()
        return tok
    if auth_mode == "service-account-file" and sa_file:
        tok, _ = _exchange_sa_jwt(json.loads(open(sa_file).read()))
        return tok
    raise ValueError(f"Unknown GCP auth_mode: {auth_mode!r}")
