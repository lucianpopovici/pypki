#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Azure authentication helpers — Managed Identity (IMDS) and client-credential flow.

Stdlib only; no azure-identity dependency.
"""

import json
import logging
import os
import time
import urllib.parse
import urllib.request
from typing import Optional, Tuple

log = logging.getLogger("pypki.auth_azure")

_IMDS_URL         = "http://169.254.169.254/metadata/identity/oauth2/token"
_IMDS_API_VERSION = "2018-02-01"

from auth import _CachedToken


# ---------------------------------------------------------------------------
# Managed Identity token retrieval (IMDS)
# ---------------------------------------------------------------------------

class ManagedIdentityToken(_CachedToken):
    """Thread-safe Azure access-token cache using IMDS managed identity."""

    def __init__(self, resource: str = "https://vault.azure.net") -> None:
        super().__init__()
        self._resource = resource

    def _fetch(self) -> tuple:
        return _fetch_imds_token(self._resource)


def _fetch_imds_token(resource: str) -> Tuple[str, int]:
    """Fetch an Azure access token from the IMDS endpoint."""
    params = urllib.parse.urlencode({
        "api-version": _IMDS_API_VERSION,
        "resource":    resource,
    })
    req = urllib.request.Request(
        f"{_IMDS_URL}?{params}",
        headers={"Metadata": "true"},
    )
    with urllib.request.urlopen(req, timeout=3) as r:
        data = json.loads(r.read())
    return data["access_token"], int(data.get("expires_in", 3600))


# ---------------------------------------------------------------------------
# Client-credential flow (for non-managed deployments)
# ---------------------------------------------------------------------------

class ClientCredentialToken(_CachedToken):
    """Thread-safe AAD token cache using client-secret credential flow."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        resource: str = "https://vault.azure.net",
    ) -> None:
        super().__init__()
        self._tenant    = tenant_id
        self._client_id = client_id
        self._secret    = client_secret
        self._resource  = resource

    def _fetch(self) -> tuple:
        return _fetch_client_credential_token(
            self._tenant, self._client_id, self._secret, self._resource
        )


def _fetch_client_credential_token(
    tenant_id: str, client_id: str, client_secret: str, resource: str
) -> Tuple[str, int]:
    """Exchange client credentials for an AAD access token."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    body = urllib.parse.urlencode({
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "resource":      resource,
    }).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read())
    return data["access_token"], int(data.get("expires_in", 3600))


def resolve_token(
    auth_mode: str = "managed-identity",
    resource: str = "https://vault.azure.net",
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret_file: Optional[str] = None,
) -> str:
    """
    Return a valid Azure access token for Key Vault.

    auth_mode:
      'managed-identity'    — Azure IMDS (VMs, AKS)
      'workload-identity'   — alias for 'managed-identity'
      'client-secret'       — client_id + client_secret from file
    """
    if auth_mode in ("managed-identity", "workload-identity"):
        tok, _ = _fetch_imds_token(resource)
        return tok
    if auth_mode == "client-secret":
        secret = open(client_secret_file).read().strip() if client_secret_file else ""
        tok, _ = _fetch_client_credential_token(tenant_id or "", client_id or "", secret, resource)
        return tok
    raise ValueError(f"Unknown Azure auth_mode: {auth_mode!r}")
