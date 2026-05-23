#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
hooks.py — §5.9 Lifecycle webhooks for PyPKI.

Events
------
cert.issued      — every successful certificate issuance
cert.revoked     — every revocation
cert.expiring    — cert within the expiry-warning window (fired by expiry monitor)
subca.issued     — sub-CA certificate issued
cross.signed     — cross-signed certificate issued
key.archived     — private key stored via the key-archival path
key.recovered    — archived key decrypted by an authorised operator

Delivery
--------
Each registered URL receives an HTTP POST with:
  Content-Type: application/json
  X-PyPKI-Event: <event_type>
  X-PyPKI-Signature: sha256=<hex>  # HMAC-SHA256 over the raw request body

Retries: up to MAX_ATTEMPTS deliveries per event, with exponential back-off
(2^attempt seconds, capped at 300 s).  Final failure is audit-logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import threading
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Set

logger = logging.getLogger("pypki.hooks")

EVENT_VERSION = 1
MAX_ATTEMPTS = 5
_BACKOFF_CAP = 300  # seconds


class WebhookDispatcher:
    """
    Async (background-thread) webhook dispatcher.

    Usage::

        wd = WebhookDispatcher(
            urls=["https://hooks.example.com/pypki"],
            secret="s3cr3t",
            enabled_events={"cert.issued", "cert.revoked"},
        )
        wd.start()                       # start background worker
        wd.emit("cert.issued", payload)  # enqueue delivery
        wd.stop()                        # drain queue and join thread
    """

    def __init__(
        self,
        urls: Sequence[str],
        secret: str = "",
        enabled_events: Optional[Set[str]] = None,
        audit_fn: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        timeout: int = 10,
    ) -> None:
        self._urls: List[str] = list(urls)
        self._secret: bytes = secret.encode() if secret else b""
        self._enabled: Optional[Set[str]] = enabled_events  # None = all
        self._audit: Optional[Callable] = audit_fn
        self._timeout = timeout
        self._queue: queue.Queue = queue.Queue()
        self._worker: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._running = True
        self._worker = threading.Thread(
            target=self._run, name="pypki-hooks", daemon=True
        )
        self._worker.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._running = False
        self._queue.put(None)  # sentinel
        if self._worker:
            self._worker.join(timeout=timeout)

    def emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if self._enabled is not None and event_type not in self._enabled:
            return
        if not self._urls:
            return
        body: Dict[str, Any] = {
            "event_version": EVENT_VERSION,
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        self._queue.put((event_type, body))

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                break
            event_type, body = item
            raw = json.dumps(body, separators=(",", ":")).encode()
            sig = self._sign(raw)
            for url in self._urls:
                self._deliver(url, event_type, raw, sig)
            self._queue.task_done()

    def _deliver(self, url: str, event_type: str, raw: bytes, sig: str) -> None:
        for attempt in range(MAX_ATTEMPTS):
            try:
                req = urllib.request.Request(
                    url,
                    data=raw,
                    headers={
                        "Content-Type": "application/json",
                        "X-PyPKI-Event": event_type,
                        "X-PyPKI-Signature": sig,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self._timeout):
                    pass
                logger.debug("hook %s → %s delivered (attempt %d)", event_type, url, attempt + 1)
                return
            except Exception as exc:
                wait = min(2 ** attempt, _BACKOFF_CAP)
                logger.warning(
                    "hook %s → %s attempt %d failed: %s; retry in %ds",
                    event_type, url, attempt + 1, exc, wait,
                )
                if attempt < MAX_ATTEMPTS - 1:
                    time.sleep(wait)
        msg = f"hook {event_type} → {url}: all {MAX_ATTEMPTS} attempts failed"
        logger.error(msg)
        if self._audit:
            try:
                self._audit("webhook_delivery_failed", {"event_type": event_type, "url": url})
            except Exception:
                pass

    def _sign(self, body: bytes) -> str:
        if not self._secret:
            return "sha256="
        mac = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        return f"sha256={mac}"

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def urls(self) -> List[str]:
        return list(self._urls)

    @property
    def enabled_events(self) -> Optional[Set[str]]:
        return set(self._enabled) if self._enabled is not None else None


# ---------------------------------------------------------------------------
# Verify a PyPKI webhook delivery (caller-side helper)
# ---------------------------------------------------------------------------

def verify_signature(body: bytes, secret: str, header: str) -> bool:
    """Return True if *header* ('sha256=<hex>') is a valid HMAC-SHA256 over *body*."""
    if not secret:
        return True
    if not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    received = header[len("sha256="):]
    return hmac.compare_digest(expected, received)
