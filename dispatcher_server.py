#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
dispatcher_server.py — Single-port HTTP dispatcher for PyPKI.

All PKI services (CMP, ACME, SCEP, EST, OCSP, IPsec, Web UI) share one
listening port.  Routing is done by URL path prefix; the prefix is stripped
before delegating to the service handler so each handler continues to work
with its own root-relative paths.

Usage (from pki_server.py)::

    import dispatcher_server

    route_table = dispatcher_server.RouteTable()
    srv = dispatcher_server.start_dispatcher_server(
        host="0.0.0.0", port=8080, route_table=route_table,
        tls_cert_path=..., tls_key_path=..., ca=ca,
    )

    # Each service registers its handler:
    cmp_proxy  = cmp_module.start_cmp_server(route_table=route_table, prefix="/cmp",  ca=ca, ...)
    acme_proxy = acme_module.start_acme_server(route_table=route_table, prefix="/acme", ...)

    # Stopping a service:
    acme_proxy.shutdown()   # unregisters /acme routes from the table
"""

from __future__ import annotations

import contextvars
import http.server
import logging
import threading
import uuid
from typing import Optional, List, Tuple

logger = logging.getLogger("dispatcher")

# §5.10 — per-request ID threaded through all handlers via ContextVar.
# Set in _dispatch; read by RequestIdFilter in pki_server.py.
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default=""
)

# HTTP methods that services may implement
_HTTP_METHODS = ("GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS")


# ---------------------------------------------------------------------------
# Route table
# ---------------------------------------------------------------------------

class RouteTable:
    """
    Thread-safe registry mapping URL path prefixes to handler classes.

    Routes are matched longest-prefix-first so more specific paths take
    priority.  The catch-all "/" prefix matches every request that is not
    claimed by a longer prefix.
    """

    def __init__(self):
        self._routes: List[Tuple[str, type]] = []
        self._lock = threading.Lock()

    def register(self, prefix: str, handler_cls: type) -> None:
        """Register (or replace) a handler for *prefix*."""
        with self._lock:
            self._routes = [(p, h) for p, h in self._routes if p != prefix]
            self._routes.append((prefix, handler_cls))
            # Longest prefix first → more specific routes win
            self._routes.sort(key=lambda x: -len(x[0]))
        logger.debug("RouteTable: registered prefix %r → %s", prefix, handler_cls.__name__)

    def unregister(self, prefix: str) -> None:
        """Remove the handler for *prefix* (no-op if not registered)."""
        with self._lock:
            self._routes = [(p, h) for p, h in self._routes if p != prefix]
        logger.debug("RouteTable: unregistered prefix %r", prefix)

    def match(self, path: str) -> Tuple[Optional[str], Optional[type]]:
        """
        Return *(prefix, handler_cls)* for *path*, or *(None, None)*.

        Query strings are stripped before matching.  The catch-all "/" prefix
        is tried last so any more specific prefix takes priority.
        """
        bare = path.split("?")[0].split("#")[0]
        with self._lock:
            for prefix, handler_cls in self._routes:
                if prefix == "/":
                    return prefix, handler_cls
                if bare == prefix or bare.startswith(prefix + "/"):
                    return prefix, handler_cls
        return None, None


# ---------------------------------------------------------------------------
# Route proxy — returned by start_*_server() functions
# ---------------------------------------------------------------------------

class _RouteProxy:
    """
    Stand-in for an HTTPServer returned by service start functions.

    When ServiceManager (or web_ui._svc_stop) calls .shutdown() the proxy
    simply unregisters the service's routes from the RouteTable, effectively
    disabling the service without touching the shared dispatcher server.
    """

    def __init__(self, route_table: RouteTable, prefix: str, label: str = ""):
        self._route_table = route_table
        self._prefix = prefix
        self._label = label or prefix
        # Compatibility stubs used by cmp_server / est_server / ipsec_server
        self._tls_watcher = None

    def shutdown(self) -> None:
        self._route_table.unregister(self._prefix)
        logger.info("Service %s (prefix %s) unregistered from dispatcher",
                    self._label, self._prefix)

    def server_close(self) -> None:
        """No-op — the shared dispatcher server owns the socket."""

    def reload_tls(self) -> bool:
        """No-op — TLS reload is handled by the dispatcher server."""
        return False


# ---------------------------------------------------------------------------
# Dispatcher handler factory
# ---------------------------------------------------------------------------

def make_dispatcher_handler(route_table: RouteTable) -> type:
    """
    Return a *BaseHTTPRequestHandler* subclass that routes requests via
    *route_table*.

    For each incoming request the handler:
    1. Looks up the matching prefix in the route table.
    2. Strips that prefix from ``self.path`` (e.g. ``/cmp/health`` → ``/health``).
    3. Calls the registered handler class's ``do_METHOD(self)`` with the
       modified path — this works because all handlers share the same
       ``BaseHTTPRequestHandler`` interface (``rfile``, ``wfile``, ``headers``, …).
    4. Restores ``self.path`` to the original value after the call.
    """

    class DispatchingHandler(http.server.BaseHTTPRequestHandler):
        _route_table: RouteTable = route_table

        def _dispatch(self) -> None:
            prefix, cls = self._route_table.match(self.path)
            if cls is None:
                self.send_error(404, "No service registered for this path")
                return
            orig_path = self.path
            # Assign a unique request ID for this HTTP request; all log records
            # emitted during _dispatch will carry it via RequestIdFilter.
            req_id = uuid.uuid4().hex[:16]
            token = request_id_var.set(req_id)
            # Strip prefix so the service handler sees its own root-relative path
            if prefix != "/":
                rest = self.path[len(prefix):]
                # Preserve query string; ensure leading slash
                if not rest or (rest[0] not in ("?", "#", "/")):
                    rest = "/" + rest
                self.path = rest
            try:
                method_name = f"do_{self.command}"
                handler_method = getattr(cls, method_name, None)
                if handler_method is None:
                    self.send_error(405, f"Method {self.command} not allowed")
                    return
                handler_method(self)
            finally:
                self.path = orig_path
                request_id_var.reset(token)

        def log_message(self, fmt, *args):
            logger.debug("%s - - %s", self.client_address[0], fmt % args)

    # Dynamically attach do_METHOD for every HTTP method
    for _m in _HTTP_METHODS:
        def _make_do(method):
            def _do(self):
                self._dispatch()
            _do.__name__ = f"do_{method}"
            return _do
        setattr(DispatchingHandler, f"do_{_m}", _make_do(_m))

    return DispatchingHandler


# ---------------------------------------------------------------------------
# Single shared server startup
# ---------------------------------------------------------------------------

def start_dispatcher_server(
    host: str,
    port: int,
    route_table: RouteTable,
    tls_cert_path: Optional[str] = None,
    tls_key_path: Optional[str] = None,
    require_client_cert: bool = False,
    tls13_only: bool = False,
    alpn_protocols: Optional[List[str]] = None,
    tls_reload_interval: int = 60,
    ca=None,
) -> http.server.HTTPServer:
    """
    Start the single shared HTTP/HTTPS server for all PyPKI services.

    Parameters
    ----------
    host, port           : bind address and port
    route_table          : RouteTable populated (or to be populated) by
                           individual start_*_server() calls
    tls_cert_path /
    tls_key_path         : PEM cert+key for HTTPS; None → plain HTTP
    require_client_cert  : True → mutual TLS (mTLS; client cert required)
    tls13_only           : restrict to TLS 1.3+
    alpn_protocols       : ALPN list (default: ["http/1.1"])
    tls_reload_interval  : seconds between cert-mtime polls for zero-downtime
                           reload (0 = disabled)
    ca                   : CertificateAuthority instance — required when TLS
                           cert/key are provided

    Returns the HTTPServer instance.  Call .shutdown() to stop all services.
    """
    # Deferred import to avoid circular dependency at module load time
    # (cmp_server imports from pki_server; this file is imported by pki_server)
    from cmp_server import (
        TLSContextHolder, TlsCertWatcher, TLSServer, ThreadedHTTPServer,
        CertificateAuthority,
    )

    handler_cls = make_dispatcher_handler(route_table)

    if tls_cert_path and tls_key_path and ca is not None:
        _alpn = alpn_protocols or [CertificateAuthority.ALPN_HTTP1]

        def _build_ctx(cert_path, key_path):
            return ca.build_tls_context(
                cert_path=cert_path,
                key_path=key_path,
                require_client_cert=require_client_cert,
                alpn_protocols=_alpn,
                tls13_only=tls13_only,
            )

        ssl_ctx = _build_ctx(tls_cert_path, tls_key_path)
        holder  = TLSContextHolder(ssl_ctx)

        srv = TLSServer((host, port), handler_cls)
        srv.ctx_holder = holder

        if tls_reload_interval > 0:
            watcher = TlsCertWatcher(
                holder=holder,
                cert_path=tls_cert_path,
                key_path=tls_key_path,
                build_ctx=_build_ctx,
                poll_interval=tls_reload_interval,
            ).start()
            srv._tls_watcher = watcher
        else:
            srv._tls_watcher = None

        def _reload_tls() -> bool:
            if srv._tls_watcher:
                return srv._tls_watcher.reload_now()
            try:
                holder.swap(_build_ctx(tls_cert_path, tls_key_path))
                logger.info("Dispatcher TLS context reloaded")
                return True
            except Exception as exc:
                logger.error("Dispatcher TLS reload failed: %s", exc)
                return False

        srv.reload_tls = _reload_tls
        scheme = "https"
    else:
        srv = ThreadedHTTPServer((host, port), handler_cls)
        srv._tls_watcher = None
        srv.reload_tls   = lambda: False
        scheme = "http"

    t = threading.Thread(target=srv.serve_forever, daemon=True, name="pypki-dispatcher")
    t.start()
    logger.info("Dispatcher server listening on %s://%s:%d", scheme, host, port)
    return srv
