#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
PyPKI Web Dashboard
===================
A lightweight HTML dashboard for managing the PyPKI CA.
Serves on a dedicated port (--web-port, default 8090).

Features:
  - Certificate inventory with search + filter
  - One-click certificate revocation
  - PKCS#12 / PFX bundle download (cert + CA chain)
  - CA certificate and CRL download
  - Live config viewer and editor (calls PATCH /config internally)
  - Sub-CA issuance form
  - Audit log viewer
  - Rate limit status
  - Services page: start, stop, configure all protocol services live

All state comes from the shared CertificateAuthority and AuditLog objects.
"""

import datetime
import http.server
import json
import logging
import re
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger("web-ui")

# ---------------------------------------------------------------------------
# PAM authentication (ctypes — zero pip dependencies)
# ---------------------------------------------------------------------------

try:
    import ctypes
    import ctypes.util as _ctutil

    _libpam_path = _ctutil.find_library("pam")
    _libc_path   = _ctutil.find_library("c")
    _libpam = ctypes.CDLL(_libpam_path) if _libpam_path else None
    _libc   = ctypes.CDLL(_libc_path)   if _libc_path   else None

    if _libpam and _libc:
        # ---- libc allocation helpers (PAM will free() these) ----
        _libc.calloc.restype  = ctypes.c_void_p
        _libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        _libc.strdup.restype  = ctypes.c_void_p
        _libc.strdup.argtypes = [ctypes.c_char_p]
        _libc.free.restype    = None
        _libc.free.argtypes   = [ctypes.c_void_p]

        # ---- PAM C structures ----
        class _PamMessage(ctypes.Structure):
            _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]

        # resp is c_void_p (not c_char_p) so we can store a raw malloc'd pointer
        # that PAM will later free() — assigning a Python c_char_p here would
        # point into Python-managed memory which PAM must not free.
        class _PamResponse(ctypes.Structure):
            _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]

        _CONV_FUNC = ctypes.CFUNCTYPE(
            ctypes.c_int,
            ctypes.c_int,
            ctypes.POINTER(ctypes.POINTER(_PamMessage)),
            ctypes.POINTER(ctypes.POINTER(_PamResponse)),
            ctypes.c_void_p,
        )

        class _PamConv(ctypes.Structure):
            _fields_ = [("conv", _CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]

        _libpam.pam_start.restype  = ctypes.c_int
        _libpam.pam_start.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.POINTER(_PamConv), ctypes.POINTER(ctypes.c_void_p),
        ]
        _libpam.pam_authenticate.restype  = ctypes.c_int
        _libpam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _libpam.pam_acct_mgmt.restype     = ctypes.c_int
        _libpam.pam_acct_mgmt.argtypes    = [ctypes.c_void_p, ctypes.c_int]
        _libpam.pam_end.restype           = ctypes.c_int
        _libpam.pam_end.argtypes          = [ctypes.c_void_p, ctypes.c_int]

        HAS_PAM = True
    else:
        HAS_PAM = False

except Exception:
    _libpam = None
    _libc   = None
    HAS_PAM = False


def pam_authenticate(username: str, password: str, service: str = "login") -> Tuple[bool, str]:
    """
    Authenticate *username* / *password* against the system PAM stack.

    Returns (True, "") on success or (False, reason) on failure.
    Requires libpam.so on the system — no pip package needed.
    """
    if not HAS_PAM or _libpam is None:
        return False, "PAM not available (libpam.so not found)"

    # Capture password in a closure for the conversation callback
    _password = password.encode()

    @_CONV_FUNC
    def _conv(n_messages, messages, p_response, app_data):
        # Allocate the response array with libc calloc so PAM can free() it.
        # Using Python's allocator here causes "free(): invalid size" / core dump
        # because PAM unconditionally calls free() on the pointer we return.
        resp_ptr = _libc.calloc(n_messages, ctypes.sizeof(_PamResponse))
        if not resp_ptr:
            return 1  # PAM_BUF_ERR
        resp = (_PamResponse * n_messages).from_address(resp_ptr)
        for i in range(n_messages):
            msg = messages[i].contents
            # PAM_PROMPT_ECHO_OFF (1) and PAM_PROMPT_ECHO_ON (2) both get the password.
            # strdup allocates with malloc so PAM can free() resp[i].resp safely.
            if msg.msg_style in (1, 2):
                resp[i].resp = _libc.strdup(_password)
            resp[i].resp_retcode = 0
        p_response[0] = ctypes.cast(resp_ptr, ctypes.POINTER(_PamResponse))
        return 0  # PAM_SUCCESS

    handle = ctypes.c_void_p()
    conv   = _PamConv(_conv, None)

    try:
        ret = _libpam.pam_start(
            service.encode(),
            username.encode(),
            ctypes.byref(conv),
            ctypes.byref(handle),
        )
        if ret != 0:
            return False, f"pam_start failed ({ret})"

        ret = _libpam.pam_authenticate(handle, 0)
        if ret != 0:
            return False, "Authentication failed"

        ret = _libpam.pam_acct_mgmt(handle, 0)
        if ret != 0:
            return False, "Account check failed"

        return True, ""
    except Exception as exc:
        return False, str(exc)
    finally:
        if handle:
            _libpam.pam_end(handle, 0)
        # Zero the password bytes in memory
        for i in range(len(_password)):
            _password = _password  # can't mutate bytes; ctypes copy was made


# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------

class SessionStore:
    """Thread-safe in-memory session store.  Tokens are 256-bit random hex strings."""

    SESSION_LIFETIME_SECONDS = 8 * 3600   # 8 hours
    COOKIE_NAME = "pypki_session"
    # Brute-force protection: max login failures per IP before lockout
    MAX_FAILURES = 10
    LOCKOUT_SECONDS = 300  # 5 minutes

    def __init__(self):
        self._lock      = threading.Lock()
        self._sessions: Dict[str, Tuple[str, float]] = {}  # token → (username, expires)
        self._failures: Dict[str, Tuple[int, float]] = {}  # ip → (count, since)

    # ---- Session management ----

    def create(self, username: str) -> str:
        token   = secrets.token_hex(32)
        expires = time.time() + self.SESSION_LIFETIME_SECONDS
        with self._lock:
            self._sessions[token] = (username, expires)
        return token

    def validate(self, token: str) -> Optional[str]:
        """Return username if token is valid and not expired, else None."""
        with self._lock:
            entry = self._sessions.get(token)
        if not entry:
            return None
        username, expires = entry
        if time.time() > expires:
            self.invalidate(token)
            return None
        return username

    def invalidate(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def purge_expired(self) -> None:
        """Remove all expired sessions (called lazily on login)."""
        now = time.time()
        with self._lock:
            expired = [t for t, (_, exp) in self._sessions.items() if now > exp]
            for t in expired:
                del self._sessions[t]

    # ---- Brute-force rate limiting ----

    def record_failure(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            count, since = self._failures.get(ip, (0, now))
            if now - since > self.LOCKOUT_SECONDS:
                count, since = 0, now   # reset window
            self._failures[ip] = (count + 1, since)

    def is_locked_out(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            count, since = self._failures.get(ip, (0, 0))
        if now - since > self.LOCKOUT_SECONDS:
            return False
        return count >= self.MAX_FAILURES

    def clear_failures(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)


# Module-level session store. Replaced by DbSessionStore in start_web_ui()
# once the CA (and its DB) is available. Falls back to in-memory SessionStore
# for the brief window before start_web_ui() runs (no sessions are issued then).
_session_store = SessionStore()

# Set to True when the server is started with authentication enabled.
# Used by _page() to conditionally render the Sign Out nav link.
_auth_enabled: bool = True



# ---------------------------------------------------------------------------
# HTML / CSS / JS templates
# ---------------------------------------------------------------------------
# Login page template
# ---------------------------------------------------------------------------

def _login_page(error: str = "") -> str:
    err_html = (
        f'<div class="login-error">{error}</div>' if error else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PyPKI — Sign In</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f4f6f9;
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; }}
    .login-card {{ background: #fff; border-radius: 10px;
                  box-shadow: 0 4px 24px rgba(0,0,0,.10);
                  padding: 40px 36px; width: 360px; }}
    .login-logo {{ text-align: center; margin-bottom: 28px; }}
    .login-logo h1 {{ font-size: 1.5rem; color: #1a2340; font-weight: 700; }}
    .login-logo p  {{ font-size: .85rem; color: #6b7280; margin-top: 4px; }}
    label {{ display: block; font-size: .84rem; font-weight: 500;
             color: #4b5563; margin-bottom: 5px; }}
    input {{ border: 1px solid #d1d5db; border-radius: 6px; padding: 9px 12px;
             font-size: .9rem; width: 100%; outline: none; }}
    input:focus {{ border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,.15); }}
    .form-row {{ margin-bottom: 16px; }}
    .btn-login {{ width: 100%; background: #1a2340; color: #fff; border: none;
                  border-radius: 6px; padding: 10px; font-size: .95rem;
                  cursor: pointer; margin-top: 6px; }}
    .btn-login:hover {{ background: #243055; }}
    .login-error {{ background: #fee2e2; color: #991b1b; border-radius: 6px;
                    padding: 9px 14px; font-size: .85rem; margin-bottom: 16px; }}
    .login-footer {{ text-align: center; font-size: .78rem; color: #9ca3af;
                     margin-top: 22px; }}
  </style>
</head>
<body>
  <div class="login-card">
    <div class="login-logo">
      <h1>🔐 PyPKI</h1>
      <p>Private Certificate Authority</p>
    </div>
    {err_html}
    <form method="POST" action="/login">
      <div class="form-row">
        <label for="username">Username</label>
        <input type="text" id="username" name="username"
               autocomplete="username" autofocus required>
      </div>
      <div class="form-row">
        <label for="password">Password</label>
        <input type="password" id="password" name="password"
               autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn-login">Sign In</button>
    </form>
    <div class="login-footer">Authenticated via system PAM</div>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------

_CSS = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f4f6f9; color: #222; }
  .topbar { background: #1a2340; color: #fff; padding: 14px 28px; display: flex; align-items: center; gap: 16px; }
  .topbar h1 { font-size: 1.2rem; font-weight: 600; }
  .topbar .badge { background: #3b82f6; border-radius: 4px; padding: 2px 8px; font-size: .75rem; }
  .nav { background: #243055; padding: 0 28px; display: flex; gap: 0; flex-wrap: wrap; }
  .nav a { color: #adb5c9; text-decoration: none; padding: 10px 18px; display: block; font-size: .88rem; }
  .nav a:hover, .nav a.active { color: #fff; background: #1a2340; }
  .container { max-width: 1200px; margin: 28px auto; padding: 0 20px; }
  .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 20px; }
  .card-head { padding: 16px 20px; border-bottom: 1px solid #eee; display: flex; align-items: center; justify-content: space-between; }
  .card-head h2 { font-size: 1rem; font-weight: 600; }
  .card-body { padding: 20px; }
  table { width: 100%; border-collapse: collapse; font-size: .86rem; }
  th { background: #f8f9fb; padding: 8px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #eee; }
  td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; }
  tr:hover td { background: #fafbff; }
  .badge-ok  { background: #d1fae5; color: #065f46; border-radius: 4px; padding: 2px 8px; font-size: .78rem; }
  .badge-rev { background: #fee2e2; color: #991b1b; border-radius: 4px; padding: 2px 8px; font-size: .78rem; }
  .badge-exp { background: #fef3c7; color: #92400e; border-radius: 4px; padding: 2px 8px; font-size: .78rem; }
  .btn { display: inline-block; padding: 6px 14px; border-radius: 5px; font-size: .83rem; cursor: pointer; border: none; text-decoration: none; }
  .btn-primary   { background: #3b82f6; color: #fff; }
  .btn-danger    { background: #ef4444; color: #fff; }
  .btn-secondary { background: #e5e7eb; color: #374151; }
  .btn-success   { background: #10b981; color: #fff; }
  .btn-warning   { background: #f59e0b; color: #fff; }
  .btn:hover { opacity: .88; }
  .btn:disabled { opacity: .5; cursor: not-allowed; }
  input, select, textarea { border: 1px solid #d1d5db; border-radius: 5px; padding: 7px 10px; font-size: .9rem; width: 100%; }
  label { display: block; font-size: .84rem; font-weight: 500; margin-bottom: 4px; color: #4b5563; }
  .form-row { margin-bottom: 14px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }
  .stat-box { background: #fff; border-radius: 8px; padding: 18px 22px; box-shadow: 0 1px 4px rgba(0,0,0,.07); }
  .stat-box .val { font-size: 2rem; font-weight: 700; color: #1a2340; }
  .stat-box .lbl { font-size: .82rem; color: #6b7280; margin-top: 4px; }
  .stats-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 22px; }
  .alert { padding: 10px 16px; border-radius: 6px; margin-bottom: 14px; font-size: .88rem; }
  .alert-success { background: #d1fae5; color: #065f46; }
  .alert-error   { background: #fee2e2; color: #991b1b; }
  .search-bar { display: flex; gap: 10px; margin-bottom: 14px; }
  .search-bar input { max-width: 320px; }
  code { background: #f3f4f6; padding: 2px 6px; border-radius: 3px; font-size: .85rem; font-family: monospace; }
  pre  { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 6px; font-size: .83rem; overflow-x: auto; }
  /* ── Services page ─────────────────────────────────────────────────── */
  .svc-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 18px; }
  .svc-card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.08); overflow: hidden; }
  .svc-head { padding: 14px 18px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #eee; }
  .svc-head h3 { font-size: .95rem; font-weight: 600; }
  .svc-body { padding: 16px 18px; }
  .svc-desc { font-size: .82rem; color: #6b7280; margin-bottom: 10px; }
  .svc-url  { font-size: .8rem; margin-bottom: 12px; word-break: break-all; }
  .svc-url a { color: #3b82f6; }
  .pill { border-radius: 20px; padding: 3px 11px; font-size: .74rem; font-weight: 600; white-space: nowrap; }
  .pill-run  { background: #d1fae5; color: #065f46; }
  .pill-stop { background: #fef3c7; color: #92400e; }
  .pill-na   { background: #f3f4f6; color: #9ca3af; }
  .svc-actions { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; align-items: center; }
  .svc-msg { font-size: .82rem; margin-top: 8px; min-height: 1.2em; }
  details summary { cursor: pointer; font-size: .83rem; color: #3b82f6; user-select: none; margin-top: 10px; }
  details[open] summary { margin-bottom: 10px; }
  @media(max-width:700px) {
    .stats-grid { grid-template-columns: 1fr 1fr; }
    .grid-2, .grid-3 { grid-template-columns: 1fr; }
    .svc-grid { grid-template-columns: 1fr; }
  }
</style>
"""

_JS = """
<script>
/* ── existing helpers ─────────────────────────────────────────────── */
function revoke(serial) {
  if (!confirm('Revoke certificate serial ' + serial + '?')) return;
  fetch('/api/revoke', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serial: serial, reason: 0})})
    .then(r => r.json()).then(() => location.reload());
}
function applyFilter() {
  const q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('table tbody tr').forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
function patchConfig() {
  const days = document.getElementById('ee_days').value;
  fetch('/api/config', {method:'PATCH', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({validity:{end_entity_days: parseInt(days)}})})
    .then(r => r.json()).then(d => {
      document.getElementById('cfg-result').textContent = JSON.stringify(d, null, 2);
    });
}
function issueSubCA() {
  const cn   = document.getElementById('subca-cn').value;
  const days = document.getElementById('subca-days').value;
  fetch('/api/issue-sub-ca', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({cn: cn, validity_days: parseInt(days)})})
    .then(r => r.json()).then(d => {
      document.getElementById('subca-result').textContent = JSON.stringify(d, null, 2);
    });
}

/* ── Services page ────────────────────────────────────────────────── */
function _svcFields(name) {
  // Collect all data-field inputs inside the named service form
  const form = document.getElementById('svc-form-' + name);
  if (!form) return {};
  const cfg = {};
  form.querySelectorAll('[data-field]').forEach(el => {
    const k = el.getAttribute('data-field');
    cfg[k] = (el.type === 'number') ? parseInt(el.value) : el.value;
  });
  return cfg;
}
function _svcMsg(name, text, ok) {
  const el = document.getElementById('svc-msg-' + name);
  if (!el) return;
  el.textContent = text;
  el.style.color = ok ? '#10b981' : '#ef4444';
}
function svcStart(name) {
  const btn = document.getElementById('svc-btn-start-' + name);
  if (btn) { btn.disabled = true; btn.textContent = 'Starting…'; }
  _svcMsg(name, '', true);
  fetch('/api/services/' + name + '/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(_svcFields(name))
  }).then(r => r.json()).then(d => {
    if (d.error) {
      _svcMsg(name, '✗ ' + d.error, false);
      if (btn) { btn.disabled = false; btn.textContent = 'Start'; }
    } else {
      _svcMsg(name, '✓ Started — reloading…', true);
      setTimeout(() => location.reload(), 900);
    }
  }).catch(e => {
    _svcMsg(name, '✗ ' + e, false);
    if (btn) { btn.disabled = false; btn.textContent = 'Start'; }
  });
}
function svcRestart(name) {
  const btn = document.getElementById('svc-btn-restart-' + name);
  if (btn) { btn.disabled = true; btn.textContent = 'Restarting…'; }
  _svcMsg(name, '', true);
  fetch('/api/services/' + name + '/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(_svcFields(name))
  }).then(r => r.json()).then(d => {
    if (d.error) {
      _svcMsg(name, '✗ ' + d.error, false);
      if (btn) { btn.disabled = false; btn.textContent = 'Restart'; }
    } else {
      _svcMsg(name, '✓ Restarted — reloading…', true);
      setTimeout(() => location.reload(), 900);
    }
  }).catch(e => {
    _svcMsg(name, '✗ ' + e, false);
    if (btn) { btn.disabled = false; btn.textContent = 'Restart'; }
  });
}
function svcStop(name) {
  if (!confirm('Stop ' + name.toUpperCase() + '? Active connections will be dropped.')) return;
  fetch('/api/services/' + name + '/stop', {method: 'POST'})
    .then(r => r.json()).then(d => {
      if (d.ok) location.reload();
      else alert('Stop failed: ' + (d.error || 'unknown error'));
    });
}

/* ── RA Queue page ────────────────────────────────────────────────── */
function raApprove(id) {
  if (!confirm('Approve request ' + id + '?')) return;
  const btn = document.getElementById('btn-approve-' + id);
  const btnD = document.getElementById('btn-deny-' + id);
  if (btn)  { btn.disabled  = true; btn.textContent  = 'Approving…'; }
  if (btnD) { btnD.disabled = true; }
  fetch('/api/ra/approve/' + id, {method: 'POST'})
    .then(r => r.json()).then(d => {
      if (d.error) { alert('Approve failed: ' + d.error); location.reload(); }
      else { location.reload(); }
    }).catch(() => location.reload());
}
function raDeny(id) {
  const reason = prompt('Denial reason (optional):');
  if (reason === null) return;   // cancelled
  const btn = document.getElementById('btn-deny-' + id);
  const btnA = document.getElementById('btn-approve-' + id);
  if (btn)  { btn.disabled  = true; btn.textContent  = 'Denying…'; }
  if (btnA) { btnA.disabled = true; }
  fetch('/api/ra/deny/' + id, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({reason: reason}),
  }).then(r => r.json()).then(d => {
    if (d.error) { alert('Deny failed: ' + d.error); location.reload(); }
    else { location.reload(); }
  }).catch(() => location.reload());
}
</script>
"""


def _page(title: str, body: str, active: str = "") -> str:
    nav_links = [
        ("Dashboard",    "/",           "dashboard"),
        ("Services",     "/services",   "services"),
        ("Certificates", "/certs",      "certs"),
        ("Expiring",     "/expiring",   "expiring"),
        ("Revocation",   "/revocation", "revocation"),
        ("Sub-CA",       "/sub-ca",     "sub-ca"),
        ("RA Queue",     "/ra-queue",   "ra-queue"),
        ("ACME EAB",     "/acme-eab",   "acme-eab"),
        ("Agility",      "/agility",    "agility"),
        ("Metrics",      "/metrics-ui", "metrics-ui"),
        ("Config",       "/config-ui",  "config-ui"),
        ("Audit Log",    "/audit",      "audit"),
        ("API Docs",     "/api-docs",   "api-docs"),
    ]
    nav = "".join(
        '<a href="{}" class="{}">{}</a>'.format(
            href, "active" if tag == active else "", label
        )
        for label, href, tag in nav_links
    )
    # Sign Out link — floated right, only when auth is enabled
    if _auth_enabled:
        nav += '<a href="/logout" style="margin-left:auto;color:#f87171;">Sign Out</a>'
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title} \u2014 PyPKI</title>
  {css}
</head>
<body>
  <div class="topbar">
    <h1>\U0001f510 PyPKI Certificate Authority</h1>
    <span class="badge">v0.10.0</span>
  </div>
  <nav class="nav">{nav}</nav>
  <div class="container">{body}</div>
  {js}
</body>
</html>""".format(title=title, css=_CSS, nav=nav, body=body, js=_JS)


# ---------------------------------------------------------------------------
# Service definitions — shared between the page renderer and the API handler
# ---------------------------------------------------------------------------

# Each entry: (key, label, icon, rfc_label, description, default_prefix, fields)
# fields: list of (field_key, label, input_type, default_value, placeholder, extra_html_attrs)
_SERVICE_DEFS = [
    (
        "cmp", "CMPv2/v3", "\U0001f510", "RFC 4210/9480",
        "Certificate Management Protocol for embedded devices and IoT",
        "/cmp",
        [
            ("prefix",   "Prefix",   "text",   "/cmp",  "/cmp",  ""),
            ("protocol", "Protocol", "select", "cmpv3", "",      ""),
        ],
    ),
    (
        "acme", "ACME", "\U0001f916", "RFC 8555",
        "Automated Certificate Management for servers and workstations",
        "/acme",
        [
            ("prefix",    "Prefix",              "text",   "/acme", "/acme", ""),
            ("base_url",  "Public base URL",     "text",   "",      "http://hostname:8080/acme", ""),
            ("cert_days", "Cert validity (days)", "number","90",    "90",   'min="1" max="3650"'),
        ],
    ),
    (
        "scep", "SCEP", "\U0001f310", "RFC 8894",
        "Simple Certificate Enrolment Protocol for network devices and MDM",
        "/scep",
        [
            ("prefix",    "Prefix",              "text",   "/scep", "/scep", ""),
            ("challenge", "Challenge password",  "text",   "",      "(leave blank = none)", ""),
        ],
    ),
    (
        "est", "EST", "\U0001f512", "RFC 7030",
        "Enrollment over Secure Transport for TLS-capable devices",
        "/est",
        [
            ("prefix",       "Prefix",       "text",   "/est", "/est", ""),
            ("require_auth", "Require auth", "select", "no",   "",     ""),
        ],
    ),
    (
        "ocsp", "OCSP", "\u2705", "RFC 6960",
        "Online Certificate Status Protocol revocation responder",
        "/ocsp",
        [
            ("prefix",        "Prefix",        "text",   "/ocsp", "/ocsp", ""),
            ("cache_seconds", "Cache TTL (s)", "number", "300",   "300",   'min="1"'),
        ],
    ),
    (
        "ipsec", "IPsec PKI", "\U0001f6e1\ufe0f", "RFC 4945/4809",
        "VPN gateway and user certificate management",
        "/ipsec",
        [
            ("prefix",   "Prefix",   "text",   "/ipsec", "/ipsec", ""),
            ("ocsp_url", "OCSP URL", "text",   "",       "http://host:8080/ocsp", ""),
            ("crl_url",  "CRL URL",  "text",   "",       "http://host:8080/ca/crl", ""),
        ],
    ),
]


def _render_select(name, field_key, cur_val):
    """Render special <select> fields for the service config form."""
    if name == "cmp" and field_key == "protocol":
        opts = (
            '<option value="cmpv3" {sel_v3}>CMPv3 (RFC 9480, recommended)</option>'
            '<option value="cmpv2" {sel_v2}>CMPv2 only</option>'
        ).format(
            sel_v3="selected" if cur_val != "cmpv2" else "",
            sel_v2="selected" if cur_val == "cmpv2" else "",
        )
        return '<select data-field="protocol">' + opts + "</select>"
    if name == "est" and field_key == "require_auth":
        opts = (
            '<option value="no" {sel_no}>No (anonymous)</option>'
            '<option value="yes" {sel_yes}>Yes (Basic auth or TLS client cert)</option>'
        ).format(
            sel_no="selected"  if cur_val not in ("yes", "true", True) else "",
            sel_yes="selected" if cur_val in ("yes", "true", True)     else "",
        )
        return '<select data-field="require_auth">' + opts + "</select>"
    return ""


def _render_svc_form(name, fields, saved_cfg):
    """Render the configuration form rows for one service card."""
    rows = ""
    for fkey, flabel, ftype, fdefault, fph, fextra in fields:
        cur = str(saved_cfg.get(fkey, fdefault))
        if ftype == "select":
            widget = _render_select(name, fkey, cur)
        else:
            widget = (
                '<input type="{ftype}" data-field="{fkey}" value="{cur}" '
                'placeholder="{fph}" {fextra}>'
            ).format(ftype=ftype, fkey=fkey, cur=cur, fph=fph, fextra=fextra)
        rows += (
            '<div class="form-row">'
            '<label>{flabel}</label>{widget}'
            "</div>"
        ).format(flabel=flabel, widget=widget)
    return rows


# ---------------------------------------------------------------------------
# Web UI HTTP handler
# ---------------------------------------------------------------------------

class WebUIHandler(http.server.BaseHTTPRequestHandler):
    """Serves the HTML dashboard and a thin REST API used by the dashboard JS."""

    ca            = None   # CertificateAuthority
    audit_log     = None   # AuditLog | None
    rate_limiter  = None   # RateLimiter | None
    require_auth: bool = True   # PAM auth gate; set False with --web-no-auth
    pam_service:  str  = "login"  # PAM service name (e.g. "login", "sshd")
    # Code-signing portal service (None = disabled)
    codesign_service = None   # Optional[codesign.CodeSignService]
    # OIDC configuration (None = PAM mode)
    oidc_config  = None   # Optional[auth.OIDCConfig]
    jwks_cache   = None   # Optional[auth.JWKSCache]
    flow_cookie_key: bytes = b""   # HMAC key for flow cookie (set in start_web_ui)
    # Per-service base URLs (updated live when a service is started/stopped)
    cmp_base_url:   str = "http://localhost:8080"
    acme_base_url:  str = ""
    scep_base_url:  str = ""
    est_base_url:   str = ""
    ocsp_base_url:  str = ""
    ipsec_base_url: str = ""
    # Service registry dict — built in start_web_ui(), shared across instances
    service_registry: "Dict[str, Any]" = None
    # RouteTable shared with the dispatcher — used by _launch_service()
    route_table = None
    # Base URL of the dispatcher server (e.g. "http://localhost:8080")
    dispatcher_base_url: str = ""

    def log_message(self, fmt, *args):
        logger.debug("WebUI %s - %s", self.client_address[0], fmt % args)

    # ------------------------------------------------------------------
    # Authentication helpers
    # ------------------------------------------------------------------

    def _get_session_token(self) -> Optional[str]:
        """Extract the session token from the Cookie header."""
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(SessionStore.COOKIE_NAME + "="):
                return part[len(SessionStore.COOKIE_NAME) + 1:]
        return None

    def _current_user(self) -> Optional[str]:
        """Return the authenticated username or None."""
        if not self.require_auth:
            return "anonymous"
        # Bearer token (Authorization header) for API automation
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            bearer = auth_hdr[7:].strip()
            if bearer:
                return _session_store.validate(bearer)
        token = self._get_session_token()
        if not token:
            return None
        return _session_store.validate(token)

    def _check_auth(self) -> Optional[str]:
        """
        Enforce authentication.  Call at the top of every handler.

        - HTML pages    → redirect to /login and return None
        - API endpoints → send 401 JSON and return None
        - Authenticated → return username (str)
        """
        user = self._current_user()
        if user:
            return user
        # Not authenticated
        if self.path.startswith("/api/") or self.path.startswith("/ca/"):
            self._send_json({"error": "Unauthorized — please sign in via /login"}, 401)
        else:
            self._redirect("/login")
        return None

    def _redirect(self, location: str, code: int = 302) -> None:
        self.send_response(code)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _set_session_cookie(self, token: str) -> None:
        """Emit a Set-Cookie header for the session token."""
        self.send_header(
            "Set-Cookie",
            f"{SessionStore.COOKIE_NAME}={token}; "
            f"Max-Age={SessionStore.SESSION_LIFETIME_SECONDS}; "
            "HttpOnly; SameSite=Strict; Path=/"
        )

    def _clear_session_cookie(self) -> None:
        """Emit a Set-Cookie header that deletes the session cookie."""
        self.send_header(
            "Set-Cookie",
            f"{SessionStore.COOKIE_NAME}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"
        )

    # ------------------------------------------------------------------
    # Login / logout handlers
    # ------------------------------------------------------------------

    def _handle_login_get(self) -> None:
        """Show login form (PAM) or redirect to IdP (OIDC)."""
        if self._current_user():
            self._redirect("/")
            return
        # OIDC mode: redirect to IdP instead of showing the form
        if self.oidc_config is not None and self.jwks_cache is not None:
            self._handle_oidc_login_redirect()
            return
        body = _login_page().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Prevent caching of the login page
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _handle_login_post(self) -> None:
        """Process login form submission."""
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length).decode("utf-8", errors="replace")
        params = urllib.parse.parse_qs(raw, keep_blank_values=True)

        username = params.get("username", [""])[0].strip()
        password = params.get("password", [""])[0]
        ip       = self.client_address[0]

        # Brute-force lockout
        if _session_store.is_locked_out(ip):
            body = _login_page("Too many failed attempts — please wait 5 minutes.").encode()
            self.send_response(429)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if not username or not password:
            body = _login_page("Username and password are required.").encode()
            self.send_response(400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if not HAS_PAM:
            body = _login_page(
                "PAM authentication is not available (libpam.so not found). "
                "Start the server with --web-no-auth to disable authentication."
            ).encode()
            self.send_response(503)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        _session_store.purge_expired()
        ok, reason = pam_authenticate(username, password, service=self.pam_service)

        if ok:
            _session_store.clear_failures(ip)
            token = _session_store.create(username, auth_backend="pam")
            logger.info("WebUI login: user=%s ip=%s", username, ip)
            if self.audit_log:
                try:
                    self.audit_log.record("web_login", f"user={username}", ip)
                except Exception:
                    pass
            self.send_response(302)
            self._set_session_cookie(token)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            _session_store.record_failure(ip)
            logger.warning("WebUI login failed: user=%s ip=%s reason=%s", username, ip, reason)
            body = _login_page("Invalid username or password.").encode()
            self.send_response(401)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def _handle_logout(self) -> None:
        """Invalidate the session and redirect to the login page."""
        token = self._get_session_token()
        user  = _session_store.validate(token) if token else None
        if token:
            _session_store.invalidate(token)
        ip = self.client_address[0]
        if user:
            logger.info("WebUI logout: user=%s ip=%s", user, ip)
            if self.audit_log:
                try:
                    self.audit_log.record("web_logout", f"user={user}", ip)
                except Exception:
                    pass
        self.send_response(302)
        self._clear_session_cookie()
        self.send_header("Location", "/login")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ------------------------------------------------------------------
    # OIDC flow handlers
    # ------------------------------------------------------------------

    def _handle_oidc_login_redirect(self) -> None:
        """Generate PKCE + state, encode in a flow cookie, redirect to IdP."""
        import oidc as _oidc_mod
        import auth as _auth_mod
        verifier, challenge = _oidc_mod.generate_pkce()
        state = _oidc_mod.generate_state()
        auth_url = _oidc_mod.build_authorization_url(
            authorization_endpoint=self.jwks_cache.authorization_endpoint,
            client_id=self.oidc_config.client_id,
            redirect_uri=self.oidc_config.redirect_uri,
            state=state,
            code_challenge=challenge,
        )
        flow_val = _auth_mod.encode_flow_cookie(state, verifier, self.flow_cookie_key)
        self.send_response(302)
        self.send_header(
            "Set-Cookie",
            f"{_auth_mod._FLOW_COOKIE_NAME}={flow_val}; "
            "Max-Age=600; HttpOnly; SameSite=Lax; Path=/"
        )
        self.send_header("Location", auth_url)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _get_flow_cookie(self) -> Optional[str]:
        import auth as _auth_mod
        cookie_header = self.headers.get("Cookie", "")
        name = _auth_mod._FLOW_COOKIE_NAME + "="
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(name):
                return part[len(name):]
        return None

    def _clear_flow_cookie(self) -> None:
        import auth as _auth_mod
        self.send_header(
            "Set-Cookie",
            f"{_auth_mod._FLOW_COOKIE_NAME}=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/"
        )

    def _handle_oidc_callback(self) -> None:
        """Handle IdP redirect: verify state, exchange code, create session."""
        import oidc as _oidc_mod
        import auth as _auth_mod
        import urllib.parse as _up

        qs = _up.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        code    = qs.get("code",  [""])[0]
        state   = qs.get("state", [""])[0]
        error   = qs.get("error", [""])[0]
        ip      = self.client_address[0]

        if error:
            logger.warning("OIDC callback error from IdP: %s ip=%s", error, ip)
            self._oidc_error("IdP returned an error. Please try again.")
            return

        flow_raw = self._get_flow_cookie()
        if not flow_raw:
            self._oidc_error("Login session expired. Please try again.")
            return

        try:
            flow = _auth_mod.decode_flow_cookie(flow_raw, self.flow_cookie_key)
        except _auth_mod.AuthError as exc:
            logger.warning("OIDC flow cookie invalid: %s ip=%s", exc, ip)
            self._oidc_error("Login session invalid or expired. Please try again.")
            return

        if flow.get("s") != state:
            logger.warning("OIDC state mismatch ip=%s", ip)
            self._oidc_error("CSRF state mismatch. Please try again.")
            return

        try:
            token_resp = _oidc_mod.exchange_code(
                token_endpoint=self.jwks_cache.token_endpoint,
                client_id=self.oidc_config.client_id,
                client_secret=self.oidc_config.client_secret,
                code=code,
                redirect_uri=self.oidc_config.redirect_uri,
                code_verifier=flow["v"],
            )
        except Exception as exc:
            logger.error("OIDC token exchange failed: %s ip=%s", exc, ip)
            self._oidc_error("Token exchange failed. Please try again.")
            return

        id_token = token_resp.get("id_token", "")
        if not id_token:
            self._oidc_error("No id_token in token response.")
            return

        try:
            header_b64 = id_token.split(".")[0]
            import base64 as _b64, json as _json
            hdr = _json.loads(_b64.urlsafe_b64decode(header_b64 + "=="))
            kid  = hdr.get("kid", "")
            jwks = self.jwks_cache.get_jwks_for_kid(kid)
            claims = _oidc_mod.verify_id_token(
                id_token, jwks,
                issuer=self.oidc_config.issuer,
                audience=self.oidc_config.client_id,
            )
        except Exception as exc:
            logger.warning("OIDC id_token verification failed: %s ip=%s", exc, ip)
            self._oidc_error("Authentication token invalid. Please try again.")
            return

        identity = claims.get(self.oidc_config.identity_claim) or claims.get("sub", "")
        if not identity:
            self._oidc_error("No identity claim found in token.")
            return

        roles = _auth_mod.map_roles(claims, self.oidc_config)
        token = _session_store.create(
            identity,
            auth_backend="oidc",
            roles=roles,
            ttl_seconds=self.oidc_config.session_ttl,
            idp_subject=claims.get("sub"),
            idp_issuer=claims.get("iss"),
        )

        claims_hash = __import__("hashlib").sha256(id_token.encode()).hexdigest()[:16]
        logger.info("OIDC login: user=%s roles=%s ip=%s", identity, roles, ip)
        if self.audit_log:
            try:
                self.audit_log.record(
                    "web_login",
                    f"user={identity} backend=oidc roles={roles} claims_hash={claims_hash}",
                    ip,
                )
            except Exception:
                pass

        self.send_response(302)
        self._clear_flow_cookie()
        self._set_session_cookie(token)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _oidc_error(self, message: str) -> None:
        """Render an OIDC-specific error page and clear the flow cookie."""
        body = _login_page(f"OIDC error: {message}").encode()
        self.send_response(400)
        self._clear_flow_cookie()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        raw = self.path.split("?")[0].rstrip("/") or "/"
        # /api/v1/* is an alias for /api/* (Terraform provider uses versioned prefix)
        if raw.startswith("/api/v1/"):
            path = "/api/" + raw[len("/api/v1/"):]
        else:
            path = raw
        try:
            # Auth-exempt routes — health, version, spec, CA materials
            if path == "/api/health":
                self._api_health()
                return
            if path == "/api/version":
                self._api_version()
                return
            if path == "/api/openapi.json":
                self._api_openapi()
                return
            if path == "/login":
                self._handle_login_get()
                return
            if path == "/logout":
                self._handle_logout()
                return
            if path == "/callback":
                self._handle_oidc_callback()
                return

            # All other routes require authentication
            if not self._check_auth():
                return

            if path in ("/", "/dashboard"):
                self._dashboard()
            elif path == "/services":
                self._services_page()
            elif path == "/certs":
                self._certs_page()
            elif path == "/revocation":
                self._revocation_page()
            elif path == "/sub-ca":
                self._subca_page()
            elif path == "/config-ui":
                self._config_page()
            elif path == "/audit":
                self._audit_page()
            elif path == "/api-docs":
                self._api_docs_page()
            elif path == "/expiring":
                self._expiring_page()
            elif path == "/ra-queue":
                self._ra_queue_page()
            elif path == "/acme-eab":
                self._acme_eab_page()
            elif path == "/api/acme/eab/keys":
                self._api_acme_eab_list()
            elif path == "/metrics-ui":
                self._metrics_page()
            elif path == "/api/certs":
                self._api_certs()
            elif path == "/api/config":
                self._api_get_config()
            elif path == "/api/audit":
                self._api_audit()
            elif path == "/api/metrics":
                self._api_metrics()
            elif path == "/api/services":
                self._api_services_status()
            elif path.startswith("/api/certs/"):
                self._route_api_cert(path)
            elif path == "/agility":
                self._agility_page()
            elif path == "/api/agility/summary":
                self._api_agility_summary()
            elif path.startswith("/api/agility/breakdown"):
                self._api_agility_breakdown()
            elif path == "/api/agility/migration-forecast":
                self._api_agility_forecast()
            elif path == "/api/agility/csr-demand":
                self._api_agility_csr_demand()
            elif path == "/ssh":
                self._ssh_page()
            elif path.startswith("/api/ssh/krl/"):
                ca_fpr = path.split("/api/ssh/krl/", 1)[1].strip("/")
                self._api_ssh_krl(ca_fpr)
            elif path == "/api/ssh/known-hosts":
                self._api_ssh_known_hosts()
            elif path == "/api/ssh/certs":
                self._api_ssh_list()
            # WireGuard GET routes
            elif path == "/api/wg/peers":
                self._api_wg_list_peers()
            elif path == "/api/wg/servers":
                self._api_wg_list_servers()
            elif re.match(r"^/api/wg/server-config/[^/]+$", path):
                server_id = path.split("/")[-1]
                self._api_wg_server_config(server_id)
            # Matter GET routes
            elif path == "/api/matter/authorities":
                self._api_matter_list_authorities()
            elif path == "/api/matter/dacs":
                self._api_matter_list_dacs()
            # Code-signing portal GET routes
            elif path.startswith("/api/codesign/verify/"):
                digest = path.split("/api/codesign/verify/", 1)[1].strip("/")
                self._api_codesign_verify(digest)
            elif path.startswith("/api/codesign/log/entries/"):
                entry_id = path.split("/api/codesign/log/entries/", 1)[1].strip("/")
                self._api_codesign_entry(entry_id)
            elif path == "/api/codesign/log/checkpoint":
                self._api_codesign_checkpoint()
            elif path == "/api/codesign/log/search":
                self._api_codesign_search()
            elif path in ("/ca/cert.pem", "/ca/cert"):
                # Serve full chain PEM (leaf + intermediates) for intermediate CA mode.
                self._send_raw(200, "application/x-pem-file", self.ca.ca_chain_pem)
            elif path == "/ca/crl":
                try:
                    self._send_raw(200, "application/pkix-crl", self.ca.generate_crl())
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
            else:
                self._send_html(404, "<h2>404 Not found</h2>")
        except Exception as e:
            logger.error("WebUI GET error: %s", e)
            self._send_html(500, "<pre>Internal error: {}</pre>".format(e))

    def do_POST(self):
        raw  = self.path.split("?")[0].rstrip("/")
        path = ("/api/" + raw[len("/api/v1/"):]) if raw.startswith("/api/v1/") else raw

        # Auth-exempt: login form
        if path == "/login":
            self._handle_login_post()
            return

        # All other POST routes require authentication
        if not self._check_auth():
            return

        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length)
        try:
            data = json.loads(raw) if raw else {}
        except Exception:
            ctype = self.headers.get("Content-Type", "")
            if "application/json" in ctype:
                self._send_json({"error": "malformed JSON"}, 400)
                return
            data = {}
        try:
            if path == "/api/issue":
                self._api_issue(data)
            elif path == "/api/revoke":
                self._api_revoke(data)
            elif path == "/api/renew":
                self._api_renew(data)
            elif path == "/api/config":
                self._api_patch_config(data)
            elif path == "/api/issue-sub-ca":
                self._api_issue_sub_ca(data)
            elif path.startswith("/api/services/"):
                self._api_service_action(path, data)
            elif path == "/api/scep/otp":
                self._api_scep_mint_otp(data)
            elif path == "/api/acme/eab/mint":
                self._api_acme_eab_mint()
            elif path.startswith("/api/acme/eab/revoke/"):
                kid = path.split("/api/acme/eab/revoke/", 1)[1].strip("/")
                self._api_acme_eab_revoke(kid)
            elif path == "/api/cross-sign":
                self._api_cross_sign(data)
            elif path == "/api/paired-issue":
                self._api_paired_issue(data)
            elif path == "/api/composite-issue":
                self._api_composite_issue(data)
            elif path == "/api/slh-dsa-issue":
                self._api_slh_dsa_issue(data)
            elif path == "/api/ssh/sign":
                self._api_ssh_sign(data)
            elif path == "/api/ssh/host-cert":
                self._api_ssh_host_cert(data)
            elif path.startswith("/api/ra/approve/"):
                req_id = path.split("/api/ra/approve/", 1)[1].strip("/")
                self._api_ra_approve(req_id)
            elif path.startswith("/api/ra/deny/"):
                req_id = path.split("/api/ra/deny/", 1)[1].strip("/")
                self._api_ra_deny(req_id, data)
            # WireGuard PKI
            elif path == "/api/wg/peers":
                self._api_wg_enroll_peer(data)
            elif path == "/api/wg/servers":
                self._api_wg_register_server(data)
            elif re.match(r"^/api/wg/peers/[^/]+/revoke$", path):
                peer_id = path.split("/")[3]
                self._api_wg_revoke_peer(peer_id)
            # Matter PKI
            elif path == "/api/matter/dac":
                self._api_matter_issue_dac(data)
            elif path == "/api/matter/dac/bulk":
                self._api_matter_bulk_dac(data)
            elif path == "/api/matter/pai":
                self._api_matter_issue_pai(data)
            # Code-signing portal
            elif path == "/api/codesign/submit":
                self._api_codesign_submit(data)
            else:
                self._send_json({"error": "not found"}, 404)
        except Exception as e:
            logger.error("WebUI POST error: %s", e)
            self._send_json({"error": str(e)}, 500)

    # PATCH /api/config — the Config page JS uses method:'PATCH'; treat identically to POST
    do_PATCH = do_POST


    # ------------------------------------------------------------------
    # Dashboard page
    # ------------------------------------------------------------------

    def _dashboard(self):
        certs   = self.ca.list_certificates()
        total   = len(certs)
        revoked = sum(1 for c in certs if c["revoked"])
        now     = datetime.datetime.now(datetime.timezone.utc)
        expired = sum(
            1 for c in certs
            if not c["revoked"] and
            datetime.datetime.fromisoformat(
                c["not_after"].replace("Z", "+00:00")
                if c["not_after"].endswith("Z") else c["not_after"]
            ).replace(tzinfo=datetime.timezone.utc) < now
        )
        active = total - revoked - expired

        stats = (
            '<div class="stats-grid">'
            '<div class="stat-box"><div class="val">{total}</div><div class="lbl">Total certificates</div></div>'
            '<div class="stat-box"><div class="val" style="color:#10b981">{active}</div><div class="lbl">Active</div></div>'
            '<div class="stat-box"><div class="val" style="color:#ef4444">{revoked}</div><div class="lbl">Revoked</div></div>'
            '<div class="stat-box"><div class="val" style="color:#f59e0b">{expired}</div><div class="lbl">Expired</div></div>'
            "</div>"
        ).format(total=total, active=active, revoked=revoked, expired=expired)

        ca_subject  = self.ca.ca_cert.subject.rfc4514_string()
        ca_expires  = self.ca.ca_cert.not_valid_after_utc.strftime("%Y-%m-%d")
        ca_serial   = self.ca.ca_cert.serial_number
        ca_mode     = "Intermediate" if self.ca.is_intermediate else "Root (self-signed)"
        ca_chain_depth = 1 + len(self.ca._parent_chain)

        # Build active-endpoints table from service registry (or fall back to URLs)
        ep_rows = ""
        reg = self.service_registry or {}
        svc_label = {
            "cmp": "CMPv2/v3", "acme": "ACME", "scep": "SCEP",
            "est": "EST", "ocsp": "OCSP", "ipsec": "IPsec PKI",
        }
        for sname, slabel in svc_label.items():
            entry = reg.get(sname, {})
            url   = entry.get("url", "") or getattr(self, sname + "_base_url", "")
            if url:
                ep_rows += (
                    "<tr><td><strong>{label}</strong></td>"
                    '<td><code>{url}</code></td></tr>'
                ).format(label=slabel, url=url)

        if not ep_rows:
            ep_rows = '<tr><td colspan="2" style="color:#999">No services running — start them on the <a href="/services">Services</a> page.</td></tr>'

        body = (
            "{stats}"
            '<div class="card">'
            '  <div class="card-head"><h2>Certificate Authority</h2>'
            '    <a href="/ca/cert.pem" class="btn btn-secondary">Download CA Cert</a>'
            "  </div>"
            '  <div class="card-body">'
            "    <table>"
            "      <tr><th>Subject</th><td><code>{subject}</code></td></tr>"
            "      <tr><th>Serial</th><td><code>{serial}</code></td></tr>"
            "      <tr><th>Expires</th><td>{expires}</td></tr>"
            "      <tr><th>CA Mode</th><td>{ca_mode}</td></tr>"
            "      <tr><th>Chain Depth</th><td>{ca_chain_depth} cert(s)</td></tr>"
            "    </table>"
            "  </div>"
            "</div>"
            '<div class="card">'
            '  <div class="card-head"><h2>Active Endpoints</h2>'
            '    <a href="/services" class="btn btn-secondary">Manage Services</a>'
            "  </div>"
            '  <div class="card-body"><table>{ep_rows}</table></div>'
            "</div>"
        ).format(
            stats=stats,
            subject=ca_subject,
            serial=ca_serial,
            expires=ca_expires,
            ca_mode=ca_mode,
            ca_chain_depth=ca_chain_depth,
            ep_rows=ep_rows,
        )
        self._send_html(200, _page("Dashboard", body, "dashboard"))

    # ------------------------------------------------------------------
    # Services page
    # ------------------------------------------------------------------

    def _services_page(self):
        reg = self.service_registry or {}

        cards = ""
        for (name, label, icon, rfc, desc, default_prefix, fields) in _SERVICE_DEFS:
            entry   = reg.get(name, {})
            running = entry.get("server") is not None
            avail   = entry.get("available", False)
            url     = entry.get("url", "")
            saved   = entry.get("config", {})
            if not saved.get("prefix"):
                saved["prefix"] = default_prefix

            # Status pill
            if running:
                pill = '<span class="pill pill-run">\u25cf Running</span>'
            elif avail:
                pill = '<span class="pill pill-stop">\u25cb Stopped</span>'
            else:
                pill = '<span class="pill pill-na">Not installed</span>'

            # URL line
            if running and url:
                url_html = (
                    '<div class="svc-url">'
                    'Endpoint: <a href="{u}" target="_blank">{u}</a>'
                    "</div>"
                ).format(u=url)
            elif not avail:
                url_html = (
                    '<div class="svc-url" style="color:#9ca3af">'
                    "Place <code>{n}_server.py</code> alongside "
                    "<code>pki_server.py</code> to enable this service."
                    "</div>"
                ).format(n=name)
            else:
                url_html = ""

            # Config form rows
            form_rows = _render_svc_form(name, fields, saved)

            # Buttons / form layout
            if running:
                # Running: show a "Reconfigure & restart" accordion + Stop button
                action_html = (
                    "<details>"
                    "  <summary>\u2699\ufe0f Reconfigure &amp; restart</summary>"
                    '  <div id="svc-form-{n}" style="margin-top:8px">{rows}</div>'
                    '  <div class="svc-actions">'
                    '    <button class="btn btn-warning" id="svc-btn-restart-{n}"'
                    '      onclick="svcRestart(\'{n}\')">Restart with new config</button>'
                    '    <button class="btn btn-danger"'
                    '      onclick="svcStop(\'{n}\')">Stop</button>'
                    "  </div>"
                    "</details>"
                ).format(n=name, rows=form_rows)
            elif avail:
                # Stopped but available: show config form + Start button
                action_html = (
                    '<div id="svc-form-{n}">{rows}</div>'
                    '<div class="svc-actions">'
                    '  <button class="btn btn-success" id="svc-btn-start-{n}"'
                    '    onclick="svcStart(\'{n}\')">Start</button>'
                    "</div>"
                ).format(n=name, rows=form_rows)
            else:
                action_html = ""

            cards += (
                '<div class="svc-card">'
                '  <div class="svc-head">'
                "    <h3>{icon} {label} "
                '      <span style="font-size:.74rem;font-weight:400;color:#6b7280">{rfc}</span>'
                "    </h3>"
                "    {pill}"
                "  </div>"
                '  <div class="svc-body">'
                '    <p class="svc-desc">{desc}</p>'
                "    {url_html}"
                "    {action_html}"
                '    <div class="svc-msg" id="svc-msg-{n}"></div>'
                "  </div>"
                "</div>"
            ).format(
                icon=icon, label=label, rfc=rfc, pill=pill,
                desc=desc, url_html=url_html, action_html=action_html, n=name,
            )

        body = (
            '<div class="card">'
            '  <div class="card-head">'
            "    <h2>Protocol Services</h2>"
            '    <span style="font-size:.82rem;color:#6b7280">'
            "      Start, stop or reconfigure any service without restarting the CA"
            "    </span>"
            "  </div>"
            "</div>"
            '<div class="svc-grid">{cards}</div>'
        ).format(cards=cards)
        self._send_html(200, _page("Services", body, "services"))

    # ------------------------------------------------------------------
    # Certificate pages
    # ------------------------------------------------------------------

    def _certs_page(self):
        certs = self.ca.list_certificates()
        now   = datetime.datetime.now(datetime.timezone.utc)
        rows  = ""
        for c in sorted(certs, key=lambda x: -x["serial"]):
            exp = datetime.datetime.fromisoformat(
                c["not_after"].replace("Z", "+00:00")
                if c["not_after"].endswith("Z") else c["not_after"]
            ).replace(tzinfo=datetime.timezone.utc)
            if c["revoked"]:
                status = '<span class="badge-rev">Revoked</span>'
                action = ""
            elif exp < now:
                status = '<span class="badge-exp">Expired</span>'
                action = ""
            else:
                status = '<span class="badge-ok">Active</span>'
                action = (
                    '<button class="btn btn-danger" onclick="revoke({s})">Revoke</button>'
                ).format(s=c["serial"])
            rows += (
                "<tr>"
                "<td><code>{serial}</code></td>"
                "<td>{subject}</td>"
                "<td>{nb}</td><td>{na}</td>"
                "<td>{status}</td>"
                "<td>"
                '  <a href="/api/certs/{serial}/pem" class="btn btn-secondary">PEM</a> '
                '  <a href="/api/certs/{serial}/p12" class="btn btn-secondary">P12</a> '
                "  {action}"
                "</td>"
                "</tr>"
            ).format(
                serial=c["serial"], subject=c["subject"],
                nb=c["not_before"][:10], na=c["not_after"][:10],
                status=status, action=action,
            )

        body = (
            '<div class="card">'
            '  <div class="card-head"><h2>Certificate Inventory ({n})</h2></div>'
            '  <div class="card-body">'
            '    <div class="search-bar">'
            '      <input id="search" placeholder="Search by subject, serial\u2026" oninput="applyFilter()">'
            "    </div>"
            "    <table>"
            "      <thead><tr>"
            "        <th>Serial</th><th>Subject</th><th>Not Before</th>"
            "        <th>Not After</th><th>Status</th><th>Actions</th>"
            "      </tr></thead>"
            "      <tbody>{rows}</tbody>"
            "    </table>"
            "  </div>"
            "</div>"
        ).format(n=len(certs), rows=rows)
        self._send_html(200, _page("Certificates", body, "certs"))

    def _revocation_page(self):
        crl_url  = self.cmp_base_url + "/ca/crl"
        ocsp_url = (self.ocsp_base_url + "/ocsp") if self.ocsp_base_url else "not configured"
        body = (
            '<div class="card">'
            '  <div class="card-head"><h2>Revocation Infrastructure</h2></div>'
            '  <div class="card-body">'
            "    <table>"
            '      <tr><th>CRL URL</th><td><code>{crl}</code>'
            '        <a href="/ca/crl" class="btn btn-secondary">Download</a></td></tr>'
            "      <tr><th>OCSP URL</th><td><code>{ocsp}</code></td></tr>"
            "    </table>"
            "  </div>"
            "</div>"
            '<div class="card">'
            '  <div class="card-head"><h2>Revoke by Serial Number</h2></div>'
            '  <div class="card-body">'
            '    <div class="form-row"><label>Serial number</label>'
            '      <input id="rev-serial" placeholder="e.g. 1001">'
            "    </div>"
            '    <div class="form-row"><label>Reason</label>'
            '      <select id="rev-reason">'
            '        <option value="0">Unspecified</option>'
            '        <option value="1">Key Compromise</option>'
            '        <option value="2">CA Compromise</option>'
            '        <option value="3">Affiliation Changed</option>'
            '        <option value="4">Superseded</option>'
            '        <option value="5">Cessation Of Operation</option>'
            "      </select>"
            "    </div>"
            "    <button class=\"btn btn-danger\" onclick=\""
            "      const s=parseInt(document.getElementById('rev-serial').value);"
            "      const r=parseInt(document.getElementById('rev-reason').value);"
            "      if(!s) return;"
            "      fetch('/api/revoke',{{method:'POST',"
            "        headers:{{'Content-Type':'application/json'}},"
            "        body:JSON.stringify({{serial:s,reason:r}})}})"
            "        .then(r=>r.json()).then(d=>{{"
            "          document.getElementById('rev-result').textContent=JSON.stringify(d,null,2);"
            "        }});"
            '    ">Revoke</button>'
            '    <pre id="rev-result" style="margin-top:14px"></pre>'
            "  </div>"
            "</div>"
        ).format(crl=crl_url, ocsp=ocsp_url)
        self._send_html(200, _page("Revocation", body, "revocation"))

    def _subca_page(self):
        body = (
            '<div class="card">'
            '  <div class="card-head"><h2>Issue Subordinate CA Certificate</h2></div>'
            '  <div class="card-body">'
            '    <p style="color:#6b7280;margin-bottom:16px;font-size:.88rem">'
            "      Issuing a sub-CA allows you to delegate certificate issuance to a"
            "      separate CA instance. The root CA key never needs to be online once"
            "      sub-CAs are deployed."
            "    </p>"
            '    <div class="grid-2">'
            '      <div class="form-row"><label>Common Name</label>'
            '        <input id="subca-cn" placeholder="Intermediate CA 1"'
            '               value="PyPKI Intermediate CA">'
            "      </div>"
            '      <div class="form-row"><label>Validity (days)</label>'
            '        <input id="subca-days" type="number" value="1825" min="1" max="7300">'
            "      </div>"
            "    </div>"
            '    <button class="btn btn-primary" onclick="issueSubCA()">Issue Sub-CA Certificate</button>'
            '    <p style="font-size:.8rem;color:#6b7280;margin-top:8px">'
            "      The sub-CA certificate and key will be returned in the JSON response below."
            "    </p>"
            '    <pre id="subca-result" style="margin-top:14px"></pre>'
            "  </div>"
            "</div>"
        )
        self._send_html(200, _page("Sub-CA Issuance", body, "sub-ca"))

    def _config_page(self):
        cfg      = self.ca.config.as_dict() if self.ca.config else {}
        cfg_json = json.dumps(cfg, indent=2)
        ee_days  = cfg.get("validity", {}).get("end_entity_days", 365)
        body = (
            '<div class="card">'
            '  <div class="card-head"><h2>Live Configuration</h2></div>'
            '  <div class="card-body">'
            "    <pre>{cfg}</pre>"
            '    <hr style="margin:18px 0">'
            '    <h3 style="font-size:.95rem;margin-bottom:12px">Update Validity Periods</h3>'
            '    <div class="grid-2">'
            '      <div class="form-row"><label>End-entity cert days</label>'
            '        <input id="ee_days" type="number" value="{ee_days}">'
            "      </div>"
            "    </div>"
            '    <button class="btn btn-primary" onclick="patchConfig()">Apply</button>'
            '    <pre id="cfg-result" style="margin-top:14px"></pre>'
            "  </div>"
            "</div>"
        ).format(cfg=cfg_json, ee_days=ee_days)
        self._send_html(200, _page("Configuration", body, "config-ui"))

    def _audit_page(self):
        events = self.audit_log.recent(100) if self.audit_log else []
        rows = "".join(
            "<tr><td>{ts}</td><td>{ev}</td><td>{det}</td><td>{ip}</td></tr>".format(
                ts=e.get("ts", "")[:19], ev=e.get("event", ""),
                det=e.get("detail", ""), ip=e.get("ip", ""),
            )
            for e in events
        ) or '<tr><td colspan="4" style="color:#999">No events yet</td></tr>'
        body = (
            '<div class="card">'
            '  <div class="card-head"><h2>Audit Log (last 100 events)</h2></div>'
            '  <div class="card-body">'
            "    <table>"
            "      <thead><tr><th>Timestamp</th><th>Event</th><th>Detail</th><th>IP</th></tr></thead>"
            "      <tbody>{rows}</tbody>"
            "    </table>"
            "  </div>"
            "</div>"
        ).format(rows=rows)
        self._send_html(200, _page("Audit Log", body, "audit"))

    def _expiring_page(self):
        now  = datetime.datetime.now(datetime.timezone.utc)
        rows = ""
        try:
            certs = self.ca.expiring_certificates(days_ahead=30)
        except AttributeError:
            all_certs = self.ca.list_certificates()
            certs = []
            for c in all_certs:
                if c.get("revoked"):
                    continue
                try:
                    exp   = datetime.datetime.fromisoformat(
                        c["not_after"].replace("Z", "+00:00")
                        if c["not_after"].endswith("Z") else c["not_after"]
                    ).replace(tzinfo=datetime.timezone.utc)
                    delta = (exp - now).days
                    if 0 <= delta <= 30:
                        certs.append({**c, "days_remaining": delta})
                except Exception:
                    pass

        for c in sorted(certs, key=lambda x: x.get("days_remaining", 9999)):
            days  = c.get("days_remaining", "?")
            color = "#ef4444" if isinstance(days, int) and days <= 7 else "#f59e0b"
            rows += (
                "<tr>"
                "<td><code>{s}</code></td>"
                "<td>{sub}</td>"
                "<td>{na}</td>"
                '<td style="color:{col};font-weight:600">{d}d</td>'
                '<td><button class="btn btn-primary"'
                '  onclick="renewCert({s})">Renew</button></td>'
                "</tr>"
            ).format(
                s=c["serial"], sub=c["subject"],
                na=c.get("not_after", "")[:10], col=color, d=days,
            )

        renew_js = (
            "<script>"
            "function renewCert(serial) {{"
            "  if (!confirm('Renew cert ' + serial + '?')) return;"
            "  fetch('/api/renew', {{method:'POST',"
            "    headers:{{'Content-Type':'application/json'}},"
            "    body: JSON.stringify({{serial: serial}})}})"
            "    .then(r => r.json()).then(d => {{"
            "      if (d.error) alert('Error: ' + d.error);"
            "      else {{ alert('Renewed! New serial: ' + d.serial); location.reload(); }}"
            "    }});"
            "}}"
            "</script>"
        )
        inner = (
            '<table><thead><tr>'
            "<th>Serial</th><th>Subject</th><th>Expires</th><th>Days Left</th><th>Action</th>"
            "</tr></thead><tbody>{rows}</tbody></table>"
        ).format(rows=rows) if rows else '<p style="color:#6b7280">No certificates expiring within 30 days.</p>'
        body = (
            '<div class="card">'
            '  <div class="card-head"><h2>Certificates Expiring Within 30 Days ({n})</h2></div>'
            '  <div class="card-body">{inner}</div>'
            "</div>{renew_js}"
        ).format(n=len(certs), inner=inner, renew_js=renew_js)
        self._send_html(200, _page("Expiring Certificates", body, "expiring"))

    def _metrics_page(self):
        try:
            raw = self.ca.metrics_prometheus()
        except AttributeError:
            raw = "# metrics_prometheus() not available on this CA object\n"
        except Exception as e:
            raw = "# Error: {}\n".format(e)
        body = (
            '<div class="card">'
            '  <div class="card-head"><h2>Prometheus Metrics</h2>'
            '    <a href="/api/metrics" class="btn btn-secondary">Raw /api/metrics</a>'
            "  </div>"
            '  <div class="card-body">'
            '    <p style="color:#6b7280;font-size:.85rem;margin-bottom:12px">'
            "      Compatible with <code>prometheus.io/scrape</code>."
            "      Scrape endpoint: <code>/api/metrics</code>"
            "    </p>"
            "    <pre>{raw}</pre>"
            "  </div>"
            "</div>"
        ).format(raw=raw)
        self._send_html(200, _page("Prometheus Metrics", body, "metrics-ui"))

    # ------------------------------------------------------------------
    # RA Queue page + API handlers
    # ------------------------------------------------------------------

    def _ra_queue_page(self):
        ra = getattr(self.ca, "ra", None)
        if ra is None:
            body = (
                '<div class="card">'
                '  <div class="card-head"><h2>RA Approval Queue</h2></div>'
                '  <div class="card-body">'
                '    <p style="color:#6b7280">The Registration Authority is not enabled. '
                '    Start the server with <code>--ra-require-approval</code> or '
                '    <code>--ra-auto-approve-profiles</code> to use the RA workflow.</p>'
                "  </div>"
                "</div>"
            )
            self._send_html(200, _page("RA Queue", body, "ra-queue"))
            return

        pending = ra.list_pending()
        recent  = ra.list_recent(50)

        # Pending table
        if pending:
            p_rows = ""
            for r in pending:
                created = datetime.datetime.fromtimestamp(
                    r["created_at"], tz=datetime.timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
                sans = ", ".join(
                    (r.get("san_dns") and json.loads(r["san_dns"]) or []) +
                    (r.get("san_ips") and json.loads(r["san_ips"]) or [])
                ) or "—"
                rid = r["request_id"]
                p_rows += (
                    "<tr>"
                    "<td><code style='font-size:.78rem'>{short}</code></td>"
                    "<td>{proto}</td><td>{profile}</td>"
                    "<td><code>{subject}</code></td>"
                    "<td>{sans}</td><td>{ip}</td><td>{created}</td>"
                    "<td>"
                    "  <button id='btn-approve-{rid}' class='btn btn-success' "
                    "          style='margin-right:4px' onclick='raApprove(\"{rid}\")'>"
                    "    Approve</button>"
                    "  <button id='btn-deny-{rid}' class='btn btn-danger' "
                    "          onclick='raDeny(\"{rid}\")'>"
                    "    Deny</button>"
                    "</td>"
                    "</tr>"
                ).format(
                    short=rid[:8] + "…",
                    proto=r.get("protocol", ""),
                    profile=r.get("profile", ""),
                    subject=r.get("subject_dn", ""),
                    sans=sans,
                    ip=r.get("requester_ip", ""),
                    created=created,
                    rid=rid,
                )
            pending_html = (
                '<table>'
                '<thead><tr>'
                '<th>Request ID</th><th>Protocol</th><th>Profile</th>'
                '<th>Subject</th><th>SANs</th><th>Requester IP</th>'
                '<th>Received</th><th>Actions</th>'
                '</tr></thead>'
                '<tbody>{rows}</tbody>'
                '</table>'
            ).format(rows=p_rows)
        else:
            pending_html = '<p style="color:#6b7280;padding:8px 0">No pending requests.</p>'

        # Recent decisions table
        decided = [r for r in recent if r.get("status") != "pending"]
        if decided:
            d_rows = ""
            for r in decided[:20]:
                status = r.get("status", "")
                badge_cls = {"issued": "badge-ok", "denied": "badge-rev"}.get(status, "")
                decided_ts = r.get("decided_at")
                decided_str = (
                    datetime.datetime.fromtimestamp(
                        decided_ts, tz=datetime.timezone.utc
                    ).strftime("%Y-%m-%d %H:%M UTC")
                    if decided_ts else "—"
                )
                d_rows += (
                    "<tr>"
                    "<td><code style='font-size:.78rem'>{short}</code></td>"
                    "<td>{proto}</td><td>{profile}</td>"
                    "<td><code>{subject}</code></td>"
                    "<td><span class='{badge}'>{status}</span></td>"
                    "<td>{approver}</td><td>{reason}</td><td>{ts}</td>"
                    "</tr>"
                ).format(
                    short=r["request_id"][:8] + "…",
                    proto=r.get("protocol", ""),
                    profile=r.get("profile", ""),
                    subject=r.get("subject_dn", ""),
                    badge=badge_cls,
                    status=status,
                    approver=r.get("approver") or "auto",
                    reason=r.get("deny_reason") or "—",
                    ts=decided_str,
                )
            recent_html = (
                '<table>'
                '<thead><tr>'
                '<th>Request ID</th><th>Protocol</th><th>Profile</th>'
                '<th>Subject</th><th>Status</th><th>Approver</th>'
                '<th>Reason</th><th>Decided</th>'
                '</tr></thead>'
                '<tbody>{rows}</tbody>'
                '</table>'
            ).format(rows=d_rows)
        else:
            recent_html = '<p style="color:#6b7280;padding:8px 0">No recent decisions.</p>'

        count_badge = (
            ' <span class="badge-rev" style="font-size:.75rem;padding:2px 8px;'
            'border-radius:4px;margin-left:8px">{n} pending</span>'.format(n=len(pending))
            if pending else ""
        )

        body = (
            '<div class="card">'
            '  <div class="card-head">'
            '    <h2>Pending Requests{badge}</h2>'
            '    <button class="btn btn-secondary" onclick="location.reload()">Refresh</button>'
            "  </div>"
            '  <div class="card-body" style="overflow-x:auto">{pending}</div>'
            "</div>"
            '<div class="card">'
            '  <div class="card-head"><h2>Recent Decisions (last 20)</h2></div>'
            '  <div class="card-body" style="overflow-x:auto">{recent}</div>'
            "</div>"
        ).format(badge=count_badge, pending=pending_html, recent=recent_html)

        self._send_html(200, _page("RA Queue", body, "ra-queue"))

    def _api_ra_approve(self, request_id: str):
        ra = getattr(self.ca, "ra", None)
        if ra is None:
            self._send_json({"error": "RA not enabled"}, 503)
            return
        approver = self._current_user() or "webui"
        cert = ra.approve(
            request_id,
            approver=approver,
            audit=self.audit_log,
            requester_ip=self.client_address[0],
        )
        if cert is None:
            self._send_json({"error": "request not found or not pending"}, 404)
        else:
            self._send_json({
                "ok": True,
                "request_id": request_id,
                "serial": cert.serial_number,
                "subject": cert.subject.rfc4514_string(),
            })

    def _api_ra_deny(self, request_id: str, data: dict):
        ra = getattr(self.ca, "ra", None)
        if ra is None:
            self._send_json({"error": "RA not enabled"}, 503)
            return
        approver = self._current_user() or "webui"
        reason = data.get("reason", "")
        ok = ra.deny(
            request_id,
            reason=reason,
            approver=approver,
            audit=self.audit_log,
            requester_ip=self.client_address[0],
        )
        if not ok:
            self._send_json({"error": "request not found or not pending"}, 404)
        else:
            self._send_json({"ok": True, "request_id": request_id})

    def _api_docs_page(self):
        rows = "\n".join(
            "        <tr><td>{m}</td><td><code>{p}</code></td><td>{d}</td></tr>".format(
                m=m, p=p, d=d
            )
            for m, p, d in [
                ("GET",  "/api/certs",                 "List all certificates (JSON)"),
                ("GET",  "/api/certs/&lt;serial&gt;/pem", "Download cert PEM"),
                ("GET",  "/api/certs/&lt;serial&gt;/p12", "Download cert + CA chain as PKCS#12"),
                ("POST", "/api/revoke",                '{&quot;serial&quot;: N, &quot;reason&quot;: 0}'),
                ("POST", "/api/renew",                 '{&quot;serial&quot;: N}'),
                ("GET",  "/api/config",                "View current config"),
                ("PATCH","/api/config",                "Update validity periods — body: {&quot;validity&quot;: {...}}"),
                ("POST", "/api/issue-sub-ca",          '{&quot;cn&quot;: &quot;...&quot;, &quot;validity_days&quot;: N}'),
                ("GET",  "/api/audit",                 "Audit log (JSON)"),
                ("GET",  "/api/metrics",               "Prometheus metrics (text/plain)"),
                ("GET",  "/api/services",              "Service status — all 6 protocol services (JSON)"),
                ("POST", "/api/services/&lt;name&gt;/start", "Start a service with config body ({port, …})"),
                ("POST", "/api/services/&lt;name&gt;/stop",  "Stop a running service"),
                ("POST", "/api/ra/approve/&lt;id&gt;", "Approve a pending RA request"),
                ("POST", "/api/ra/deny/&lt;id&gt;",    '{&quot;reason&quot;: &quot;optional text&quot;}'),
                ("GET",  "/ca/cert.pem",               "CA certificate (PEM)"),
                ("GET",  "/ca/crl",                    "Certificate Revocation List (DER)"),
            ]
        )
        body = (
            '<div class="card">'
            '  <div class="card-head"><h2>REST API Reference</h2></div>'
            '  <div class="card-body">'
            "    <table>"
            "      <thead><tr><th>Method</th><th>Path</th><th>Description</th></tr></thead>"
            "      <tbody>{rows}</tbody>"
            "    </table>"
            "  </div>"
            "</div>"
        ).format(rows=rows)
        self._send_html(200, _page("API Docs", body, "api-docs"))

    # ------------------------------------------------------------------
    # JSON API — certificates
    # ------------------------------------------------------------------

    def _route_api_cert(self, path):
        parts = path.split("/")
        # ['', 'api', 'certs', '<serial>']         → JSON detail
        # ['', 'api', 'certs', '<serial>', '<fmt>'] → file download
        if len(parts) == 4:
            try:
                serial = int(parts[3])
                self._api_cert_detail(serial)
                return
            except ValueError:
                pass
        elif len(parts) == 5:
            try:
                serial = int(parts[3])
                fmt    = parts[4]
                if fmt in ("pem", "p12"):
                    self._api_cert_download(serial, fmt)
                    return
            except (ValueError, IndexError):
                pass
        self._send_json({"error": "not found"}, 404)

    def _api_cert_detail(self, serial: int):
        """GET /api/certs/<serial> — JSON cert metadata + PEM."""
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives.serialization import Encoding as _Enc
        import hashlib as _hashlib
        der = self.ca.get_cert_by_serial(serial)
        if not der:
            self._send_json({"error": "certificate not found"}, 404)
            return
        try:
            cert = _x509.load_der_x509_certificate(der)
            pem  = cert.public_bytes(_Enc.PEM).decode()
            fp   = _hashlib.sha256(der).hexdigest()
            row  = next((c for c in self.ca.list_certificates() if c["serial"] == serial), {})
            self._send_json({
                "serial":            serial,
                "subject":           cert.subject.rfc4514_string(),
                "not_before":        cert.not_valid_before_utc.isoformat(),
                "not_after":         cert.not_valid_after_utc.isoformat(),
                "revoked":           bool(row.get("revoked", False)),
                "profile":           row.get("profile", "default"),
                "cert_pem":          pem,
                "sha256_fingerprint": fp,
            })
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)

    def _api_cert_download(self, serial: int, fmt: str):
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives.serialization import Encoding as _Enc
        der = self.ca.get_cert_by_serial(serial)
        if not der:
            self._send_json({"error": "certificate not found"}, 404)
            return
        cert = None
        try:
            cert = _x509.load_der_x509_certificate(der)
        except Exception:
            pass
        if fmt == "pem":
            pem = cert.public_bytes(_Enc.PEM) if cert else der
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Disposition",
                             'attachment; filename="cert-{}.pem"'.format(serial))
            self.send_header("Content-Length", str(len(pem)))
            self.end_headers()
            self.wfile.write(pem)
        elif fmt == "p12":
            try:
                p12 = self.ca.export_pkcs12(serial)
                if not p12:
                    self._send_json({"error": "certificate not found"}, 404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pkcs12")
                self.send_header("Content-Disposition",
                                 'attachment; filename="cert-{}.p12"'.format(serial))
                self.send_header("Content-Length", str(len(p12)))
                self.end_headers()
                self.wfile.write(p12)
            except Exception as e:
                self._send_json({"error": "PKCS#12 generation failed: {}".format(e)}, 500)

    def _api_certs(self):
        self._send_json({"certificates": self.ca.list_certificates()})

    def _api_get_config(self):
        self._send_json(self.ca.config.as_dict() if self.ca.config else {})

    def _api_revoke(self, data: dict):
        serial = data.get("serial")
        reason = data.get("reason", 0)
        if serial is None:
            self._send_json({"error": "serial required"}, 400)
            return
        ok = self.ca.revoke_certificate(int(serial), int(reason))
        if self.audit_log:
            self.audit_log.record("revoke",
                                  "serial={} reason={}".format(serial, reason),
                                  self.client_address[0])
        self._send_json({"ok": ok, "serial": serial})

    def _api_renew(self, data: dict):
        serial = data.get("serial")
        if serial is None:
            self._send_json({"error": "serial required"}, 400)
            return
        try:
            result = self.ca.renew_certificate(int(serial))
            if isinstance(result, dict) and result.get("error"):
                self._send_json(result, 400)
                return
            if hasattr(result, "serial_number"):
                self._send_json({
                    "ok": True,
                    "serial": result.serial_number,
                    "not_after": result.not_valid_after_utc.isoformat(),
                })
            else:
                self._send_json(result if isinstance(result, dict) else {"ok": True})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _api_patch_config(self, data: dict):
        if self.ca.config:
            result = self.ca.config.patch(data)
            self._send_json({"ok": True, "config": result})
        else:
            self._send_json({"error": "config not available"}, 500)

    def _api_issue_sub_ca(self, data: dict):
        """
        POST /api/issue-sub-ca

        Request body:
            {
              "cn":              "k8s-cluster-ca",           // required
              "validity_days":   1825,                        // optional (default 1825)
              "path_length":     0,                           // optional (default 0)
              "permitted_dns":   ["cluster.local", "svc"],    // optional (RFC 5280 §4.2.1.10)
              "excluded_dns":    ["internal.example.com"],    // optional
              "permitted_emails":["@example.com"],            // optional
              "excluded_ips":    ["0.0.0.0/0"]                // optional
            }

        When any name-constraints field is present, issues via
        ``issue_sub_ca_with_name_constraints`` so a rogue cluster cannot mint
        certs outside its permitted subtrees.

        Response: { ok, serial, subject, cert_pem, key_pem }
            - cert_pem: PEM X.509 certificate
            - key_pem:  PEM PKCS#8 private key (RFC 5958)
        """
        cn            = data.get("cn", "Intermediate CA")
        validity_days = int(data.get("validity_days", 1825))
        path_length   = int(data.get("path_length", 0))

        permitted_dns    = data.get("permitted_dns") or []
        excluded_dns     = data.get("excluded_dns") or []
        permitted_emails = data.get("permitted_emails") or []
        excluded_ips     = data.get("excluded_ips") or []

        use_name_constraints = any([
            permitted_dns, excluded_dns, permitted_emails, excluded_ips,
        ])

        export_format = data.get("export_format", "pem").lower()
        p12_password  = data.get("p12_password", "")

        try:
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
            from cryptography.hazmat.primitives.serialization import (
                Encoding as _Enc, PrivateFormat, NoEncryption,
                BestAvailableEncryption, pkcs12 as _pkcs12,
            )
            import base64 as _b64

            if use_name_constraints:
                # issue_certificate_with_name_constraints takes subject + public key
                # and accepts **kwargs threaded to issue_certificate.
                sub_ca_priv = _rsa.generate_private_key(
                    public_exponent=65537, key_size=4096
                )
                subject_str = f"CN={cn},O=PyPKI Subordinate CA"
                sub_ca_cert = self.ca.issue_certificate_with_name_constraints(
                    subject_str=subject_str,
                    public_key=sub_ca_priv.public_key(),
                    permitted_dns=permitted_dns,
                    excluded_dns=excluded_dns,
                    permitted_emails=permitted_emails,
                    excluded_ips=excluded_ips,
                    validity_days=validity_days,
                    path_length=path_length,
                )
                sub_ca_key = sub_ca_priv
            else:
                sub_ca_key, sub_ca_cert = self.ca.issue_sub_ca(
                    cn, validity_days, path_length=path_length,
                )

            if self.audit_log:
                nc_summary = ""
                if use_name_constraints:
                    nc_summary = (
                        f" permitted_dns={permitted_dns}"
                        f" excluded_dns={excluded_dns}"
                        f" permitted_emails={permitted_emails}"
                        f" excluded_ips={excluded_ips}"
                    )
                self.audit_log.record(
                    "issue_sub_ca",
                    f"cn={cn} days={validity_days} path_length={path_length}{nc_summary}"
                    f" export_format={export_format}",
                    self.client_address[0],
                )

            if export_format == "pkcs12":
                # Build PKCS#12 bundle: sub-CA key + cert + issuing CA chain.
                # Password is required unless the caller explicitly passes "".
                friendly = cn.encode() or b"sub-ca"
                ca_chain = [self.ca.ca_cert] + list(self.ca._parent_chain)
                enc = (
                    BestAvailableEncryption(p12_password.encode())
                    if p12_password
                    else NoEncryption()
                )
                p12_bytes = _pkcs12.serialize_key_and_certificates(
                    name=friendly,
                    key=sub_ca_key,
                    cert=sub_ca_cert,
                    cas=ca_chain,
                    encryption_algorithm=enc,
                )
                self._send_json({
                    "ok":      True,
                    "serial":  sub_ca_cert.serial_number,
                    "subject": sub_ca_cert.subject.rfc4514_string(),
                    "p12_b64": _b64.b64encode(p12_bytes).decode(),
                })
            else:
                cert_pem = sub_ca_cert.public_bytes(_Enc.PEM).decode()
                key_pem = sub_ca_key.private_bytes(
                    _Enc.PEM, PrivateFormat.PKCS8, NoEncryption(),
                ).decode()
                self._send_json({
                    "ok":       True,
                    "serial":   sub_ca_cert.serial_number,
                    "subject":  sub_ca_cert.subject.rfc4514_string(),
                    "cert_pem": cert_pem,
                    "key_pem":  key_pem,
                })
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _api_audit(self):
        events = self.audit_log.recent(200) if self.audit_log else []
        self._send_json({"events": events})

    def _api_metrics(self):
        try:
            text = self.ca.metrics_prometheus()
        except AttributeError:
            text = "# metrics_prometheus() not available\n"
        except Exception as e:
            text = "# error: {}\n".format(e)
        data = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8; version=0.0.4")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _api_cross_sign(self, data: dict):
        """POST /api/cross-sign — cross-sign a PEM certificate with this CA's key."""
        from cryptography.x509 import load_pem_x509_certificate
        pem = data.get("certificate_pem", "")
        if not pem:
            self._send_json({"error": "certificate_pem required"}, 400)
            return
        validity_days = int(data.get("validity_days", 365))
        if validity_days < 1 or validity_days > 7300:
            self._send_json({"error": "validity_days must be 1–7300"}, 400)
            return
        try:
            cert_in = load_pem_x509_certificate(pem.encode())
        except Exception as e:
            self._send_json({"error": f"invalid certificate_pem: {e}"}, 400)
            return
        cert_out = self.ca.cross_sign(
            cert_in,
            validity_days=validity_days,
            audit=self.audit_log,
            requester_ip=self.client_address[0] if self.client_address else "",
        )
        from cryptography.hazmat.primitives.serialization import Encoding as _Enc
        pem_out = cert_out.public_bytes(_Enc.PEM).decode()
        self._send_json({
            "certificate_pem": pem_out,
            "serial": cert_out.serial_number,
        })

    def _api_paired_issue(self, data: dict):
        """POST /api/paired-issue — RFC 9763 paired classical + ML-DSA certificate issuance."""
        import pki_server as _pki_mod
        if not _pki_mod.HAS_MLDSA:
            self._send_json({"error": "ML-DSA not available (requires cryptography ≥ 44)"}, 501)
            return
        from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import (
            Encoding as _Enc, PrivateFormat as _PF, NoEncryption as _NE,
            PublicFormat as _PuF,
        )

        subject = data.get("subject", "CN=PQC Entity")
        validity_days = int(data.get("validity_days", 365))
        san_emails = data.get("san_emails") or None
        classical_key_type = data.get("classical_key_type", "ec-p256")
        ml_dsa_variant = data.get("ml_dsa_variant", "ml-dsa-44")

        # Generate classical key
        classical_factories = {
            "ec-p256": lambda: ec.generate_private_key(ec.SECP256R1()),
            "ec-p384": lambda: ec.generate_private_key(ec.SECP384R1()),
            "rsa-2048": lambda: __import__("cryptography.hazmat.primitives.asymmetric.rsa",
                                           fromlist=["generate_private_key"]).generate_private_key(
                                               public_exponent=65537, key_size=2048),
        }
        if classical_key_type not in classical_factories:
            self._send_json({"error": f"classical_key_type must be one of {list(classical_factories)}"}, 400)
            return
        classical_key = classical_factories[classical_key_type]()

        # Generate ML-DSA key
        mldsa_factories = {
            "ml-dsa-44": _mldsa.MLDSA44PrivateKey.generate,
            "ml-dsa-65": _mldsa.MLDSA65PrivateKey.generate,
            "ml-dsa-87": _mldsa.MLDSA87PrivateKey.generate,
        }
        if ml_dsa_variant not in mldsa_factories:
            self._send_json({"error": f"ml_dsa_variant must be one of {list(mldsa_factories)}"}, 400)
            return
        mldsa_key = mldsa_factories[ml_dsa_variant]()
        mldsa_spki_der = mldsa_key.public_key().public_bytes(_Enc.DER, _PuF.SubjectPublicKeyInfo)

        classical_cert_pem, ml_dsa_cert_der = self.ca.issue_paired_certs(
            subject_str=subject,
            classical_public_key=classical_key.public_key(),
            mldsa_spki_der=mldsa_spki_der,
            validity_days=validity_days,
            san_emails=san_emails,
            audit=self.audit_log,
            requester_ip=self.client_address[0] if self.client_address else "",
        )

        classical_key_pem = classical_key.private_bytes(
            _Enc.PEM, _PF.PKCS8, _NE()
        ).decode()
        mldsa_key_der = mldsa_key.private_bytes(_Enc.DER, _PF.PKCS8, _NE())

        import base64 as _b64
        self._send_json({
            "classical_cert_pem": classical_cert_pem,
            "classical_private_key_pem": classical_key_pem,
            "ml_dsa_cert_b64": _b64.b64encode(ml_dsa_cert_der).decode(),
            "ml_dsa_private_key_b64": _b64.b64encode(mldsa_key_der).decode(),
            "ml_dsa_variant": ml_dsa_variant,
            "classical_key_type": classical_key_type,
        })

    def _api_composite_issue(self, data: dict) -> None:
        """POST /api/composite-issue — Composite ML-DSA certificate issuance."""
        import pki_server as _pki_mod
        if not _pki_mod.HAS_COMPOSITE_MLDSA:
            self._send_json({"error": "Composite ML-DSA not enabled (requires --enable-composite-mldsa)"}, 501)
            return
        import composite as _comp
        import base64 as _b64

        composite_name = data.get("composite_name", "composite-mldsa44-ecdsa-p256")
        if composite_name not in _comp.COMPOSITE_OIDS:
            self._send_json({"error": f"composite_name must be one of {list(_comp.COMPOSITE_OIDS)}"}, 400)
            return

        subject = data.get("subject", "CN=Composite Entity")
        validity_days = int(data.get("validity_days", 365))

        key = _comp.generate_composite_key(composite_name)
        spki_der = _comp.composite_spki_der(key)

        cert_der = self.ca.issue_composite_certificate(
            subject_str=subject,
            composite_spki_der=spki_der,
            composite_name=composite_name,
            validity_days=validity_days,
            audit=self.audit_log,
            requester_ip=self.client_address[0] if self.client_address else "",
        )
        private_key_der = _comp.composite_private_key_der(key)
        self._send_json({
            "cert_b64": _b64.b64encode(cert_der).decode(),
            "private_key_b64": _b64.b64encode(private_key_der).decode(),
            "composite_name": composite_name,
        })

    def _api_slh_dsa_issue(self, data: dict) -> None:
        """POST /api/slh-dsa-issue — SLH-DSA (FIPS 205) leaf certificate issuance."""
        import pki_server as _pki_mod
        if not _pki_mod.HAS_SLHDSA:
            self._send_json({"error": "SLH-DSA not enabled (requires --enable-slh-dsa)"}, 501)
            return
        import slh_dsa as _slhdsa
        import base64 as _b64

        param_name = data.get("param_name", "slh-dsa-sha2-128s")
        if param_name not in _slhdsa.SLH_DSA_OIDS:
            self._send_json(
                {"error": f"param_name must be one of {sorted(_slhdsa.SLH_DSA_OIDS)}"}, 400
            )
            return

        subject = data.get("subject", "CN=SLH-DSA Entity")
        validity_days = int(data.get("validity_days", 365))
        san_emails = data.get("san_emails") or None

        slhdsa_key = _slhdsa.generate(param_name)
        pub = slhdsa_key.public_key()
        spki_der = pub.to_spki_der()

        cert_der = self.ca.issue_slh_dsa_certificate(
            subject_str=subject,
            slhdsa_spki_der=spki_der,
            param_name=param_name,
            validity_days=validity_days,
            san_emails=san_emails,
            audit=self.audit_log,
            requester_ip=self.client_address[0] if self.client_address else "",
        )
        self._send_json({
            "cert_b64": _b64.b64encode(cert_der).decode(),
            "private_key_b64": _b64.b64encode(slhdsa_key.to_pkcs8_der()).decode(),
            "param_name": param_name,
            "sig_size_bytes": _slhdsa.SIG_SIZE.get(param_name, 0),
            "pk_size_bytes": _slhdsa.PK_SIZE.get(param_name, 0),
        })

    # ------------------------------------------------------------------
    # ACME EAB management page + API
    # ------------------------------------------------------------------

    def _acme_eab_db(self):
        """Return the ACMEDatabase from the running ACME server, or None."""
        srv = (self.service_registry or {}).get("acme", {}).get("server")
        return getattr(srv, "acme_db", None)

    def _acme_eab_page(self):
        acme_db = self._acme_eab_db()
        if acme_db is None:
            body = (
                '<div class="card">'
                '  <div class="card-head"><h2>ACME External Account Binding</h2></div>'
                '  <div class="card-body">'
                '    <p style="color:#6b7280">The ACME service is not running. '
                '    Start the server with <code>--acme</code> to use EAB management.</p>'
                "  </div>"
                "</div>"
            )
            self._send_html(200, _page("ACME EAB", body, "acme-eab"))
            return

        keys = acme_db.list_eab_keys()
        require_eab = bool(
            (self.service_registry or {}).get("acme", {}).get("config", {}).get("require_eab")
        )

        if keys:
            rows_html = ""
            for k in keys:
                kid = k["kid"]
                created = datetime.datetime.fromtimestamp(
                    k["created_at"], tz=datetime.timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
                if k["revoked_at"]:
                    revoked = datetime.datetime.fromtimestamp(
                        k["revoked_at"], tz=datetime.timezone.utc
                    ).strftime("%Y-%m-%d %H:%M UTC")
                    status_html = "<span class='badge-rev'>Revoked {}</span>".format(revoked)
                    action_html = "—"
                else:
                    status_html = "<span class='badge-ok'>Active</span>"
                    action_html = (
                        "<button class='btn btn-danger' style='font-size:.8rem;padding:3px 10px' "
                        "onclick='revokeKey(\"{kid}\")'>Revoke</button>"
                    ).format(kid=kid)
                rows_html += (
                    "<tr>"
                    "<td><code style='font-size:.78rem'>{kid}</code></td>"
                    "<td>{created}</td><td>{status}</td><td>{action}</td>"
                    "</tr>"
                ).format(kid=kid, created=created, status=status_html, action=action_html)
            table_html = (
                "<table>"
                "<thead><tr><th>Key ID (kid)</th><th>Created</th><th>Status</th><th>Action</th></tr></thead>"
                "<tbody>{}</tbody>"
                "</table>"
            ).format(rows_html)
        else:
            table_html = '<p style="color:#6b7280;padding:8px 0">No EAB keys yet. Use the button above to mint one.</p>'

        eab_notice = (
            '<div style="background:#fef3c7;border:1px solid #f59e0b;border-radius:6px;'
            'padding:10px 14px;margin-bottom:16px;font-size:.9rem">'
            '  <strong>Note:</strong> EAB enforcement is currently <strong>disabled</strong>. '
            '  Start the server with <code>--acme-require-eab</code> to gate account creation '
            '  behind these keys.'
            "</div>"
        ) if not require_eab else ""

        body = (
            '<div class="card">'
            '  <div class="card-head">'
            '    <h2>ACME External Account Binding</h2>'
            '    <button class="btn btn-primary" onclick="mintKey()">Mint New Key</button>'
            "  </div>"
            '  <div class="card-body">'
            "    {notice}"
            '    <p style="font-size:.9rem;color:#6b7280;margin-bottom:12px">'
            "      EAB keys are pre-shared secrets issued by the CA admin. ACME clients present "
            "      an HMAC-HS256 JWS signed with the mac_key when creating accounts. "
            "      Each mac_key is shown exactly once at mint time — it cannot be retrieved later."
            "    </p>"
            '    <div style="overflow-x:auto">{table}</div>'
            "  </div>"
            "</div>"
            "<div id='mint-result' style='display:none' class='card'>"
            "  <div class='card-head'><h2>New EAB Key — Save This Now</h2></div>"
            "  <div class='card-body'>"
            "    <p style='color:#b45309'>The mac_key is shown only once and cannot be recovered. "
            "    Copy it before navigating away.</p>"
            "    <table><tbody>"
            "      <tr><td><strong>kid</strong></td><td><code id='new-kid'></code></td></tr>"
            "      <tr><td><strong>mac_key</strong></td><td><code id='new-mac'></code></td></tr>"
            "    </tbody></table>"
            "    <button class='btn btn-secondary' style='margin-top:12px' "
            "            onclick=\"document.getElementById('mint-result').style.display='none'\">Dismiss</button>"
            "  </div>"
            "</div>"
            "<script>"
            "async function mintKey() {{"
            "  const r = await fetch('/api/acme/eab/mint', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:'{{}}'}});"
            "  const d = await r.json();"
            "  if (!r.ok) {{ alert('Error: ' + (d.error || r.status)); return; }}"
            "  document.getElementById('new-kid').textContent = d.kid;"
            "  document.getElementById('new-mac').textContent = d.mac_key;"
            "  document.getElementById('mint-result').style.display = '';"
            "  location.reload();"
            "}}"
            "async function revokeKey(kid) {{"
            "  if (!confirm('Revoke key ' + kid + '?')) return;"
            "  const r = await fetch('/api/acme/eab/revoke/' + kid, {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:'{{}}'}});"
            "  const d = await r.json();"
            "  if (!r.ok) {{ alert('Error: ' + (d.error || r.status)); return; }}"
            "  location.reload();"
            "}}"
            "</script>"
        ).format(notice=eab_notice, table=table_html)

        self._send_html(200, _page("ACME EAB", body, "acme-eab"))

    def _api_acme_eab_list(self):
        """GET /api/acme/eab/keys — list all EAB keys (no mac_key in response)."""
        acme_db = self._acme_eab_db()
        if acme_db is None:
            self._send_json({"error": "ACME service not running"}, 503)
            return
        keys = acme_db.list_eab_keys()
        self._send_json({"keys": keys})

    def _api_acme_eab_mint(self):
        """POST /api/acme/eab/mint — generate and return a new EAB kid + mac_key."""
        acme_db = self._acme_eab_db()
        if acme_db is None:
            self._send_json({"error": "ACME service not running"}, 503)
            return
        kid, mac_key = acme_db.mint_eab_key()
        self._send_json({"kid": kid, "mac_key": mac_key})

    def _api_acme_eab_revoke(self, kid: str):
        """POST /api/acme/eab/revoke/<kid> — revoke an EAB key."""
        acme_db = self._acme_eab_db()
        if acme_db is None:
            self._send_json({"error": "ACME service not running"}, 503)
            return
        if not kid:
            self._send_json({"error": "kid required"}, 400)
            return
        ok = acme_db.revoke_eab_key(kid)
        if not ok:
            self._send_json({"error": "key not found"}, 404)
        else:
            self._send_json({"ok": True, "kid": kid})

    def _api_scep_mint_otp(self, data: dict):
        """POST /api/scep/otp — mint a single-use SCEP enrolment OTP."""
        scep_mod = (self.service_registry or {}).get("_modules", {}).get("scep")
        if scep_mod is None:
            self._send_json({"error": "SCEP module not loaded"}, 404)
            return
        ttl = int(data.get("ttl_seconds", 86400))
        if ttl < 60 or ttl > 7 * 86400:
            self._send_json({"error": "ttl_seconds must be 60–604800"}, 400)
            return
        token = scep_mod.mint_otp(self.ca.ca_dir, ttl)
        self._send_json({"otp": token, "ttl_seconds": ttl})

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Crypto Agility Dashboard
    # ------------------------------------------------------------------

    def _agility_page(self):
        try:
            import agility as _ag
            summ = _ag.summary(self.ca._pki_db)
        except Exception as exc:
            body = '<div class="card"><div class="card-body"><p>Agility module error: {}</p></div></div>'.format(exc)
            self._send_html(200, _page("Crypto Agility", body, "agility"))
            return

        total  = summ["total_active_certs"]
        pq_pct = summ["pq_capable_pct"]
        by_cls = summ["by_class"]

        # ── Class palette ───────────────────────────────────────────────
        _colours = {
            "classical-rsa":   "#94a3b8",
            "classical-ec":    "#64748b",
            "classical-eddsa": "#475569",
            "hybrid-9763":     "#60a5fa",
            "composite-mldsa": "#34d399",
            "mldsa-only":      "#10b981",
            "slhdsa-only":     "#059669",
            "unknown":         "#e5e7eb",
        }

        # ── Distribution table ──────────────────────────────────────────
        dist_rows = ""
        for cls, info in sorted(by_cls.items(), key=lambda kv: -kv[1]["count"]):
            colour = _colours.get(cls, "#e5e7eb")
            pq_badge = (
                '<span class="badge-ok" style="margin-left:6px">PQ</span>'
                if cls in ("hybrid-9763", "composite-mldsa", "mldsa-only", "slhdsa-only")
                else ""
            )
            bar_w = max(info["pct"], 1)
            dist_rows += (
                "<tr>"
                "<td><span style='display:inline-block;width:12px;height:12px;"
                "border-radius:2px;background:{colour};margin-right:6px;vertical-align:middle'></span>"
                "<code>{cls}</code>{badge}</td>"
                "<td style='text-align:right'>{count:,}</td>"
                "<td style='text-align:right'>{pct}%</td>"
                "<td style='width:220px;padding-right:16px'>"
                "<div style='background:#f3f4f6;border-radius:4px;height:10px;overflow:hidden'>"
                "<div style='background:{colour};width:{bar_w}%;height:10px'></div>"
                "</div></td>"
                "</tr>"
            ).format(cls=cls, badge=pq_badge, colour=colour,
                     count=info["count"], pct=info["pct"], bar_w=bar_w)

        dist_card = """
<div class="card">
  <div class="card-head">
    <h2>Active Certificate Distribution</h2>
    <span style="color:#6b7280;font-size:.85rem">{total:,} active certs &mdash; {pq_pct}% PQ-capable</span>
  </div>
  <div class="card-body">
    <table><thead><tr>
      <th>Crypto class</th><th style="text-align:right">Count</th>
      <th style="text-align:right">%</th><th>Bar</th>
    </tr></thead><tbody>{rows}</tbody></table>
  </div>
</div>""".format(total=total, pq_pct=pq_pct, rows=dist_rows)

        # ── Profile hotspots table ──────────────────────────────────────
        try:
            bkdn = _ag.breakdown(self.ca._pki_db, by="profile")
            groups = bkdn.get("groups", [])
        except Exception:
            groups = []

        hotspot_rows = ""
        for g in groups:
            prof  = g["key"]
            tot   = g["total"]
            bc    = g["by_class"]
            pq    = sum(bc.get(c, 0) for c in _ag.PQ_CLASSES)
            pq_f  = round(pq / tot * 100, 1) if tot > 0 else 0.0
            colour = "#ef4444" if pq_f < 10 else ("#f59e0b" if pq_f < 50 else "#10b981")
            hotspot_rows += (
                "<tr>"
                "<td><code>{prof}</code></td>"
                "<td style='text-align:right'>{tot:,}</td>"
                "<td style='text-align:right'>"
                "<span style='color:{colour};font-weight:600'>{pq_f}%</span></td>"
                "</tr>"
            ).format(prof=prof, tot=tot, pq_f=pq_f, colour=colour)

        hotspot_card = """
<div class="card">
  <div class="card-head">
    <h2>Profile Hotspots <span style="font-size:.8rem;font-weight:400;color:#6b7280">(sorted by % PQ ascending — worst first)</span></h2>
    <a href="/api/agility/breakdown?by=profile" class="btn btn-secondary" target="_blank">JSON</a>
  </div>
  <div class="card-body">
    {content}
  </div>
</div>""".format(content=(
            "<table><thead><tr><th>Profile</th><th style='text-align:right'>Active</th>"
            "<th style='text-align:right'>PQ %</th></tr></thead>"
            "<tbody>" + hotspot_rows + "</tbody></table>"
        ) if hotspot_rows else "<p style='color:#6b7280'>No active certs.</p>")

        # ── Forecast card ───────────────────────────────────────────────
        try:
            fc = _ag.forecast(self.ca._pki_db)
            ms = fc.get("milestones", [])
            milestone_html = ""
            for m in ms:
                tgt = m["target_pq_pct"]
                eta = m["estimated_at"]
                colour = "#10b981" if eta in ("already met",) else "#3b82f6"
                milestone_html += (
                    "<div style='display:flex;justify-content:space-between;"
                    "border-bottom:1px solid #f0f0f0;padding:6px 0'>"
                    "<span>{tgt}% PQ-capable</span>"
                    "<strong style='color:{colour}'>{eta}</strong></div>"
                ).format(tgt=tgt, eta=eta, colour=colour)
            caveats_html = "".join(
                "<li style='color:#6b7280;font-size:.83rem'>{}</li>".format(c)
                for c in fc.get("caveats", [])
            )
            inp = fc.get("model_inputs", {})
            inputs_html = (
                "<p style='font-size:.82rem;color:#6b7280;margin-bottom:10px'>"
                "Window: {wd}d &bull; Current PQ: {cpq}% &bull; "
                "Renewal rate: {rr}/day &bull; PQ adoption: {pa}/day"
                "</p>"
            ).format(
                wd=inp.get("window_days", "?"),
                cpq=inp.get("current_pq_pct", "?"),
                rr=inp.get("renewal_rate_per_day", "?"),
                pa=inp.get("pq_adoption_rate_per_day", "?"),
            )
            forecast_body = inputs_html + (milestone_html or "<p style='color:#6b7280'>Insufficient data.</p>")
            if caveats_html:
                forecast_body += "<ul style='margin-top:10px;padding-left:18px'>" + caveats_html + "</ul>"
        except Exception as exc:
            forecast_body = "<p style='color:#6b7280'>Forecast unavailable: {}</p>".format(exc)

        forecast_card = """
<div class="card">
  <div class="card-head">
    <h2>Migration Forecast (linear extrapolation)</h2>
    <a href="/api/agility/migration-forecast" class="btn btn-secondary" target="_blank">JSON</a>
  </div>
  <div class="card-body">{body}</div>
</div>""".format(body=forecast_body)

        # ── CSR demand card ─────────────────────────────────────────────
        try:
            demand = _ag.csr_demand(self.ca._pki_db, window_days=30)
            demand_rows = ""
            dem_total = demand.get("csrs_total", 0)
            for cls, n in sorted(demand.get("by_issued_class", {}).items(),
                                  key=lambda kv: -kv[1]):
                pct = round(n / dem_total * 100, 1) if dem_total > 0 else 0.0
                colour = _colours.get(cls, "#e5e7eb")
                demand_rows += (
                    "<tr><td><code>{cls}</code></td>"
                    "<td style='text-align:right'>{n:,}</td>"
                    "<td style='text-align:right'>{pct}%</td></tr>"
                ).format(cls=cls, n=n, pct=pct, colour=colour)
            demand_note = demand.get("note", "")
            demand_body = (
                "<table><thead><tr>"
                "<th>Crypto class</th><th style='text-align:right'>Issued</th>"
                "<th style='text-align:right'>%</th>"
                "</tr></thead><tbody>" + demand_rows + "</tbody></table>"
                + ("<p style='font-size:.8rem;color:#6b7280;margin-top:8px'>{}</p>".format(demand_note) if demand_note else "")
            ) if demand_rows else "<p style='color:#6b7280'>No issuances in last 30 days.</p>"
        except Exception as exc:
            demand_body = "<p style='color:#6b7280'>CSR demand unavailable: {}</p>".format(exc)

        demand_card = """
<div class="card">
  <div class="card-head">
    <h2>CSR Demand — last 30 days</h2>
    <a href="/api/agility/csr-demand" class="btn btn-secondary" target="_blank">JSON</a>
  </div>
  <div class="card-body">{body}</div>
</div>""".format(body=demand_body)

        body = dist_card + hotspot_card + forecast_card + demand_card
        self._send_html(200, _page("Crypto Agility", body, "agility"))

    def _api_agility_summary(self):
        try:
            import agility as _ag
            self._send_json(_ag.summary(self.ca._pki_db))
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)

    def _api_agility_breakdown(self):
        try:
            import agility as _ag
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            )
            by = (qs.get("by") or ["profile"])[0]
            if by not in ("profile", "month", "ca"):
                self._send_json({"error": "by must be profile|month|ca"}, 400)
                return
            self._send_json(_ag.breakdown(self.ca._pki_db, by=by))
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)

    def _api_agility_forecast(self):
        try:
            import agility as _ag
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            )
            window = int((qs.get("window_days") or [180])[0])
            self._send_json(_ag.forecast(self.ca._pki_db, window_days=window))
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)

    def _api_agility_csr_demand(self):
        try:
            import agility as _ag
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            )
            since_days = int((qs.get("since_days") or [30])[0])
            self._send_json(_ag.csr_demand(self.ca._pki_db, window_days=since_days))
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)

    # SSH CA — issuance, KRL, known-hosts
    # ------------------------------------------------------------------

    def _ssh_page(self):
        body = """
<h2>SSH Certificate Authority</h2>
<p>Issue short-lived SSH user and host certificates signed by this CA.</p>
<h3>Sign User Key</h3>
<form id='user-form'>
  <div style='margin-bottom:8px'>
    <label>Public key (authorized_keys format):</label><br>
    <textarea id='pubkey' rows='3' style='width:100%;font-family:monospace'></textarea>
  </div>
  <div style='margin-bottom:8px'>
    <label>Key ID (audit label):</label>
    <input id='key_id' type='text' style='width:100%'>
  </div>
  <div style='margin-bottom:8px'>
    <label>Principals (comma-separated):</label>
    <input id='principals' type='text' style='width:100%'>
  </div>
  <div style='margin-bottom:8px'>
    <label>Valid seconds (max 86400):</label>
    <input id='valid_seconds' type='number' value='3600' min='60' max='86400'>
  </div>
  <button class='btn' onclick='signUser(event)'>Sign User Cert</button>
</form>
<pre id='user-result' style='background:#111;color:#0f0;padding:12px;margin-top:12px;
  white-space:pre-wrap;display:none'></pre>
<h3 style='margin-top:24px'>Sign Host Key</h3>
<form id='host-form'>
  <div style='margin-bottom:8px'>
    <label>Public key:</label><br>
    <textarea id='host-pubkey' rows='3' style='width:100%;font-family:monospace'></textarea>
  </div>
  <div style='margin-bottom:8px'>
    <label>Key ID:</label>
    <input id='host-key_id' type='text' style='width:100%'>
  </div>
  <div style='margin-bottom:8px'>
    <label>Principals (hostnames, comma-separated):</label>
    <input id='host-principals' type='text' style='width:100%'>
  </div>
  <button class='btn' onclick='signHost(event)'>Sign Host Cert</button>
</form>
<pre id='host-result' style='background:#111;color:#0f0;padding:12px;margin-top:12px;
  white-space:pre-wrap;display:none'></pre>
<h3 style='margin-top:24px'>CA Known-Hosts Line</h3>
<button class='btn btn-outline' onclick='getKnownHosts()'>Get @cert-authority line</button>
<pre id='kh-result' style='background:#111;color:#0f0;padding:12px;margin-top:12px;
  white-space:pre-wrap;display:none'></pre>
<script>
async function signUser(e) {
  e.preventDefault();
  const p = document.getElementById('principals').value.split(',').map(s => s.trim()).filter(Boolean);
  const r = await fetch('/api/ssh/sign', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      public_key: document.getElementById('pubkey').value.trim(),
      key_id: document.getElementById('key_id').value.trim(),
      principals: p,
      valid_seconds: parseInt(document.getElementById('valid_seconds').value),
    })
  });
  const j = await r.json();
  const el = document.getElementById('user-result');
  el.style.display = 'block';
  el.textContent = j.certificate || j.error;
}
async function signHost(e) {
  e.preventDefault();
  const p = document.getElementById('host-principals').value.split(',').map(s => s.trim()).filter(Boolean);
  const r = await fetch('/api/ssh/host-cert', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      public_key: document.getElementById('host-pubkey').value.trim(),
      key_id: document.getElementById('host-key_id').value.trim(),
      principals: p,
    })
  });
  const j = await r.json();
  const el = document.getElementById('host-result');
  el.style.display = 'block';
  el.textContent = j.certificate || j.error;
}
async function getKnownHosts() {
  const r = await fetch('/api/ssh/known-hosts');
  const j = await r.json();
  const el = document.getElementById('kh-result');
  el.style.display = 'block';
  el.textContent = j.line || j.error;
}
</script>"""
        self._send_html(200, _page("SSH CA", body, "ssh"))

    def _api_ssh_sign(self, data: dict):
        """POST /api/ssh/sign — issue an SSH user certificate."""
        if not getattr(self.ca, "_ssh_enabled", False):
            self._send_json({"error": "SSH CA not enabled on this server"}, 503)
            return
        pubkey_str   = data.get("public_key", "")
        key_id       = data.get("key_id", "")
        principals   = data.get("principals", [])
        valid_seconds = int(data.get("valid_seconds", 3600))
        critical_opts = data.get("critical_options", {})
        extensions    = data.get("extensions")
        profile       = data.get("profile", "ssh_user")

        if not pubkey_str:
            self._send_json({"error": "public_key required"}, 400)
            return
        if not key_id:
            self._send_json({"error": "key_id required"}, 400)
            return

        try:
            cert_line = self.ca.issue_ssh_user_cert(
                public_key_str=pubkey_str,
                key_id=key_id,
                principals=principals,
                valid_seconds=valid_seconds,
                critical_options=critical_opts or None,
                extensions=extensions,
                profile_name=profile,
            )
            self._send_json({"certificate": cert_line})
        except Exception as exc:
            self._send_json({"error": str(exc)}, 400)

    def _api_ssh_host_cert(self, data: dict):
        """POST /api/ssh/host-cert — issue an SSH host certificate."""
        if not getattr(self.ca, "_ssh_enabled", False):
            self._send_json({"error": "SSH CA not enabled on this server"}, 503)
            return
        pubkey_str    = data.get("public_key", "")
        key_id        = data.get("key_id", "")
        principals    = data.get("principals", [])
        valid_seconds = int(data.get("valid_seconds", 2592000))
        profile       = data.get("profile", "ssh_host")

        if not pubkey_str:
            self._send_json({"error": "public_key required"}, 400)
            return
        if not key_id:
            self._send_json({"error": "key_id required"}, 400)
            return

        try:
            cert_line = self.ca.issue_ssh_host_cert(
                public_key_str=pubkey_str,
                key_id=key_id,
                principals=principals,
                valid_seconds=valid_seconds,
                profile_name=profile,
            )
            self._send_json({"certificate": cert_line})
        except Exception as exc:
            self._send_json({"error": str(exc)}, 400)

    def _api_ssh_krl(self, ca_fpr: str):
        """GET /api/ssh/krl/<ca-key-fpr> — download the current signed KRL."""
        if not getattr(self.ca, "_ssh_enabled", False):
            self._send_json({"error": "SSH CA not enabled"}, 503)
            return
        try:
            krl_bytes = self.ca.build_ssh_krl()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="krl"')
            self.send_header("Content-Length", str(len(krl_bytes)))
            self.end_headers()
            self.wfile.write(krl_bytes)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)

    def _api_ssh_known_hosts(self):
        """GET /api/ssh/known-hosts — CA public key in @cert-authority format."""
        if not getattr(self.ca, "_ssh_enabled", False):
            self._send_json({"error": "SSH CA not enabled"}, 503)
            return
        try:
            line = self.ca.ssh_known_hosts_line()
            self._send_json({"line": line})
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)

    def _api_ssh_list(self):
        """GET /api/ssh/certs — list issued SSH certificates."""
        if not getattr(self.ca, "_ssh_enabled", False):
            self._send_json({"error": "SSH CA not enabled"}, 503)
            return
        certs = self.ca.list_ssh_certs(include_revoked=True)
        self._send_json({"certs": certs})

    # ------------------------------------------------------------------
    # JSON API — service management
    # ------------------------------------------------------------------

    def _api_services_status(self):
        reg = self.service_registry or {}
        out = {}
        for name, entry in reg.items():
            if name.startswith("_"):
                continue
            out[name] = {
                "running":   entry.get("server") is not None,
                "available": entry.get("available", False),
                "url":       entry.get("url", ""),
                "config":    entry.get("config", {}),
            }
        self._send_json(out)

    def _api_service_action(self, path: str, data: dict):
        # path: /api/services/<name>/start|stop
        parts  = [p for p in path.split("/") if p]
        # ['api', 'services', '<name>', 'start'|'stop']
        if len(parts) != 4:
            self._send_json({"error": "invalid path"}, 400)
            return
        name, action = parts[2], parts[3]
        reg = self.service_registry
        if reg is None:
            self._send_json({"error": "service registry not available"}, 500)
            return
        if name not in reg or name.startswith("_"):
            self._send_json({"error": "unknown service: {}".format(name)}, 404)
            return
        if action == "stop":
            self._svc_stop(name)
        elif action == "start":
            self._svc_start(name, data)
        else:
            self._send_json({"error": "unknown action: {}".format(action)}, 400)

    def _svc_stop(self, name: str):
        entry = self.service_registry[name]
        srv   = entry.get("server")
        if srv is None:
            self._send_json({"ok": True, "note": "already stopped"})
            return
        try:
            srv.shutdown()
            srv.server_close()
        except Exception as e:
            logger.warning("Error shutting down %s: %s", name, e)
        entry["server"] = None
        entry["url"]    = ""
        self._update_url_attr(name, "")
        if self.audit_log:
            self.audit_log.record("service_stop", "service={}".format(name),
                                  self.client_address[0])
        logger.info("Service %s stopped via Web UI", name)
        self._send_json({"ok": True, "service": name})

    def _svc_start(self, name: str, cfg: dict):
        entry = self.service_registry[name]
        if not entry.get("available"):
            self._send_json({"error": "{} module not installed".format(name)}, 503)
            return
        # Stop existing instance first
        old_srv = entry.get("server")
        if old_srv:
            try:
                old_srv.shutdown()
                old_srv.server_close()
            except Exception:
                pass
            entry["server"] = None

        # Merge submitted config over saved defaults (ignore blanks)
        for k, v in cfg.items():
            if v != "" and v is not None:
                entry["config"][k] = v
        final = entry["config"]

        try:
            srv, url = self._launch_service(name, entry.get("bind_host", "0.0.0.0"), final)
        except Exception as e:
            logger.error("Failed to start %s: %s", name, e)
            self._send_json({"error": str(e)}, 500)
            return

        entry["server"] = srv
        entry["url"]    = url
        self._update_url_attr(name, url)
        if self.audit_log:
            self.audit_log.record("service_start",
                                  "service={} url={}".format(name, url),
                                  self.client_address[0])
        logger.info("Service %s started via Web UI → %s", name, url)
        self._send_json({"ok": True, "service": name, "url": url})

    def _launch_service(self, name: str, host: str, cfg: dict):
        """Start the named protocol service. Returns (server_object, url_string)."""
        mods        = (self.service_registry or {}).get("_modules", {})
        route_table = type(self).route_table
        prefix      = cfg.get("prefix", "/{}".format(name))

        # Replace 0.0.0.0/empty with localhost so generated URLs are clickable in a browser
        display_host = "localhost" if host in ("0.0.0.0", "") else host
        # Derive base URL from the dispatcher's address (stored on the class)
        dispatcher_url = getattr(type(self), "dispatcher_base_url", "http://{}:8080".format(display_host))

        if name == "cmp":
            use_v3 = cfg.get("protocol", "cmpv3") != "cmpv2"
            srv    = mods["cmp"].start_cmp_server(
                route_table=route_table, prefix=prefix, ca=self.ca, use_cmpv3=use_v3,
                audit_log=self.audit_log,
                rate_limiter=self.rate_limiter,
            )
            url = "{}/{}".format(dispatcher_url.rstrip("/"), prefix.lstrip("/"))

        elif name == "acme":
            base_url = cfg.get("base_url") or "{}/{}".format(
                dispatcher_url.rstrip("/"), prefix.lstrip("/"))
            srv = mods["acme"].start_acme_server(
                route_table=route_table, prefix=prefix, ca=self.ca,
                ca_dir=self.ca.ca_dir,
                auto_approve_dns=False,
                base_url=base_url,
                cert_validity_days=int(cfg.get("cert_days", 90)),
            )
            url = base_url.rstrip("/") + "/directory"

        elif name == "scep":
            srv = mods["scep"].start_scep_server(
                route_table=route_table, prefix=prefix, ca=self.ca,
                ca_dir=self.ca.ca_dir,
                challenge=cfg.get("challenge", ""),
            )
            url = "{}/{}".format(dispatcher_url.rstrip("/"), prefix.lstrip("/"))

        elif name == "est":
            srv = mods["est"].start_est_server(
                route_table=route_table, prefix=prefix, ca=self.ca,
                ca_dir=self.ca.ca_dir,
                require_auth=cfg.get("require_auth", "no") in ("yes", "true", True),
            )
            url = "{}/{}/.well-known/est".format(dispatcher_url.rstrip("/"), prefix.lstrip("/"))

        elif name == "ocsp":
            srv = mods["ocsp"].start_ocsp_server(
                route_table=route_table, prefix=prefix, ca=self.ca,
                cache_seconds=int(cfg.get("cache_seconds", 300)),
            )
            url = "{}/{}".format(dispatcher_url.rstrip("/"), prefix.lstrip("/"))

        elif name == "ipsec":
            srv = mods["ipsec"].start_ipsec_server(
                route_table=route_table, prefix=prefix, ca=self.ca,
                ocsp_url=cfg.get("ocsp_url", ""),
                crl_url=cfg.get("crl_url", ""),
            )
            url = "{}/{}".format(dispatcher_url.rstrip("/"), prefix.lstrip("/"))

        else:
            raise ValueError("unknown service: {}".format(name))

        return srv, url

    def _update_url_attr(self, name: str, url: str):
        """Sync class-level base-URL attributes so the dashboard reflects live state."""
        attr = {
            "cmp":   "cmp_base_url",
            "acme":  "acme_base_url",
            "scep":  "scep_base_url",
            "est":   "est_base_url",
            "ocsp":  "ocsp_base_url",
            "ipsec": "ipsec_base_url",
        }.get(name)
        if attr:
            setattr(type(self), attr, url)

    # ------------------------------------------------------------------
    # WireGuard PKI API handlers
    # ------------------------------------------------------------------

    def _wg_ca(self):
        import wireguard_ca as _wg
        return _wg.WireGuardCA(self.ca._pki_db, self.audit_log)

    def _api_wg_enroll_peer(self, data: dict):
        import wireguard_ca as _wg
        wg = self._wg_ca()
        peer_name   = data.get("peer_name", "unnamed")
        allowed_ips = data.get("allowed_ips", [])
        profile     = data.get("profile", "wg_user_vpn")
        public_key  = data.get("public_key") or None
        result = wg.enroll_peer(
            peer_name=peer_name,
            allowed_ips=allowed_ips,
            profile_name=profile,
            public_key=public_key,
            endpoint=data.get("endpoint"),
            persistent_keepalive=data.get("persistent_keepalive"),
            valid_seconds=data.get("valid_seconds"),
            server_ids=data.get("server_ids"),
            requester_ip=self.client_address[0],
        )
        self._send_json(result, 201)

    def _api_wg_register_server(self, data: dict):
        wg = self._wg_ca()
        result = wg.register_server(
            server_id=data.get("server_id", ""),
            public_key=data.get("public_key", ""),
            endpoint=data.get("endpoint", ""),
            listen_port=data.get("listen_port", 51820),
            network_cidr=data.get("network_cidr", "10.10.0.0/24"),
        )
        self._send_json(result, 201)

    def _api_wg_revoke_peer(self, peer_id: str):
        wg = self._wg_ca()
        ok = wg.revoke_peer(peer_id, requester_ip=self.client_address[0])
        if ok:
            self._send_json({"revoked": peer_id})
        else:
            self._send_json({"error": "peer not found"}, 404)

    def _api_wg_list_peers(self):
        wg = self._wg_ca()
        include_revoked = "include_revoked" in self.path
        self._send_json(wg.list_peers(include_revoked=include_revoked))

    def _api_wg_list_servers(self):
        self._send_json(self._wg_ca().list_servers())

    def _api_wg_server_config(self, server_id: str):
        wg = self._wg_ca()
        cfg = wg.get_server_config(server_id)
        if cfg is None:
            self._send_json({"error": "server not found"}, 404)
            return
        body = cfg.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # Matter PKI API handlers
    # ------------------------------------------------------------------

    def _matter_ca(self):
        import matter as _matter
        return _matter.MatterCA(self.ca._pki_db, self.ca, self.audit_log)

    def _api_matter_issue_dac(self, data: dict):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        mc = self._matter_ca()
        public_key = load_pem_public_key(data["public_key_pem"].encode())
        cert, pem_chain = mc.issue_dac(
            vendor_id=data["vendor_id"],
            product_id=data["product_id"],
            subject_serial=data.get("subject_serial", ""),
            public_key=public_key,
            pai_id=data.get("pai_id"),
            valid_years=data.get("valid_years", 10),
            requester_ip=self.client_address[0],
        )
        self._send_json({
            "cert_serial": format(cert.serial_number, "x"),
            "pem":         pem_chain,
        }, 201)

    def _api_matter_bulk_dac(self, data):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        import json as _json
        mc = self._matter_ca()
        if not isinstance(data, dict):
            self._send_json({"error": "body must be a JSON object with items[]"}, 400)
            return
        vendor_id  = data.get("vendor_id", "")
        product_id = data.get("product_id", "")
        pai_id     = data.get("pai_id")
        valid_years= data.get("valid_years", 10)
        items      = data.get("items", [])

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for result in mc.issue_dac_bulk(
            vendor_id, product_id, items,
            pai_id=pai_id, valid_years=valid_years,
            requester_ip=self.client_address[0],
        ):
            line = (_json.dumps(result) + "\n").encode()
            self.wfile.write(line)

    def _api_matter_issue_pai(self, data: dict):
        mc = self._matter_ca()
        import matter as _matter
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        # PAI uses a freshly generated P-256 key
        pai_key  = _ec.generate_private_key(_ec.SECP256R1())
        name     = data.get("name", "Matter PAI")
        vendor_id= data.get("vendor_id", "")
        product_ids = data.get("product_ids")
        valid_years = data.get("valid_years", 20)

        subject_name = _matter.build_pai_subject(vendor_id, name, product_ids)
        cert = self.ca.issue_certificate(
            subject_str=name,
            public_key=pai_key.public_key(),
            profile="matter_pai",
            subject_name=subject_name,
            is_ca=True,
            path_length=0,
            validity_days=valid_years * 365,
            crl_url="",
            ocsp_url="",
            ca_issuers_url="",
        )
        serial_hex = format(cert.serial_number, "x")
        from cryptography.hazmat.primitives import serialization
        not_after_ts = int(cert.not_valid_after_utc.timestamp())
        auth_id = mc.register_authority(
            name=name, role="pai",
            vendor_id=vendor_id,
            serial=serial_hex,
            not_after=not_after_ts,
            product_ids=product_ids,
        )
        pem_cert = cert.public_bytes(serialization.Encoding.PEM).decode()
        pem_key  = pai_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        self._send_json({
            "pai_id":      auth_id,
            "cert_serial": serial_hex,
            "cert_pem":    pem_cert,
            "private_key_pem": pem_key,
        }, 201)

    def _api_matter_list_authorities(self):
        self._send_json(self._matter_ca().list_authorities())

    def _api_matter_list_dacs(self):
        import urllib.parse as _up
        qs = dict(_up.parse_qsl(self.path.split("?", 1)[1] if "?" in self.path else ""))
        mc = self._matter_ca()
        self._send_json(mc.list_dacs(
            vendor_id=qs.get("vendor_id"),
            product_id=qs.get("product_id"),
        ))

    # ------------------------------------------------------------------
    # Low-level send helpers
    # ------------------------------------------------------------------

    def _send_html(self, code: int, html: str):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data, code: int = 200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # Code-signing portal API handlers
    # ------------------------------------------------------------------

    def _api_codesign_submit(self, data: dict):
        if self.codesign_service is None:
            self._send_json({"error": "Code-signing portal is not enabled"}, 503)
            return
        try:
            result = self.codesign_service.submit(
                artifacts=data.get("artifacts", []),
                attestations_b64=data.get("attestations", []),
                oidc_token=data.get("oidc_token", ""),
                requester_ip=self.client_address[0],
            )
            self._send_json(result, 201)
        except PermissionError as exc:
            self._send_json({"error": str(exc)}, 403)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)

    def _api_codesign_verify(self, digest: str):
        if self.codesign_service is None:
            self._send_json({"error": "Code-signing portal is not enabled"}, 503)
            return
        result = self.codesign_service.verify(digest)
        code = 200 if result["found"] else 404
        self._send_json(result, code)

    def _api_codesign_entry(self, entry_id: str):
        if self.codesign_service is None:
            self._send_json({"error": "Code-signing portal is not enabled"}, 503)
            return
        entry = self.codesign_service.get_entry(entry_id)
        if entry is None:
            self._send_json({"error": "entry not found"}, 404)
        else:
            self._send_json(entry)

    def _api_codesign_checkpoint(self):
        if self.codesign_service is None:
            self._send_json({"error": "Code-signing portal is not enabled"}, 503)
            return
        self._send_json(self.codesign_service.get_checkpoint())

    def _api_codesign_search(self):
        if self.codesign_service is None:
            self._send_json({"error": "Code-signing portal is not enabled"}, 503)
            return
        import urllib.parse as _up
        qs = dict(_up.parse_qsl(self.path.split("?", 1)[1] if "?" in self.path else ""))
        results = self.codesign_service.search(
            artifact_digest=qs.get("artifact-digest"),
            identity=qs.get("issuer"),  # 'issuer' param matches identity field
        )
        self._send_json({"entries": results})

    # ------------------------------------------------------------------
    # Infrastructure API handlers (no auth required)
    # ------------------------------------------------------------------

    def _api_health(self):
        """GET /api/health — health check (no auth)."""
        try:
            # Quick DB check
            self.ca._pki_db.fetchone("SELECT 1")
            status = "ok"
            code   = 200
        except Exception:
            status = "error"
            code   = 503
        import time as _time
        self._send_json({"status": status, "ca_name": str(self.ca.ca_dir)}, code)

    def _api_version(self):
        """GET /api/version — version metadata (no auth)."""
        import sys as _sys
        self._send_json({
            "version":     "1.0.0",
            "api_version": "1.0",
            "python":      _sys.version.split()[0],
        })

    def _api_openapi(self):
        """GET /api/openapi.json — serve OpenAPI spec (no auth)."""
        try:
            import openapi as _openapi
            body = _openapi.spec_json_pretty().encode()
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # POST /api/issue — issue a certificate (Terraform provider path)
    # ------------------------------------------------------------------

    def _api_issue(self, data: dict):
        """
        POST /api/issue — issue an end-entity certificate.

        Accepts either a subject string + optional SANs (server builds the
        cert) or a csr_pem (CSR-based — private key never leaves requester).
        """
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives.serialization import Encoding as _Enc
        import hashlib as _hashlib

        profile     = data.get("profile", "tls_server")
        validity    = data.get("validity_days", 90)
        csr_pem     = data.get("csr_pem")

        if csr_pem:
            # CSR-based issuance: extract public key and SANs from the CSR
            from cryptography.x509 import load_pem_x509_csr
            csr     = load_pem_x509_csr(csr_pem.encode())
            pub_key = csr.public_key()
            subject = csr.subject.rfc4514_string() or data.get("subject", "")
            san_dns = []
            san_ips = []
            san_uris= []
            try:
                san_ext = csr.extensions.get_extension_for_class(_x509.SubjectAlternativeName).value
                san_dns = [n.value for n in san_ext if isinstance(n, _x509.DNSName)]
                san_ips = [str(n.value) for n in san_ext if isinstance(n, _x509.IPAddress)]
                san_uris= [n.value for n in san_ext if isinstance(n, _x509.UniformResourceIdentifier)]
            except Exception:
                pass
        else:
            subject = data.get("subject", "")
            san_dns = data.get("san_dns", [])
            san_ips = data.get("san_ips", [])
            san_uris= data.get("san_uris", [])
            if not subject and not san_dns:
                self._send_json({"error": "subject or csr_pem required"}, 400)
                return
            # Generate an ephemeral key so the endpoint can work without CSR;
            # for production use csr_pem so the private key never leaves the client.
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            priv    = _ec.generate_private_key(_ec.SECP256R1())
            pub_key = priv.public_key()

        try:
            cert = self.ca.issue_certificate(
                subject_str  = subject,
                public_key   = pub_key,
                profile      = profile,
                validity_days= validity,
                san_dns      = san_dns or None,
                san_ips      = san_ips or None,
                san_uris     = san_uris or None,
                requester_ip = self.client_address[0],
            )
        except PermissionError as exc:
            self._send_json({"error": str(exc)}, 403)
            return
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)
            return

        der     = cert.public_bytes(_Enc.DER)
        pem     = cert.public_bytes(_Enc.PEM).decode()
        chain   = self.ca.ca_chain_pem.decode() if isinstance(self.ca.ca_chain_pem, bytes) else self.ca.ca_chain_pem
        fp      = _hashlib.sha256(der).hexdigest()

        self._send_json({
            "serial":            cert.serial_number,
            "cert_pem":          pem,
            "chain_pem":         chain,
            "fullchain_pem":     pem + chain,
            "not_before":        cert.not_valid_before_utc.isoformat(),
            "not_after":         cert.not_valid_after_utc.isoformat(),
            "sha256_fingerprint":fp,
        }, 201)

    def _send_raw(self, code: int, ctype: str, data: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------------------
# Integration entry point
# ---------------------------------------------------------------------------

def start_web_ui(
    route_table=None,
    prefix: str = "/",
    ca=None,
    audit_log=None,
    rate_limiter=None,
    # Authentication
    require_auth: bool = True,   # set False with --web-no-auth
    pam_service:  str  = "login",
    oidc_config=None,            # Optional[auth.OIDCConfig] — set for OIDC mode
    # Standalone mode: pass host + port instead of route_table + prefix
    host: str = None,
    port: int = None,
    # Base URL of the dispatcher (e.g. "http://localhost:8080") — used to
    # build clickable URLs in the Services page when launching a sub-service.
    dispatcher_base_url: str = "",
    # Currently-running base URLs (shown on dashboard)
    cmp_base_url:   str = "",
    acme_base_url:  str = "",
    scep_base_url:  str = "",
    est_base_url:   str = "",
    ocsp_base_url:  str = "",
    ipsec_base_url: str = "",
    # Running server objects (pass the return value of each start_*_server call).
    # None  → service shows as Stopped and can be started from the Services page.
    cmp_server=None,
    acme_server=None,
    scep_server=None,
    est_server=None,
    ocsp_server=None,
    ipsec_server=None,
    # Imported module objects — pass the module so the UI can start stopped services.
    # None  → service shows as "Not installed".
    cmp_module=None,
    acme_module=None,
    scep_module=None,
    est_module=None,
    ocsp_module=None,
    ipsec_module=None,
):
    """
    Register the Web UI handler with the shared route table.

    Standalone mode: pass *host* and *port* instead of *route_table* and
    *prefix*; a real ``ThreadingHTTPServer`` is started and returned.

    Pass the running server objects (*_server kwargs) so the Services page
    reflects which protocols are already active.

    Pass the imported module objects (*_module kwargs) to allow starting and
    stopping services live from the dashboard, without restarting the process.
    If a module is None the service card shows "Not installed".

    Returns a _RouteProxy (dispatcher mode) or a real HTTP server (standalone
    mode).  Both support ``.shutdown()``.
    """
    # Standalone mode: host + port provided
    if host is not None and port is not None:
        return _start_web_ui_standalone(
            host=host, port=port, ca=ca,
            audit_log=audit_log, rate_limiter=rate_limiter,
            require_auth=require_auth, pam_service=pam_service,
            oidc_config=oidc_config,
            cmp_module=cmp_module, acme_module=acme_module,
            scep_module=scep_module, est_module=est_module,
            ocsp_module=ocsp_module, ipsec_module=ipsec_module,
        )

    from dispatcher_server import _RouteProxy

    # bind_host is used by _launch_service — derive it from dispatcher_base_url
    # or fall back to "0.0.0.0" as a sensible default.
    bind_host = "0.0.0.0"

    def _entry(srv_obj, mod, url: str, default_prefix: str, extra: dict = None):
        cfg = {"prefix": default_prefix}
        if extra:
            cfg.update(extra)
        return {
            "server":    srv_obj,
            "available": mod is not None,
            "url":       url,
            "bind_host": bind_host,
            "config":    cfg,
        }

    service_registry: Dict[str, Any] = {
        "cmp":   _entry(cmp_server,   cmp_module,   cmp_base_url,   "/cmp"),
        "acme":  _entry(acme_server,  acme_module,  acme_base_url,  "/acme",
                        {"cert_days": 90}),
        "scep":  _entry(scep_server,  scep_module,  scep_base_url,  "/scep",
                        {"challenge": ""}),
        "est":   _entry(est_server,   est_module,   est_base_url,   "/est",
                        {"require_auth": "no"}),
        "ocsp":  _entry(ocsp_server,  ocsp_module,  ocsp_base_url,  "/ocsp",
                        {"cache_seconds": 300}),
        "ipsec": _entry(ipsec_server, ipsec_module, ipsec_base_url, "/ipsec",
                        {"ocsp_url": "", "crl_url": ""}),
        # Private slot for module references (not rendered as a service card)
        "_modules": {
            "cmp":   cmp_module,
            "acme":  acme_module,
            "scep":  scep_module,
            "est":   est_module,
            "ocsp":  ocsp_module,
            "ipsec": ipsec_module,
        },
    }

    class BoundWebUIHandler(WebUIHandler):
        pass

    # Update module-level flag so _page() knows whether to show Sign Out
    global _auth_enabled, _session_store
    _auth_enabled = require_auth

    # Upgrade session store to DB-backed once the CA DB is available
    if ca is not None:
        try:
            import auth as _auth_mod
            _session_store = _auth_mod.DbSessionStore(ca._pki_db)
            logger.info("Session store upgraded to DB-backed (sso_sessions)")
        except Exception as exc:
            logger.warning("Could not init DbSessionStore, using in-memory: %s", exc)

    # Set up OIDC if configured
    jwks_cache = None
    flow_key   = b""
    if oidc_config is not None and ca is not None:
        try:
            import auth as _auth_mod
            import secrets as _sec
            jwks_cache = _auth_mod.JWKSCache(ca._pki_db, oidc_config)
            jwks_cache.startup_load()
            # Derive flow cookie key from a stable random secret stored in CA dir
            key_file = ca.ca_dir / ".oidc_flow_key"
            if key_file.exists():
                flow_key = bytes.fromhex(key_file.read_text().strip())
            else:
                flow_key = _sec.token_bytes(32)
                key_file.write_text(flow_key.hex())
                key_file.chmod(0o600)
        except Exception as exc:
            logger.error("OIDC setup failed: %s", exc)

    BoundWebUIHandler.ca                  = ca
    BoundWebUIHandler.codesign_service    = None  # set separately via start_codesign
    BoundWebUIHandler.audit_log           = audit_log
    BoundWebUIHandler.rate_limiter        = rate_limiter
    BoundWebUIHandler.require_auth        = require_auth
    BoundWebUIHandler.pam_service         = pam_service
    BoundWebUIHandler.oidc_config         = oidc_config
    BoundWebUIHandler.jwks_cache          = jwks_cache
    BoundWebUIHandler.flow_cookie_key     = flow_key
    BoundWebUIHandler.cmp_base_url        = cmp_base_url   or ""
    BoundWebUIHandler.acme_base_url       = acme_base_url  or ""
    BoundWebUIHandler.scep_base_url       = scep_base_url  or ""
    BoundWebUIHandler.est_base_url        = est_base_url   or ""
    BoundWebUIHandler.ocsp_base_url       = ocsp_base_url  or ""
    BoundWebUIHandler.ipsec_base_url      = ipsec_base_url or ""
    BoundWebUIHandler.service_registry    = service_registry
    BoundWebUIHandler.route_table         = route_table
    BoundWebUIHandler.dispatcher_base_url = dispatcher_base_url or ""

    route_table.register(prefix, BoundWebUIHandler)
    logger.info("Web UI handler registered at prefix %r", prefix)
    return _RouteProxy(route_table, prefix, label="web_ui")


def _start_web_ui_standalone(
    host: str,
    port: int,
    ca,
    *,
    audit_log=None,
    rate_limiter=None,
    require_auth: bool = True,
    pam_service: str = "login",
    oidc_config=None,
    cmp_module=None,
    acme_module=None,
    scep_module=None,
    est_module=None,
    ocsp_module=None,
    ipsec_module=None,
):
    """Start a real standalone HTTP web UI server on host:port (backwards-compat mode)."""
    import http.server
    import threading

    service_registry: Dict[str, Any] = {
        "cmp":   {"server": None, "available": cmp_module is not None,   "url": "", "bind_host": host, "config": {"prefix": "/cmp"}},
        "acme":  {"server": None, "available": acme_module is not None,  "url": "", "bind_host": host, "config": {"prefix": "/acme"}},
        "scep":  {"server": None, "available": scep_module is not None,  "url": "", "bind_host": host, "config": {"prefix": "/scep"}},
        "est":   {"server": None, "available": est_module is not None,   "url": "", "bind_host": host, "config": {"prefix": "/est"}},
        "ocsp":  {"server": None, "available": ocsp_module is not None,  "url": "", "bind_host": host, "config": {"prefix": "/ocsp"}},
        "ipsec": {"server": None, "available": ipsec_module is not None, "url": "", "bind_host": host, "config": {"prefix": "/ipsec"}},
        "_modules": {
            "cmp": cmp_module, "acme": acme_module, "scep": scep_module,
            "est": est_module, "ocsp": ocsp_module, "ipsec": ipsec_module,
        },
    }

    class BoundHandler(WebUIHandler):
        pass

    global _auth_enabled, _session_store
    _auth_enabled = require_auth

    if ca is not None:
        try:
            import auth as _auth_mod
            _session_store = _auth_mod.DbSessionStore(ca._pki_db)
        except Exception:
            pass

    BoundHandler.ca               = ca
    BoundHandler.audit_log        = audit_log
    BoundHandler.rate_limiter     = rate_limiter
    BoundHandler.require_auth     = require_auth
    BoundHandler.pam_service      = pam_service
    BoundHandler.service_registry = service_registry
    BoundHandler.route_table      = None
    BoundHandler.dispatcher_base_url = ""
    BoundHandler.cmp_base_url  = ""
    BoundHandler.acme_base_url = ""
    BoundHandler.scep_base_url = ""
    BoundHandler.est_base_url  = ""
    BoundHandler.ocsp_base_url = ""
    BoundHandler.ipsec_base_url = ""

    srv = http.server.ThreadingHTTPServer((host, port), BoundHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info("Web UI standalone server started on %s:%d", host, srv.server_address[1])
    return srv
