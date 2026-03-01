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
import threading
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger("web-ui")


# ---------------------------------------------------------------------------
# HTML / CSS / JS templates
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
    <span class="badge">v0.9.0</span>
  </div>
  <nav class="nav">{nav}</nav>
  <div class="container">{body}</div>
  {js}
</body>
</html>""".format(title=title, css=_CSS, nav=nav, body=body, js=_JS)


# ---------------------------------------------------------------------------
# Service definitions — shared between the page renderer and the API handler
# ---------------------------------------------------------------------------

# Each entry: (key, label, icon, rfc_label, description, default_port, fields)
# fields: list of (field_key, label, input_type, default_value, placeholder, extra_html_attrs)
_SERVICE_DEFS = [
    (
        "cmp", "CMPv2/v3", "\U0001f510", "RFC 4210/9480",
        "Certificate Management Protocol for embedded devices and IoT",
        8080,
        [
            ("port",     "Port",     "number", "8080", "8080",  'min="1" max="65535"'),
            ("protocol", "Protocol", "select", "cmpv3", "",     ""),
        ],
    ),
    (
        "acme", "ACME", "\U0001f916", "RFC 8555",
        "Automated Certificate Management for servers and workstations",
        8888,
        [
            ("port",      "Port",               "number", "8888", "8888", 'min="1" max="65535"'),
            ("base_url",  "Public base URL",     "text",   "",     "http://hostname:8888", ""),
            ("cert_days", "Cert validity (days)", "number","90",   "90",  'min="1" max="3650"'),
        ],
    ),
    (
        "scep", "SCEP", "\U0001f310", "RFC 8894",
        "Simple Certificate Enrolment Protocol for network devices and MDM",
        8889,
        [
            ("port",      "Port",               "number", "8889", "8889", 'min="1" max="65535"'),
            ("challenge", "Challenge password",  "text",   "",     "(leave blank = none)", ""),
        ],
    ),
    (
        "est", "EST", "\U0001f512", "RFC 7030",
        "Enrollment over Secure Transport for TLS-capable devices",
        8443,
        [
            ("port",         "Port",         "number", "8443", "8443", 'min="1" max="65535"'),
            ("require_auth", "Require auth", "select", "no",   "",     ""),
        ],
    ),
    (
        "ocsp", "OCSP", "\u2705", "RFC 6960",
        "Online Certificate Status Protocol revocation responder",
        8082,
        [
            ("port",          "Port",          "number", "8082", "8082", 'min="1" max="65535"'),
            ("cache_seconds", "Cache TTL (s)", "number", "300",  "300",  'min="1"'),
        ],
    ),
    (
        "ipsec", "IPsec PKI", "\U0001f6e1\ufe0f", "RFC 4945/4809",
        "VPN gateway and user certificate management",
        8085,
        [
            ("port",     "Port",     "number", "8085", "8085", 'min="1" max="65535"'),
            ("ocsp_url", "OCSP URL", "text",   "",     "http://host:8082/ocsp", ""),
            ("crl_url",  "CRL URL",  "text",   "",     "http://host:8080/ca/crl", ""),
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
    # Per-service base URLs (updated live when a service is started/stopped)
    cmp_base_url:   str = "http://localhost:8080"
    acme_base_url:  str = ""
    scep_base_url:  str = ""
    est_base_url:   str = ""
    ocsp_base_url:  str = ""
    ipsec_base_url: str = ""
    # Service registry dict — built in start_web_ui(), shared across instances
    service_registry: "Dict[str, Any]" = None

    def log_message(self, fmt, *args):
        logger.debug("WebUI %s - %s", self.client_address[0], fmt % args)

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        try:
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
        path   = self.path.split("?")[0].rstrip("/")
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length)
        try:
            data = json.loads(raw) if raw else {}
        except Exception:
            data = {}
        try:
            if path == "/api/revoke":
                self._api_revoke(data)
            elif path == "/api/renew":
                self._api_renew(data)
            elif path == "/api/config":
                self._api_patch_config(data)
            elif path == "/api/issue-sub-ca":
                self._api_issue_sub_ca(data)
            elif path.startswith("/api/services/"):
                self._api_service_action(path, data)
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
        for (name, label, icon, rfc, desc, default_port, fields) in _SERVICE_DEFS:
            entry   = reg.get(name, {})
            running = bool(entry.get("server"))
            avail   = entry.get("available", False)
            url     = entry.get("url", "")
            saved   = entry.get("config", {})
            if not saved.get("port"):
                saved["port"] = default_port

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
            "      fetch('/api/revoke',{method:'POST',"
            "        headers:{'Content-Type':'application/json'},"
            "        body:JSON.stringify({serial:s,reason:r})})"
            "        .then(r=>r.json()).then(d=>{"
            "          document.getElementById('rev-result').textContent=JSON.stringify(d,null,2);"
            "        });"
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
            "function renewCert(serial) {"
            "  if (!confirm('Renew cert ' + serial + '?')) return;"
            "  fetch('/api/renew', {method:'POST',"
            "    headers:{'Content-Type':'application/json'},"
            "    body: JSON.stringify({serial: serial})})"
            "    .then(r => r.json()).then(d => {"
            "      if (d.error) alert('Error: ' + d.error);"
            "      else { alert('Renewed! New serial: ' + d.serial); location.reload(); }"
            "    });"
            "}"
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
        # ['', 'api', 'certs', '<serial>', '<fmt>']
        if len(parts) == 5:
            try:
                serial = int(parts[3])
                fmt    = parts[4]
                if fmt in ("pem", "p12"):
                    self._api_cert_download(serial, fmt)
                    return
            except (ValueError, IndexError):
                pass
        self._send_json({"error": "not found"}, 404)

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
                from cryptography.hazmat.primitives.serialization import pkcs12
                from cryptography.hazmat.primitives.serialization import NoEncryption
                p12 = pkcs12.serialize_key_and_certificates(
                    name=b"pypki-cert", key=None, cert=cert,
                    cas=[self.ca.ca_cert],
                    encryption_algorithm=NoEncryption(),
                )
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
        cn           = data.get("cn", "Intermediate CA")
        validity_days = int(data.get("validity_days", 1825))
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding as _Enc, PrivateFormat, NoEncryption,
            )
            sub_ca_key, sub_ca_cert = self.ca.issue_sub_ca(cn, validity_days)
            cert_pem = sub_ca_cert.public_bytes(_Enc.PEM).decode()
            key_pem  = sub_ca_key.private_bytes(
                _Enc.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption(),
            ).decode()
            if self.audit_log:
                self.audit_log.record("issue_sub_ca",
                                      "cn={} days={}".format(cn, validity_days),
                                      self.client_address[0])
            self._send_json({
                "ok": True,
                "serial":  sub_ca_cert.serial_number,
                "subject": sub_ca_cert.subject.rfc4514_string(),
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
                "running":   bool(entry.get("server")),
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
        mods = (self.service_registry or {}).get("_modules", {})
        port = int(cfg.get("port", 0))
        if not port:
            raise ValueError("port is required")

        # Replace 0.0.0.0/empty with localhost so generated URLs are clickable in a browser
        display_host = "localhost" if host in ("0.0.0.0", "") else host

        if name == "cmp":
            use_v3 = cfg.get("protocol", "cmpv3") != "cmpv2"
            srv    = mods["cmp"].start_cmp_server(
                host=host, port=port, ca=self.ca, use_cmpv3=use_v3,
                audit_log=self.audit_log,
                rate_limiter=self.rate_limiter,
            )
            url = "http://{}:{}".format(display_host, port)

        elif name == "acme":
            base_url = cfg.get("base_url") or "http://{}:{}".format(display_host, port)
            srv = mods["acme"].start_acme_server(
                host=host, port=port, ca=self.ca,
                ca_dir=self.ca.ca_dir,
                auto_approve_dns=False,
                base_url=base_url,
                cert_validity_days=int(cfg.get("cert_days", 90)),
            )
            url = base_url.rstrip("/") + "/acme/directory"

        elif name == "scep":
            srv = mods["scep"].start_scep_server(
                host=host, port=port, ca=self.ca,
                ca_dir=self.ca.ca_dir,
                challenge=cfg.get("challenge", ""),
            )
            url = "http://{}:{}/scep".format(display_host, port)

        elif name == "est":
            srv = mods["est"].start_est_server(
                host=host, port=port, ca=self.ca,
                ca_dir=self.ca.ca_dir,
                require_auth=cfg.get("require_auth", "no") in ("yes", "true", True),
            )
            url = "https://{}:{}/.well-known/est".format(display_host, port)

        elif name == "ocsp":
            srv = mods["ocsp"].start_ocsp_server(
                host=host, port=port, ca=self.ca,
                cache_seconds=int(cfg.get("cache_seconds", 300)),
            )
            url = "http://{}:{}/ocsp".format(display_host, port)

        elif name == "ipsec":
            srv = mods["ipsec"].start_ipsec_server(
                host=host, port=port, ca=self.ca,
                ocsp_url=cfg.get("ocsp_url", ""),
                crl_url=cfg.get("crl_url", ""),
            )
            url = "https://{}:{}/ipsec".format(display_host, port)

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
    # Low-level send helpers
    # ------------------------------------------------------------------

    def _send_html(self, code: int, html: str):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data, code: int = 200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
    host: str,
    port: int,
    ca,
    audit_log=None,
    rate_limiter=None,
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
) -> http.server.HTTPServer:
    """
    Start the PyPKI web dashboard in a background daemon thread.

    New in this version
    -------------------
    Pass the running server objects (*_server kwargs) so the Services page
    reflects which protocols are already active.

    Pass the imported module objects (*_module kwargs) to allow starting and
    stopping services live from the dashboard, without restarting the process.
    If a module is None the service card shows "Not installed".

    All existing callers continue to work unchanged (new kwargs default to None).
    """

    def _entry(srv_obj, mod, url: str, default_port: int, extra: dict = None):
        cfg = {"port": default_port}
        if extra:
            cfg.update(extra)
        return {
            "server":    srv_obj,
            "available": mod is not None,
            "url":       url,
            "bind_host": host,
            "config":    cfg,
        }

    service_registry: Dict[str, Any] = {
        "cmp":   _entry(cmp_server,   cmp_module,   cmp_base_url,   8080),
        "acme":  _entry(acme_server,  acme_module,  acme_base_url,  8888,
                        {"cert_days": 90}),
        "scep":  _entry(scep_server,  scep_module,  scep_base_url,  8889,
                        {"challenge": ""}),
        "est":   _entry(est_server,   est_module,   est_base_url,   8443,
                        {"require_auth": "no"}),
        "ocsp":  _entry(ocsp_server,  ocsp_module,  ocsp_base_url,  8082,
                        {"cache_seconds": 300}),
        "ipsec": _entry(ipsec_server, ipsec_module, ipsec_base_url, 8085,
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

    BoundWebUIHandler.ca               = ca
    BoundWebUIHandler.audit_log        = audit_log
    BoundWebUIHandler.rate_limiter     = rate_limiter
    BoundWebUIHandler.cmp_base_url     = cmp_base_url  or ""
    BoundWebUIHandler.acme_base_url    = acme_base_url or ""
    BoundWebUIHandler.scep_base_url    = scep_base_url or ""
    BoundWebUIHandler.est_base_url     = est_base_url  or ""
    BoundWebUIHandler.ocsp_base_url    = ocsp_base_url or ""
    BoundWebUIHandler.ipsec_base_url   = ipsec_base_url or ""
    BoundWebUIHandler.service_registry = service_registry

    class _ThreadedServer(http.server.ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads      = True

    srv = _ThreadedServer((host, port), BoundWebUIHandler)
    t   = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info("Web UI listening on http://%s:%s", host, port)
    return srv
