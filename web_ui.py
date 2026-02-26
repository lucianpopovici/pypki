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
  - PKCS#12 / PFX bundle download (cert + key? No: cert + CA chain — key is never stored)
  - CA certificate and CRL download
  - Live config viewer and editor (calls PATCH /config internally)
  - Sub-CA issuance form
  - Audit log viewer
  - Rate limit status

All state comes from the shared CertificateAuthority and AuditLog objects.
"""

import datetime
import html
import hmac
import http.server
import json
import logging
import os
import re
import threading
import urllib.parse
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding

logger = logging.getLogger("web-ui")

__version__ = "0.9.0"


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

_CSS = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f4f6f9; color: #222; }
  .topbar { background: #1a2340; color: #fff; padding: 14px 28px; display: flex; align-items: center; gap: 16px; }
  .topbar h1 { font-size: 1.2rem; font-weight: 600; }
  .topbar .badge { background: #3b82f6; border-radius: 4px; padding: 2px 8px; font-size: .75rem; }
  .nav { background: #243055; padding: 0 28px; display: flex; gap: 0; }
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
  .btn-primary { background: #3b82f6; color: #fff; }
  .btn-danger  { background: #ef4444; color: #fff; }
  .btn-secondary { background: #e5e7eb; color: #374151; }
  .btn:hover { opacity: .88; }
  input, select, textarea { border: 1px solid #d1d5db; border-radius: 5px; padding: 7px 10px; font-size: .9rem; width: 100%; }
  label { display: block; font-size: .84rem; font-weight: 500; margin-bottom: 4px; color: #4b5563; }
  .form-row { margin-bottom: 14px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
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
  pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 6px; font-size: .83rem; overflow-x: auto; }
  @media(max-width:700px){ .stats-grid{grid-template-columns:1fr 1fr;} .grid-2{grid-template-columns:1fr;} }
</style>
"""

_JS = """
<script>
function revoke(serial) {
  if (!confirm('Revoke certificate serial ' + serial + '?')) return;
  fetch('/api/revoke', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serial: serial, reason: 0})})
    .then(r => r.json()).then(d => { location.reload(); });
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
  const cn = document.getElementById('subca-cn').value;
  const days = document.getElementById('subca-days').value;
  fetch('/api/issue-sub-ca', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({cn: cn, validity_days: parseInt(days)})})
    .then(r => r.json()).then(d => {
      document.getElementById('subca-result').textContent = JSON.stringify(d, null, 2);
    });
}
</script>
"""


def _page(title: str, body: str, active: str = "") -> str:
    nav_links = [
        ("Dashboard", "/", "dashboard"),
        ("Certificates", "/certs", "certs"),
        ("Expiring", "/expiring", "expiring"),
        ("Revocation", "/revocation", "revocation"),
        ("Sub-CA", "/sub-ca", "sub-ca"),
        ("Metrics", "/metrics-ui", "metrics-ui"),
        ("Config", "/config-ui", "config-ui"),
        ("Audit Log", "/audit", "audit"),
        ("API Docs", "/api-docs", "api-docs"),
    ]
    nav = "".join(
        f'<a href="{href}" class="{"active" if tag==active else ""}">{label}</a>'
        for label, href, tag in nav_links
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title} — PyPKI</title>
  {_CSS}
</head>
<body>
  <div class="topbar">
    <h1>🔐 PyPKI Certificate Authority</h1>
    <span class="badge">v{__version__}</span>
  </div>
  <nav class="nav">{nav}</nav>
  <div class="container">{body}</div>
  {_JS}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Web UI HTTP handler
# ---------------------------------------------------------------------------

class WebUIHandler(http.server.BaseHTTPRequestHandler):
    """Serves the HTML dashboard and a thin REST API used by the dashboard JS."""

    ca: "CertificateAuthority" = None
    audit_log: "AuditLog" = None
    rate_limiter: "RateLimiter" = None
    admin_api_key: Optional[str] = None   # If set, required for mutating endpoints
    admin_allowed_cns: Optional[list] = None  # mTLS CN allowlist
    cmp_base_url: str = "http://localhost:8080"
    acme_base_url: str = ""
    scep_base_url: str = ""
    est_base_url: str = ""
    ocsp_base_url: str = ""

    # POST endpoints that require admin auth
    _ADMIN_POST_PATHS = {"/api/revoke", "/api/renew", "/api/config", "/api/issue-sub-ca"}

    def _require_admin(self) -> bool:
        """Check admin auth. Returns True if allowed, False if denied (sends 403)."""
        if not self.admin_api_key and not self.admin_allowed_cns:
            return True  # No auth configured — allow (backward compat)

        # Check API key header
        if self.admin_api_key:
            provided = self.headers.get("X-Admin-Key", "")
            if provided and hmac.compare_digest(provided, self.admin_api_key):
                return True

        # Check mTLS client CN allowlist
        if self.admin_allowed_cns:
            # Try to extract CN from TLS peer cert if available
            try:
                peer_cert = self.connection.getpeercert()
                if peer_cert:
                    for rdn in peer_cert.get("subject", ()):
                        for attr_type, attr_value in rdn:
                            if attr_type == "commonName" and attr_value in self.admin_allowed_cns:
                                return True
            except Exception:
                pass

        body = json.dumps({"error": "admin authentication required"}).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def log_message(self, fmt, *args):
        logger.debug(f"WebUI {self.client_address[0]} - {fmt % args}")

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        try:
            # Dynamic routes: /api/certs/<serial>/<fmt>
            if path.startswith("/api/certs/"):
                parts = path.split("/")
                if len(parts) == 5:
                    try:
                        serial = int(parts[3])
                        fmt = parts[4]
                        if fmt in ("pem", "p12"):
                            self.do_GET_api_cert(serial, fmt)
                            return
                    except (ValueError, IndexError):
                        pass
                # Fall through to 404

            # CA certificate and CRL downloads
            elif path in ("/ca/cert.pem", "/ca/cert"):
                data = self.ca.ca_cert_pem
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pem-file")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            elif path == "/ca/crl":
                try:
                    data = self.ca.generate_crl()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/pkix-crl")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
                return

            # Static pages
            elif path == "/" or path == "/dashboard":
                self._dashboard()
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
            else:
                self._send_html(404, "<h2>404 Not found</h2>")
        except Exception as e:
            logger.error(f"WebUI GET error: {e}")
            self._send_html(500, f"<pre>Internal error: {e}</pre>")

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        self._handle_write(path)

    def do_PATCH(self):
        path = self.path.split("?")[0].rstrip("/")
        self._handle_write(path)

    def _handle_write(self, path: str):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError as e:
            self._send_json({"error": f"invalid JSON: {e}"}, 400)
            return

        # Require admin auth for mutating endpoints
        if path in self._ADMIN_POST_PATHS:
            # CSRF check: verify Origin or Referer header for browser requests
            origin = self.headers.get("Origin", "")
            referer = self.headers.get("Referer", "")
            content_type = self.headers.get("Content-Type", "")
            # Allow requests with API key (non-browser clients)
            has_api_key = bool(self.headers.get("X-Admin-Key", ""))
            if not has_api_key and "application/json" in content_type:
                # Browser fetch() with JSON — check Origin
                if origin and not origin.startswith(f"http://{self.headers.get('Host', '')}") and \
                   not origin.startswith(f"https://{self.headers.get('Host', '')}"):
                    self._send_json({"error": "CSRF check failed: invalid Origin"}, 403)
                    return
            if not self._require_admin():
                return

        try:
            if path == "/api/revoke":
                self._api_revoke(data)
            elif path == "/api/renew":
                self._api_renew(data)
            elif path == "/api/config":
                self._api_patch_config(data)
            elif path == "/api/issue-sub-ca":
                self._api_issue_sub_ca(data)
            else:
                self._send_json({"error": "not found"}, 404)
        except Exception as e:
            logger.error(f"WebUI POST error: {e}")
            self._send_json({"error": str(e)}, 500)

    # ------------------------------------------------------------------
    # Pages
    # ------------------------------------------------------------------

    def _dashboard(self):
        certs = self.ca.list_certificates()
        total = len(certs)
        revoked = sum(1 for c in certs if c["revoked"])
        now = datetime.datetime.now(datetime.timezone.utc)
        expired = sum(
            1 for c in certs
            if not c["revoked"] and datetime.datetime.fromisoformat(c["not_after"].replace("Z","+00:00") if c["not_after"].endswith("Z") else c["not_after"]).replace(tzinfo=datetime.timezone.utc) < now
        )
        active = total - revoked - expired

        stats = f"""
<div class="stats-grid">
  <div class="stat-box"><div class="val">{total}</div><div class="lbl">Total certificates</div></div>
  <div class="stat-box"><div class="val" style="color:#10b981">{active}</div><div class="lbl">Active</div></div>
  <div class="stat-box"><div class="val" style="color:#ef4444">{revoked}</div><div class="lbl">Revoked</div></div>
  <div class="stat-box"><div class="val" style="color:#f59e0b">{expired}</div><div class="lbl">Expired</div></div>
</div>"""

        ca_subject = html.escape(self.ca.ca_cert.subject.rfc4514_string())
        ca_expires = self.ca.ca_cert.not_valid_after_utc.strftime("%Y-%m-%d")
        ca_serial  = self.ca.ca_cert.serial_number

        endpoints = ""
        for label, url in [
            ("CMPv2/v3", self.cmp_base_url),
            ("ACME", self.acme_base_url),
            ("SCEP", self.scep_base_url),
            ("EST", self.est_base_url),
            ("OCSP", self.ocsp_base_url),
        ]:
            if url:
                endpoints += f"<tr><td><strong>{label}</strong></td><td><code>{url}</code></td></tr>"

        body = f"""
{stats}
<div class="card">
  <div class="card-head"><h2>Certificate Authority</h2>
    <a href="/ca/cert.pem" class="btn btn-secondary">Download CA Cert</a>
  </div>
  <div class="card-body">
    <table>
      <tr><th>Subject</th><td><code>{ca_subject}</code></td></tr>
      <tr><th>Serial</th><td><code>{ca_serial}</code></td></tr>
      <tr><th>Expires</th><td>{ca_expires}</td></tr>
    </table>
  </div>
</div>
<div class="card">
  <div class="card-head"><h2>Active Endpoints</h2></div>
  <div class="card-body"><table>{endpoints}</table></div>
</div>"""
        self._send_html(200, _page("Dashboard", body, "dashboard"))

    def _certs_page(self):
        certs = self.ca.list_certificates()
        now = datetime.datetime.now(datetime.timezone.utc)
        rows = ""
        for c in sorted(certs, key=lambda x: -x["serial"]):
            exp = datetime.datetime.fromisoformat(c["not_after"].replace("Z","+00:00") if c["not_after"].endswith("Z") else c["not_after"]).replace(tzinfo=datetime.timezone.utc)
            if c["revoked"]:
                status = '<span class="badge-rev">Revoked</span>'
                action = ""
            elif exp < now:
                status = '<span class="badge-exp">Expired</span>'
                action = ""
            else:
                status = '<span class="badge-ok">Active</span>'
                action = f'<button class="btn btn-danger" onclick="revoke({c["serial"]})">Revoke</button>'
            subj = html.escape(c["subject"])
            rows += f"""<tr>
              <td><code>{c["serial"]}</code></td>
              <td>{subj}</td>
              <td>{html.escape(c["not_before"][:10])}</td>
              <td>{html.escape(c["not_after"][:10])}</td>
              <td>{status}</td>
              <td>
                <a href="/api/certs/{c["serial"]}/pem" class="btn btn-secondary">PEM</a>
                <a href="/api/certs/{c["serial"]}/p12" class="btn btn-secondary">P12</a>
                {action}
              </td>
            </tr>"""

        body = f"""
<div class="card">
  <div class="card-head"><h2>Certificate Inventory ({len(certs)})</h2></div>
  <div class="card-body">
    <div class="search-bar">
      <input id="search" placeholder="Search by subject, serial…" oninput="applyFilter()">
    </div>
    <table>
      <thead><tr><th>Serial</th><th>Subject</th><th>Not Before</th><th>Not After</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>"""
        self._send_html(200, _page("Certificates", body, "certs"))

    def _revocation_page(self):
        crl_url = self.cmp_base_url + "/ca/crl"
        ocsp_url = self.ocsp_base_url + "/ocsp" if self.ocsp_base_url else "not configured"
        body = f"""
<div class="card">
  <div class="card-head"><h2>Revocation Infrastructure</h2></div>
  <div class="card-body">
    <table>
      <tr><th>CRL URL</th><td><code>{crl_url}</code> <a href="/ca/crl" class="btn btn-secondary">Download</a></td></tr>
      <tr><th>OCSP URL</th><td><code>{ocsp_url}</code></td></tr>
    </table>
  </div>
</div>
<div class="card">
  <div class="card-head"><h2>Revoke by Serial Number</h2></div>
  <div class="card-body">
    <div class="form-row"><label>Serial number</label><input id="rev-serial" placeholder="e.g. 1001"></div>
    <div class="form-row"><label>Reason</label>
      <select id="rev-reason">
        <option value="0">Unspecified</option>
        <option value="1">Key Compromise</option>
        <option value="2">CA Compromise</option>
        <option value="3">Affiliation Changed</option>
        <option value="4">Superseded</option>
        <option value="5">Cessation Of Operation</option>
      </select>
    </div>
    <button class="btn btn-danger" onclick="
      const s=parseInt(document.getElementById('rev-serial').value);
      const r=parseInt(document.getElementById('rev-reason').value);
      if(!s) return;
      fetch('/api/revoke',{{method:'POST',headers:{{'Content-Type':'application/json'}},
        body:JSON.stringify({{serial:s,reason:r}})}})
        .then(r=>r.json()).then(d=>{{
          document.getElementById('rev-result').textContent=JSON.stringify(d,null,2);
        }});
    ">Revoke</button>
    <pre id="rev-result" style="margin-top:14px;display:none"></pre>
    <script>document.getElementById('rev-result').style.display='block'</script>
  </div>
</div>"""
        self._send_html(200, _page("Revocation", body, "revocation"))

    def _subca_page(self):
        body = """
<div class="card">
  <div class="card-head"><h2>Issue Subordinate CA Certificate</h2></div>
  <div class="card-body">
    <p style="color:#6b7280;margin-bottom:16px;font-size:.88rem">
      Issuing a sub-CA allows you to delegate certificate issuance to a separate CA instance.
      The root CA key never needs to be online once sub-CAs are deployed.
    </p>
    <div class="grid-2">
      <div class="form-row"><label>Common Name</label>
        <input id="subca-cn" placeholder="Intermediate CA 1" value="PyPKI Intermediate CA">
      </div>
      <div class="form-row"><label>Validity (days)</label>
        <input id="subca-days" type="number" value="1825" min="1" max="7300">
      </div>
    </div>
    <button class="btn btn-primary" onclick="issueSubCA()">Issue Sub-CA Certificate</button>
    <p style="font-size:.8rem;color:#6b7280;margin-top:8px">
      The sub-CA certificate (DER) will be returned in the JSON response below.
    </p>
    <pre id="subca-result" style="margin-top:14px"></pre>
  </div>
</div>"""
        self._send_html(200, _page("Sub-CA Issuance", body, "sub-ca"))

    def _config_page(self):
        cfg = self.ca.config.as_dict() if self.ca.config else {}
        cfg_json = html.escape(json.dumps(cfg, indent=2))
        body = f"""
<div class="card">
  <div class="card-head"><h2>Live Configuration</h2></div>
  <div class="card-body">
    <pre>{cfg_json}</pre>
    <hr style="margin:18px 0">
    <h3 style="font-size:.95rem;margin-bottom:12px">Update Validity Periods</h3>
    <div class="grid-2">
      <div class="form-row"><label>End-entity cert days</label>
        <input id="ee_days" type="number" value="{cfg.get('validity',{}).get('end_entity_days',365)}">
      </div>
    </div>
    <button class="btn btn-primary" onclick="patchConfig()">Apply</button>
    <pre id="cfg-result" style="margin-top:14px"></pre>
  </div>
</div>"""
        self._send_html(200, _page("Configuration", body, "config-ui"))

    def _audit_page(self):
        events = []
        if self.audit_log:
            events = self.audit_log.recent(100)

        rows = ""
        for e in events:
            rows += f"<tr><td>{html.escape(e.get('ts','')[:19])}</td><td>{html.escape(e.get('event',''))}</td><td>{html.escape(e.get('detail',''))}</td><td>{html.escape(e.get('ip',''))}</td></tr>"

        body = f"""
<div class="card">
  <div class="card-head"><h2>Audit Log (last 100 events)</h2></div>
  <div class="card-body">
    <table>
      <thead><tr><th>Timestamp</th><th>Event</th><th>Detail</th><th>IP</th></tr></thead>
      <tbody>{rows if rows else '<tr><td colspan="4" style="color:#999">No events yet</td></tr>'}</tbody>
    </table>
  </div>
</div>"""
        self._send_html(200, _page("Audit Log", body, "audit"))

    def _expiring_page(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        rows = ""
        try:
            certs = self.ca.expiring_certificates(days_ahead=30)
        except AttributeError:
            # Fallback: compute from list_certificates
            all_certs = self.ca.list_certificates()
            certs = []
            for c in all_certs:
                if c.get("revoked"):
                    continue
                try:
                    exp = datetime.datetime.fromisoformat(
                        c["not_after"].replace("Z", "+00:00") if c["not_after"].endswith("Z") else c["not_after"]
                    ).replace(tzinfo=datetime.timezone.utc)
                    delta = (exp - now).days
                    if 0 <= delta <= 30:
                        certs.append({**c, "days_remaining": delta})
                except Exception:
                    pass

        for c in sorted(certs, key=lambda x: x.get("days_remaining", 9999)):
            days = c.get("days_remaining", "?")
            color = "#ef4444" if isinstance(days, int) and days <= 7 else "#f59e0b"
            action = f'<button class="btn btn-primary" onclick="renewCert({c["serial"]})">Renew</button>'
            rows += f"""<tr>
              <td><code>{c["serial"]}</code></td>
              <td>{html.escape(str(c["subject"]))}</td>
              <td>{html.escape(c.get("not_after","")[:10])}</td>
              <td style="color:{color};font-weight:600">{days}d</td>
              <td>{action}</td>
            </tr>"""

        renew_js = """
<script>
function renewCert(serial) {
  if (!confirm('Renew certificate serial ' + serial + '? A new certificate will be issued.')) return;
  fetch('/api/renew', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serial: serial})})
    .then(r => r.json()).then(d => {
      if (d.error) alert('Error: ' + d.error);
      else { alert('Renewed! New serial: ' + d.serial); location.reload(); }
    });
}
</script>"""

        body = f"""
<div class="card">
  <div class="card-head"><h2>Certificates Expiring Within 30 Days ({len(certs)})</h2></div>
  <div class="card-body">
    {'<table><thead><tr><th>Serial</th><th>Subject</th><th>Expires</th><th>Days Left</th><th>Action</th></tr></thead><tbody>' + rows + '</tbody></table>' if rows else '<p style="color:#6b7280">No certificates expiring within 30 days.</p>'}
  </div>
</div>{renew_js}"""
        self._send_html(200, _page("Expiring Certificates", body, "expiring"))

    def _metrics_page(self):
        try:
            raw = self.ca.metrics_prometheus()
        except AttributeError:
            raw = "# metrics_prometheus() not available on this CA object\n"
        except Exception as e:
            raw = f"# Error: {e}\n"

        body = f"""
<div class="card">
  <div class="card-head"><h2>Prometheus Metrics</h2>
    <a href="/api/metrics" class="btn btn-secondary">Raw /api/metrics</a>
  </div>
  <div class="card-body">
    <p style="color:#6b7280;font-size:.85rem;margin-bottom:12px">
      Compatible with <code>prometheus.io/scrape</code>. Scrape endpoint: <code>/api/metrics</code>
    </p>
    <pre>{html.escape(raw)}</pre>
  </div>
</div>"""
        self._send_html(200, _page("Prometheus Metrics", body, "metrics-ui"))

    def _api_docs_page(self):
        body = """
<div class="card">
  <div class="card-head"><h2>REST API Reference</h2></div>
  <div class="card-body">
    <table>
      <thead><tr><th>Method</th><th>Path</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>GET</td><td><code>/api/certs</code></td><td>List all certificates (JSON)</td></tr>
        <tr><td>GET</td><td><code>/api/certs/&lt;serial&gt;/pem</code></td><td>Download cert PEM</td></tr>
        <tr><td>GET</td><td><code>/api/certs/&lt;serial&gt;/p12</code></td><td>Download cert + CA chain as PKCS#12</td></tr>
        <tr><td>POST</td><td><code>/api/revoke</code></td><td>Revoke cert — body: {"serial": N, "reason": 0}</td></tr>
        <tr><td>POST</td><td><code>/api/renew</code></td><td>Renew cert — body: {"serial": N}</td></tr>
        <tr><td>GET</td><td><code>/api/config</code></td><td>View current config</td></tr>
        <tr><td>PATCH</td><td><code>/api/config</code></td><td>Update config — body: {"validity": {...}}</td></tr>
        <tr><td>POST</td><td><code>/api/issue-sub-ca</code></td><td>Issue sub-CA cert — body: {"cn": "...", "validity_days": N}</td></tr>
        <tr><td>GET</td><td><code>/api/audit</code></td><td>Audit log (JSON)</td></tr>
        <tr><td>GET</td><td><code>/api/metrics</code></td><td>Prometheus metrics (text/plain)</td></tr>
        <tr><td>GET</td><td><code>/ca/cert.pem</code></td><td>CA certificate (PEM)</td></tr>
        <tr><td>GET</td><td><code>/ca/crl</code></td><td>Certificate Revocation List (DER)</td></tr>
      </tbody>
    </table>
  </div>
</div>"""
        self._send_html(200, _page("API Docs", body, "api-docs"))

    # ------------------------------------------------------------------
    # JSON API handlers
    # ------------------------------------------------------------------

    def do_GET_api_cert(self, serial: int, fmt: str):
        """Download cert PEM or PKCS#12."""
        der = self.ca.get_cert_by_serial(serial)
        if not der:
            self._send_json({"error": "certificate not found"}, 404)
            return

        cert = None
        try:
            from cryptography import x509 as _x509
            cert = _x509.load_der_x509_certificate(der)
        except Exception:
            pass

        if fmt == "pem":
            if cert:
                pem = cert.public_bytes(Encoding.PEM)
            else:
                pem = der
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Disposition", f'attachment; filename="cert-{serial}.pem"')
            self.send_header("Content-Length", str(len(pem)))
            self.end_headers()
            self.wfile.write(pem)

        elif fmt == "p12":
            # PKCS#12 — cert + CA chain (no private key, key is not stored server-side)
            try:
                from cryptography.hazmat.primitives.serialization import pkcs12
                p12 = pkcs12.serialize_key_and_certificates(
                    name=b"pypki-cert",
                    key=None,
                    cert=cert,
                    cas=[self.ca.ca_cert],
                    encryption_algorithm=serialization.NoEncryption(),
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pkcs12")
                self.send_header("Content-Disposition", f'attachment; filename="cert-{serial}.p12"')
                self.send_header("Content-Length", str(len(p12)))
                self.end_headers()
                self.wfile.write(p12)
            except Exception as e:
                self._send_json({"error": f"PKCS#12 generation failed: {e}"}, 500)

        else:
            self._send_json({"error": f"unknown format: {fmt}. Use 'pem' or 'p12'."}, 400)

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

    def _api_metrics(self):
        try:
            text = self.ca.metrics_prometheus()
        except AttributeError:
            text = "# metrics_prometheus() not available\n"
        except Exception as e:
            text = f"# error: {e}\n"
        data = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8; version=0.0.4")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _api_certs(self):
        self._send_json({"certificates": self.ca.list_certificates()})

    def _api_get_config(self):
        cfg = self.ca.config.as_dict() if self.ca.config else {}
        self._send_json(cfg)

    def _api_revoke(self, data: dict):
        serial = data.get("serial")
        reason = data.get("reason", 0)
        if serial is None:
            self._send_json({"error": "serial required"}, 400)
            return
        ok = self.ca.revoke_certificate(int(serial), int(reason))
        if self.audit_log:
            self.audit_log.record("revoke", f"serial={serial} reason={reason}",
                                  self.client_address[0])
        self._send_json({"ok": ok, "serial": serial})

    def _api_patch_config(self, data: dict):
        if self.ca.config:
            result = self.ca.config.patch(data)
            self._send_json({"ok": True, "config": result})
        else:
            self._send_json({"error": "config not available"}, 500)

    def _api_issue_sub_ca(self, data: dict):
        cn = data.get("cn", "Intermediate CA")
        # Sanitize CN — only allow safe characters
        cn = re.sub(r'[^a-zA-Z0-9._\- ]', '_', cn)[:64]
        validity_days = int(data.get("validity_days", 1825))
        try:
            sub_ca_key, sub_ca_cert = self.ca.issue_sub_ca(cn, validity_days)
            cert_pem = sub_ca_cert.public_bytes(Encoding.PEM).decode()
            key_pem = sub_ca_key.private_bytes(
                Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ).decode()
            if self.audit_log:
                self.audit_log.record("issue_sub_ca", f"cn={cn} days={validity_days}",
                                      self.client_address[0])
            self._send_json({
                "ok": True,
                "serial": sub_ca_cert.serial_number,
                "subject": sub_ca_cert.subject.rfc4514_string(),
                "cert_pem": cert_pem,
                "key_pem": key_pem,
            })
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _api_audit(self):
        events = self.audit_log.recent(200) if self.audit_log else []
        self._send_json({"events": events})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send_html(self, code: int, html_content: str):
        body = html_content.encode()
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
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Integration entry point
# ---------------------------------------------------------------------------

def start_web_ui(
    host: str,
    port: int,
    ca: "CertificateAuthority",
    audit_log: Optional["AuditLog"] = None,
    rate_limiter: Optional["RateLimiter"] = None,
    cmp_base_url: str = "",
    acme_base_url: str = "",
    scep_base_url: str = "",
    est_base_url: str = "",
    ocsp_base_url: str = "",
    admin_api_key: Optional[str] = None,
    admin_allowed_cns: Optional[list] = None,
) -> http.server.HTTPServer:
    """Start the web UI in a background daemon thread."""

    class BoundWebUIHandler(WebUIHandler):
        pass

    BoundWebUIHandler.ca = ca
    BoundWebUIHandler.audit_log = audit_log
    BoundWebUIHandler.rate_limiter = rate_limiter
    BoundWebUIHandler.cmp_base_url = cmp_base_url
    BoundWebUIHandler.acme_base_url = acme_base_url
    BoundWebUIHandler.scep_base_url = scep_base_url
    BoundWebUIHandler.est_base_url = est_base_url
    BoundWebUIHandler.ocsp_base_url = ocsp_base_url
    BoundWebUIHandler.admin_api_key = admin_api_key
    BoundWebUIHandler.admin_allowed_cns = admin_allowed_cns

    import http.server as _hs

    class _ThreadedServer(_hs.ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = _ThreadedServer((host, port), BoundWebUIHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info(f"Web UI listening on http://{host}:{port}")
    return srv
