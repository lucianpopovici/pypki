#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
PyPKI Self-Service Portal
=========================
Scope-restricted portal for end users to manage their own certificates.

Mounted at --portal-prefix (default: /portal).  Each user sees only
the certificates they own.  Renewal and self-revocation are gated by
CertProfile.portal_self_renew / CertProfile.portal_self_revoke.

Authorization model:
  - OIDC sessions → owner (oidc, idp_subject) + (oidc, identity/email)
  - PAM sessions  → owner (pam, username)
  - Token sessions→ owner (static, identity)
  - Static mappings: subject-DN regex → (kind, id), from --portal-owner-mapping-file

No admin endpoints are reachable through this handler.
"""

import http.server
import json
import logging
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("pypki.portal")

# ---------------------------------------------------------------------------
# Ownership functions
# ---------------------------------------------------------------------------

def resolve_owners(session, db) -> List[Tuple[str, str]]:
    """
    Return all (owner_kind, owner_id) pairs claimable by *session*.

    Works for DbSessionStore SessionRecord objects (auth_backend attribute)
    as well as plain strings (legacy PAM identity).
    """
    if session is None:
        return []

    owners: List[Tuple[str, str]] = []
    backend  = getattr(session, "auth_backend", "pam")
    identity = getattr(session, "identity", str(session))

    if backend == "oidc":
        sub = getattr(session, "idp_subject", None)
        if sub:
            owners.append(("oidc", sub))
        if identity and identity != sub:
            owners.append(("oidc", identity))
    elif backend in ("pam",):
        owners.append(("pam", identity))
    else:
        # token / unknown — treat identity as a static owner
        owners.append(("static", identity))

    # Always add a static entry so explicit grants via `link-account` work
    # regardless of auth backend.
    static_entry = ("static", identity)
    if static_entry not in owners:
        owners.append(static_entry)

    # Deduplicate preserving order
    seen: set = set()
    unique: List[Tuple[str, str]] = []
    for pair in owners:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)
    return unique


def tag_owner(db, serial: int, owner_kind: str, owner_id: str) -> None:
    """Associate an owner with a certificate (idempotent)."""
    db.execute(
        "INSERT OR IGNORE INTO cert_owners (serial, owner_kind, owner_id, granted_at) "
        "VALUES (?, ?, ?, ?)",
        (serial, owner_kind, owner_id, int(time.time())),
    )


def my_certs(owners: List[Tuple[str, str]], db, limit: int = 200) -> List[Dict]:
    """Return cert rows visible to any of the given (kind, id) owners."""
    if not owners:
        return []
    cond = " OR ".join(
        ["(o.owner_kind = ? AND o.owner_id = ?)"] * len(owners)
    )
    params: tuple = tuple(v for pair in owners for v in pair) + (limit,)
    rows = db.fetchall(
        f"""SELECT DISTINCT c.serial, c.subject, c.not_before, c.not_after,
                   c.profile, c.revoked, c.reason
            FROM certificates c
            JOIN cert_owners o ON o.serial = c.serial
            WHERE {cond}
            ORDER BY c.not_after DESC
            LIMIT ?""",
        params,
    )
    return [dict(row) for row in rows]


def my_cert_detail(serial: int, owners: List[Tuple[str, str]], db) -> Optional[Dict]:
    """Return a single cert row, or None if the user doesn't own it."""
    if not owners:
        return None
    cond = " OR ".join(
        ["(o.owner_kind = ? AND o.owner_id = ?)"] * len(owners)
    )
    params: tuple = (serial,) + tuple(v for pair in owners for v in pair)
    rows = db.fetchall(
        f"""SELECT DISTINCT c.serial, c.subject, c.not_before, c.not_after,
                   c.profile, c.revoked, c.reason, c.der
            FROM certificates c
            JOIN cert_owners o ON o.serial = c.serial
            WHERE c.serial = ? AND ({cond})""",
        params,
    )
    return dict(rows[0]) if rows else None


def apply_static_mappings(mappings: list, db) -> int:
    """
    Apply static subject-DN regex → owner mappings to all existing certs.

    Each mapping is a dict: {subject_regex, owner_kind, owner_id}.
    Returns the number of new ownership rows inserted.
    """
    rows = db.fetchall("SELECT serial, subject FROM certificates")
    count = 0
    for m in mappings:
        try:
            pat = re.compile(m["subject_regex"])
        except re.error as exc:
            logger.warning("Invalid subject_regex %r: %s", m["subject_regex"], exc)
            continue
        kind = m.get("owner_kind", "static")
        oid  = m.get("owner_id", "")
        if not oid:
            continue
        for row in rows:
            if pat.search(row["subject"] or ""):
                tag_owner(db, row["serial"], kind, oid)
                count += 1
    return count


def load_owner_mapping_file(path: str) -> list:
    """Load owner mappings from a JSON file. Returns list of mapping dicts."""
    try:
        return json.loads(Path(path).read_text()).get("mappings", [])
    except Exception as exc:
        logger.error("Failed to load owner mapping file %r: %s", path, exc)
        return []


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

_CSS = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f4f6f9; color: #222; }
  .topbar { background: #1a6340; color: #fff; padding: 14px 28px; display: flex; align-items: center; gap: 16px; }
  .topbar h1 { font-size: 1.2rem; font-weight: 600; }
  .topbar .badge { background: #2d9d65; border-radius: 4px; padding: 2px 8px; font-size: .75rem; }
  .nav { background: #1f7a4e; padding: 0 28px; display: flex; gap: 0; flex-wrap: wrap; }
  .nav a { color: #a7d9c0; text-decoration: none; padding: 10px 18px; display: block; font-size: .88rem; }
  .nav a:hover, .nav a.active { color: #fff; background: #1a6340; }
  .container { max-width: 1100px; margin: 28px auto; padding: 0 20px; }
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
  .btn-primary { background: #1a6340; color: #fff; }
  .btn-danger  { background: #ef4444; color: #fff; }
  .btn-secondary { background: #e5e7eb; color: #374151; }
  .btn:hover { opacity: .88; }
  .stat-box { background: #fff; border-radius: 8px; padding: 18px 22px; box-shadow: 0 1px 4px rgba(0,0,0,.07); }
  .stat-box .val { font-size: 2rem; font-weight: 700; color: #1a6340; }
  .stat-box .lbl { font-size: .82rem; color: #6b7280; margin-top: 4px; }
  .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 22px; }
  .alert { padding: 10px 16px; border-radius: 6px; margin-bottom: 14px; font-size: .88rem; }
  .alert-success { background: #d1fae5; color: #065f46; }
  .alert-error   { background: #fee2e2; color: #991b1b; }
  code { background: #f3f4f6; padding: 2px 6px; border-radius: 3px; font-size: .85rem; font-family: monospace; }
  dl.detail { display: grid; grid-template-columns: 160px 1fr; gap: 8px 16px; font-size: .88rem; }
  dt { font-weight: 600; color: #4b5563; }
  dd { word-break: break-all; }
  .form-row { margin-bottom: 14px; }
  label { display: block; font-size: .84rem; font-weight: 500; margin-bottom: 4px; color: #4b5563; }
  input, textarea { border: 1px solid #d1d5db; border-radius: 5px; padding: 7px 10px; font-size: .9rem; width: 100%; }
  @media(max-width:700px) { .stats-grid { grid-template-columns: 1fr; } }
</style>
"""


def _page(title: str, body: str, user: str, prefix: str) -> str:
    p = prefix.rstrip("/")
    nav_links = [
        (f"{p}/", "Dashboard"),
        (f"{p}/certs", "My Certificates"),
        (f"{p}/audit", "My Audit Log"),
    ]
    nav_html = "".join(
        f'<a href="{href}">{label}</a>' for href, label in nav_links
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PyPKI Portal — {title}</title>
  {_CSS}
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; img-src 'self' data:; script-src 'none'; style-src 'self' 'unsafe-inline'">
</head>
<body>
  <div class="topbar">
    <h1>PyPKI Portal</h1>
    <span class="badge">Self-service</span>
    <span style="margin-left:auto;font-size:.85rem">Signed in as <strong>{user}</strong>
      &nbsp;·&nbsp;<a href="/logout" style="color:#a7d9c0">Sign out</a></span>
  </div>
  <div class="nav">{nav_html}</div>
  <div class="container">{body}</div>
</body>
</html>"""


def _cert_status(row: dict) -> str:
    if row.get("revoked"):
        return '<span class="badge-rev">Revoked</span>'
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    if row.get("not_after", "") < now:
        return '<span class="badge-exp">Expired</span>'
    return '<span class="badge-ok">Valid</span>'


# ---------------------------------------------------------------------------
# Portal HTTP handler
# ---------------------------------------------------------------------------

class PortalHandler(http.server.BaseHTTPRequestHandler):
    """
    Serves the self-service portal.  Class-level attributes are set by
    start_portal() before the first request is served.
    """

    ca            = None    # CertificateAuthority
    audit_log     = None    # AuditLog | None
    session_store = None    # auth.DbSessionStore
    prefix: str   = "/portal"
    owner_mappings: list = []   # static mappings loaded from --portal-owner-mapping-file

    def log_message(self, fmt, *args):
        logger.debug("Portal %s - %s", self.client_address[0], fmt % args)

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def _get_session_token(self) -> Optional[str]:
        # Bearer token first
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            return auth_hdr[7:].strip() or None
        # Session cookie
        from auth import DbSessionStore
        cookie_header = self.headers.get("Cookie", "")
        name = DbSessionStore.COOKIE_NAME + "="
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(name):
                return part[len(name):]
        return None

    def _current_session(self):
        """Return a SessionRecord if authenticated, else None."""
        token = self._get_session_token()
        if not token or self.session_store is None:
            return None
        return self.session_store.validate_record(token)

    def _require_session(self):
        """Return session or send 401/redirect and return None."""
        session = self._current_session()
        if session:
            return session
        if self.path.startswith("/api/"):
            self._send_json({"error": "Unauthorized"}, 401)
        else:
            self._redirect("/login")
        return None

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    def _redirect(self, location: str, code: int = 302) -> None:
        self.send_response(code)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_html(self, code: int, html: str) -> None:
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data: Any, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # Route dispatch
    # ------------------------------------------------------------------

    def do_GET(self):
        raw_path = self.path.split("?")[0]
        # Strip portal prefix
        prefix = self.prefix.rstrip("/")
        if raw_path == prefix or raw_path == prefix + "/":
            path = "/"
        elif raw_path.startswith(prefix + "/"):
            path = raw_path[len(prefix):]
        else:
            self._send_html(404, "<h2>404 Not found</h2>")
            return

        try:
            session = self._require_session()
            if not session:
                return

            if path in ("/", ""):
                self._dashboard(session)
            elif path == "/certs":
                self._certs_list(session)
            elif path.startswith("/certs/"):
                serial_str = path[len("/certs/"):].split("/")[0]
                try:
                    serial = int(serial_str)
                except ValueError:
                    self._send_html(400, "<h2>Bad serial</h2>")
                    return
                self._cert_detail(session, serial)
            elif path == "/audit":
                self._audit_page(session)
            else:
                self._send_html(404, "<h2>404 Not found</h2>")
        except Exception as exc:
            logger.error("Portal GET error: %s", exc, exc_info=True)
            self._send_html(500, f"<pre>Internal error: {exc}</pre>")

    def do_POST(self):
        raw_path = self.path.split("?")[0]
        prefix = self.prefix.rstrip("/")
        if raw_path.startswith(prefix + "/"):
            path = raw_path[len(prefix):]
        else:
            self._send_html(404, "<h2>404 Not found</h2>")
            return

        try:
            session = self._require_session()
            if not session:
                return

            # /certs/<serial>/renew  or  /certs/<serial>/revoke
            m = re.match(r"^/certs/(\d+)/(renew|revoke)$", path)
            if m:
                serial = int(m.group(1))
                action = m.group(2)
                if action == "renew":
                    self._renew(session, serial)
                else:
                    self._revoke(session, serial)
                return

            self._send_html(404, "<h2>404 Not found</h2>")
        except Exception as exc:
            logger.error("Portal POST error: %s", exc, exc_info=True)
            self._send_html(500, f"<pre>Internal error: {exc}</pre>")

    # ------------------------------------------------------------------
    # Page handlers
    # ------------------------------------------------------------------

    def _dashboard(self, session) -> None:
        db = self.ca._pki_db
        owners = resolve_owners(session, db)
        certs = my_certs(owners, db)

        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        in_14d = time.strftime(
            "%Y-%m-%dT%H:%M:%S",
            time.gmtime(time.time() + 14 * 86400),
        )

        active = [c for c in certs if not c["revoked"] and c["not_after"] >= now]
        expiring = [c for c in active if c["not_after"] <= in_14d]
        revoked  = [c for c in certs if c["revoked"]]

        expiring_rows = "".join(
            f"<tr><td><a href='{self.prefix.rstrip('/')}/certs/{c['serial']}'>"
            f"<code>{c['serial']}</code></a></td>"
            f"<td>{c['subject'][:60]}</td>"
            f"<td>{c['not_after'][:10]}</td></tr>"
            for c in expiring[:5]
        )
        expiring_table = (
            f"<table><thead><tr><th>Serial</th><th>Subject</th><th>Expires</th></tr></thead>"
            f"<tbody>{expiring_rows}</tbody></table>"
            if expiring else "<p>No certificates expiring in the next 14 days.</p>"
        )

        body = f"""
        <div class="stats-grid">
          <div class="stat-box"><div class="val">{len(active)}</div><div class="lbl">Active certificates</div></div>
          <div class="stat-box"><div class="val">{len(expiring)}</div><div class="lbl">Expiring in 14 days</div></div>
          <div class="stat-box"><div class="val">{len(revoked)}</div><div class="lbl">Revoked</div></div>
        </div>
        <div class="card">
          <div class="card-head"><h2>Expiring soon</h2>
            <a class="btn btn-secondary" href="{self.prefix.rstrip('/')}/certs">All certificates</a>
          </div>
          <div class="card-body">{expiring_table}</div>
        </div>"""
        self._send_html(200, _page("Dashboard", body, session.identity, self.prefix))

    def _certs_list(self, session) -> None:
        db = self.ca._pki_db
        owners = resolve_owners(session, db)
        certs = my_certs(owners, db)

        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        rows_html = "".join(
            f"<tr>"
            f"<td><a href='{self.prefix.rstrip('/')}/certs/{c['serial']}'><code>{c['serial']}</code></a></td>"
            f"<td style='max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>{c['subject']}</td>"
            f"<td>{c['profile'] or 'default'}</td>"
            f"<td>{c['not_after'][:10]}</td>"
            f"<td>{_cert_status(c)}</td>"
            f"</tr>"
            for c in certs
        )
        table = (
            f"<table><thead><tr>"
            f"<th>Serial</th><th>Subject</th><th>Profile</th><th>Expires</th><th>Status</th>"
            f"</tr></thead><tbody>{rows_html}</tbody></table>"
            if certs else "<p>No certificates found for your identity.</p>"
        )
        body = f"""
        <div class="card">
          <div class="card-head"><h2>My Certificates ({len(certs)})</h2></div>
          <div class="card-body">{table}</div>
        </div>"""
        self._send_html(200, _page("My Certificates", body, session.identity, self.prefix))

    def _cert_detail(self, session, serial: int) -> None:
        db = self.ca._pki_db
        owners = resolve_owners(session, db)
        row = my_cert_detail(serial, owners, db)

        if row is None:
            self._send_html(404, "<h2>Certificate not found or not owned by you.</h2>")
            return

        profile_name = row.get("profile") or "default"
        prof = {}
        try:
            from pki_server import CertProfile
            prof = CertProfile.get(profile_name)
        except Exception:
            pass

        can_revoke = not row["revoked"] and prof.get("portal_self_revoke", True)
        can_renew  = not row["revoked"] and prof.get("portal_self_renew",  True)
        status     = _cert_status(row)
        p = self.prefix.rstrip("/")

        revoke_btn = (
            f"<form method='POST' action='{p}/certs/{serial}/revoke' style='display:inline'>"
            f"<button class='btn btn-danger' onclick=\"return confirm('Revoke this certificate?')\">Revoke</button></form>"
            if can_revoke else ""
        )
        renew_btn = (
            f"<form method='POST' action='{p}/certs/{serial}/renew' style='display:inline'>"
            f"<button class='btn btn-primary'>Renew (same key)</button></form>"
            if can_renew else ""
        )

        body = f"""
        <div class="card">
          <div class="card-head">
            <h2>Certificate <code>{serial}</code></h2>
            <div style="display:flex;gap:8px">{renew_btn} {revoke_btn}</div>
          </div>
          <div class="card-body">
            <dl class="detail">
              <dt>Status</dt><dd>{status}</dd>
              <dt>Subject</dt><dd><code>{row['subject']}</code></dd>
              <dt>Profile</dt><dd>{profile_name}</dd>
              <dt>Not Before</dt><dd>{row['not_before']}</dd>
              <dt>Not After</dt><dd>{row['not_after']}</dd>
              {'<dt>Revoked at</dt><dd>' + (row.get("revoked_at","") or "—") + '</dd>' if row["revoked"] else ""}
            </dl>
            <div style="margin-top:16px">
              <a class="btn btn-secondary" href="{p}/certs">&#8592; Back</a>
            </div>
          </div>
        </div>"""
        self._send_html(200, _page(f"Cert {serial}", body, session.identity, self.prefix))

    def _audit_page(self, session) -> None:
        db = self.ca._pki_db
        identity = session.identity
        try:
            rows = db.fetchall(
                "SELECT event, detail, timestamp FROM audit_log "
                "WHERE detail LIKE ? ORDER BY timestamp DESC LIMIT 100",
                (f"%user={identity}%",),
            )
        except Exception:
            rows = []

        rows_html = "".join(
            f"<tr><td>{r['timestamp']}</td><td>{r['event']}</td>"
            f"<td style='max-width:400px;font-size:.8rem'>{r['detail']}</td></tr>"
            for r in rows
        )
        table = (
            f"<table><thead><tr><th>Time</th><th>Event</th><th>Detail</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table>"
            if rows else "<p>No audit events found for your identity.</p>"
        )
        body = f"""
        <div class="card">
          <div class="card-head"><h2>My Audit Log</h2></div>
          <div class="card-body">{table}</div>
        </div>"""
        self._send_html(200, _page("My Audit Log", body, session.identity, self.prefix))

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _renew(self, session, serial: int) -> None:
        db = self.ca._pki_db
        owners = resolve_owners(session, db)
        row = my_cert_detail(serial, owners, db)
        ip = self.client_address[0]

        if row is None:
            self._send_html(403, "<h2>Not authorized or cert not found.</h2>")
            return

        profile_name = row.get("profile") or "default"
        try:
            from pki_server import CertProfile
            prof = CertProfile.get(profile_name)
        except Exception:
            prof = {}

        if not prof.get("portal_self_renew", True):
            self._send_html(403, "<h2>Self-service renewal is not permitted for this certificate profile.</h2>")
            return

        if row["revoked"]:
            self._send_html(400, "<h2>Cannot renew a revoked certificate.</h2>")
            return

        try:
            # Load the existing cert to extract the public key
            from cryptography.x509 import load_der_x509_certificate
            der = db.fetchone("SELECT der FROM certificates WHERE serial = ?", (serial,))
            if der is None:
                self._send_html(500, "<h2>Certificate DER not found.</h2>")
                return
            existing_cert = load_der_x509_certificate(bytes(der["der"]))
            pub_key = existing_cert.public_key()

            # Issue new cert with same subject + public key
            new_cert = self.ca.issue_certificate(
                subject=row["subject"],
                public_key=pub_key,
                profile=profile_name,
                protocol="portal",
                requester_ip=ip,
            )
            new_serial = new_cert.serial_number

            # Tag the new cert with the same owners
            for kind, oid in owners:
                tag_owner(db, new_serial, kind, oid)

            # Revoke the predecessor with reason superseded (4)
            self.ca.revoke_certificate(serial, reason=4)

            if self.audit_log:
                try:
                    self.audit_log.record(
                        "portal.renew",
                        f"user={session.identity} old_serial={serial} new_serial={new_serial}",
                        ip,
                    )
                except Exception:
                    pass

            logger.info("Portal renewal: user=%s serial=%s → %s", session.identity, serial, new_serial)
            p = self.prefix.rstrip("/")
            self._redirect(f"{p}/certs/{new_serial}", 303)
        except Exception as exc:
            logger.error("Portal renewal failed: %s", exc, exc_info=True)
            self._send_html(500, f"<h2>Renewal failed: {exc}</h2>")

    def _revoke(self, session, serial: int) -> None:
        db = self.ca._pki_db
        owners = resolve_owners(session, db)
        row = my_cert_detail(serial, owners, db)
        ip = self.client_address[0]

        if row is None:
            self._send_html(403, "<h2>Not authorized or cert not found.</h2>")
            return

        profile_name = row.get("profile") or "default"
        try:
            from pki_server import CertProfile
            prof = CertProfile.get(profile_name)
        except Exception:
            prof = {}

        if not prof.get("portal_self_revoke", True):
            self._send_html(403, "<h2>Self-service revocation is not permitted for this certificate profile.</h2>")
            return

        if row["revoked"]:
            self._send_html(400, "<h2>Certificate is already revoked.</h2>")
            return

        try:
            self.ca.revoke_certificate(serial, reason=0)  # unspecified

            if self.audit_log:
                try:
                    self.audit_log.record(
                        "portal.revoke",
                        f"user={session.identity} serial={serial}",
                        ip,
                    )
                except Exception:
                    pass

            logger.info("Portal revocation: user=%s serial=%s", session.identity, serial)
            p = self.prefix.rstrip("/")
            self._redirect(f"{p}/certs", 303)
        except Exception as exc:
            logger.error("Portal revocation failed: %s", exc, exc_info=True)
            self._send_html(500, f"<h2>Revocation failed: {exc}</h2>")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def start_portal(
    route_table=None,
    prefix: str = "/portal",
    ca=None,
    audit_log=None,
    owner_mapping_file: str = "",
):
    """
    Register the portal handler with the shared route table.

    Parameters
    ----------
    route_table         : Dispatcher route table (from dispatcher_server.py)
    prefix              : URL prefix (default: /portal)
    ca                  : CertificateAuthority instance
    audit_log           : AuditLog instance (optional)
    owner_mapping_file  : Path to a JSON owner-mapping file (optional)
    """
    from dispatcher_server import _RouteProxy

    class BoundPortalHandler(PortalHandler):
        pass

    # Build a per-portal DbSessionStore pointing at the same CA DB
    session_store = None
    if ca is not None:
        try:
            from auth import DbSessionStore
            session_store = DbSessionStore(ca._pki_db)
        except Exception as exc:
            logger.warning("Could not init portal DbSessionStore: %s", exc)

    # Load and apply static owner mappings
    mappings: list = []
    if owner_mapping_file and ca is not None:
        mappings = load_owner_mapping_file(owner_mapping_file)
        if mappings:
            n = apply_static_mappings(mappings, ca._pki_db)
            logger.info("Portal: applied %d static ownership rows from %s", n, owner_mapping_file)

    BoundPortalHandler.ca            = ca
    BoundPortalHandler.audit_log     = audit_log
    BoundPortalHandler.session_store = session_store
    BoundPortalHandler.prefix        = prefix
    BoundPortalHandler.owner_mappings = mappings

    route_table.register(prefix, BoundPortalHandler)
    logger.info("Portal registered at prefix %r", prefix)
    return _RouteProxy(route_table, prefix, label="portal")
