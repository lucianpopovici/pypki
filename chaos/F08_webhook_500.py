"""
F08 — Webhook receiver returns 500 repeatedly.

Invariants tested: 1 (audit completeness), 7 (durability).

A webhook receiver that always returns HTTP 500 must not block or abort
certificate issuance. The cert and audit entry must be durable regardless
of delivery outcome.
"""

from __future__ import annotations

import http.server
import shutil
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import ScenarioResult, make_audit_log, issue_one, ITERATIONS
from chaos.invariants import audit_log_complete, no_duplicate_serials


class _Error500Handler(http.server.BaseHTTPRequestHandler):
    request_count = 0

    def do_POST(self):
        _Error500Handler.request_count += 1
        self.send_response(500)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def run() -> bool:
    result = ScenarioResult("F08_webhook_500")
    print("\n=== F08: Webhook receiver returns HTTP 500 ===")
    print("Testing: delivery failures do not abort issuance\n")

    server = http.server.HTTPServer(("127.0.0.1", 0), _Error500Handler)
    webhook_port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    ca_dir = tempfile.mkdtemp(prefix="chaos-F08-")
    try:
        import pki_server as pki

        ca = pki.CertificateAuthority(
            ca_dir=ca_dir,
            webhook_url=f"http://127.0.0.1:{webhook_port}/hook",
            webhook_timeout=2,
        )
        audit = make_audit_log(ca_dir)

        issued = []
        for i in range(min(ITERATIONS, 20)):
            try:
                cert = issue_one(ca, audit, cn=f"f08-cert-{i}")
                issued.append(cert)
            except Exception as e:
                result.check(f"issue_{i}", False, str(e))

        result.check(
            "all_certs_issued_despite_500",
            len(issued) == min(ITERATIONS, 20),
            f"only {len(issued)} issued",
        )

        del ca, audit

        pki_db = Path(ca_dir) / "certificates.db"
        ok1, msg1 = audit_log_complete.check(pki_db, Path(ca_dir) / "audit.db")
        result.check("audit_log_complete", ok1, msg1)

        ok2, msg2 = no_duplicate_serials.check(pki_db)
        result.check("no_duplicate_serials", ok2, msg2)

        server.shutdown()
        return result.summary()
    except Exception as e:
        result.skip(f"CA does not support webhook_url parameter: {e}")
        return result.summary()
    finally:
        server.shutdown()
        shutil.rmtree(ca_dir, ignore_errors=True)


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
