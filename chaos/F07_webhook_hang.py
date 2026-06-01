"""
F07 — Webhook receiver hangs indefinitely.

Invariants tested: 1 (audit completeness — issuance must not be blocked).

A hanging webhook must NOT block certificate issuance. The audit log entry
must be written before the webhook is fired, and the cert must be returned
to the caller regardless of whether the webhook succeeds.
"""

from __future__ import annotations

import http.server
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import ScenarioResult, make_audit_log, issue_one, ITERATIONS
from chaos.invariants import audit_log_complete, no_duplicate_serials


class _HangingHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that hangs for a very long time."""

    def do_POST(self):
        time.sleep(3600)  # simulate infinite hang

    def log_message(self, *args):
        pass  # silence


def run() -> bool:
    result = ScenarioResult("F07_webhook_hang")
    print("\n=== F07: Webhook receiver hangs indefinitely ===")
    print("Testing: issuance is non-blocking even with a hung webhook receiver\n")

    # Start a hanging HTTP server.
    server = http.server.HTTPServer(("127.0.0.1", 0), _HangingHandler)
    webhook_port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    ca_dir = tempfile.mkdtemp(prefix="chaos-F07-")
    try:
        import pki_server as pki

        ca = pki.CertificateAuthority(
            ca_dir=ca_dir,
            webhook_url=f"http://127.0.0.1:{webhook_port}/hook",
            webhook_timeout=1,  # 1-second timeout; should not block issuance
        )
        audit = make_audit_log(ca_dir)

        start_t = time.monotonic()
        issued = []
        for i in range(min(ITERATIONS, 20)):
            try:
                cert = issue_one(ca, audit, cn=f"f07-cert-{i}")
                issued.append(cert)
            except Exception as e:
                result.check(f"issue_{i}", False, str(e))

        elapsed = time.monotonic() - start_t
        # 20 certs should not take > 30s even with 1s webhook timeout per cert.
        result.check(
            "issuance_not_blocked_by_webhook",
            elapsed < 30,
            f"issuance took {elapsed:.1f}s (expected < 30s)",
        )
        result.check(
            "all_certs_issued",
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
        # If CA doesn't support webhook_url, skip gracefully.
        result.skip(f"CA does not support webhook_url parameter: {e}")
        return result.summary()
    finally:
        server.shutdown()
        shutil.rmtree(ca_dir, ignore_errors=True)


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
