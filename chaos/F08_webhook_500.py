"""
F08 — Webhook receiver returns 500 repeatedly.

Invariants tested: 1 (audit completeness), 7 (durability).

A webhook receiver that always returns HTTP 500 must not block or abort
certificate issuance.  The cert and audit entry must be durable regardless
of delivery outcome.

The dispatcher retries deliveries with exponential backoff, but these retries
run on a background daemon thread — they must not affect the issuance return
time.  We check:
  1. All certs were issued (delivery failures didn't abort issuance).
  2. Issuance completed fast (not synchronously waiting for delivery retries).
  3. At least one delivery was attempted (the dispatcher is actually firing).
  4. DB invariants hold.
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


class _Error500Handler(http.server.BaseHTTPRequestHandler):
    request_count = 0
    _lock = threading.Lock()

    def do_POST(self):
        with _Error500Handler._lock:
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

    _Error500Handler.request_count = 0
    server = http.server.HTTPServer(("127.0.0.1", 0), _Error500Handler)
    webhook_port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    ca_dir = tempfile.mkdtemp(prefix="chaos-F08-")
    try:
        import pki_server as pki
        import hooks as hooks_mod

        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = make_audit_log(ca_dir)

        webhook_timeout = 2  # seconds per HTTP request
        dispatcher = hooks_mod.WebhookDispatcher(
            urls=[f"http://127.0.0.1:{webhook_port}/hook"],
            timeout=webhook_timeout,
        )
        dispatcher.start()
        ca._webhook = dispatcher

        n_certs = min(ITERATIONS, 10)
        t0 = time.monotonic()

        issued = []
        for i in range(n_certs):
            try:
                cert = issue_one(ca, audit, cn=f"f08-cert-{i}")
                issued.append(cert)
            except Exception as e:
                result.check(f"issue_{i}", False, str(e))

        issuance_elapsed = time.monotonic() - t0

        result.check(
            "all_certs_issued_despite_500",
            len(issued) == n_certs,
            f"only {len(issued)}/{n_certs} issued",
        )
        result.check(
            "issuance_not_blocked_by_delivery_retries",
            issuance_elapsed < webhook_timeout,
            f"issuance took {issuance_elapsed:.2f}s — expected < {webhook_timeout}s "
            f"(would be much longer if blocking on delivery retries)",
        )

        # Let the dispatcher attempt at least the first delivery for each cert.
        # The 500 response arrives in < 1ms, so 1 second is more than enough
        # for first-attempt deliveries to complete.
        time.sleep(1)

        with _Error500Handler._lock:
            attempts = _Error500Handler.request_count
        result.check(
            "webhook_deliveries_attempted",
            attempts > 0,
            "dispatcher made no webhook delivery attempts",
        )
        print(f"  [info] webhook delivery attempts so far: {attempts}")

        # Stop the dispatcher (don't wait for all retries — daemon thread).
        ca._webhook = None
        dispatcher.stop(timeout=0.1)
        del ca, audit

        pki_db = Path(ca_dir) / "certificates.db"
        ok1, msg1 = audit_log_complete.check(pki_db, Path(ca_dir) / "audit.db")
        result.check("audit_log_complete", ok1, msg1)

        ok2, msg2 = no_duplicate_serials.check(pki_db)
        result.check("no_duplicate_serials", ok2, msg2)

        server.shutdown()
        return result.summary()
    finally:
        server.shutdown()
        shutil.rmtree(ca_dir, ignore_errors=True)


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
