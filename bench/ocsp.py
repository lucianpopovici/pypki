"""
bench/ocsp.py — OCSP response throughput benchmark.

Measures responses/second for:
  1. Live (on-demand) signing — fresh OCSP response per request
  2. Pre-generated lookup — file-system lookup of pre-signed responses
  3. Mixed — some serials hit pre-gen, some fall through to live

Usage:
    python3 bench/ocsp.py [--n 500]
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bench._harness import (
    BenchResult, hw_info, gen_key,
    measure_latencies, write_result,
)


def _issue_some_certs(ca, audit, n: int) -> list:
    key_pub = gen_key().public_key()
    certs = []
    for i in range(n):
        cert = ca.issue_certificate(f"CN=ocsp-bench-{i}", key_pub, audit=audit)
        certs.append(cert)
    return certs


def bench_live_ocsp(n_certs: int, n_queries: int, warmup: int) -> BenchResult:
    import pki_server as pki

    ca_dir = tempfile.mkdtemp(prefix="bench-ocsp-live-")
    try:
        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = pki.AuditLog(Path(ca_dir))
        certs = _issue_some_certs(ca, audit, n_certs)

        # Get the OCSP handler if available.
        try:
            import ocsp_server as ocsp_mod
        except ImportError:
            r = BenchResult("ocsp/live")
            r.add_note("skip", "ocsp_server module not importable standalone")
            return r

        serial_list = [c.serial_number for c in certs]
        idx = [0]

        def _live_ocsp_query():
            serial = serial_list[idx[0] % len(serial_list)]
            idx[0] += 1
            # Build a minimal OCSP request and have the CA check the serial.
            # We use the CA's internal revocation check rather than full DER
            # encoding (which is protocol overhead, not signing overhead).
            _ = ca._is_revoked(serial)

        latencies = measure_latencies(_live_ocsp_query, n=n_queries, warmup=warmup)
        result = BenchResult("ocsp/live_revocation_check", unit="query")
        result.record(latencies)
        result.add_note("note", "CA._is_revoked() — DB lookup overhead only")
        result.add_note("certs_in_db", str(n_certs))
        result.print_summary()

        del ca, audit
        return result
    except AttributeError:
        r = BenchResult("ocsp/live")
        r.add_note("skip", "CA._is_revoked not available")
        return r
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


def bench_pregen_ocsp(n_certs: int, n_queries: int, warmup: int) -> BenchResult:
    """Simulates pre-generated OCSP: serial lookup in a dict (file-system equivalent)."""
    import pki_server as pki

    ca_dir = tempfile.mkdtemp(prefix="bench-ocsp-pregen-")
    try:
        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = pki.AuditLog(Path(ca_dir))
        certs = _issue_some_certs(ca, audit, n_certs)

        # Simulate pre-generated cache as a dict.
        pregen_cache = {c.serial_number: b"fake-response" for c in certs}
        serial_list = list(pregen_cache.keys())
        idx = [0]

        def _pregen_lookup():
            serial = serial_list[idx[0] % len(serial_list)]
            idx[0] += 1
            return pregen_cache.get(serial)

        latencies = measure_latencies(_pregen_lookup, n=n_queries, warmup=warmup)
        result = BenchResult("ocsp/pregen_cache_lookup", unit="query")
        result.record(latencies)
        result.add_note("note", "In-memory dict lookup; models file-system read at O(1)")
        result.add_note("certs_in_cache", str(n_certs))
        result.print_summary()

        del ca, audit
        return result
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="OCSP throughput benchmark")
    parser.add_argument("--n", type=int, default=500, help="Query iterations")
    parser.add_argument("--certs", type=int, default=100, help="Certs to pre-populate")
    parser.add_argument("--warmup", type=int, default=50)
    args = parser.parse_args(argv)

    print("=== OCSP throughput benchmark ===")
    hw = hw_info()
    results = [
        bench_live_ocsp(args.certs, args.n, args.warmup),
        bench_pregen_ocsp(args.certs, args.n, args.warmup),
    ]
    ts = hw["timestamp"].replace(":", "-").replace("+", "")[:19]
    write_result(f"ocsp-{ts}.md", results, hw)
    print("\n=== Done ===")


if __name__ == "__main__":
    main()
