"""
bench/crl_gen.py — CRL generation time benchmark.

Measures time to generate and sign a CRL with varying numbers of revoked certs:
  1k, 10k, 100k, 1M revoked (skip if too slow).

Usage:
    python3 bench/crl_gen.py [--max-revoked 100000]
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bench._harness import BenchResult, hw_info, gen_key, write_result


def _revoke_n(ca, audit, n: int) -> None:
    """Issue and revoke n certs to populate the revocation list."""
    key_pub = gen_key().public_key()
    batch = 100
    for start in range(0, n, batch):
        count = min(batch, n - start)
        for i in range(count):
            cert = ca.issue_certificate(
                f"CN=crl-revoked-{start+i}", key_pub, audit=audit
            )
            ca.revoke_certificate(cert.serial_number, reason=0, audit=audit)


def bench_crl_gen(n_revoked: int, label: str) -> BenchResult:
    import pki_server as pki

    ca_dir = tempfile.mkdtemp(prefix=f"bench-crl-{label}-")
    try:
        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = pki.AuditLog(Path(ca_dir))

        print(f"  Populating {n_revoked:,} revocations ... ", end="", flush=True)
        t0 = time.perf_counter()
        _revoke_n(ca, audit, n_revoked)
        setup_time = time.perf_counter() - t0
        print(f"done ({setup_time:.1f}s)")

        # Measure CRL generation.
        n_runs = max(1, min(5, 100_000 // (n_revoked + 1)))
        latencies: list[float] = []
        for _ in range(n_runs):
            t = time.perf_counter()
            try:
                ca.generate_crl(audit=audit)
            except Exception as e:
                print(f"  [warn] generate_crl failed: {e}")
                break
            latencies.append(time.perf_counter() - t)

        result = BenchResult(f"crl_gen/{label}", unit="CRL")
        if latencies:
            result.record(latencies)
            result.add_note("n_revoked", f"{n_revoked:,}")
            result.add_note("n_runs", str(n_runs))
            result.print_summary()
        else:
            result.add_note("skip", "generate_crl() not available or failed")

        del ca, audit
        return result
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="CRL generation benchmark")
    parser.add_argument("--max-revoked", type=int, default=100_000,
                        help="Maximum revoked certs to test")
    args = parser.parse_args(argv)

    print("=== CRL generation benchmark ===")
    hw = hw_info()

    sizes = [1_000, 10_000, 100_000, 1_000_000]
    sizes = [s for s in sizes if s <= args.max_revoked]
    if not sizes:
        sizes = [1_000]

    results = []
    for n in sizes:
        label = f"{n//1000}k"
        print(f"\nBenchmarking CRL with {n:,} revoked certs ...")
        results.append(bench_crl_gen(n, label))

    ts = hw["timestamp"].replace(":", "-").replace("+", "")[:19]
    write_result(f"crl_gen-{ts}.md", results, hw)
    print("\n=== Done ===")


if __name__ == "__main__":
    main()
