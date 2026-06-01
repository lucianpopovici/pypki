"""
bench/issuance.py — Issuance throughput benchmark.

Measures certs/second for each CA key type, with and without audit logging.
Uses the in-process CertificateAuthority API (not HTTP), so numbers reflect
signing + DB + advisory-lock overhead without HTTP framing.

Usage:
    python3 bench/issuance.py [--n 200] [--key-type ecdsa_p256]
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bench._harness import (
    BenchResult, hw_info, make_bench_ca, gen_key,
    measure_latencies, write_result,
)


# ---------------------------------------------------------------------------
# Key types to benchmark
# ---------------------------------------------------------------------------

_KEY_CONFIGS: list[tuple[str, str | None]] = [
    ("ecdsa_p256",   None),           # default (EC P-256 CA)
    ("ecdsa_p384",   None),
    ("ed25519",      None),
    ("rsa_2048",     None),
    ("rsa_4096",     None),
    ("ml_dsa_44",    "ml-dsa-44"),    # requires --enable-mldsa
]


def _issue_fn(ca, audit, key_pub):
    """Return a closure that issues one cert."""
    counter = [0]

    def _fn():
        counter[0] += 1
        ca.issue_certificate(f"CN=bench-{counter[0]}", key_pub, audit=audit)

    return _fn


def bench_key_type(label: str, ca_key_type: str | None, n: int, warmup: int) -> BenchResult:
    ca_dir = tempfile.mkdtemp(prefix=f"bench-issue-{label}-")
    try:
        import pki_server as pki

        kwargs: dict = {}
        if ca_key_type:
            kwargs["ca_key_type"] = ca_key_type

        try:
            ca = pki.CertificateAuthority(ca_dir=ca_dir, **kwargs)
        except Exception as e:
            r = BenchResult(f"issuance/{label}")
            r.add_note("skip", str(e))
            return r

        audit = pki.AuditLog(Path(ca_dir))
        key_pub = gen_key().public_key()

        fn = _issue_fn(ca, audit, key_pub)
        latencies = measure_latencies(fn, n=n, warmup=warmup)

        result = BenchResult(f"issuance/{label}", unit="cert")
        result.record(latencies)
        result.add_note("CA_key_type", ca_key_type or "default")
        result.add_note("backend", "SQLite")
        result.print_summary()

        del ca, audit
        return result
    except Exception as e:
        r = BenchResult(f"issuance/{label}")
        r.add_note("error", str(e))
        return r
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


def bench_no_audit(n: int, warmup: int) -> BenchResult:
    """Baseline: issuance without audit logging (shows signing+DB overhead only)."""
    ca_dir = tempfile.mkdtemp(prefix="bench-issue-noaudit-")
    try:
        import pki_server as pki

        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        key_pub = gen_key().public_key()
        counter = [0]

        def _fn():
            counter[0] += 1
            ca.issue_certificate(f"CN=noaudit-{counter[0]}", key_pub, audit=None)

        latencies = measure_latencies(_fn, n=n, warmup=warmup)
        result = BenchResult("issuance/no_audit", unit="cert")
        result.record(latencies)
        result.add_note("note", "audit=None; isolates signing+DB cost")
        result.print_summary()
        del ca
        return result
    finally:
        shutil.rmtree(ca_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Issuance throughput benchmark")
    parser.add_argument("--n", type=int, default=200, help="Iterations per benchmark")
    parser.add_argument("--warmup", type=int, default=20, help="Warmup iterations")
    parser.add_argument("--key-type", default=None,
                        help="Only run this key type (e.g. ecdsa_p256)")
    args = parser.parse_args(argv)

    print("=== Issuance throughput benchmark ===")
    hw = hw_info()
    results: list[BenchResult] = []

    configs = _KEY_CONFIGS
    if args.key_type:
        configs = [(label, kt) for label, kt in configs if label == args.key_type]
        if not configs:
            print(f"Unknown key type: {args.key_type}")
            sys.exit(1)

    for label, ca_key_type in configs:
        print(f"\nBenchmarking: {label} ...")
        r = bench_key_type(label, ca_key_type, n=args.n, warmup=args.warmup)
        results.append(r)

    if not args.key_type:
        results.append(bench_no_audit(n=args.n, warmup=args.warmup))

    ts = hw["timestamp"].replace(":", "-").replace("+", "")[:19]
    write_result(f"issuance-{ts}.md", results, hw)
    print("\n=== Done ===")


if __name__ == "__main__":
    main()
