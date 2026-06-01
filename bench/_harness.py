"""
bench/_harness.py — Shared timing and metric collection for bench suite.

All benchmarks produce a BenchResult with p50/p95/p99 latency and
sustained throughput. Results are written as Markdown to bench/results/.
"""

from __future__ import annotations

import datetime
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

_RESULTS_DIR = Path(__file__).parent / "results"
_RESULTS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# CA factory
# ---------------------------------------------------------------------------

def make_bench_ca(ca_dir: str | None = None):
    """Return (ca_dir, ca, audit) ready for benchmarking."""
    import pki_server as pki

    d = ca_dir or tempfile.mkdtemp(prefix="bench-ca-")
    ca = pki.CertificateAuthority(ca_dir=d)
    audit = pki.AuditLog(Path(d))
    return d, ca, audit


def gen_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------

class Timer:
    """Context manager that records elapsed time."""

    def __init__(self):
        self.elapsed: float = 0.0

    def __enter__(self) -> "Timer":
        self._t = time.perf_counter()
        return self

    def __exit__(self, *_) -> None:
        self.elapsed = time.perf_counter() - self._t


def measure_latencies(fn: Callable, n: int, warmup: int = 10) -> list[float]:
    """
    Call fn() n times after warmup iterations.
    Returns list of elapsed seconds for each call.
    """
    for _ in range(warmup):
        fn()

    latencies: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        latencies.append(time.perf_counter() - t0)
    return latencies


def percentile(data: list[float], p: float) -> float:
    """Return the p-th percentile of data."""
    if not data:
        return 0.0
    data_s = sorted(data)
    k = (len(data_s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(data_s) - 1)
    return data_s[lo] + (data_s[hi] - data_s[lo]) * (k - lo)


def throughput(latencies: list[float]) -> float:
    """Operations per second (sustained rate)."""
    total_time = sum(latencies)
    return len(latencies) / total_time if total_time > 0 else 0.0


# ---------------------------------------------------------------------------
# Result record
# ---------------------------------------------------------------------------

class BenchResult:
    def __init__(self, name: str, unit: str = "op"):
        self.name = name
        self.unit = unit
        self.latencies: list[float] = []
        self.extra: dict[str, str] = {}

    def record(self, latencies: list[float]) -> "BenchResult":
        self.latencies = latencies
        return self

    def add_note(self, key: str, value: str) -> "BenchResult":
        self.extra[key] = value
        return self

    def p50(self) -> float:
        return percentile(self.latencies, 50) * 1000  # ms

    def p95(self) -> float:
        return percentile(self.latencies, 95) * 1000  # ms

    def p99(self) -> float:
        return percentile(self.latencies, 99) * 1000  # ms

    def ops_per_sec(self) -> float:
        return throughput(self.latencies)

    def print_summary(self) -> None:
        print(f"\n  {self.name}")
        print(f"    n={len(self.latencies)}")
        print(f"    p50={self.p50():.1f}ms  p95={self.p95():.1f}ms  p99={self.p99():.1f}ms")
        print(f"    throughput={self.ops_per_sec():.1f} {self.unit}/s")
        for k, v in self.extra.items():
            print(f"    {k}: {v}")


# ---------------------------------------------------------------------------
# Hardware fingerprint
# ---------------------------------------------------------------------------

def hw_info() -> dict[str, str]:
    info: dict[str, str] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cpu_count": str(os.cpu_count()),
        "pypki_commit": _git_rev(),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    try:
        import psutil
        info["ram_gb"] = f"{psutil.virtual_memory().total / 1e9:.1f}"
    except ImportError:
        pass
    return info


def _git_rev() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=_ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Markdown writer
# ---------------------------------------------------------------------------

def write_result(filename: str, results: list[BenchResult], hw: dict[str, str]) -> None:
    lines = [
        f"# Bench results — {filename}\n\n",
        f"**Generated:** {hw.get('timestamp', '')}\n",
        f"**Python:** {hw.get('python', '')}\n",
        f"**Platform:** {hw.get('platform', '')}\n",
        f"**CPU count:** {hw.get('cpu_count', '')}\n",
        f"**RAM:** {hw.get('ram_gb', 'N/A')} GB\n",
        f"**Commit:** {hw.get('pypki_commit', '')}\n\n",
        "| Benchmark | n | p50 (ms) | p95 (ms) | p99 (ms) | ops/s |\n",
        "|-----------|---|---------|---------|---------|-------|\n",
    ]
    for r in results:
        lines.append(
            f"| {r.name} | {len(r.latencies)} "
            f"| {r.p50():.2f} | {r.p95():.2f} | {r.p99():.2f} "
            f"| {r.ops_per_sec():.1f} |\n"
        )
    for r in results:
        if r.extra:
            lines.append(f"\n**{r.name} notes:**\n")
            for k, v in r.extra.items():
                lines.append(f"- {k}: {v}\n")

    out = _RESULTS_DIR / filename
    out.write_text("".join(lines))
    print(f"\n  Results written to {out}")
