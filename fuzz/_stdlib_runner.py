"""
_stdlib_runner.py — Coverage-free fallback fuzzer for environments where
Atheris / libFuzzer are unavailable.

Interface: the runner is never imported into PyPKI server modules. It lives
under fuzz/ and imports upward into the repo.

Usage (invoked by run_fuzz.sh or directly):
    python3 fuzz/_stdlib_runner.py harness_tlv --budget 300 --seed 42
    python3 fuzz/_stdlib_runner.py harness_scep_envelope --budget 300
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import os
import random
import sys
import time
import traceback
from pathlib import Path

# Repo root on sys.path so harnesses can import PyPKI modules.
_REPO = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO))
_FUZZ_DIR = Path(__file__).parent


# ---------------------------------------------------------------------------
# Mutation primitives
# ---------------------------------------------------------------------------

def _bit_flip(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return data
    b = bytearray(data)
    idx = rng.randrange(len(b))
    b[idx] ^= 1 << rng.randrange(8)
    return bytes(b)


def _byte_change(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return bytes([rng.randrange(256)])
    b = bytearray(data)
    b[rng.randrange(len(b))] = rng.randrange(256)
    return bytes(b)


def _byte_insert(data: bytes, rng: random.Random) -> bytes:
    b = bytearray(data)
    b.insert(rng.randrange(len(b) + 1), rng.randrange(256))
    return bytes(b)


def _byte_delete(data: bytes, rng: random.Random) -> bytes:
    if len(data) <= 1:
        return data
    b = bytearray(data)
    del b[rng.randrange(len(b))]
    return bytes(b)


def _chunk_duplicate(data: bytes, rng: random.Random) -> bytes:
    if len(data) < 2:
        return data
    start = rng.randrange(len(data))
    end = rng.randrange(start, min(start + 64, len(data)) + 1)
    chunk = data[start:end]
    ins = rng.randrange(len(data) + 1)
    return data[:ins] + chunk + data[ins:]


def _chunk_delete(data: bytes, rng: random.Random) -> bytes:
    if len(data) < 2:
        return data
    start = rng.randrange(len(data))
    end = rng.randrange(start, min(start + 32, len(data)) + 1)
    return data[:start] + data[end:]


def _length_manip(data: bytes, rng: random.Random) -> bytes:
    """Replace a length byte with extreme values to trigger overflow/underflow."""
    if len(data) < 2:
        return data
    b = bytearray(data)
    idx = rng.randrange(1, len(b))
    b[idx] = rng.choice([0, 1, 0x7F, 0x80, 0x81, 0x83, 0xFF, min(len(b), 0xFF)])
    return bytes(b)


def _interesting_int(data: bytes, rng: random.Random) -> bytes:
    """Replace up to 4 bytes with interesting integer boundary values."""
    if not data:
        return data
    b = bytearray(data)
    interesting = [0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF,
                   0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
    val = rng.choice(interesting)
    size = rng.choice([1, 2, 4])
    idx = rng.randrange(len(b))
    vb = val.to_bytes(size, "big", signed=False) if val < (1 << (size * 8)) else bytes([0xFF] * size)
    b[idx:idx + size] = vb[:min(size, len(b) - idx)]
    return bytes(b)


_MUTATIONS = [
    _bit_flip, _byte_change, _byte_insert, _byte_delete,
    _chunk_duplicate, _chunk_delete, _length_manip, _interesting_int,
]


# ---------------------------------------------------------------------------
# Corpus management
# ---------------------------------------------------------------------------

def load_corpus(corpus_dir: Path) -> list[bytes]:
    """Load all non-hidden files from corpus_dir."""
    inputs = []
    if corpus_dir.exists():
        for f in sorted(corpus_dir.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                inputs.append(f.read_bytes())
    if not inputs:
        # Bootstrap with minimal DER primitives if corpus is empty.
        inputs = [
            b"\x30\x00",          # empty SEQUENCE
            b"\x02\x01\x00",      # INTEGER 0
            b"\x04\x00",          # empty OCTET STRING
            b"\x06\x01\x00",      # OID arc 0.0
            b"\x00",              # single zero byte
            b"\xff",              # single 0xFF byte
        ]
    return inputs


def save_crash(corpus_dir: Path, data: bytes, label: str = "") -> Path:
    sha = hashlib.sha256(data).hexdigest()[:16]
    dest = corpus_dir.parent / "regressions" / sha
    dest.parent.mkdir(exist_ok=True)
    dest.write_bytes(data)
    if label:
        dest.with_suffix(".txt").write_text(label)
    return dest


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

# Exception types that are *expected* escape paths from a parser (not bugs).
_EXPECTED = (
    ValueError, IndexError, KeyError, TypeError, OverflowError,
    UnicodeDecodeError, ArithmeticError, AttributeError,
)


def run(harness_module, corpus_dir: Path, budget_seconds: int,
        seed: int | None = None, verbose: bool = False) -> int:
    """
    Run the stdlib fuzzer against harness_module.TestOneInput.
    Returns the number of unique crashes found.
    """
    rng = random.Random(seed)
    corpus = load_corpus(corpus_dir)
    print(f"[stdlib-fuzz] harness={harness_module.__name__} "
          f"corpus={len(corpus)} budget={budget_seconds}s seed={seed}")

    runs = 0
    crashes = 0
    seen_crashes: set[str] = set()
    start = time.monotonic()
    report_every = 5000

    while True:
        elapsed = time.monotonic() - start
        if elapsed >= budget_seconds:
            break

        # Splice two corpus entries occasionally for cross-pollination.
        if len(corpus) >= 2 and rng.random() < 0.1:
            a, b = rng.sample(corpus, 2)
            split = rng.randrange(len(a) + 1)
            data = a[:split] + b[split:]
        else:
            data = rng.choice(corpus)

        # Apply 1–4 mutations.
        for _ in range(rng.randint(1, 4)):
            data = rng.choice(_MUTATIONS)(data, rng)

        try:
            harness_module.TestOneInput(data)
        except SystemExit as e:
            # Atheris uses SystemExit(-1) to signal a crash; propagate.
            raise
        except _EXPECTED:
            # Expected parse failures — count but don't crash.
            pass
        except RecursionError:
            sha = hashlib.sha256(data).hexdigest()[:16]
            if sha not in seen_crashes:
                seen_crashes.add(sha)
                crashes += 1
                dest = save_crash(corpus_dir, data, "RecursionError")
                print(f"  CRASH RecursionError sha={sha} -> {dest}")
        except MemoryError:
            sha = hashlib.sha256(data).hexdigest()[:16]
            if sha not in seen_crashes:
                seen_crashes.add(sha)
                crashes += 1
                dest = save_crash(corpus_dir, data, "MemoryError")
                print(f"  CRASH MemoryError sha={sha} -> {dest}")
        except Exception as exc:
            sha = hashlib.sha256(data).hexdigest()[:16]
            if sha not in seen_crashes:
                seen_crashes.add(sha)
                crashes += 1
                label = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
                dest = save_crash(corpus_dir, data, label)
                print(f"  CRASH {type(exc).__name__} sha={sha} -> {dest}")

        runs += 1
        if verbose and runs % report_every == 0:
            print(f"  runs={runs} crashes={crashes} elapsed={elapsed:.1f}s "
                  f"corpus={len(corpus)}")

    elapsed = time.monotonic() - start
    print(f"[stdlib-fuzz] done runs={runs} crashes={crashes} elapsed={elapsed:.1f}s")
    return crashes


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        description="stdlib fallback fuzzer — no Atheris required"
    )
    parser.add_argument("harness", help="harness module name (e.g. harness_tlv)")
    parser.add_argument("--budget", type=int, default=300,
                        help="wallclock budget in seconds (default 300)")
    parser.add_argument("--seed", type=int, default=None,
                        help="RNG seed for reproducibility")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    # Import the harness from the fuzz/ directory.
    sys.path.insert(0, str(_FUZZ_DIR))
    harness_mod = importlib.import_module(args.harness)

    # Corpus directory: fuzz/corpus/<harness_name_without_harness_prefix>/
    target_name = args.harness.removeprefix("harness_")
    corpus_dir = _FUZZ_DIR / "corpus" / target_name

    crashes = run(harness_mod, corpus_dir, args.budget,
                  seed=args.seed, verbose=args.verbose)
    sys.exit(1 if crashes else 0)


if __name__ == "__main__":
    _main()
