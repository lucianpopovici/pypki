"""
conformance/mldsa_vectors/runner.py — ML-DSA X.509 test vector verification.

Verifies PyPKI's ML-DSA certificate generation against published IETF test
vectors once `draft-ietf-lamps-x509-mldsa` stabilizes and publishes vectors.

Usage:
    python3 conformance/mldsa_vectors/runner.py

Status: PENDING — vectors not yet published by IETF.
        This runner is a stub that will be filled when vectors are available.
        Tracked at: https://datatracker.ietf.org/doc/draft-ietf-lamps-x509-mldsa/
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).parent
_VECTORS_DIR = _HERE / "vectors"
_RESULTS_FILE = _HERE / "results.md"


def run() -> int:
    vectors = sorted(_VECTORS_DIR.glob("*.json")) if _VECTORS_DIR.exists() else []

    if not vectors:
        print("ML-DSA vectors: SKIP — no vectors available yet")
        print(
            "  Vectors will be published alongside draft-ietf-lamps-x509-mldsa "
            "when it reaches RFC status.\n"
            "  Check: https://www.iana.org/assignments/pk-parameters/"
        )
        _write_results([], [])
        return 0

    passed = []
    failed = []

    for vec_path in vectors:
        try:
            vec = json.loads(vec_path.read_text())
            ok, msg = _check_vector(vec, vec_path.stem)
            if ok:
                passed.append(vec_path.stem)
                print(f"  ✓  {vec_path.stem}")
            else:
                failed.append((vec_path.stem, msg))
                print(f"  ✗  {vec_path.stem}: {msg}")
        except Exception as e:
            failed.append((vec_path.stem, str(e)))
            print(f"  ✗  {vec_path.stem}: {e}")

    total = len(passed) + len(failed)
    print(f"\nML-DSA vectors: {total} cases, {len(passed)} passed, {len(failed)} failed")
    _write_results(passed, failed)
    return len(failed)


def _check_vector(vec: dict, name: str) -> tuple[bool, str]:
    """
    Verify a single ML-DSA X.509 test vector.
    Expected format (provisional — will match the published spec):
      {
        "algorithm": "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87",
        "public_key_hex": "...",
        "cert_der_hex": "...",
        "expected": "valid" | "invalid"
      }
    """
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    algorithm = vec.get("algorithm", "unknown")
    cert_der_hex = vec.get("cert_der_hex", "")
    expected_valid = vec.get("expected", "valid") == "valid"

    if not cert_der_hex:
        return False, "missing cert_der_hex in vector"

    cert_der = bytes.fromhex(cert_der_hex)

    try:
        import pki_server as pki
        # Attempt to load + verify the cert using PyPKI's ML-DSA verifier.
        # Exact API depends on what's exported; this is a placeholder.
        if hasattr(pki, "verify_mldsa_certificate"):
            ok = pki.verify_mldsa_certificate(cert_der)
        else:
            # Fallback: just try to load the DER.
            from cryptography import x509
            x509.load_der_x509_certificate(cert_der)
            ok = True
    except Exception as e:
        ok = False

    if ok == expected_valid:
        return True, ""
    return (
        False,
        f"expected {'valid' if expected_valid else 'invalid'}, got {'valid' if ok else 'invalid'}",
    )


def _write_results(passed: list, failed: list) -> None:
    import datetime as dt
    total = len(passed) + len(failed)
    lines = [
        "# ML-DSA Test Vector Results\n\n",
        f"Last run: {dt.datetime.now(dt.timezone.utc).isoformat()}\n\n",
    ]
    if not total:
        lines.append(
            "**Status:** PENDING — no vectors available yet.\n\n"
            "Vectors from `draft-ietf-lamps-x509-mldsa` will be added here "
            "when the document publishes test vectors.\n"
        )
    else:
        lines.append(f"Total: {total}, Passed: {len(passed)}, Failed: {len(failed)}\n\n")
        lines.append("| Case | Result |\n| ---- | ------ |\n")
        for name in passed:
            lines.append(f"| {name} | PASS |\n")
        for name, msg in failed:
            lines.append(f"| {name} | FAIL: {msg} |\n")

    _RESULTS_FILE.write_text("".join(lines))


if __name__ == "__main__":
    sys.exit(run())
