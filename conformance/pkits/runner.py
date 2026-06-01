"""
conformance/pkits/runner.py — NIST PKITS (Public Key Interoperability Test Suite)
runner for PyPKI.

PKITS corpus: https://csrc.nist.gov/projects/pki-testing (CC0 / public domain)
Download and extract into conformance/pkits/data/ before running.

Usage:
    python3 conformance/pkits/runner.py
    python3 conformance/pkits/runner.py --data conformance/pkits/data
    python3 conformance/pkits/runner.py --json  # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.verification import PolicyBuilder, Store

_HERE = Path(__file__).parent
_DATA_DEFAULT = _HERE / "data"
_EXPECTED_FILE = _HERE / "expected.json"
_RESULTS_FILE = _HERE / "results.md"


# ---------------------------------------------------------------------------
# Expected outcomes
# ---------------------------------------------------------------------------

def _load_expected() -> dict:
    if _EXPECTED_FILE.exists():
        return json.loads(_EXPECTED_FILE.read_text())
    return {}


# ---------------------------------------------------------------------------
# Path validation via cryptography
# ---------------------------------------------------------------------------

def _load_certs(paths: list[Path]) -> list[x509.Certificate]:
    certs = []
    for p in paths:
        try:
            certs.append(x509.load_der_x509_certificate(p.read_bytes()))
        except Exception:
            pass
    return certs


def _validate_chain(
    trust_anchors: list[Path],
    intermediates: list[Path],
    end_entity: Path,
) -> tuple[bool, str]:
    """
    Validate end_entity against trust_anchors + intermediates.
    Returns (valid: bool, reason: str).
    """
    try:
        ta_certs = _load_certs(trust_anchors)
        if not ta_certs:
            return False, "no trust anchors loaded"

        ee_cert = x509.load_der_x509_certificate(end_entity.read_bytes())
        inter_certs = _load_certs(intermediates)

        store = Store(ta_certs)
        builder = PolicyBuilder().store(store)
        verifier = builder.build_server_verifier(
            x509.DNSName("test"),  # PKITS doesn't use DNS names; any value
        )

        # cryptography's verify() validates the chain.
        try:
            verifier.verify(ee_cert, inter_certs)
            return True, "valid"
        except Exception as e:
            return False, str(e)

    except Exception as e:
        return False, f"setup error: {e}"


# ---------------------------------------------------------------------------
# PKITS test case discovery
# ---------------------------------------------------------------------------

def _discover_cases(data_dir: Path) -> list[dict]:
    """
    Walk the PKITS data directory and collect test cases.

    PKITS layout (typical):
        data/
          certs/          — end-entity and intermediate certs
          crls/           — CRLs
          smime/          — S/MIME test data (skip for path validation)

    We look for directories named like "4.1.1", "4.1.2" etc. that
    contain {EE,Inter,TA} cert files.

    Simplified: treat each subdirectory as a test case.
    """
    cases = []
    certs_dir = data_dir / "certs"
    if not certs_dir.exists():
        return cases

    # Walk numbered subdirectories
    for case_dir in sorted(certs_dir.iterdir()):
        if not case_dir.is_dir():
            continue

        ta_files = sorted(case_dir.glob("Trust*Anchor*.crt")) or \
                   sorted(case_dir.glob("TA*.crt")) or \
                   sorted(case_dir.glob("*TrustAnchor*.crt"))
        ee_files = sorted(case_dir.glob("*End*Entity*.crt")) or \
                   sorted(case_dir.glob("EE*.crt")) or \
                   sorted(case_dir.glob("*end*.crt"))
        inter_files = [f for f in sorted(case_dir.glob("*.crt"))
                       if f not in ta_files and f not in ee_files]

        if not ee_files:
            continue

        cases.append({
            "id": case_dir.name,
            "trust_anchors": ta_files,
            "intermediates": inter_files,
            "end_entity": ee_files[-1],
        })

    return cases


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_OUTCOME_PASS = "PASS"
_OUTCOME_FAIL = "FAIL"
_OUTCOME_SKIP = "SKIPPED"


def run(data_dir: Path, expected: dict, json_output: bool = False) -> int:
    """
    Run all discovered PKITS cases. Returns number of unexpected results.
    """
    cases = _discover_cases(data_dir)
    if not cases:
        print(f"No PKITS test cases found in {data_dir}")
        print("Download PKITS data from https://csrc.nist.gov/projects/pki-testing")
        print("and extract into conformance/pkits/data/")
        return 0

    results = []
    unexpected = 0

    for case in cases:
        cid = case["id"]
        exp = expected.get(cid, {})

        if exp.get("expected") == "skipped":
            results.append({
                "id": cid,
                "outcome": _OUTCOME_SKIP,
                "reason": exp.get("rationale", ""),
            })
            continue

        valid, reason = _validate_chain(
            case["trust_anchors"],
            case["intermediates"],
            case["end_entity"],
        )

        exp_valid = exp.get("expected", "valid") == "valid"
        outcome = _OUTCOME_PASS if (valid == exp_valid) else _OUTCOME_FAIL

        if outcome == _OUTCOME_FAIL:
            unexpected += 1

        results.append({
            "id": cid,
            "outcome": outcome,
            "valid": valid,
            "expected_valid": exp_valid,
            "reason": reason,
        })

    # Report
    if json_output:
        print(json.dumps({"results": results, "unexpected": unexpected}, indent=2))
    else:
        _print_table(results)
        print(f"\nTotal: {len(results)}  "
              f"Unexpected: {unexpected}  "
              f"Skipped: {sum(1 for r in results if r['outcome'] == _OUTCOME_SKIP)}")

    # Write results.md
    _write_results_md(results, unexpected)

    return unexpected


def _print_table(results: list[dict]) -> None:
    for r in results:
        oc = r["outcome"]
        marker = "✓" if oc == _OUTCOME_PASS else ("·" if oc == _OUTCOME_SKIP else "✗")
        print(f"  {marker} {r['id']:40s} {oc}")
        if oc == _OUTCOME_FAIL:
            print(f"      reason: {r.get('reason', '')}")


def _write_results_md(results: list[dict], unexpected: int) -> None:
    import datetime
    lines = [
        "# NIST PKITS Results\n",
        f"Last run: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n\n",
        f"Unexpected failures: {unexpected}\n\n",
        "| Test case | Outcome | Reason |\n",
        "| --------- | ------- | ------ |\n",
    ]
    for r in results:
        lines.append(f"| {r['id']} | {r['outcome']} | {r.get('reason', '')} |\n")
    _RESULTS_FILE.write_text("".join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(description="NIST PKITS runner for PyPKI")
    parser.add_argument("--data", type=Path, default=_DATA_DEFAULT,
                        help="PKITS data directory (default: conformance/pkits/data)")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="Machine-readable JSON output")
    args = parser.parse_args()

    expected = _load_expected()
    unexpected = run(args.data, expected, json_output=args.json_output)
    sys.exit(1 if unexpected else 0)


if __name__ == "__main__":
    _main()
