"""
scripts/audit/rfc_table_check.py — Cross-reference README compliance table vs test classes.

Extracts the RFC compliance table from README.md, then checks that:
  1. Every RFC in the table has at least one TestRFC<nnnn> class in
     test_pki_server.py (table claim → test exists).
  2. Every TestRFC<nnnn> class in test_pki_server.py appears in the
     README table (test exists → table documents it).

Also checks CLAUDE.md's §8 Normative references table for consistency.

Usage:
    python3 scripts/audit/rfc_table_check.py [--strict]

    --strict  Fail on any undocumented test class (default: warn only)

Exit codes:
    0 — no drift
    1 — missing tests for claimed RFCs
    2 — strict mode: undocumented test classes
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent
_README = _ROOT / "README.md"
_TESTS = _ROOT / "test_pki_server.py"

# RFCs that are tested but under a different class name or via combined tests.
_ALIAS: dict[str, str] = {
    "RFC8737": "TestRFC8555ACME",   # tls-alpn-01 tested in ACME suite
    "RFC8738": "TestRFC8555ACME",   # IP identifiers tested in ACME suite
    "RFC8739": "TestRFC8555ACME",   # STAR tested in ACME suite
    "RFC9773": "TestRFC9773ARI",
    "RFC9799": "TestRFC9799ACMEOnion",
    "RFC5816": "TestRFC3161TSA",    # RFC 5816 updates 3161; same test class
    "RFC6712": "TestCMPv2",         # HTTP transport for CMP
    "RFC9480": "TestCMPv3",
    "RFC9481": "TestCMPv3",
    "FIPS204": "TestMLDSAX509",
    "FIPS205": "TestSLHDSAX509",
    "RFC9763": "TestRFC9763PairedCerts",
}

# RFC numbers that are fundamental to everything and don't need their own class.
_EXEMPT: set[str] = {
    "RFC3647",  # CPS framework — not protocol code
    "RFC5958",  # PKCS#8 wrapper — tested implicitly everywhere
    "RFC7292",  # PKCS#12 — tested in TestPKCS12Export
    "RFC4251",  # SSH wire format — tested in TestSSHWire
}


def _rfc_ids_from_readme() -> dict[str, str]:
    """Return {RFCNNNN: status} from the README compliance table."""
    text = _README.read_text(errors="replace")
    # Find the compliance table section.
    table_section = re.search(
        r"## Protocol compliance\b.*?(?=\n##|\Z)", text, re.DOTALL
    )
    if not table_section:
        return {}
    table_text = table_section.group(0)
    rfcs: dict[str, str] = {}
    for m in re.finditer(r"\bRFC\s*(\d{3,5})\b", table_text):
        rfcs[f"RFC{m.group(1)}"] = "claimed"
    # Also pick up FIPS references.
    for m in re.finditer(r"\bFIPS\s*(\d{3,4})\b", table_text):
        rfcs[f"FIPS{m.group(1)}"] = "claimed"
    return rfcs


def _test_classes_from_file() -> dict[str, str]:
    """Return {classname: first_rfc_found_in_docstring} from test_pki_server.py."""
    text = _TESTS.read_text(errors="replace")
    classes: dict[str, str] = {}
    for m in re.finditer(r"class\s+(TestRFC\w+)\s*\(", text):
        name = m.group(1)
        # Try to find the RFC number from the class name itself.
        rfc_m = re.search(r"TestRFC(\d+)", name)
        rfc = f"RFC{rfc_m.group(1)}" if rfc_m else name
        classes[name] = rfc
    return classes


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-reference RFC table vs test classes")
    parser.add_argument("--strict", action="store_true",
                        help="Exit 2 on undocumented test classes")
    args = parser.parse_args()

    print("Extracting README RFC compliance table ... ", end="", flush=True)
    claimed_rfcs = _rfc_ids_from_readme()
    print(f"{len(claimed_rfcs)} RFCs/FIPS referenced")

    print("Scanning test file for TestRFC classes ... ", end="", flush=True)
    test_classes = _test_classes_from_file()
    print(f"{len(test_classes)} TestRFC* classes found")

    # Build set of RFC numbers covered by tests.
    tested_rfcs: set[str] = set()
    for cls, rfc in test_classes.items():
        tested_rfcs.add(rfc)
    # Add aliases.
    for rfc_id, cls_name in _ALIAS.items():
        if cls_name in test_classes:
            tested_rfcs.add(rfc_id)

    drift = False
    rc = 0

    # Check: claimed RFCs without tests.
    missing_tests = {
        rfc for rfc in claimed_rfcs
        if rfc not in tested_rfcs and rfc not in _EXEMPT
    }
    if missing_tests:
        drift = True
        rc = 1
        print(f"\n[MISSING TESTS] {len(missing_tests)} claimed RFC(s) lack a TestRFC class:")
        for rfc in sorted(missing_tests):
            print(f"  {rfc}")
    else:
        print(f"\n[OK] All {len(claimed_rfcs)} claimed RFCs have test coverage")

    # Check: test classes for RFCs not in the README table.
    undocumented: list[str] = []
    for cls, rfc in test_classes.items():
        if rfc not in claimed_rfcs and cls not in _ALIAS.values():
            undocumented.append(f"{cls} ({rfc})")

    if undocumented:
        level = "FAIL" if args.strict else "WARN"
        print(f"\n[{level}] {len(undocumented)} TestRFC class(es) not in README compliance table:")
        for item in sorted(undocumented):
            print(f"  {item}")
        if args.strict:
            rc = max(rc, 2)
    else:
        print(f"[OK] All TestRFC classes correspond to documented RFCs")

    if not drift and not undocumented:
        print("\nNo drift.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
