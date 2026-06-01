"""
scripts/audit/cli_flag_diff.py — Diff documented flags vs --help output.

Scans all Markdown files under docs/ and README.md for CLI flag mentions
(--flag-name), then compares them against the flags that pki_server.py
actually exposes.  Reports flags referenced in docs but missing from --help
(doc rot) and flags in --help but absent from docs (undocumented flags).

Usage:
    python3 scripts/audit/cli_flag_diff.py [--help-only] [--docs-only]

Exit codes:
    0 — no drift
    1 — drift found
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent
_DOCS = _ROOT / "docs"
_README = _ROOT / "README.md"

# Flags that are intentionally undocumented (internal / testing only).
_KNOWN_UNDOCUMENTED: set[str] = {
    "--skip-preflight",      # implementation detail; not user-facing
    "--no-cmpv3",            # inverse of --cmpv3; both not needed in docs
    "--no-audit",            # inverse of --audit; docs mention --audit
    "--web-port",            # port-hint only, dispatcher binds --port
    "--acme-port",
    "--scep-port",
    "--est-port",
    "--ocsp-port",
    "--ipsec-port",
    "--ipsec-prefix",
    "--ipsec-tls-cert",
    "--ipsec-tls-key",
}


def get_help_flags() -> set[str]:
    """Run pki_server.py --help and extract all --flag-name tokens."""
    result = subprocess.run(
        [sys.executable, str(_ROOT / "pki_server.py"), "--help"],
        capture_output=True, text=True, timeout=30,
    )
    text = result.stdout + result.stderr
    return set(re.findall(r"--[\w-]+", text))


def get_doc_flags() -> dict[str, list[str]]:
    """
    Scan all docs and return a mapping of flag → [files it appears in].
    Excludes code blocks to reduce false positives.
    """
    flag_files: dict[str, list[str]] = {}

    doc_files = list(_DOCS.rglob("*.md")) + [_README]
    for path in doc_files:
        text = path.read_text(errors="replace")
        # Remove fenced code blocks to avoid counting example output.
        text_no_code = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
        flags = set(re.findall(r"--[\w-]+", text_no_code))
        for f in flags:
            flag_files.setdefault(f, []).append(str(path.relative_to(_ROOT)))

    return flag_files


def main() -> int:
    parser = argparse.ArgumentParser(description="Diff doc flags vs --help")
    parser.add_argument("--help-only", action="store_true",
                        help="Show only flags in --help not in docs")
    parser.add_argument("--docs-only", action="store_true",
                        help="Show only flags in docs not in --help")
    args = parser.parse_args()

    print("Fetching --help flags ... ", end="", flush=True)
    help_flags = get_help_flags()
    print(f"{len(help_flags)} flags")

    print("Scanning docs ... ", end="", flush=True)
    doc_flags_map = get_doc_flags()
    doc_flags = set(doc_flags_map.keys())
    print(f"{len(doc_flags)} distinct flags referenced")

    drift = False

    # Flags in docs but not in --help (doc rot).
    if not args.help_only:
        extra_in_docs = doc_flags - help_flags
        if extra_in_docs:
            drift = True
            print(f"\n[DOC ROT] {len(extra_in_docs)} flag(s) in docs but not in --help:")
            for f in sorted(extra_in_docs):
                files = ", ".join(doc_flags_map[f][:3])
                print(f"  {f:40s}  ({files})")
        else:
            print("\n[OK] No doc-rot flags (all documented flags exist in --help)")

    # Flags in --help but not in docs.
    if not args.docs_only:
        undocumented = help_flags - doc_flags - _KNOWN_UNDOCUMENTED
        if undocumented:
            drift = True
            print(f"\n[UNDOCUMENTED] {len(undocumented)} flag(s) in --help but not in docs:")
            for f in sorted(undocumented):
                print(f"  {f}")
        else:
            print("[OK] All --help flags are documented (or on the known-undocumented list)")

    if drift:
        print("\nDrift detected. Fix docs or add flags to _KNOWN_UNDOCUMENTED.")
        return 1
    print("\nNo drift.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
