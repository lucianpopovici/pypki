"""
scripts/audit/add_last_reviewed.py — Add/update "Last reviewed" headers in docs.

Inserts `> Last reviewed: <date> (commit <sha>)` after the first heading
in each Markdown file under docs/ and in README.md (if not already present).
If the header already exists, updates the date and SHA.

Usage:
    python3 scripts/audit/add_last_reviewed.py [--dry-run] [--file PATH]

    --dry-run  Print changes without writing.
    --file     Process only this specific file.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent
_DOCS = _ROOT / "docs"

_REVIEWED_RE = re.compile(r"^> Last reviewed:.*$", re.MULTILINE)
_HEADER_RE = re.compile(r"^(#[^\n]+\n)", re.MULTILINE)

# Files to skip (generated or not user-facing docs).
_SKIP: set[str] = {
    "docs/TIER_6/6.1-FUZZING.md",
    "docs/TIER_6/6.2-INTEROP.md",
    "docs/TIER_6/6.3-THREAT-MODEL-WALKBACK.md",
    "docs/TIER_6/6.4-SUPPLY-CHAIN.md",
    "docs/TIER_6/6.5-CHAOS.md",
    "docs/TIER_6/6.6-CONFORMANCE.md",
    "docs/TIER_6/6.7-PERFORMANCE.md",
    "docs/TIER_6/README.md",
    "docs/TIER_6/RELEASE_GATING.md",
    "docs/TIER_8/8.1-DOC-AUDIT.md",
    "docs/TIER_8/8.2-SERVICE-DEPLOYMENT-GUIDES.md",
    "docs/TIER_8/README.md",
}


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=_ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


def _update_file(path: Path, today: str, sha: str, dry_run: bool) -> bool:
    text = path.read_text(errors="replace")
    tag = f"> Last reviewed: {today} (commit {sha})"

    # Already up-to-date?
    existing = _REVIEWED_RE.search(text)
    if existing and existing.group(0) == tag:
        return False  # no change

    if existing:
        new_text = _REVIEWED_RE.sub(tag, text, count=1)
    else:
        # Insert after the first heading.
        m = _HEADER_RE.search(text)
        if m:
            insert_pos = m.end()
            new_text = text[:insert_pos] + "\n" + tag + "\n" + text[insert_pos:]
        else:
            new_text = tag + "\n\n" + text

    if dry_run:
        print(f"  [DRY] would update: {path.relative_to(_ROOT)}")
        return True

    path.write_text(new_text)
    print(f"  updated: {path.relative_to(_ROOT)}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Add/update Last reviewed headers")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--file", metavar="PATH", help="Process only this file")
    args = parser.parse_args()

    today = date.today().isoformat()
    sha = _git_sha()

    if args.file:
        target = Path(args.file)
        if not target.exists():
            print(f"File not found: {target}")
            return 1
        _update_file(target, today, sha, args.dry_run)
        return 0

    doc_files = sorted(_DOCS.rglob("*.md")) + [_ROOT / "README.md"]
    updated = 0
    for path in doc_files:
        rel = str(path.relative_to(_ROOT))
        if rel in _SKIP:
            continue
        if _update_file(path, today, sha, args.dry_run):
            updated += 1

    print(f"\n{'Would update' if args.dry_run else 'Updated'} {updated} file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
