"""
scripts/audit/link_check.py — HTTP-check external links in all docs.

Scans docs/ and README.md for external URLs (http:// and https://) and
sends a HEAD request to each.  Reports broken links (HTTP 4xx/5xx or
connection error) and redirects.

Usage:
    python3 scripts/audit/link_check.py [--timeout 10] [--skip-domains DOMAIN,...]

Exit codes:
    0 — all links OK (or only redirects)
    1 — broken link(s) found
"""

from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).parent.parent.parent
_DOCS = _ROOT / "docs"
_README = _ROOT / "README.md"

# Domains to skip (shields.io, badge services, etc. rate-limit aggressively).
_DEFAULT_SKIP: set[str] = {
    "shields.io",
    "img.shields.io",
    "badge.fury.io",
    "github.com",   # GitHub rate-limits unauthenticated HEAD; skip by default
    "rfc-editor.org",  # Often returns 403 to scripts; manually verified
    "datatracker.ietf.org",
}


def _extract_links(text: str) -> list[str]:
    """Return all http/https URLs from Markdown text."""
    return re.findall(r"https?://[^\s\)\]\"\'<>]+", text)


def _check_url(url: str, timeout: int) -> tuple[int, Optional[str]]:
    """
    Returns (status_code, redirect_url_or_None).
    status_code 0 means connection error.
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "pypki-link-checker/1.0"},
        method="HEAD",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            final = r.url if r.url != url else None
            return r.status, final
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:
        return 0, str(e)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check external links in docs")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--skip-domains", default="",
                        help="Comma-separated extra domains to skip")
    args = parser.parse_args()

    skip_domains = _DEFAULT_SKIP | {d.strip() for d in args.skip_domains.split(",") if d.strip()}

    # Collect all unique URLs.
    all_links: dict[str, list[str]] = {}
    doc_files = list(_DOCS.rglob("*.md")) + [_README]
    for doc in doc_files:
        for url in _extract_links(doc.read_text(errors="replace")):
            # Strip trailing punctuation.
            url = url.rstrip(".,;:")
            domain = re.sub(r"^https?://([^/]+).*", r"\1", url)
            if domain in skip_domains:
                continue
            all_links.setdefault(url, []).append(str(doc.relative_to(_ROOT)))

    print(f"Checking {len(all_links)} unique URL(s) (skipping: {', '.join(sorted(skip_domains))})")
    print()

    broken: list[tuple[str, int, str]] = []
    redirects: list[tuple[str, str]] = []

    for i, (url, files) in enumerate(sorted(all_links.items()), 1):
        status, redirect = _check_url(url, args.timeout)
        if redirect:
            redirects.append((url, redirect))
            print(f"  [REDIR] {url}")
        elif status in (200, 201, 204, 206):
            print(f"  [OK   ] {url}")
        elif status == 0:
            broken.append((url, status, str(redirect)))
            print(f"  [ERR  ] {url}  (connection failed: {redirect})")
        else:
            broken.append((url, status, ""))
            print(f"  [FAIL ] {url}  (HTTP {status})")
        # Rate-limit courtesy.
        if i % 5 == 0:
            time.sleep(0.5)

    print()
    print(f"Summary: {len(all_links)} checked, {len(broken)} broken, {len(redirects)} redirect(s)")

    if redirects:
        print("\nRedirects (update docs to canonical URL):")
        for old, new in redirects[:10]:
            print(f"  {old}\n    → {new}")

    if broken:
        print("\nBroken links:")
        for url, code, msg in broken:
            print(f"  HTTP {code:4d}  {url}" + (f"  ({msg})" if msg else ""))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
