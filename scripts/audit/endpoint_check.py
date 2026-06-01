"""
scripts/audit/endpoint_check.py — Verify documented endpoints against dispatcher routing.

Extracts URL paths from docs/ and README.md, then checks them against
the route table defined in dispatcher_server.py and web_ui.py.  Reports
paths that are documented but absent from the router (potential doc rot or
renamed endpoints).

Usage:
    python3 scripts/audit/endpoint_check.py [--live URL]

    --live URL  Also hit a running PyPKI instance to verify HTTP status.
                Example: --live http://localhost:8080

Exit codes:
    0 — no drift
    1 — drift found
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent
_DOCS = _ROOT / "docs"
_README = _ROOT / "README.md"

# Paths that are intentionally not in the route table
# (they're handled dynamically or by the client itself).
_KNOWN_DYNAMIC: set[str] = {
    "/acme/directory",
    "/acme/new-account",
    "/acme/new-order",
    "/acme/new-nonce",
    "/acme/revoke-cert",
    "/acme/key-change",
    "/.well-known/acme-challenge/",
    "/cmp/ir",
    "/cmp/cr",
    "/cmp/kur",
    "/cmp/rr",
    "/cmp/genm",
    "/.well-known/est/",
    "/scep",
    "/ocsp",
    "/tsa",
    "/smime/sign",
    "/smime/verify",
    "/smime/encrypt",
    "/smime/decrypt",
}

# Paths extracted from docs that are purely illustrative (not real routes).
_EXAMPLE_ONLY: set[str] = {
    "/path/to/",
    "/your/prefix/",
}


def _get_router_paths() -> set[str]:
    """Extract route paths from web_ui.py and dispatcher_server.py."""
    paths: set[str] = set()
    for module in ("web_ui.py", "dispatcher_server.py", "pki_server.py"):
        src = _ROOT / module
        if not src.exists():
            continue
        text = src.read_text(errors="replace")
        # Match path comparisons: path == "/foo" or path.startswith("/foo")
        for m in re.finditer(r'path\s*(?:==|\.startswith\()\s*["\']([^"\']+)["\']', text):
            p = m.group(1).rstrip("(")
            paths.add(p)
        # Match route() / add_route() patterns.
        for m in re.finditer(r'route\(["\']([^"\']+)["\']', text):
            paths.add(m.group(1))
    return paths


def _get_doc_paths() -> dict[str, list[str]]:
    """Extract URL paths from docs."""
    path_files: dict[str, list[str]] = {}
    doc_files = list(_DOCS.rglob("*.md")) + [_README]
    for doc in doc_files:
        text = doc.read_text(errors="replace")
        # Match /api/..., /acme/..., /ca/... etc.
        for m in re.finditer(r"`(/(?:api|acme|scep|est|cmp|ocsp|tsa|smime|ca|health|metrics)[^`\s]*)`", text):
            p = m.group(1).split("?")[0].split("{")[0]  # strip query + template vars
            path_files.setdefault(p, []).append(str(doc.relative_to(_ROOT)))
    return path_files


def _live_check(base_url: str, paths: list[str]) -> list[tuple[str, int]]:
    """Hit each path and return (path, status_code) pairs."""
    results = []
    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                results.append((path, r.status))
        except urllib.error.HTTPError as e:
            results.append((path, e.code))
        except Exception:
            results.append((path, 0))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Check documented endpoints vs router")
    parser.add_argument("--live", metavar="URL",
                        help="Also hit a running PyPKI to verify HTTP responses")
    args = parser.parse_args()

    print("Extracting router paths ... ", end="", flush=True)
    router_paths = _get_router_paths()
    print(f"{len(router_paths)} paths")

    print("Scanning docs for paths ... ", end="", flush=True)
    doc_paths_map = _get_doc_paths()
    print(f"{len(doc_paths_map)} distinct paths")

    drift = False
    missing_from_router = []
    for path, files in sorted(doc_paths_map.items()):
        if path in _KNOWN_DYNAMIC or any(path.startswith(p) for p in _EXAMPLE_ONLY):
            continue
        # Check if any router path is a prefix match.
        matched = any(
            rp == path or path.startswith(rp) or rp.startswith(path.rstrip("/"))
            for rp in router_paths
        )
        if not matched:
            missing_from_router.append((path, files))

    if missing_from_router:
        drift = True
        print(f"\n[DOC ROT] {len(missing_from_router)} documented path(s) not found in router:")
        for path, files in missing_from_router:
            print(f"  {path:50s}  ({', '.join(files[:2])})")
    else:
        print(f"\n[OK] All {len(doc_paths_map)} documented paths match router or are known-dynamic")

    if args.live:
        print(f"\nLive check against {args.live} ...")
        paths_to_check = ["/health", "/metrics", "/ca/cert.pem", "/ca/crl"]
        results = _live_check(args.live, paths_to_check)
        for path, code in results:
            status = "OK" if code in (200, 301, 302, 401, 403) else "FAIL"
            print(f"  [{status}] {path} → HTTP {code}")

    if drift:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
