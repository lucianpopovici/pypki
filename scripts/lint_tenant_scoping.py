#!/usr/bin/env python3
"""
lint_tenant_scoping.py — Check that bare DB queries against tenant-scoped
tables are either using TenantScopedConnection or carry an explicit
'# tenant_scoped' annotation.

Usage:
    python scripts/lint_tenant_scoping.py [files...]

Exit code:
    0 = no violations
    1 = violations found

CI: add to pre-merge checks. Bare SQL against tenant-scoped tables without
    a scoping annotation is a potential cross-tenant data leak.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple

# Tables that require tenant scoping (mirrors tenant.TENANT_SCOPED_TABLES)
TENANT_SCOPED_TABLES = {
    "certificates",
    "key_archive",
    "ca_keys",
    "cert_owners",
    "sso_sessions",
    "wg_peers",
    "matter_dacs",
    "matter_authorities",
    "policy_decisions",
    "policy_versions",
    "pending_requests",
}

# Pattern: bare db.fetchall/fetchone/execute with a tenant-scoped table,
# but NOT inside a TenantScopedConnection context and NOT annotated.
_SQL_PAT = re.compile(
    r'\b(fetchall|fetchone|execute)\s*\(',
    re.IGNORECASE,
)

_TABLE_PAT = re.compile(
    r'\b(?:FROM|INTO|UPDATE|JOIN)\s+(' + '|'.join(TENANT_SCOPED_TABLES) + r')\b',
    re.IGNORECASE,
)


def check_file(path: Path) -> List[Tuple[int, str]]:
    """Return list of (line_number, line_content) violations."""
    violations = []
    lines = path.read_text(encoding="utf-8").splitlines()

    for i, line in enumerate(lines, start=1):
        # Skip comments and blank lines
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Look for SQL queries referencing tenant-scoped tables
        if not _TABLE_PAT.search(line):
            continue

        # Check if it's in a string (crude but fast: look for quote + table)
        if not ('"' in line or "'" in line):
            continue

        # Check for explicit scoping markers
        context_line = line
        # Check surrounding lines for TenantScopedConnection or annotation
        start = max(0, i - 5)
        end   = min(len(lines), i + 2)
        context = "\n".join(lines[start:end])

        if "TenantScopedConnection" in context:
            continue  # Using scoped connection — OK
        if "# tenant_scoped" in context:
            continue  # Explicitly annotated — OK
        if "unscoped(" in context:
            continue  # Explicit escape hatch — OK

        # Check if this is in a test file (tests set tenant_id explicitly)
        if "test_" in str(path):
            continue

        # Check if this is in tenant.py itself (the implementation)
        if path.name == "tenant.py":
            continue

        violations.append((i, line.rstrip()))

    return violations


def main(argv: List[str] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if argv:
        paths = [Path(p) for p in argv if p.endswith(".py")]
    else:
        # Default: scan all .py files except tests, migrations, and this script
        root = Path(__file__).parent.parent
        paths = [
            p for p in root.glob("*.py")
            if not p.name.startswith("test_")
            and p.name not in ("tenant.py",)
        ]

    total_violations = 0
    for path in sorted(paths):
        if not path.exists():
            continue
        violations = check_file(path)
        for line_no, content in violations:
            print(f"{path}:{line_no}: bare SQL against tenant-scoped table "
                  f"(add TenantScopedConnection or # tenant_scoped annotation)")
            print(f"    {content}")
            total_violations += 1

    if total_violations:
        print(f"\n{total_violations} violation(s) found.")
        print("Either use TenantScopedConnection or add '# tenant_scoped' annotation.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
