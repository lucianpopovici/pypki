#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
pypki_admin.py — operator CLI for offline PyPKI tasks.

This is separate from ``pki_server.py`` (the running server) on purpose —
admin tasks are offline, run by humans, and shouldn't share argparse with
the 100+ server-runtime flags. Today it covers only data migration; future
admin tasks (rotate-ca-passphrase, monitor-expiry, etc.) belong here too.

Subcommands
-----------

  migrate-data       Copy all canonical state from one DAL backend to another.
  verify-migration   Confirm a destination matches its source after migration.

Both subcommands operate on ALL FOUR PyPKI logical databases (pki, audit,
acme, scep) by default. Supply ``--namespace`` to limit scope.

Examples
--------

  # SQLite ./ca/ → Postgres (one DB per namespace; the destination
  # databases must already exist and have schema migrations applied).
  python pypki_admin.py migrate-data \\
      --from-ca-dir ./ca \\
      --to-db-url-tmpl 'postgresql://pypki@localhost/pypki_{namespace}'

  python pypki_admin.py verify-migration \\
      --from-ca-dir ./ca \\
      --to-db-url-tmpl 'postgresql://pypki@localhost/pypki_{namespace}'

  # Per-namespace explicit URLs:
  python pypki_admin.py migrate-data \\
      --from-url-pki   sqlite:///ca/certificates.db \\
      --from-url-audit sqlite:///ca/audit.db \\
      --to-url-pki     postgresql://localhost/pypki_pki \\
      --to-url-audit   postgresql://localhost/pypki_audit \\
      --namespace pki --namespace audit

The runbook in ``docs/MIGRATION.md`` and ``docs/STORAGE.md`` walks through
the full operator procedure (stop service, run migrate-data, run
verify-migration, restart with new URL).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

import db
import migration
import migrations as migration_runner_mod

try:
    import ceremony as _ceremony_mod
    HAS_CEREMONY = True
except ImportError:
    HAS_CEREMONY = False
    _ceremony_mod = None  # type: ignore[assignment]


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


# ---------------------------------------------------------------------------
# URL resolution
# ---------------------------------------------------------------------------

def _resolve_urls(args: argparse.Namespace, side: str) -> Dict[str, str]:
    """Return ``{namespace: db_url}`` for ``side`` ('from' or 'to').

    Argument precedence (most to least specific):
      1. ``--{side}-url-<namespace>`` per-namespace explicit URL
      2. ``--{side}-db-url-tmpl`` template like ``postgresql://.../{namespace}``
      3. ``--{side}-ca-dir`` directory containing the four .db files (sqlite only)
    """
    out: Dict[str, str] = {}
    for ns, default_file, _ in migration_runner_mod.PYPKI_NAMESPACES:
        explicit = getattr(args, f"{side}_url_{ns}", None)
        if explicit:
            out[ns] = explicit
            continue
        tmpl = getattr(args, f"{side}_db_url_tmpl", None)
        if tmpl:
            out[ns] = tmpl.format(namespace=ns)
            continue
        ca_dir = getattr(args, f"{side}_ca_dir", None)
        if ca_dir:
            out[ns] = f"sqlite:///{Path(ca_dir).resolve() / default_file}"
            continue
    return out


def _make_factory(urls: Dict[str, str]) -> Callable[[str], db.Database]:
    """Return a function that opens the right DB for a given namespace."""
    def factory(ns: str) -> db.Database:
        if ns not in urls:
            raise SystemExit(
                f"no database URL configured for namespace {ns!r} — "
                f"pass --from-ca-dir/--to-ca-dir, "
                f"--from-db-url-tmpl/--to-db-url-tmpl, "
                f"or --from-url-{ns}/--to-url-{ns}"
            )
        return db.make_db(urls[ns])
    return factory


def _selected_namespaces(args: argparse.Namespace) -> List[str]:
    if not args.namespace:
        return list(migration.TABLE_CATALOG.keys())
    bad = [ns for ns in args.namespace if ns not in migration.TABLE_CATALOG]
    if bad:
        raise SystemExit(f"unknown namespace(s): {', '.join(bad)}. "
                         f"Valid: {', '.join(migration.TABLE_CATALOG)}")
    return list(args.namespace)


# ---------------------------------------------------------------------------
# Subcommand: migrate-data
# ---------------------------------------------------------------------------

def cmd_migrate_data(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    log = logging.getLogger("pypki.migrate-data")

    src_urls = _resolve_urls(args, "from")
    dst_urls = _resolve_urls(args, "to")
    namespaces = _selected_namespaces(args)

    missing = [ns for ns in namespaces if ns not in src_urls or ns not in dst_urls]
    if missing:
        raise SystemExit(
            f"missing source or destination URL for: {', '.join(missing)}"
        )

    log.info(f"migrating namespaces: {', '.join(namespaces)}")
    for ns in namespaces:
        log.info(f"  {ns}: {src_urls[ns]!r} → {dst_urls[ns]!r}")

    if not args.yes:
        log.warning(
            "PyPKI MUST be stopped before running migrate-data. "
            "Continuing without --yes prompts for confirmation."
        )
        try:
            ans = input("Type 'yes' to proceed: ").strip().lower()
        except EOFError:
            ans = ""
        if ans != "yes":
            log.error("aborted by user")
            return 1

    src_factory = _make_factory(src_urls)
    dst_factory = _make_factory(dst_urls)

    try:
        results = migration.migrate_all(
            src_factory, dst_factory,
            batch=args.batch,
            namespaces=namespaces,
        )
    except migration.MigrationError as e:
        log.error(f"migration failed: {e}")
        return 2

    total_rows = 0
    for ns, table_counts in results.items():
        for table, n in table_counts.items():
            total_rows += n
    log.info(f"✅ migration complete: {total_rows} rows copied across "
             f"{len(results)} namespace(s)")
    log.info("Next: run `pypki-admin verify-migration` with the same URLs.")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: verify-migration
# ---------------------------------------------------------------------------

def cmd_verify_migration(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    log = logging.getLogger("pypki.verify-migration")

    src_urls = _resolve_urls(args, "from")
    dst_urls = _resolve_urls(args, "to")
    namespaces = _selected_namespaces(args)

    missing = [ns for ns in namespaces if ns not in src_urls or ns not in dst_urls]
    if missing:
        raise SystemExit(
            f"missing source or destination URL for: {', '.join(missing)}"
        )

    src_factory = _make_factory(src_urls)
    dst_factory = _make_factory(dst_urls)

    errors = migration.verify_all(
        src_factory, dst_factory,
        sample=args.sample,
        namespaces=namespaces,
    )

    total_errors = sum(len(v) for v in errors.values())
    if total_errors == 0:
        log.info(f"✅ verification PASSED for namespaces: {', '.join(namespaces)}")
        return 0

    log.error(f"❌ verification FAILED with {total_errors} error(s)")
    for ns in namespaces:
        for err in errors.get(ns, []):
            log.error(f"  {err}")
    log.error("Migration is NOT safe to commit. Investigate and re-run.")
    return 3


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _add_url_args(p: argparse.ArgumentParser, side: str) -> None:
    """Add the {side}-url group: ca-dir / db-url-tmpl / per-namespace URLs."""
    side_label = "source" if side == "from" else "destination"
    g = p.add_argument_group(
        f"{side_label} URL ({side}-side)",
        f"How to reach the {side_label} databases. "
        f"Use --{side}-ca-dir for the SQLite-only common case, "
        f"--{side}-db-url-tmpl for a Postgres-deployment-per-namespace, "
        f"or per-namespace --{side}-url-NS for full control.",
    )
    g.add_argument(
        f"--{side}-ca-dir", default=None, metavar="DIR",
        help=f"Directory holding the four logical SQLite files "
             f"({', '.join(f for _, f, _ in migration_runner_mod.PYPKI_NAMESPACES)}). "
             f"Resolves to sqlite:///<dir>/<file> per namespace.",
    )
    g.add_argument(
        f"--{side}-db-url-tmpl", default=None, metavar="URL_TMPL",
        help="DAL URL template with literal '{namespace}' placeholder, e.g. "
             "'postgresql://pypki@localhost/pypki_{namespace}'.",
    )
    for ns, _, _ in migration_runner_mod.PYPKI_NAMESPACES:
        g.add_argument(
            f"--{side}-url-{ns}", default=None, metavar="URL",
            help=f"Explicit DAL URL for the '{ns}' namespace. "
                 f"Wins over both --{side}-ca-dir and --{side}-db-url-tmpl.",
        )


def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--namespace", action="append", default=None,
        choices=list(migration.TABLE_CATALOG.keys()),
        help="Limit operation to one or more namespaces (repeat the flag to "
             "select several). Default: all four namespaces.",
    )
    p.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Default INFO.",
    )


def _ceremony_cmd(fn_name: str):
    """Return a wrapper that calls ceremony.<fn_name> or prints an error."""
    def _run(args: argparse.Namespace) -> int:
        _setup_logging(getattr(args, "log_level", "INFO"))
        if not HAS_CEREMONY:
            print("ERROR: ceremony.py not found — place it in the same directory.")
            return 1
        return getattr(_ceremony_mod, f"cmd_{fn_name}")(args)
    return _run


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="pypki-admin",
        description="Offline admin tools for PyPKI deployments.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = root.add_subparsers(dest="command", required=True)

    md = sub.add_parser(
        "migrate-data",
        help="Copy canonical state from one DAL backend to another.",
        description=(
            "Copy all canonical (non-ephemeral) state from a source backend "
            "to a destination. The destination MUST already have its schema "
            "applied at the same version as the source — run "
            "`pypki migrate --db-url <dst>` against each destination DB first."
        ),
    )
    _add_url_args(md, "from")
    _add_url_args(md, "to")
    _add_common_args(md)
    md.add_argument(
        "--batch", type=int, default=10_000,
        help="Rows per batch when copying large tables (default 10000).",
    )
    md.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the 'PyPKI must be stopped' confirmation prompt.",
    )
    md.set_defaults(func=cmd_migrate_data)

    vm = sub.add_parser(
        "verify-migration",
        help="Confirm a destination matches its source after migration.",
        description=(
            "Compare row counts, randomly-sampled row contents, and sequence "
            "state between the source and destination backends. Exit code 0 "
            "means safe to cut over; non-zero means there's drift."
        ),
    )
    _add_url_args(vm, "from")
    _add_url_args(vm, "to")
    _add_common_args(vm)
    vm.add_argument(
        "--sample", type=int, default=100,
        help="Per-table random sample size for content comparison "
             "(default 100). Larger = slower but stronger evidence.",
    )
    vm.set_defaults(func=cmd_verify_migration)

    # ------------------------------------------------------------------
    # Ceremony subcommands (§5.3)
    # ------------------------------------------------------------------

    _cer_help = (
        "§5.3 offline root CA key ceremony. "
        "Requires ceremony.py in the same directory."
    )

    er = sub.add_parser(
        "export-root",
        help="Export offline root CA bundle (§5.3).",
        description=(
            "Package the root CA private key, certificate, and counters "
            "into an AES-256-GCM encrypted tar.gz bundle suitable for "
            "airgapped signing ceremonies."
        ),
    )
    er.add_argument("--ca-dir", default="./ca", metavar="DIR")
    er.add_argument("--out", required=True, metavar="BUNDLE.tar.gz.enc",
                    help="Output path for the encrypted bundle.")
    er.add_argument("--passphrase-env", default=None, metavar="ENV_VAR",
                    help="Read passphrase from this environment variable instead of prompting.")
    er.add_argument("--threshold", type=int, default=0, metavar="M",
                    help="Shamir M-of-N threshold (≥2 to enable splitting).")
    er.add_argument("--shares", type=int, default=0, metavar="N",
                    help="Total Shamir shares to generate.")
    er.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    er.set_defaults(func=_ceremony_cmd("export_root"))

    sc = sub.add_parser(
        "sign-csr",
        help="Sign a sub-CA CSR from the offline bundle (§5.3).",
        description=(
            "Decrypt the offline root bundle and issue a sub-CA certificate "
            "for the supplied CSR.  Runs entirely from the bundle; "
            "no DB writes, no network access required."
        ),
    )
    sc.add_argument("--bundle", required=True, metavar="BUNDLE.tar.gz.enc")
    sc.add_argument("--csr-in", required=True, metavar="CSR.pem")
    sc.add_argument("--cert-out", required=True, metavar="CERT.pem")
    sc.add_argument("--passphrase-env", default=None, metavar="ENV_VAR")
    sc.add_argument("--share", action="append", default=[], metavar="SHARE",
                    help="Shamir share (repeat M times to reconstruct passphrase).")
    sc.add_argument("--validity-days", type=int, default=1825, metavar="N")
    sc.add_argument("--path-length", type=int, default=None, metavar="N")
    sc.add_argument("--permitted-dns", nargs="+", default=[], metavar="DOMAIN")
    sc.add_argument("--excluded-dns", nargs="+", default=[], metavar="DOMAIN")
    sc.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sc.set_defaults(func=_ceremony_cmd("sign_csr"))

    ic = sub.add_parser(
        "import-cert",
        help="Import a ceremony-signed cert into an online CA (§5.3).",
    )
    ic.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ic.add_argument("--cert-in", required=True, metavar="CERT.pem")
    ic.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ic.set_defaults(func=_ceremony_cmd("import_cert"))

    op = sub.add_parser(
        "ocsp-prebuild",
        help="Pre-generate OCSP response files for static serving (RFC 5019 §6).",
        description=(
            "Generate one signed .ocsp file per certificate in the CA database. "
            "Files are written under OUTPUT/<sha1-issuer-key>/<sha1-issuer-name>/<serial>.ocsp, "
            "a layout compatible with nginx proxy_cache and Apache mod_ssl_ct static serving."
        ),
    )
    op.add_argument(
        "--ca-dir", default="./ca", metavar="DIR",
        help="CA data directory (default: ./ca).",
    )
    op.add_argument(
        "--output", required=True, metavar="DIR",
        help="Root directory for generated .ocsp files.",
    )
    op.add_argument(
        "--validity-hours", type=int, default=24, metavar="N",
        help="nextUpdate = now + N hours (default 24).",
    )
    op.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Default INFO.",
    )
    op.set_defaults(func=cmd_ocsp_prebuild)

    # ------------------------------------------------------------------
    # Audit-chain subcommands
    # ------------------------------------------------------------------

    av = sub.add_parser(
        "audit-verify",
        help="Verify the hash chain integrity of the audit log.",
        description=(
            "Walk audit rows in insertion order and recompute each hash. "
            "Exit code 0 = chain intact; 2 = breaks detected. "
            "Breaks indicate tampering, deletion, or a concurrency bug."
        ),
    )
    av.add_argument("--ca-dir", default="./ca", metavar="DIR",
                    help="CA data directory (default: ./ca).")
    av.add_argument("--audit-db-url", default=None, metavar="URL",
                    help="Explicit audit DB URL (overrides ca-dir default).")
    av.add_argument("--from-id", type=int, default=1, metavar="N",
                    help="Start verification at row id N (default 1).")
    av.add_argument("--to-id", type=int, default=None, metavar="M",
                    help="Stop at row id M inclusive (default: last row).")
    av.add_argument("--json", dest="json_output", action="store_true",
                    help="Emit JSON instead of human-readable output.")
    av.add_argument("--log-level", default="WARNING",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    av.set_defaults(func=cmd_audit_verify)

    ae = sub.add_parser(
        "audit-export",
        help="Export a chain segment with its final hash.",
        description=(
            "Write a JSON document containing the requested audit rows plus "
            "the final_hash so operators can publish an external anchor "
            "(git commit, S3 object, transparency log entry)."
        ),
    )
    ae.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ae.add_argument("--audit-db-url", default=None, metavar="URL")
    ae.add_argument("--since", default=None, metavar="ISO8601",
                    help="Include rows with ts >= this ISO-8601 timestamp.")
    ae.add_argument("--from-id", type=int, default=1, metavar="N")
    ae.add_argument("--to-id", type=int, default=None, metavar="M")
    ae.add_argument("--out", default="-", metavar="FILE",
                    help="Output path; '-' writes to stdout (default).")
    ae.add_argument("--log-level", default="WARNING",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ae.set_defaults(func=cmd_audit_export)

    asw = sub.add_parser(
        "ari-set-window",
        help="Set or override the ARI renewal window for a specific certificate.",
        description=(
            "Write an admin override for the suggestedWindow returned by "
            "GET /acme/renewal-info/{certId}. Use this during incident response "
            "to force clients to renew immediately (set end in the past) or "
            "to extend the normal window."
        ),
    )
    asw.add_argument("cert_id", metavar="CERT_ID",
                     help="RFC 9773 certId: base64url(AKI).base64url(serial).")
    asw.add_argument("--start", required=True, metavar="ISO8601",
                     help="Window start (ISO-8601 UTC, e.g. 2026-06-01T00:00:00Z).")
    asw.add_argument("--end", required=True, metavar="ISO8601",
                     help="Window end (ISO-8601 UTC).")
    asw.add_argument("--retry-after", type=int, default=21600, metavar="SECONDS",
                     help="Retry-After seconds for clients (default: 21600).")
    asw.add_argument("--explanation", default=None, metavar="URL",
                     help="Optional explanationURL to include in the response.")
    asw.add_argument("--set-by", default="admin", metavar="USER",
                     help="Who set the override (audit trail, default: admin).")
    asw.add_argument("--ca-dir", default="./ca", metavar="DIR")
    asw.add_argument("--acme-db-url", default=None, metavar="URL",
                     help="Explicit ACME DB URL (overrides ca-dir default).")
    asw.add_argument("--log-level", default="WARNING",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    asw.set_defaults(func=cmd_ari_set_window)

    abs_ = sub.add_parser(
        "ari-bulk-shorten",
        help="Force immediate renewal for all matching certificates (incident response).",
        description=(
            "Set the suggestedWindow.end to now (or a specified time) for all "
            "certificates whose certId matches the given SQL LIKE pattern. "
            "Used when a CA must revoke a population of certs on a deadline."
        ),
    )
    abs_.add_argument("--filter", required=True, metavar="PATTERN",
                      help="SQL LIKE pattern matched against certId (e.g. 'abc123.%%').")
    abs_.add_argument("--end", default=None, metavar="ISO8601",
                      help="Override window end (default: now — forces immediate renewal).")
    abs_.add_argument("--retry-after", type=int, default=300, metavar="SECONDS",
                      help="Retry-After seconds during incident (default: 300).")
    abs_.add_argument("--explanation", default=None, metavar="URL",
                      help="Incident explanation URL to surface to clients.")
    abs_.add_argument("--set-by", default="admin", metavar="USER")
    abs_.add_argument("--ca-dir", default="./ca", metavar="DIR")
    abs_.add_argument("--acme-db-url", default=None, metavar="URL")
    abs_.add_argument("--log-level", default="WARNING",
                      choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    abs_.set_defaults(func=cmd_ari_bulk_shorten)

    return root


def cmd_ocsp_prebuild(args: argparse.Namespace) -> int:
    """Pre-generate one OCSP response file per certificate in the CA."""
    _setup_logging(args.log_level)
    try:
        from pki_server import CertificateAuthority, ServerConfig
    except ImportError:
        print("ERROR: pki_server.py not found — place it in the same directory.")
        return 1
    try:
        import ocsp_server
    except ImportError:
        print("ERROR: ocsp_server.py not found — place it in the same directory.")
        return 1

    ca_dir = Path(args.ca_dir)
    if not ca_dir.is_dir():
        print(f"ERROR: CA directory not found: {ca_dir}")
        return 1

    config = ServerConfig(ca_dir=ca_dir)
    ca = CertificateAuthority(ca_dir=str(ca_dir), config=config)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    count = ocsp_server.generate_static_responses(
        ca=ca,
        output_dir=out,
        validity_hours=args.validity_hours,
    )
    print(f"Wrote {count} OCSP response(s) to {out}")
    return 0


def _audit_db(args: argparse.Namespace):
    """Return an open Database for the audit log."""
    from pathlib import Path as _P
    url = getattr(args, "audit_db_url", None)
    if not url:
        ca_dir = _P(getattr(args, "ca_dir", "./ca"))
        url = f"sqlite:///{ca_dir / 'audit.db'}"
    return db.make_db(url)


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify hash chain integrity. Exit 0 = ok; 2 = breaks found."""
    import json as _json
    import time as _time
    _setup_logging(args.log_level)
    try:
        import audit_chain
    except ImportError:
        print("ERROR: audit_chain.py not found.")
        return 1

    d = _audit_db(args)
    try:
        t0 = _time.monotonic()
        report = audit_chain.verify_chain(d, start_id=args.from_id, end_id=args.to_id)
        elapsed = _time.monotonic() - t0
    finally:
        d.close()

    end_id_str = str(args.to_id) if args.to_id else "last"
    if args.json_output:
        out = {
            "rows_checked": report.rows_checked,
            "ok": report.ok,
            "elapsed_s": round(elapsed, 3),
            "final_hash": report.final_hash,
            "breaks": [
                {"id": b.id, "kind": b.kind, "expected": b.expected, "found": b.found}
                for b in report.breaks
            ],
        }
        print(_json.dumps(out, indent=2))
    else:
        print(f"Verified rows {args.from_id}..{end_id_str} in {elapsed:.1f}s")
        if report.ok:
            print("Chain intact.")
            print(f"Final hash: {report.final_hash[:16]}...{report.final_hash[-4:]}")
        else:
            first = report.breaks[0]
            print(f"CHAIN BROKEN at row {first.id}:")
            print(f"  {first.kind}: expected {first.expected[:16]}..., "
                  f"found {first.found[:16] if first.found else '(null)'}...")
            subsequent = sum(
                1 for b in report.breaks[1:] if b.id > first.id
            )
            if subsequent:
                print(f"{subsequent} subsequent row(s) are unverifiable from this point.")

    return 0 if report.ok else 2


def cmd_audit_export(args: argparse.Namespace) -> int:
    """Export a chain segment as JSON."""
    import json as _json
    import sys as _sys
    _setup_logging(args.log_level)
    try:
        import audit_chain
    except ImportError:
        print("ERROR: audit_chain.py not found.")
        return 1

    d = _audit_db(args)
    try:
        payload = audit_chain.export_chain(
            d,
            since=args.since,
            start_id=args.from_id,
            end_id=args.to_id,
        )
    finally:
        d.close()

    text = _json.dumps(payload, indent=2)
    if args.out == "-":
        print(text)
    else:
        from pathlib import Path as _P
        _P(args.out).write_text(text, encoding="utf-8")
        print(f"Exported {len(payload['rows'])} row(s) to {args.out}")
    return 0


def _acme_db(args: argparse.Namespace):
    """Return an open ACME Database object from args."""
    from pathlib import Path as _P
    url = getattr(args, "acme_db_url", None)
    if not url:
        ca_dir = _P(getattr(args, "ca_dir", "./ca"))
        url = f"sqlite:///{ca_dir / 'acme.db'}"
    try:
        import acme_server
    except ImportError:
        print("ERROR: acme_server.py not found — place it in the same directory.")
        raise SystemExit(1)
    return acme_server.ACMEDatabase(url)


def cmd_ari_set_window(args: argparse.Namespace) -> int:
    """Set or update the ARI renewal-window override for one certificate."""
    _setup_logging(args.log_level)
    try:
        acme_db = _acme_db(args)
    except SystemExit:
        return 1

    acme_db.set_renewal_override(
        cert_id_str=args.cert_id,
        window_start=args.start,
        window_end=args.end,
        retry_after=args.retry_after,
        explanation=args.explanation,
        set_by=args.set_by,
    )
    print(
        f"Override set for {args.cert_id}: "
        f"window=[{args.start}, {args.end}] retry_after={args.retry_after}s"
    )
    return 0


def cmd_ari_bulk_shorten(args: argparse.Namespace) -> int:
    """Force immediate renewal for all certificates matching a certId pattern."""
    import datetime as _dt
    _setup_logging(args.log_level)
    try:
        acme_db = _acme_db(args)
    except SystemExit:
        return 1

    now_str = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = args.end if args.end else now_str

    # Find all certIds matching the pattern (LIKE query on overrides + certs tables)
    rows = acme_db._db.fetchall(
        "SELECT DISTINCT cert_id FROM acme_renewal_overrides WHERE cert_id LIKE ?",
        (args.filter,),
    )
    cert_ids_from_overrides = {r["cert_id"] for r in rows}

    # Also search the certificates table by constructing certIds
    # for certs whose serial matches the AKI pattern portion.
    # Simpler: bulk-set overrides for cert_ids already in the override table,
    # then let the operator also pass explicit cert_ids for new ones.
    count = 0
    for row in rows:
        cid = row["cert_id"]
        acme_db.set_renewal_override(
            cert_id_str=cid,
            window_start=now_str,
            window_end=end_str,
            retry_after=args.retry_after,
            explanation=args.explanation,
            set_by=args.set_by,
        )
        count += 1

    # Also update any certs not yet in overrides whose cert_id matches the pattern.
    # We scan acme_replacements.new_serial and certificates.serial to compute certIds.
    try:
        import acme_server as _acme
        from cryptography import x509 as _x509
        cert_rows = acme_db._db.fetchall("SELECT pem_chain, serial FROM certificates")
        for cr in cert_rows:
            end_marker = "-----END CERTIFICATE-----"
            pem = cr["pem_chain"].split(end_marker)[0].strip() + "\n" + end_marker
            try:
                cert_obj = _x509.load_pem_x509_certificate(pem.encode())
                cid = _acme.cert_id_from_cert(cert_obj)
            except Exception:
                continue
            if cid is None:
                continue
            # Apply LIKE matching (simple: use SQL fnmatch-style %)
            import fnmatch
            pat = args.filter.replace("%", "*").replace("_", "?")
            if not fnmatch.fnmatch(cid, pat):
                continue
            if cid in cert_ids_from_overrides:
                continue  # already updated above
            acme_db.set_renewal_override(
                cert_id_str=cid,
                window_start=now_str,
                window_end=end_str,
                retry_after=args.retry_after,
                explanation=args.explanation,
                set_by=args.set_by,
            )
            count += 1
    except Exception as e:
        print(f"WARNING: cert scan failed: {e}")

    print(f"Bulk-shorten: set window_end={end_str} on {count} certificate(s).")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
