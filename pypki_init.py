"""
First-run bootstrap CLI (CLAUDE-bootstrap-cli.md).

Usage:
  pypki_init.py --homelab
  pypki_init.py --enterprise
  pypki_init.py --from-answers /etc/pypki/init-answers.yaml
  pypki_init.py --dry-run --homelab
  pypki_init.py --print-defaults
"""
from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default answers for homelab mode
# ---------------------------------------------------------------------------

HOMELAB_DEFAULTS = {
    "topology": "homelab",
    "ca_hierarchy": "single-root",
    "ca_key_type": "ec-p256",
    "ca_validity_years": 30,
    "key_backend": "file",
    "db_backend": "sqlite",
    "auth_backend": "pam",
    "tls_mode": "self-bootstrap",
    "tls_hostname": "localhost",
    "admin_port": 8443,
    "backup_target": "file:///var/lib/pypki/backups/",
    "hardening_level": "standard",
    "log_format": "text",
    "audit_chain": True,
    "web_ui": True,
    "state_dir": "/var/lib/pypki",
    "config_dir": "/etc/pypki",
}


def _write_answers_yaml(answers: dict, path: Path) -> None:
    """Write answers as YAML (stdlib only)."""
    from wizard import _to_yaml
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    doc = {
        "format_version": 1,
        "created_at": now,
        "created_by": "pypki init",
        "deployment": {
            "topology": answers.get("topology", "homelab"),
            "state_dir": answers.get("state_dir", "/var/lib/pypki"),
            "config_dir": answers.get("config_dir", "/etc/pypki"),
        },
        "ca_hierarchy": {
            "type": answers.get("ca_hierarchy", "single-root"),
            "key_type": answers.get("ca_key_type", "ec-p256"),
            "validity_years": answers.get("ca_validity_years", 30),
            "backend": answers.get("key_backend", "file"),
        },
        "db": {"backend": answers.get("db_backend", "sqlite")},
        "auth": {"backends": [answers.get("auth_backend", "pam")]},
        "tls": {
            "mode": answers.get("tls_mode", "self-bootstrap"),
            "hostname": answers.get("tls_hostname", "localhost"),
        },
        "ports": {
            "admin": answers.get("admin_port", 8443),
        },
        "backup": {
            "targets": [answers.get("backup_target", "file:///var/lib/pypki/backups/")],
            "schedule": "daily",
            "retention_days": 90,
        },
        "hardening": {
            "level": answers.get("hardening_level", "standard"),
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_to_yaml(doc))


def _detect_existing(state_dir: Path, config_dir: Path) -> dict:
    from bootstrap.ca_setup import detect_existing_state
    return detect_existing_state(state_dir, config_dir)


def run_homelab(answers: dict, *, dry_run: bool = False) -> int:
    """Execute homelab bootstrap in ≤60 seconds."""
    state_dir = Path(answers["state_dir"])
    config_dir = Path(answers["config_dir"])
    ca_dir = state_dir / "ca"

    # Check for existing state
    existing = _detect_existing(state_dir, config_dir)
    if any(existing.values()) and not dry_run:
        log.error(
            "Existing state detected: %s\n"
            "Use --resume, --reconfigure, or --force-reset --i-understand.",
            {k: v for k, v in existing.items() if v},
        )
        return 1

    log.info("=== PyPKI Homelab Init ===")

    # 1. DB
    log.info("[1/6] Initializing database...")
    from bootstrap.db_setup import setup_db
    db_url = setup_db(
        backend=answers["db_backend"],
        state_dir=state_dir,
        dry_run=dry_run,
    )
    log.info("  DB: %s", db_url)

    # 2. CA
    log.info("[2/6] Initializing CA...")
    from bootstrap.ca_setup import setup_ca
    setup_ca(
        ca_dir=ca_dir,
        ca_key_type=answers.get("ca_key_type", "ec-p256"),
        ca_name="PyPKI Root CA",
        validity_years=answers.get("ca_validity_years", 30),
        dry_run=dry_run,
    )

    # 3. TLS bootstrap cert
    log.info("[3/6] Generating TLS bootstrap cert...")
    tls_dir = config_dir / "tls"
    from bootstrap.tls_setup import setup_bootstrap_tls
    cert_path, key_path = setup_bootstrap_tls(
        hostname=answers.get("tls_hostname", "localhost"),
        tls_dir=tls_dir,
        dry_run=dry_run,
    )

    # 4. Write init-answers.yaml
    log.info("[4/6] Writing init-answers.yaml...")
    answers_path = config_dir / "init-answers.yaml"
    if not dry_run:
        _write_answers_yaml(answers, answers_path)

    # 5. Systemd unit
    log.info("[5/6] Installing systemd unit...")
    from bootstrap.systemd_setup import install_systemd_unit
    install_systemd_unit(dry_run=dry_run)

    # 6. Firewall
    log.info("[6/6] Applying firewall rules...")
    from bootstrap.firewall_setup import apply_firewall_template
    apply_firewall_template(dry_run=dry_run)

    print("\n✓ PyPKI homelab init complete!")
    print(f"  CA dir:    {ca_dir}")
    print(f"  DB:        {db_url}")
    print(f"  TLS cert:  {cert_path}")
    print(f"  Answers:   {answers_path}")
    print("\nNext: systemctl start pypki.service")
    return 0


def run_enterprise(*, dry_run: bool = False, resume: bool = False) -> int:
    """Run the interactive enterprise wizard then execute init."""
    config_dir = Path("/etc/pypki")
    state_dir = Path("/var/lib/pypki")
    answers_path = config_dir / ".wizard-progress.json"

    from wizard import Wizard
    w = Wizard(answers_path=answers_path, resume=resume)
    answers = w.run()

    # Write final answers.yaml
    final_path = config_dir / "init-answers.yaml"
    if not dry_run:
        _write_answers_yaml(answers, final_path)
        # Clean up wizard progress
        if answers_path.exists():
            answers_path.unlink()

    # Merge with homelab defaults for missing keys
    full_answers = {**HOMELAB_DEFAULTS, **answers,
                    "state_dir": str(state_dir),
                    "config_dir": str(config_dir)}
    return run_homelab(full_answers, dry_run=dry_run)


def run_from_answers(answers_file: Path, *, dry_run: bool = False) -> int:
    """Replay init from an existing answers file."""
    if not answers_file.exists():
        log.error("Answers file not found: %s", answers_file)
        return 1

    data = json.loads(answers_file.read_text())
    if data.get("format_version", 0) < 1:
        log.error("Unsupported answers file format version: %s", data.get("format_version"))
        return 1

    # Flatten nested structure into flat answers dict
    answers = {**HOMELAB_DEFAULTS}
    dep = data.get("deployment", {})
    answers["state_dir"] = dep.get("state_dir", answers["state_dir"])
    answers["config_dir"] = dep.get("config_dir", answers["config_dir"])

    ca = data.get("ca_hierarchy", {})
    answers["ca_hierarchy"] = ca.get("type", answers["ca_hierarchy"])
    answers["ca_key_type"] = ca.get("key_type", answers["ca_key_type"])

    answers["db_backend"] = data.get("db", {}).get("backend", answers["db_backend"])
    answers["tls_mode"] = data.get("tls", {}).get("mode", answers["tls_mode"])
    answers["tls_hostname"] = data.get("tls", {}).get("hostname", answers["tls_hostname"])
    answers["hardening_level"] = data.get("hardening", {}).get("level", answers["hardening_level"])

    return run_homelab(answers, dry_run=dry_run)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="PyPKI first-run bootstrap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  pypki_init.py --homelab\n"
            "  pypki_init.py --enterprise\n"
            "  pypki_init.py --from-answers /etc/pypki/init-answers.yaml\n"
            "  pypki_init.py --dry-run --homelab\n"
        ),
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--homelab", action="store_true",
                      help="Unattended homelab bootstrap with opinionated defaults")
    mode.add_argument("--enterprise", action="store_true",
                      help="Interactive enterprise wizard")
    mode.add_argument("--from-answers", metavar="FILE",
                      help="Replay from an existing init-answers.yaml")
    mode.add_argument("--print-defaults", action="store_true",
                      help="Print homelab default answers as YAML and exit")

    p.add_argument("--dry-run", action="store_true",
                   help="Print what would happen without making changes")
    p.add_argument("--resume", action="store_true",
                   help="Resume a partial enterprise wizard from saved progress")
    p.add_argument("--reconfigure", action="store_true",
                   help="Re-run wizard with existing answers as defaults (update mode)")
    p.add_argument("--force-reset", action="store_true",
                   help="Destroy existing state and re-initialize (destructive!)")
    p.add_argument("--i-understand", action="store_true",
                   help="Required with --force-reset to confirm destructive intent")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    # Homelab overrides
    p.add_argument("--hostname", default=None, metavar="FQDN",
                   help="Hostname for TLS cert SAN (default: localhost)")
    p.add_argument("--state-dir", default="/var/lib/pypki", metavar="DIR")
    p.add_argument("--config-dir", default="/etc/pypki", metavar="DIR")
    p.add_argument("--db-backend", default="sqlite", choices=["sqlite", "postgres"])
    p.add_argument("--key-type", default="ec-p256",
                   choices=["ec-p256", "ec-p384", "rsa-2048", "rsa-4096", "ed25519"])

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s: %(message)s",
    )

    if args.print_defaults:
        from wizard import _to_yaml
        print(_to_yaml(HOMELAB_DEFAULTS))
        return 0

    if args.force_reset and not args.i_understand:
        log.error("--force-reset requires --i-understand (this destroys all CA data!)")
        return 1

    if args.homelab:
        answers = dict(HOMELAB_DEFAULTS)
        answers["state_dir"] = args.state_dir
        answers["config_dir"] = args.config_dir
        answers["db_backend"] = args.db_backend
        answers["ca_key_type"] = args.key_type
        if args.hostname:
            answers["tls_hostname"] = args.hostname
        return run_homelab(answers, dry_run=args.dry_run)

    if args.enterprise:
        return run_enterprise(dry_run=args.dry_run, resume=args.resume)

    if args.from_answers:
        return run_from_answers(Path(args.from_answers), dry_run=args.dry_run)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
