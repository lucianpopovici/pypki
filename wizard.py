"""
Enterprise init wizard (CLAUDE-bootstrap-cli.md).

Walks through the meaningful deployment choices via an interactive Q&A,
writes an init-answers.yaml after every answer (crash-safe), and returns
a dict of all answers for the init runner to act on.

No Jinja, no yaml library — uses stdlib json for state, a simple flat-YAML
writer for the output file.
"""
from __future__ import annotations

import datetime
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Simple YAML writer (stdlib only — no pyyaml dep)
# ---------------------------------------------------------------------------

def _to_yaml(obj: Any, indent: int = 0) -> str:
    prefix = "  " * indent
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        lines = []
        for k, v in obj.items():
            val = _to_yaml(v, indent + 1)
            if isinstance(v, dict) and v:
                lines.append(f"{prefix}{k}:")
                lines.append(val)
            elif isinstance(v, list) and v:
                lines.append(f"{prefix}{k}:")
                lines.append(val)
            else:
                lines.append(f"{prefix}{k}: {val}")
        return "\n".join(lines)
    if isinstance(obj, list):
        if not obj:
            return "[]"
        items = []
        for item in obj:
            val = _to_yaml(item, indent + 1)
            items.append(f"{prefix}- {val.lstrip()}")
        return "\n".join(items)
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if obj is None:
        return "null"
    if isinstance(obj, (int, float)):
        return str(obj)
    # String — quote if contains special chars
    s = str(obj)
    if any(c in s for c in (':', '#', '{', '}', '[', ']', ',', '&', '*', '?', '|', '-', '<', '>', '=')):
        return f'"{s}"'
    return s


# ---------------------------------------------------------------------------
# Question runner
# ---------------------------------------------------------------------------

class Wizard:
    """Interactive question runner with crash-safe answer persistence."""

    QUESTIONS = [
        {
            "key": "topology",
            "prompt": "Deployment topology",
            "choices": ["homelab", "single-vm-enterprise", "ha-enterprise", "kubernetes"],
            "default": "single-vm-enterprise",
            "help": (
                "homelab: SQLite, file keys, 30-minute setup.\n"
                "single-vm-enterprise: Postgres, HSM/KMS, two NICs.\n"
                "ha-enterprise: Multiple nodes, Patroni Postgres, cloud KMS.\n"
                "kubernetes: Helm chart, Postgres operator, cert-manager."
            ),
        },
        {
            "key": "ca_hierarchy",
            "prompt": "CA hierarchy",
            "choices": ["single-root", "two-tier", "three-tier", "import-existing"],
            "default": "two-tier",
            "help": (
                "single-root: One CA, simpler. Good for homelab.\n"
                "two-tier: Offline root + online intermediate (recommended).\n"
                "three-tier: Root + intermediate + policy CAs.\n"
                "import-existing: Import an existing CA cert+key."
            ),
        },
        {
            "key": "key_backend",
            "prompt": "Intermediate CA key backend",
            "choices": ["file", "pkcs11", "aws-kms", "gcp-kms", "azure-kv"],
            "default": "file",
            "help": (
                "file: Key stored on disk (encrypted with passphrase).\n"
                "pkcs11: Hardware security module (YubiHSM2, nShield, Luna).\n"
                "aws-kms: AWS KMS (asymmetric key, CloudHSM optional).\n"
                "gcp-kms: GCP Cloud KMS.\n"
                "azure-kv: Azure Key Vault."
            ),
        },
        {
            "key": "db_backend",
            "prompt": "Database backend",
            "choices": ["sqlite", "postgres"],
            "default": "sqlite",
            "help": (
                "sqlite: File-based, zero config, great for single-node.\n"
                "postgres: Multi-node, HA, point-in-time recovery."
            ),
        },
        {
            "key": "auth_backend",
            "prompt": "Authentication backend",
            "choices": ["pam", "oidc", "both"],
            "default": "pam",
            "help": (
                "pam: Local Unix users; simple, no external deps.\n"
                "oidc: Federated (Keycloak, Okta, Entra ID).\n"
                "both: PAM for local emergency access + OIDC for normal ops."
            ),
        },
        {
            "key": "tls_mode",
            "prompt": "TLS termination mode",
            "choices": ["self-bootstrap", "external-frontend", "external-cert"],
            "default": "self-bootstrap",
            "help": (
                "self-bootstrap: PyPKI issues its own admin cert from its own CA (homelab default).\n"
                "external-frontend: nginx/Traefik terminates TLS (Let's Encrypt recommended).\n"
                "external-cert: You provide cert+key from a corporate CA."
            ),
        },
        {
            "key": "backup_target",
            "prompt": "Backup target URI",
            "choices": None,  # free text
            "default": "file:///var/lib/pypki/backups/",
            "help": (
                "Examples:\n"
                "  file:///var/lib/pypki/backups/\n"
                "  s3://my-bucket/pypki/\n"
                "  azure://container/pypki/"
            ),
        },
        {
            "key": "hardening_level",
            "prompt": "Hardening level",
            "choices": ["standard", "paranoid"],
            "default": "standard",
            "help": (
                "standard: systemd hardening directives (most deployments).\n"
                "paranoid: Adds AppArmor/SELinux enforcement; may need tweaking for edge features."
            ),
        },
    ]

    def __init__(
        self,
        answers_path: Path,
        *,
        resume: bool = False,
        non_interactive: bool = False,
    ) -> None:
        self._answers_path = answers_path
        self._answers: dict[str, Any] = {}
        self._non_interactive = non_interactive

        if resume and answers_path.exists():
            saved = json.loads(answers_path.read_text())
            self._answers = saved.get("answers", {})

    def run(self) -> dict[str, Any]:
        """Ask all unanswered questions; return the full answers dict."""
        print("\nPyPKI Enterprise Setup Wizard")
        print("=" * 40)
        print("Press ? at any prompt for an explanation.")
        print("Press Enter to accept the default.\n")

        for q in self.QUESTIONS:
            if q["key"] in self._answers:
                print(f"  {q['prompt']}: {self._answers[q['key']]} (from saved answers)")
                continue

            answer = self._ask(q)
            self._answers[q["key"]] = answer
            self._save_progress()

        return dict(self._answers)

    def _ask(self, q: dict) -> Any:
        choices = q.get("choices")
        default = q.get("default")
        prompt = q["prompt"]

        if choices:
            display = "/".join(
                f"[{c}]" if c == default else c for c in choices
            )
            full_prompt = f"  {prompt} ({display}): "
        else:
            full_prompt = f"  {prompt} [{default}]: "

        while True:
            if self._non_interactive:
                print(f"{full_prompt}{default}")
                return default

            try:
                raw = input(full_prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.")
                sys.exit(1)

            if raw == "?":
                print(f"\n  {q.get('help', 'No additional help available.')}\n")
                continue

            if not raw:
                return default

            if choices and raw not in choices:
                print(f"  Invalid choice. Options: {', '.join(choices)}")
                continue

            return raw

    def _save_progress(self) -> None:
        self._answers_path.parent.mkdir(parents=True, exist_ok=True)
        self._answers_path.write_text(
            json.dumps(
                {
                    "format_version": 1,
                    "saved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "answers": self._answers,
                },
                indent=2,
            )
        )

    def to_yaml(self) -> str:
        """Render answers as YAML for init-answers.yaml."""
        answers = dict(self._answers)
        doc = {
            "format_version": 1,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "created_by": "pypki init/wizard",
            "deployment": {
                "topology": answers.get("topology", "homelab"),
                "state_dir": "/var/lib/pypki",
                "config_dir": "/etc/pypki",
            },
            "ca_hierarchy": {
                "type": answers.get("ca_hierarchy", "two-tier"),
            },
            "db": {
                "backend": answers.get("db_backend", "sqlite"),
            },
            "auth": {
                "backends": answers.get("auth_backend", "pam").split("+"),
            },
            "tls": {
                "mode": answers.get("tls_mode", "self-bootstrap"),
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
        return _to_yaml(doc)
