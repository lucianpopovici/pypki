# CLAUDE-bootstrap-cli.md — First-Run Bootstrap CLI (`pypki init`)

Companion to `CLAUDE.md`. Follow all conventions there. The single
biggest UX gap in PyPKI today: going from `git clone` to "working CA"
takes too many manual steps and too much reading. This spec closes
that gap with a two-mode entry point and reproducible config output.

---

## What this is

A new top-level command `pypki init` that produces a working
deployment in one of two modes:

- `pypki init --homelab` — runs unattended with opinionated defaults.
  60 seconds from invocation to "you can issue your first cert."
- `pypki init --enterprise` — interactive wizard. Walks through the
  meaningful choices (CA hierarchy, key backend, DB backend, auth
  backend), explains each, and emits a complete config tree, systemd
  unit, and ready-to-run setup.

Both modes write an `init-answers.yaml` capturing every decision so
the same setup can be reproduced unattended in CI or staging
(`pypki init --from-answers init-answers.yaml`).

The init flow is idempotent: rerunning it on an already-bootstrapped
system detects existing state, prompts for confirmation, and either
no-ops or runs the documented re-init recovery path.

---

## Homelab mode defaults

| Decision           | Default                                                  |
| ------------------ | -------------------------------------------------------- |
| CA hierarchy       | Single root, 30-year validity, ECDSA P-256               |
| Key backend        | File, passphrase-encrypted (prompt at init)              |
| DB backend         | SQLite at `/var/lib/pypki/db/pki.db`                     |
| Auth backend       | PAM, one admin user (current user if interactive, else `pypki-admin` w/ password prompt) |
| TLS                | Self-signed bootstrap cert, 24h, auto-rotates to own-CA-issued |
| Ports              | 8443 (admin + API + ACME), 80 (ACME http-01 only)        |
| State directory    | `/var/lib/pypki/`                                        |
| Config directory   | `/etc/pypki/`                                            |
| Service supervisor | systemd if PID 1 is systemd, else printed run command    |
| Backup target      | `file:///var/lib/pypki/backups/`, weekly                 |
| Audit chain        | Enabled                                                  |
| Web UI             | Enabled at `/admin/`                                     |

These defaults are deliberately conservative. Operators who outgrow
homelab move to `--enterprise` by running `pypki init --upgrade-mode`
which re-runs the wizard with the existing answers as starting points.

---

## Enterprise wizard

Question sequence, in order. Each question shows its rationale and
defaults; answers persist to `init-answers.yaml` after every step so
a crash mid-wizard resumes from the last answered question.

1. **Deployment topology** — single-VM, HA-cluster, Kubernetes. Links
   to `CLAUDE-deployment-topologies.md` for the implications of each.
2. **CA hierarchy** — single root, two-tier (offline root +
   intermediate), three-tier (root + intermediate + policy CAs),
   import existing CA. Default: two-tier.
3. **Root key ceremony** — interactive at this terminal,
   air-gapped (write key material to USB and return signed CSR), or
   import. If air-gapped, the wizard emits a script bundle for the
   air-gapped machine.
4. **Shamir splitting for root** — y/n; if y, prompt for `m, n` and
   collect share-holder identities (free-text). Links to
   `CLAUDE-backup-restore.md` for the ceremony.
5. **Intermediate key backend** — file, PKCS#11 (prompts for
   `slot-id`, label, PIN source), AWS KMS (prompts for region, ARN,
   auth mechanism), GCP Cloud KMS (project, location, keyring, key,
   version, auth), Azure Key Vault (URL, key name, version, auth).
   Verifies connectivity before continuing.
6. **DB backend** — SQLite or Postgres. Postgres prompts for DSN,
   tests connection, runs `db-init` automatically.
7. **Auth backend** — PAM, OIDC (prompts for issuer, client ID,
   secret source, audience, role-mapping claim), or both (PAM for
   local, OIDC for federated). Verifies OIDC discovery URL.
8. **TLS termination** — self-bootstrap (PyPKI issues its own admin
   cert), Let's Encrypt via nginx, external CA (operator provides
   cert+key paths). Links to `CLAUDE-tls-bootstrap.md`.
9. **Ports and binding** — admin port, public port, bind address.
   Defaults to `0.0.0.0:443` admin + `0.0.0.0:80` for ACME.
10. **Backup configuration** — target URI(s), passphrase source,
    recipient public keys, schedule, retention. Verifies write access
    to each target.
11. **Observability** — Prometheus endpoint, OTel collector URL (if
    any), log destination (journald, file, syslog, stdout for
    containers).
12. **Hardening level** — `standard` (systemd hardening directives)
    or `paranoid` (adds AppArmor/SELinux, strict ulimits, additional
    `SystemCallFilter` restrictions, may break edge-case features).
    Default: `standard`.
13. **Review and confirm** — prints the full plan, requires explicit
    `yes` to proceed.

Every prompt accepts `?` for an expanded explanation. Every default is
pre-populated with the most secure reasonable choice; only a deliberate
override picks a weaker option.

---

## `init-answers.yaml`

```yaml
format_version: 1
created_at: "2026-05-25T12:34:56Z"
created_by: "pypki init/wizard"
pypki_version: "x.y.z"

deployment:
  topology: single-vm-enterprise
  state_dir: /var/lib/pypki
  config_dir: /etc/pypki

ca_hierarchy:
  type: two-tier
  root:
    name: "Acme Root CA 2026"
    algorithm: ecdsa-p384
    validity_years: 30
    backend: file
    backend_ref: /var/lib/pypki/ca/root.key
    shamir:
      enabled: true
      shares: 5
      threshold: 3
  intermediates:
    - name: "Acme Internal Intermediate"
      algorithm: ecdsa-p256
      validity_years: 10
      backend: aws-kms
      backend_ref: alias/pypki-intermediate-internal

db:
  backend: postgres
  dsn_source: env://PYPKI_DB_DSN
  tls: required

auth:
  backends: [pam, oidc]
  oidc:
    issuer: https://accounts.example.com
    client_id: pypki
    client_secret_source: file:///etc/pypki/secrets/oidc.secret
    audience: pypki
    role_map:
      pki-admins: pki:admin
      pki-ops: pki:operator

tls:
  mode: self-bootstrap
  admin_cert_profile: tls_server
  admin_san: pki.example.com

ports:
  admin: 8443
  public: 443
  acme_http: 80
  bind_address: 0.0.0.0

backup:
  targets:
    - s3://acme-backups/pypki/
    - file:///var/lib/pypki/backups/
  passphrase_source: file:///etc/pypki/secrets/backup.passphrase
  recipients:
    - age1abc...
    - age1def...
  schedule: daily
  retention_days: 90

observability:
  prometheus:
    enabled: true
    bind: 127.0.0.1:9090
  otel:
    enabled: false
  logging:
    target: journald

hardening:
  level: standard
  systemd_hardening: true
  apparmor: false
  selinux: false

audit:
  chain_enabled: true
  seal_target: file:///var/lib/pypki/audit-seals/
  seal_interval_seconds: 3600
```

Secrets (passphrases, OIDC client secrets, backup keys) are **never**
stored in `init-answers.yaml` — only references to where they live.
This makes the answers file safe to check into infrastructure repos.

---

## What gets created

A successful `init` produces this filesystem layout:

```
/etc/pypki/
├── config.yaml                  # PyPKI runtime config (generated from answers)
├── init-answers.yaml            # the answers file
├── policy.yaml                  # empty/default policy if engine enabled
├── codesign-issuers.yaml        # if code-signing portal enabled
├── secrets/                     # mode 0700, owned by pypki:pypki
│   ├── ca-root.passphrase
│   ├── backup.passphrase
│   └── oidc.secret              # if OIDC enabled
└── tls/
    ├── admin-bootstrap.crt
    └── admin-bootstrap.key

/var/lib/pypki/
├── ca/
│   ├── root.key                 # mode 0600
│   ├── root.crt
│   ├── intermediates/
│   └── audit-seal.key           # for backup signing
├── db/
│   └── pki.db                   # if SQLite
├── backups/
└── audit-seals/

/etc/systemd/system/
└── pypki.service                # if systemd present, see CLAUDE-systemd-hardening.md

/etc/nginx/conf.d/               # if Let's Encrypt TLS selected
└── pypki.conf
```

Plus, depending on selections: AppArmor profile (`/etc/apparmor.d/pypki`),
SELinux module (`/etc/selinux/local/pypki.pp`), firewall rules
(`/etc/nftables.d/pypki.nft` or equivalent — links to
`CLAUDE-os-hardening-firewall.md`).

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `pypki_init.py`   | New top-level CLI entry                                      |
| `wizard.py`       | New module: question runner, answer persistence              |
| `bootstrap/`      | New package with one module per setup concern:               |
|   `ca_setup.py`   | CA hierarchy creation                                        |
|   `db_setup.py`   | Calls into `db_bootstrap` (see CLAUDE-db-bootstrap.md)       |
|   `auth_setup.py` | PAM user / OIDC config                                       |
|   `tls_setup.py`  | Calls into `tls_bootstrap` (see CLAUDE-tls-bootstrap.md)     |
|   `systemd_setup.py` | Calls into `systemd-hardening` (see CLAUDE-systemd-hardening.md) |
|   `firewall_setup.py` | Calls into `os-hardening-firewall`                        |
|   `backup_setup.py` | Verifies backup targets writable, schedules                |
| `templates/`      | Jinja-free templates (str.format) for config files          |
| `test_pypki_init.py` | `TestHomelabInit`, `TestEnterpriseWizard`, `TestAnswersReplay`, `TestIdempotency`, `TestPartialFailureRecovery` |
| `README.md`       | "Quick start: `pypki init --homelab`"                        |
| `CHANGELOG.md`    | `### Added`                                                  |
| `docs/INSTALL.md` | Walkthrough of both modes                                    |

### Idempotency and re-init

Detect existing state at the start of init:

```python
def detect_existing_state(state_dir: Path, config_dir: Path) -> Existing:
    return Existing(
        config_present=(config_dir / "config.yaml").exists(),
        db_present=_db_initialized(state_dir),
        ca_present=_any_ca_keys_present(state_dir),
        running=_is_service_running(),
        answers_present=(config_dir / "init-answers.yaml").exists(),
    )
```

If anything exists, the default action is **refuse** and explain how
to proceed:

- `pypki init --resume` — continues from the last unanswered question
  in a partial wizard.
- `pypki init --reconfigure` — re-runs the wizard with existing
  answers as defaults; updates only the components whose answers
  changed. Doesn't touch the CA hierarchy.
- `pypki init --upgrade-mode` — re-asks the topology question and
  migrates (homelab → enterprise is the supported direction).
- `pypki init --force-reset --i-understand` — nukes everything.
  Documented but loud.

### Partial-failure recovery

If init fails at step N, the answers file is intact and the staged
filesystem changes are in `/var/lib/pypki/.staging/`. On retry:

1. Detect staging dir.
2. Prompt: continue from step N, restart from step N, abandon (clean staging).
3. Continuing re-validates earlier steps (connectivity tests etc.) before resuming.

No step is allowed to modify production state outside `.staging/`
until the final atomic promotion. The promotion step itself is a
single `mv .staging/* .` after every other check passes.

---

## CLI flags

```
pypki init --homelab                          # unattended defaults
pypki init --enterprise                       # interactive wizard
pypki init --from-answers init-answers.yaml   # reproducible replay
pypki init --resume                           # continue partial wizard
pypki init --reconfigure                      # update select choices
pypki init --upgrade-mode                     # homelab → enterprise
pypki init --dry-run                          # print plan, change nothing
pypki init --force-reset --i-understand       # destructive
pypki init --print-defaults                   # emit homelab answers.yaml without running
```

`--dry-run` is critical — operators want to see what's about to happen
before any side effects. Output is the complete answers file plus a
list of filesystem operations that would be performed.

---

## Tests

```
class TestHomelabInit(unittest.TestCase):
    def test_homelab_completes_in_under_60_seconds(self): ...   # CI timing
    def test_homelab_produces_working_ca(self): ...
    def test_homelab_first_issue_succeeds(self): ...
    def test_homelab_audit_chain_starts_clean(self): ...
    def test_homelab_systemd_unit_passes_security_analysis(self): ...

class TestEnterpriseWizard(unittest.TestCase):
    # Wizard runs with scripted inputs
    def test_wizard_path_two_tier_postgres_kms(self): ...
    def test_wizard_path_single_root_sqlite_file(self): ...
    def test_wizard_path_three_tier_pkcs11(self): ...
    def test_invalid_oidc_issuer_blocks_progression(self): ...
    def test_invalid_db_dsn_blocks_progression(self): ...
    def test_unreachable_kms_blocks_progression(self): ...
    def test_question_mark_prints_explanation(self): ...

class TestAnswersReplay(unittest.TestCase):
    def test_homelab_answers_replay_identical(self): ...
    def test_enterprise_answers_replay_identical(self): ...
    def test_answers_file_has_no_secrets(self): ...
    def test_old_format_version_rejected_gracefully(self): ...

class TestIdempotency(unittest.TestCase):
    def test_second_init_refused_without_flag(self): ...
    def test_resume_continues_from_last_answer(self): ...
    def test_reconfigure_changes_only_affected_components(self): ...
    def test_force_reset_requires_i_understand(self): ...

class TestPartialFailureRecovery(unittest.TestCase):
    def test_kms_unreachable_mid_init_leaves_no_partial_state(self): ...
    def test_db_init_failure_leaves_no_partial_state(self): ...
    def test_resume_after_kms_recovery_succeeds(self): ...
    def test_atomic_promotion_no_partial_filesystem(self): ...
```

The 60-second homelab test is non-negotiable and runs on every PR.
The first-issue-succeeds test is the real proof: bootstrap, request a
cert via the local API, validate the chain, revoke it, verify
revocation in the CRL.

---

## Per-change checklist

- [ ] `pypki_init.py` — CLI entry
- [ ] `wizard.py` — question runner
- [ ] `bootstrap/` — setup modules
- [ ] `templates/` — config templates
- [ ] `test_pypki_init.py` — five test classes
- [ ] `pypki_admin.py` — wire `init` as an admin subcommand alias
- [ ] `README.md` — front-page quickstart now reads
      `pypki init --homelab && pypki issue --cn example.local`
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `docs/INSTALL.md` — full walkthrough, both modes
- [ ] `docs/UPGRADE.md` — section on `--upgrade-mode`
- [ ] `pypki-flows.html` — init flow diagram
- [ ] `examples/init-answers/` — sample answer files for each topology

Run `./run_tests.sh`. The first-issue-succeeds test is gating.

---

## Open questions

1. **Containerized init**: in Docker / Kubernetes, the "init" step
   happens during image build or at first-container-start, not as a
   user-driven CLI. Provide `pypki init --container` mode that reads
   answers from env vars and stdout-only-logs without prompts. The
   Helm chart from `CLAUDE-deployment-topologies.md` invokes this.

2. **Air-gapped root ceremony tooling**: if root ceremony is
   `air-gapped`, init produces a portable bundle: a tarball containing
   a minimal `pypki-ceremony` binary, the CSR, and a verification
   script. The operator runs it on the air-gapped machine. Document
   the bundle format in `docs/CEREMONY.md`.

3. **Wizard UX for blind / screen-reader users**: prompts should be
   purely textual, no ASCII-art tables that screen readers stumble on.
   `?` expansion is the accessibility win — anyone can get the same
   explanation without scanning visual hierarchy. Test with a real
   screen reader before release.

4. **Cluster bootstrap**: HA deployments need init on one node and a
   `join` operation on the rest (importing the same CA material,
   pointing at the same DB). Add `pypki init --join <leader-url>
   --token <bootstrap-token>` that pulls the right state from the
   leader and registers as a peer. Out of scope for the v1 init; ship
   when HA is formalized.

5. **Quickstart docs vs init**: the README's existing "Getting started"
   should reduce to a one-liner. Move all the longer-form material to
   `docs/INSTALL.md`. README's job is to be persuasive in 30 seconds;
   init's job is to deliver the result in 60. Don't compete.
