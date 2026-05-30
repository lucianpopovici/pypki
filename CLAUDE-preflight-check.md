# CLAUDE-preflight-check.md — Preflight Check CLI

Companion to `CLAUDE.md`. Follow all conventions there. A single
diagnostic command that audits a PyPKI deployment against a known-good
baseline. Runs at startup (warnings only, never blocks), on demand
(`--exit-on-warning` for CI), and on a schedule (cron / systemd
timer) for ongoing drift detection.

---

## What this is

Operators of running CA software spend disproportionate time on
"is this still healthy?" questions — file permissions, expired
internal certs, missing backups, drifted firewall rules, clock skew,
HSM unreachable. PyPKI's runtime ignores most of these until they
cause issuance failures, at which point the CA is already broken.

`pypki_admin.py preflight` shifts that detection left: a structured,
fast (sub-5-second) audit that an operator runs after any change and
that monitoring runs every hour. Output is both human-readable
(default) and JSON (`--format json`), with a non-zero exit code for
the `--exit-on-warning` mode that makes it usable in CI / cron.

The check is read-only. It diagnoses; it never fixes. Fixes are the
operator's call, with `pypki_admin.py hardening-apply` / `tls-rotate`
/ `backup-now` etc. as the explicit remediation commands.

---

## Check catalog

Each check has: id, severity, category, description, what passing
looks like, what failing looks like, recommended remediation. The
catalog is data, not code — so adding a check is one entry, not a
patch to a switch statement.

| ID                          | Severity | Category | What it checks |
| --------------------------- | -------- | -------- | -------------- |
| `ca-key-permissions`        | critical | secrets  | All CA key files are mode 0600, owned by pypki user |
| `secrets-dir-permissions`   | critical | secrets  | `/etc/pypki/secrets/` is mode 0700, no world-readable files inside |
| `ca-key-backend-reachable`  | critical | backends | Every CA's configured backend (file/PKCS#11/cloud KMS) signs a test digest |
| `db-connection`             | critical | runtime  | DB reachable, schema version matches binary version, no pending migrations |
| `audit-chain-intact`        | critical | audit    | Last 1000 audit entries verify against their hash chain |
| `time-sync`                 | high     | runtime  | NTP drift < 1 second; chronyd/timesyncd active |
| `entropy-available`         | high     | runtime  | `/proc/sys/kernel/random/entropy_avail` > 256 |
| `admin-tls-expiry`          | high     | tls      | Admin endpoint cert > 7 days from expiry |
| `backup-recent`             | high     | backup   | Most recent backup ≤ configured interval × 1.5 |
| `backup-target-reachable`   | high     | backup   | Each configured backup target is writable (test write + delete) |
| `backup-last-verified`      | high     | backup   | Most recent backup passed dry-run restore within 7 days |
| `audit-seal-recent`         | medium   | audit    | Last audit seal ≤ configured interval × 1.5 |
| `audit-seal-anchored`       | medium   | audit    | If external anchor configured, latest seal is present at target |
| `firewall-rules-match-port-matrix` | medium | network | Detected firewall stack permits exactly the expected ports |
| `systemd-hardening-score`   | medium   | hardening | `systemd-analyze security pypki.service` ≤ 1.0 |
| `mac-policy-enforcing`      | medium   | hardening | AppArmor/SELinux profile in enforce mode (not complain/permissive) |
| `sysctl-applied`            | medium   | hardening | Every key from `packaging/sysctl/pypki.conf` matches at runtime |
| `disk-free-state`           | medium   | runtime  | State dir has > 20% free; > 3× current DB size |
| `disk-free-backup`          | medium   | backup   | Backup target has retention-worth of space remaining |
| `cert-expiry-soon`          | medium   | issuance | Any active CA cert < 90 days from expiry (warn early) |
| `crl-fresh`                 | medium   | issuance | Each CA's CRL was regenerated within nextUpdate / 2 |
| `ocsp-responder-fresh`      | medium   | issuance | OCSP signer's cert valid, pre-computed responses < refresh window old |
| `webhook-targets-reachable` | low      | runtime  | Configured webhook URLs respond (with `OPTIONS` or HEAD) |
| `oidc-jwks-fresh`           | low      | auth     | If OIDC enabled, JWKS last refresh ≤ 24h ago |
| `policy-loaded`             | low      | runtime  | If policy engine enabled, policy file loaded and hash recorded |
| `metrics-endpoint`          | info     | observability | Prometheus metrics endpoint returns 200 with the expected gauges |
| `version-current`           | info     | upgrade  | Current version vs configured `--upgrade-channel` (no auto-action) |
| `topology-hint-applied`     | info     | runtime  | If `--topology-hint` set, defaults match hinted topology |

Severities map to exit codes in `--exit-on-warning` mode:

| Severity | Exit code | Meaning                                       |
| -------- | --------- | --------------------------------------------- |
| critical | 4         | CA cannot operate correctly; immediate attention |
| high     | 3         | Imminent failure; fix this week                |
| medium   | 2         | Drift from baseline; fix this month            |
| low      | 1         | Minor issue; convenient to fix                 |
| info     | 0         | Informational only                             |

`--exit-on-warning <severity>` exits non-zero when any check at or
above that severity fails. Cron / monitoring uses `medium` by default;
CI's "production deployment must be clean" gate uses `high`.

---

## Check shape

Each check is a function returning a `CheckResult`:

```python
@dataclass(frozen=True)
class CheckResult:
    id: str
    severity: Severity
    category: str
    status: Status           # PASS | WARN | FAIL | SKIP | ERROR
    description: str         # Static; what this check audits
    finding: str             # Dynamic; what was actually observed
    remediation: str | None  # Command or doc reference to fix
    timing_ms: int
    metadata: dict           # Structured details for JSON output
```

```python
def check_ca_key_permissions(env: CheckEnv) -> CheckResult:
    bad = []
    for key_path in env.ca_key_paths:
        st = key_path.stat()
        if stat.S_IMODE(st.st_mode) != 0o600:
            bad.append((str(key_path), oct(stat.S_IMODE(st.st_mode))))
    if not bad:
        return CheckResult(
            id="ca-key-permissions",
            severity=Severity.CRITICAL,
            category="secrets",
            status=Status.PASS,
            description="All CA key files are mode 0600",
            finding=f"{len(env.ca_key_paths)} keys checked, all 0600",
            remediation=None,
            timing_ms=...,
            metadata={"checked": len(env.ca_key_paths)},
        )
    return CheckResult(
        id="ca-key-permissions",
        severity=Severity.CRITICAL,
        category="secrets",
        status=Status.FAIL,
        description="All CA key files must be mode 0600",
        finding=f"{len(bad)} key(s) with wrong permissions: {bad}",
        remediation=f"chmod 0600 {' '.join(p for p, _ in bad)}",
        timing_ms=...,
        metadata={"violations": bad},
    )
```

Checks are pure functions of `CheckEnv`, which carries the loaded
config, DB handle, and discovery results. This makes each check
trivially unit-testable in isolation and trivially parallelizable.

---

## Parallel execution

The runner dispatches all checks concurrently, bounded by a thread
pool (default 8 workers). A single slow check (HSM round-trip,
backup-target reachability) doesn't block the others.

Each check has a per-check timeout (default 10s, overridable). On
timeout the check reports `ERROR` with the timeout as the finding
— never silently hang.

Total preflight runtime target: ≤ 5 seconds on a typical deployment.
Measured in CI; regression in timing is a soft alert.

---

## Output formats

### Human (default)

```
PyPKI preflight — 2026-05-25 14:32:11 UTC
Instance: pki.example.com  Version: 2.4.0  Topology: single-vm

  ✓ ca-key-permissions      critical   secrets       (12ms)
  ✓ secrets-dir-permissions critical   secrets       (3ms)
  ✓ ca-key-backend-reachable critical  backends      (842ms)  ← AWS KMS
  ✓ db-connection           critical   runtime       (18ms)
  ✓ audit-chain-intact      critical   audit         (134ms)  ← last 1000
  ⚠ time-sync               high       runtime       (210ms)
      drift: 2.4s (threshold: 1.0s)
      fix:   systemctl restart chronyd; chronyc tracking
  ✓ entropy-available       high       runtime       (1ms)
  ⚠ admin-tls-expiry        high       tls           (8ms)
      expires: 2026-06-01 (6 days)
      fix:   pypki_admin.py tls-rotate
  ✓ backup-recent           high       backup        (4ms)
  ✓ backup-target-reachable high       backup        (1240ms) ← S3 write probe
  ✓ backup-last-verified    high       backup        (2ms)
  ...

Summary: 24 PASS · 2 WARN · 0 FAIL · 0 ERROR · 0 SKIP
Total time: 3.4s
Highest severity not passing: high

To remediate warnings:
  - time-sync         systemctl restart chronyd; chronyc tracking
  - admin-tls-expiry  pypki_admin.py tls-rotate
```

Color: green ✓ pass, yellow ⚠ warn, red ✗ fail, blue ℹ info, grey →
skip. Disabled with `--no-color` or when stdout is not a TTY.

### JSON

```json
{
  "schema_version": 1,
  "generated_at": "2026-05-25T14:32:11Z",
  "instance": "pki.example.com",
  "version": "2.4.0",
  "topology": "single-vm",
  "total_time_ms": 3421,
  "summary": {
    "pass": 24,
    "warn": 2,
    "fail": 0,
    "error": 0,
    "skip": 0,
    "highest_unpassed": "high"
  },
  "checks": [
    {
      "id": "ca-key-permissions",
      "severity": "critical",
      "category": "secrets",
      "status": "PASS",
      "finding": "3 keys checked, all 0600",
      "remediation": null,
      "timing_ms": 12,
      "metadata": {"checked": 3}
    },
    {
      "id": "time-sync",
      "severity": "high",
      "category": "runtime",
      "status": "WARN",
      "finding": "drift: 2.4s (threshold: 1.0s)",
      "remediation": "systemctl restart chronyd; chronyc tracking",
      "timing_ms": 210,
      "metadata": {"drift_seconds": 2.4, "threshold": 1.0, "source": "chronyd"}
    }
  ]
}
```

JSON is stable across versions modulo `schema_version`. Adding a
field doesn't bump the version; renaming or removing one does.

### Prometheus

`--format prometheus` emits text-format metrics:

```
# HELP pypki_preflight_check_status Status of each preflight check (0=pass, 1=warn, 2=fail, 3=error, 4=skip)
# TYPE pypki_preflight_check_status gauge
pypki_preflight_check_status{check="ca-key-permissions",severity="critical",category="secrets"} 0
pypki_preflight_check_status{check="time-sync",severity="high",category="runtime"} 1
...

# HELP pypki_preflight_check_timing_ms Per-check execution time
# TYPE pypki_preflight_check_timing_ms gauge
pypki_preflight_check_timing_ms{check="ca-key-backend-reachable"} 842
...

# HELP pypki_preflight_summary Counts by status
# TYPE pypki_preflight_summary gauge
pypki_preflight_summary{status="pass"} 24
pypki_preflight_summary{status="warn"} 2
```

Cron writes this to a textfile collector path that node_exporter
picks up. Grafana dashboards from `CLAUDE-deployment-topologies.md`
include a "preflight status" panel out of the box.

---

## Startup integration

PyPKI runs preflight on startup, before opening the listener:

```python
def main():
    config = load_config()
    db = open_db(config)
    results = preflight.run(env=CheckEnv.from(config, db))

    for r in results:
        if r.severity == Severity.CRITICAL and r.status != Status.PASS:
            log.error(f"Critical preflight failure: {r.id} — {r.finding}")
            log.error(f"Remediation: {r.remediation}")
            sys.exit(4)
        elif r.status not in (Status.PASS, Status.SKIP):
            log.warning(f"Preflight {r.status}: {r.id} — {r.finding}")

    # Critical checks all passed (or --skip-critical-preflight set)
    start_listener(config, db)
```

**Critical** checks block startup. **High** and below warn but proceed
— the CA stays operable, the operator gets paged via monitoring.

`--skip-preflight` exists for emergency recovery scenarios (e.g.
"audit chain is broken but I need to serve OCSP while I diagnose").
It logs a loud warning every minute it's in use; monitoring should
alert on the warning.

---

## Periodic integration

A systemd timer runs preflight every 30 minutes:

```ini
# /etc/systemd/system/pypki-preflight.timer
[Unit]
Description=PyPKI preflight check

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min
RandomizedDelaySec=2min

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/pypki-preflight.service
[Unit]
Description=PyPKI preflight check (oneshot)

[Service]
Type=oneshot
User=pypki
ExecStart=/usr/bin/pypki_admin.py preflight \
  --format prometheus \
  --output /var/lib/node_exporter/textfile_collector/pypki-preflight.prom \
  --exit-on-warning medium
```

The cron equivalent ships in `packaging/cron/pypki-preflight`.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `preflight.py`    | New module: runner, output formatters, severity logic        |
| `checks/`         | New package, one file per check or check family:             |
|   `secrets.py`    | `ca-key-permissions`, `secrets-dir-permissions`              |
|   `backends.py`   | `ca-key-backend-reachable` (file/PKCS#11/AWS/GCP/Azure)      |
|   `runtime.py`    | `db-connection`, `time-sync`, `entropy-available`, `disk-free-*` |
|   `audit.py`      | `audit-chain-intact`, `audit-seal-recent`, `audit-seal-anchored` |
|   `tls.py`        | `admin-tls-expiry`                                           |
|   `backup.py`     | `backup-recent`, `backup-target-reachable`, `backup-last-verified` |
|   `hardening.py`  | `firewall-rules-match-port-matrix`, `systemd-hardening-score`, `mac-policy-enforcing`, `sysctl-applied` |
|   `issuance.py`   | `cert-expiry-soon`, `crl-fresh`, `ocsp-responder-fresh`      |
|   `runtime_misc.py` | `webhook-targets-reachable`, `oidc-jwks-fresh`, `policy-loaded`, `metrics-endpoint`, `version-current`, `topology-hint-applied` |
| `pypki_admin.py`  | `preflight` subcommand                                        |
| `pki_server.py`   | Startup integration, `--skip-preflight` flag                 |
| `packaging/systemd/pypki-preflight.{service,timer}` | Periodic timer  |
| `packaging/cron/pypki-preflight` | Cron equivalent                       |
| `test_pypki_init.py` | `TestPreflightRunner`, `TestPreflightCheckCatalog`,        |
|                   | `TestPreflightOutputFormats`, `TestPreflightStartupIntegration`, |
|                   | one focused test class per `checks/*.py` module              |
| `README.md`       | Preflight section                                            |
| `CHANGELOG.md`    | `### Added`                                                  |
| `docs/PREFLIGHT.md`| Full catalog reference + remediation playbook               |

### Adding new checks

Single-file pattern. Drop a function into the right `checks/*.py`,
register it with the catalog:

```python
# checks/runtime.py
@register_check(
    id="entropy-available",
    severity=Severity.HIGH,
    category="runtime",
    timeout_seconds=2,
)
def check_entropy_available(env: CheckEnv) -> CheckResult:
    avail = int(Path("/proc/sys/kernel/random/entropy_avail").read_text())
    threshold = 256
    if avail >= threshold:
        return _pass(f"entropy_avail = {avail}")
    return _fail(
        f"entropy_avail = {avail} (threshold: {threshold})",
        remediation="apt install rng-tools; systemctl enable --now rngd",
    )
```

`@register_check` adds the check to `CHECK_CATALOG`. The runner
discovers everything in the catalog at startup. No central
registration file to keep updated; tests assert that the catalog is
non-empty and that every registered check has a corresponding
documentation entry in `docs/PREFLIGHT.md`.

---

## CLI flags

```
pypki_admin.py preflight
  --format human|json|prometheus           # default: human, or json if stdout not a TTY
  --output <path>                          # default: stdout
  --include <category>[,<category>...]     # only run these
  --exclude <category>[,<category>...]
  --include-check <id>[,<id>...]           # only run these specific checks
  --exclude-check <id>[,<id>...]
  --exit-on-warning critical|high|medium|low|none   # default: critical
  --timeout <seconds>                      # per-check timeout, default 10
  --parallelism <n>                        # default 8
  --no-color
  --skip-slow                              # skip checks > 1s (KMS, S3 probe)

# Convenience modes
pypki_admin.py preflight --quick          # = --skip-slow --exit-on-warning high
pypki_admin.py preflight --thorough       # all checks, no exits
pypki_admin.py preflight --ci             # = --format json --exit-on-warning high
```

`pki_server.py` startup flags:

```
--skip-preflight                          # do not run preflight on startup
--preflight-block-on critical             # what severities block startup
```

---

## Tests

```
class TestPreflightRunner(unittest.TestCase):
    def test_runner_executes_all_registered_checks(self): ...
    def test_parallel_execution_respects_pool_size(self): ...
    def test_per_check_timeout_returns_error_not_hang(self): ...
    def test_slow_check_does_not_block_fast_checks(self): ...
    def test_total_time_under_5s_for_default_set(self): ...
    def test_include_exclude_filters(self): ...
    def test_exit_code_maps_to_severity(self): ...
    def test_skip_slow_omits_kms_and_s3_probes(self): ...

class TestPreflightCheckCatalog(unittest.TestCase):
    def test_catalog_non_empty(self): ...
    def test_every_check_has_unique_id(self): ...
    def test_every_check_has_documented_remediation(self): ...
    def test_every_check_in_docs_preflight_md(self): ...
    def test_severity_values_are_canonical(self): ...

class TestPreflightOutputFormats(unittest.TestCase):
    def test_human_output_uses_color_on_tty(self): ...
    def test_human_output_no_color_off_tty(self): ...
    def test_json_schema_version_present(self): ...
    def test_json_schema_stable_across_versions(self): ...
    def test_prometheus_text_format_valid(self): ...
    def test_prometheus_textfile_collector_compatible(self): ...

class TestPreflightStartupIntegration(unittest.TestCase):
    def test_critical_failure_blocks_startup(self): ...
    def test_high_failure_warns_but_starts(self): ...
    def test_skip_preflight_flag_logs_loud_warning(self): ...
    def test_startup_preflight_under_5s(self): ...

# One focused test class per checks/*.py:
class TestSecretsChecks(unittest.TestCase):
    def test_ca_key_permissions_pass_on_0600(self): ...
    def test_ca_key_permissions_fail_on_0644(self): ...
    def test_ca_key_permissions_fail_remediation_is_chmod(self): ...
    def test_secrets_dir_world_readable_fails(self): ...

class TestBackendsChecks(unittest.TestCase):
    def test_file_backend_signs_test_digest(self): ...
    def test_pkcs11_backend_signs_via_softhsm_in_ci(self): ...
    @skip_unless_env("PYPKI_TEST_AWS_KMS_ARN")
    def test_aws_kms_backend_signs(self): ...
    def test_unreachable_backend_returns_fail_not_error(self): ...

class TestAuditChecks(unittest.TestCase):
    def test_intact_chain_passes(self): ...
    def test_broken_chain_fails(self): ...
    def test_recent_seal_passes(self): ...
    def test_stale_seal_warns(self): ...

# ... one per checks/ module
```

The `test_total_time_under_5s_for_default_set` and
`test_startup_preflight_under_5s` regressions are tracked over time;
sudden 10× slowdown is a CI alert.

---

## Per-change checklist

- [ ] `preflight.py` — runner
- [ ] `checks/` — one file per category, every check from the catalog
- [ ] `pypki_admin.py` — `preflight` subcommand
- [ ] `pki_server.py` — startup integration
- [ ] `packaging/systemd/pypki-preflight.{service,timer}` — periodic
- [ ] `packaging/cron/pypki-preflight` — cron alternative
- [ ] `test_pypki_init.py` — runner / catalog / output / startup
- [ ] One test module per `checks/*.py`
- [ ] `README.md` — Preflight section
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `docs/PREFLIGHT.md` — catalog reference, remediation playbook,
      how to add a check
- [ ] `pypki-flows.html` — preflight runner illustration
- [ ] `dashboards/pypki-preflight.json` — Grafana dashboard

Run `./run_tests.sh`. The "docs catalog matches code catalog" test
prevents documentation drift.

---

## Open questions

1. **Self-healing**: should preflight optionally remediate? E.g.
   `chmod 0600` if file perms are wrong. Resist. Diagnostic and
   remediation are deliberately separate so a misdiagnosis can't
   cascade into a worse state. The remediation field's value is
   that operators see exactly what they're about to run.

2. **Per-tenant preflight**: in multi-tenant deployments
   (`CLAUDE-multitenancy.md`), some checks are global (entropy,
   sysctl, MAC), others are per-tenant (audit chain, CA backend
   reachability). Add a `--tenant <slug>` filter that runs only the
   per-tenant checks scoped to that tenant. System-tenant admin
   sees all; tenant admin sees only theirs.

3. **External health-check protocol**: load balancers want a single
   HTTP endpoint to poll for "is this node healthy?" Add
   `GET /healthz` that runs a tight subset of preflight (no slow
   checks, < 100ms) and returns 200 if all critical pass, 503
   otherwise. Use the same machinery; surface as a separate
   endpoint, not a separate code path.

4. **Historical preflight log**: optionally persist preflight results
   to `preflight_runs` table so operators can answer "when did
   `time-sync` start failing?" Schema is small; retention default
   90 days. Useful for post-incident review.

5. **Compliance reporting**: a "CIS-style PyPKI benchmark" is the
   same data viewed through a compliance lens. Map each preflight
   check to a CIS / NIST 800-53 / ISO 27001 control ID, emit a
   compliance-formatted report. Out of scope for v1; sketch in
   `docs/COMPLIANCE.md` as a future deliverable.
