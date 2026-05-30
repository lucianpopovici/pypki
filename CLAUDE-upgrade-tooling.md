# CLAUDE-upgrade-tooling.md — In-Place Upgrade Tooling

Companion to `CLAUDE.md`. Follow all conventions there. Adds a
documented upgrade path with automatic backup, transactional schema
migrations, health-checked promotion, and automatic rollback. Without
this, "PyPKI upgrade broke our production CA" is the worst Monday
morning anyone could have.

---

## What this is

`pypki_admin.py upgrade --to <version>` runs a complete upgrade
cycle:

1. **Pre-flight** — compatibility check, disk space, current health,
   not-already-running.
2. **Backup** — full backup via the system from
   `CLAUDE-backup-restore.md`. Mandatory; refuses to proceed without it.
3. **Drain** (HA only) — load balancer marks this node out, in-flight
   requests complete.
4. **Stop** — service stop, gracefully.
5. **Install** — new binary / package in place.
6. **Migrate** — schema migrations in transactional batches with
   savepoints for rollback.
7. **Start** — service start with `--upgrade-in-progress` flag.
8. **Health-check window** — 5 minutes of observation. If any check
   fails, auto-rollback fires.
9. **Promote** (HA only) — load balancer adds node back.
10. **Finalize** — clear `--upgrade-in-progress`, audit-log the
    successful upgrade, drop the upgrade-protected backup retention.

Every step is logged with timing and outcome. The whole sequence is
re-runnable: if it fails at step 6, fixing the cause and re-running
resumes at step 6.

---

## Compatibility matrix

Every release declares its supported upgrade paths in
`docs/UPGRADE_PATHS.json`:

```json
{
  "current_version": "2.4.0",
  "supported_upgrade_from": [
    "2.3.x",
    "2.2.x"
  ],
  "blocked_upgrade_from": [
    {"version": "2.1.x", "reason": "schema migration only validated from 2.2+", "recommended": "Upgrade to 2.3.5 first"},
    {"version": "1.x", "reason": "major version transition; see MIGRATION_1_TO_2.md"}
  ],
  "breaking_changes": [
    "EST endpoint moved from /est/ to /est/v1/; redirect provided for one minor release",
    "Postgres minimum version raised from 14 to 15"
  ],
  "schema_migrations": [
    {"id": "00042_add_crypto_class", "reversible": true},
    {"id": "00043_audit_chain_columns", "reversible": false}
  ]
}
```

The upgrade tool reads this from the *new* release and from the
current install, computes a path, and refuses to proceed if the path
isn't supported. "Refuses" means a clear error with the recommended
intermediate version, never a silent best-effort attempt.

N→N+1 minor and N.x.y→N.x.z patch upgrades are always supported.
Major-version transitions get their own documented migration path
(separate spec, not this one).

---

## The pre-flight check

Distinct from the runtime preflight from `CLAUDE-preflight-check.md`
(they share machinery). Upgrade pre-flight asserts:

| Check                                     | Failure mode                          |
| ----------------------------------------- | ------------------------------------- |
| Current version in `supported_upgrade_from` of target | refuse              |
| Postgres version meets target's minimum   | refuse                                |
| SQLite version meets target's minimum     | refuse                                |
| Disk free in state dir > 3× DB size       | refuse                                |
| Disk free in backup dir > 1.5× state size | refuse                                |
| Most recent backup ≤ 24 hours old         | warn, can override                    |
| Audit chain currently verifies            | refuse without `--audit-chain-broken-ok` |
| No in-flight ceremonies (Shamir, root)    | refuse                                |
| HSM/KMS reachable for every CA key        | refuse                                |
| No outstanding RA approvals               | warn, can override                    |
| Cron / systemd timers active              | warn — they'll fire during the window |
| Config schema validates against new release | refuse                              |

Output is structured: human readable + JSON for tooling.

---

## Schema migrations during upgrade

The DAL's existing `migrations.py` runs migrations on startup. Upgrade
makes that explicit and transactional:

```python
def upgrade_run_migrations(db: Database, target_version: str) -> MigrationReport:
    pending = _list_pending(db, target_version)
    applied = []
    with db.transaction() as tx:                       # outer tx
        for m in pending:
            sp = tx.savepoint(f"before_{m.id}")
            try:
                _apply_migration(tx, m)
                applied.append(m)
            except Exception as e:
                tx.rollback_to_savepoint(sp)
                raise MigrationFailed(m, e, applied)
        # All succeeded; outer tx commits.
    return MigrationReport(applied=applied)
```

A failure at migration N rolls back to the savepoint *and* aborts
the outer transaction (so even successfully-applied earlier
migrations are rolled back). The DB ends up exactly where it
started; the upgrade reports the failure with the failing
migration's ID, error, and recovery suggestion.

`reversible: true` migrations have explicit down-scripts in
`db_migrations/<dir>/down/<id>.sql`. `reversible: false` migrations
don't — those are one-way. The upgrade tool refuses to cross a
non-reversible migration without `--accept-irreversible`.

### Long-running migrations on Postgres

Schema changes on large tables (CREATE INDEX, ADD COLUMN with default)
can take hours. The naive approach blocks the upgrade for that whole
time. Postgres-only strategy:

1. **CREATE INDEX CONCURRENTLY** — runs outside transactions, takes
   longer but doesn't block writes.
2. **ADD COLUMN ... DEFAULT NULL** + backfill in batches + later
   change default — instead of `ADD COLUMN ... NOT NULL DEFAULT 'x'`
   which rewrites the table.
3. **pre-stage migrations**: a separate `pypki_admin.py
   upgrade-prestage` runs the slow steps against the *running*
   system, before the upgrade window. Then the actual upgrade is fast.

Document this pattern. Mark long migrations in `UPGRADE_PATHS.json`
as `requires_prestage: true` and refuse the regular upgrade path
without `upgrade-prestage` completion.

---

## Health-check window

After service start, PyPKI runs in `--upgrade-in-progress` mode for
5 minutes (configurable). During this window:

- Issuance succeeds for all active profiles.
- A canary cert is issued every 30s and revoked immediately.
- Every CA's key backend (file, HSM, KMS) does a test sign.
- ACME directory is reachable, returns the expected JSON shape.
- OCSP responses are signed and verifiable.
- CRL generation completes for every CA.
- The audit chain continues to verify (incremental check, last 1000
  entries).
- p99 response latency is within 2× the pre-upgrade baseline.

If any check fails (after one retry), the upgrade tool fires
auto-rollback.

Operators can extend the window (`--health-window 15m`) for
high-risk upgrades, or shorten it (`--health-window 1m`) for trivial
patches. The default 5 minutes is the balance between "real
production load saw the new version" and "operator isn't waiting
forever."

---

## Auto-rollback

On health-check failure:

1. Stop the new PyPKI service.
2. Restore from the upgrade pre-backup (kept hot during the upgrade
   window — see backup-restore spec).
3. Restore the binary / package to the previous version.
4. Run the down-migrations for any reversible migrations that were
   applied.
5. Start the old PyPKI service.
6. Re-run the post-start health checks against the rolled-back
   version.
7. Promote back (HA).
8. Audit-log the rollback with the original failure's details.

If rollback itself fails (e.g. down-migration crashes), PyPKI ends
up in `--emergency-rolled-back` mode: service refuses to issue, only
reads work, alerts fire. The operator gets a clear "manual recovery
required" with the exact state and a runbook reference.

Auto-rollback is opt-out via `--no-rollback` for operators who'd
rather diagnose forward. Default is on.

---

## HA mode considerations

HA deployments drain one node at a time (rolling upgrade):

```
for node in nodes:
    drain(node)            # tell load balancer "stop sending traffic"
    wait_for_drain(node)   # in-flight requests complete
    upgrade(node)          # all 10 steps
    if not promoted(node): bail()
    sleep(60)              # cooldown
```

The DB's schema migrations run *once*, on the first node. Subsequent
nodes detect the schema is already at target version and skip the
migration step. The DB schema must be backwards-compatible during
the rolling window — old PyPKI nodes must continue working against
the new schema. This constrains migration design:

- **Allowed**: ADD COLUMN with default NULL, CREATE INDEX, ADD TABLE.
- **Not allowed during rolling**: DROP COLUMN, RENAME COLUMN, NOT
  NULL constraint addition without default.

Renames and removals happen across two releases: release N adds the
new name and migrates writes to it (still reads the old); release
N+1 removes the old. This is the standard expand/contract pattern;
document it in `docs/UPGRADE.md` for migration authors.

---

## Channels and version pinning

Configure release channels:

```
--upgrade-channel stable      # default; only point releases
--upgrade-channel security    # security patches as soon as available
--upgrade-channel preview     # release candidates
--upgrade-channel pinned      # never auto-upgrade; manual only
```

`pypki_admin.py upgrade-check` queries the configured upgrade source
for available versions in the channel. `upgrade-check --notify` writes
a Prometheus metric / sends a webhook so monitoring catches "upgrade
available." Doesn't auto-apply.

Upgrade source: by default, the project's GitHub releases. Operators
in air-gapped environments point at their own internal mirror:

```
--upgrade-source https://internal-mirror.example.com/pypki/releases.json
```

The releases.json format is the schema of `UPGRADE_PATHS.json` per
version plus signature verification (the release is signed by
PyPKI's own release-signing key).

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `upgrade.py`      | New module: orchestrator, pre-flight, health-check, rollback |
| `pypki_admin.py`  | `upgrade`, `upgrade-check`, `upgrade-prestage`,              |
|                   | `upgrade-status`, `upgrade-rollback`                         |
| `migrations.py`   | Add savepoint + transactional batch support                  |
| `db_migrations/*/down/` | New: down-scripts for reversible migrations            |
| `pki_server.py`   | `--upgrade-in-progress` flag, canary issuance loop           |
| `docs/UPGRADE_PATHS.json` | New: compat matrix, generated per release            |
| `test_pypki_init.py` | `TestUpgradePreflight`, `TestUpgradeMigrationRollback`,    |
|                   | `TestUpgradeHealthCheck`, `TestUpgradeAutoRollback`,         |
|                   | `TestUpgradeChannels`                                        |
| `.github/workflows/upgrade-matrix.yml` | Nightly N-1→N tests             |
| `README.md`       | Upgrade section                                              |
| `CHANGELOG.md`    | `### Added`, `### Security`                                  |
| `docs/UPGRADE.md` | Operator runbook + migration-author guide                    |

### Upgrade-matrix CI

Every PR merge runs:

```yaml
# .github/workflows/upgrade-matrix.yml
jobs:
  upgrade-from-previous:
    strategy:
      matrix:
        from_version: [N-1.latest, N-2.latest]
        db_backend: [sqlite, postgres]
    runs-on: ubuntu-latest
    steps:
      - name: Install old version
        run: install-pypki ${{ matrix.from_version }}
      - name: Seed realistic data
        run: ./test/seed-data.sh
      - name: Backup
        run: pypki_admin.py backup-now
      - name: Upgrade to current
        run: pypki_admin.py upgrade --to HEAD --health-window 1m
      - name: Verify
        run: ./test/verify-post-upgrade.sh
      - name: Roll back
        run: pypki_admin.py upgrade-rollback --confirm
      - name: Verify rolled back
        run: ./test/verify-rolled-back.sh
```

This is the only test that catches "the upgrade tool itself is broken."
It's the highest-value workflow in the entire CI surface.

---

## CLI flags

```
pypki_admin.py upgrade
  --to <version>                     # e.g. 2.5.0, or "latest"
  --channel stable|security|preview|pinned
  --source <url>
  --backup-target file://...         # override
  --health-window 5m
  --rollback-on-failure              # default true; --no-rollback to disable
  --accept-irreversible              # cross non-reversible migrations
  --skip-prestage-check              # if you've prestaged differently
  --dry-run                          # plan, change nothing
  --audit-chain-broken-ok            # paper over a known issue

pypki_admin.py upgrade-check         # show available
pypki_admin.py upgrade-prestage      # run long migrations against live
pypki_admin.py upgrade-status        # current state machine position
pypki_admin.py upgrade-rollback      # manual trigger of rollback
```

---

## Tests

```
class TestUpgradePreflight(unittest.TestCase):
    def test_unsupported_source_version_refused(self): ...
    def test_blocked_version_lists_recommended_intermediate(self): ...
    def test_insufficient_disk_refused(self): ...
    def test_postgres_version_too_old_refused(self): ...
    def test_audit_chain_broken_blocks_without_flag(self): ...
    def test_dry_run_makes_no_changes(self): ...
    def test_preflight_passes_normal_case(self): ...

class TestUpgradeMigrationRollback(unittest.TestCase):
    def test_failed_migration_rolls_back_outer_tx(self): ...
    def test_reversible_migration_has_down_script(self): ...
    def test_non_reversible_migration_blocks_without_flag(self): ...
    def test_savepoint_rollback_clean(self): ...
    def test_prestage_long_migration_completes_without_blocking_writes(self): ...

class TestUpgradeHealthCheck(unittest.TestCase):
    def test_canary_issuance_during_window(self): ...
    def test_failed_canary_triggers_rollback(self): ...
    def test_window_extends_when_within_p99_envelope(self): ...
    def test_window_aborts_on_audit_chain_break(self): ...
    def test_health_check_runs_all_ca_backends(self): ...

class TestUpgradeAutoRollback(unittest.TestCase):
    def test_rollback_restores_binary_and_db(self): ...
    def test_rollback_runs_down_migrations(self): ...
    def test_rollback_failure_enters_emergency_mode(self): ...
    def test_rollback_audit_logged_with_failure_details(self): ...
    def test_no_rollback_flag_skips_auto_recovery(self): ...

class TestUpgradeChannels(unittest.TestCase):
    def test_channel_filtering_applied(self): ...
    def test_pinned_channel_never_upgrades(self): ...
    def test_air_gapped_source_signature_verified(self): ...
    def test_security_channel_includes_patch_only(self): ...
```

The `TestUpgradeMigrationRollback.test_prestage_long_migration` test
is the most operationally important — it proves that long Postgres
migrations actually work without blocking the live system.

---

## Per-change checklist

- [ ] `upgrade.py` — orchestrator
- [ ] `migrations.py` — savepoint + transactional batches
- [ ] `db_migrations/*/down/` — down-scripts for every reversible
      migration (audit existing migrations for retroactive `down`)
- [ ] `pki_server.py` — `--upgrade-in-progress`, canary loop,
      emergency mode
- [ ] `pypki_admin.py` — five new subcommands
- [ ] `docs/UPGRADE_PATHS.json` — generated per release
- [ ] `test_pypki_init.py` — five test classes
- [ ] `.github/workflows/upgrade-matrix.yml` — nightly upgrade tests
- [ ] `scripts/release/sign-release.sh` — release-signing
- [ ] `README.md` — Upgrade section
- [ ] `CHANGELOG.md` — `### Added`, `### Security`
- [ ] `docs/UPGRADE.md` — operator runbook + migration-author guide
- [ ] `pypki-flows.html` — upgrade state machine

Run `./run_tests.sh`. The upgrade-matrix workflow is the gating CI.

---

## Open questions

1. **Blue-green upgrades**: keep the old version running in parallel
   on a different port, switch traffic atomically. More complex,
   safer for very high-stakes deployments. Out of scope for v1; the
   HA rolling upgrade gives most of the benefit.

2. **Container upgrade**: in K8s, the upgrade tool runs as an Init
   Container or a Job, not via this CLI. Pre-flight + migration
   happen in an Init Container; the regular Pods only start when
   migration is complete. The Helm chart from
   `CLAUDE-deployment-topologies.md` orchestrates this. Document.

3. **Downgrade**: not supported beyond rollback during an upgrade
   window. Downgrading later than that (e.g. "switch back to last
   month's version") requires a backup restore. Document the
   limitation; don't try to be clever.

4. **Configuration migration**: config schema changes between
   versions. The upgrade tool runs the config through a validator
   for the new schema, applies any auto-migrations, and emits a
   diff for operator review. Reject incompatible config with clear
   guidance. Sketch in `docs/UPGRADE.md`.

5. **Release signing key rotation**: the key signing `releases.json`
   has its own rotation problem. Pin two keys (current + next),
   sign with current, prepare next, publish a key-rotation
   announcement, switch, sunset old. Document in `docs/RELEASE.md`.
