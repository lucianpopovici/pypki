# Tier 6.5 — Chaos & Failure Injection

The chaos suite proves PyPKI's durability invariants hold under failure conditions that unit tests cannot exercise: process kills, DB interruptions, disk-full events, concurrent issuance races, and clock manipulation.

## Invariants

| # | Invariant | Checker |
|---|-----------|---------|
| 1 | Every issued cert is in `audit` | `invariants/audit_log_complete.py` |
| 2 | No two certs share a serial number | `invariants/no_duplicate_serials.py` |
| 3 | `cRLNumber` is strictly monotonic | `invariants/crl_number_monotonic.py` |
| 4 | A revoked cert stays revoked after restart | `invariants/revocation_persists.py` |

## Scenarios

| File | Failure | Invariants | Infra required |
|------|---------|------------|----------------|
| F01_kill_mid_sign.py | SIGKILL between sign and audit-log commit | 1, 7 | None |
| F02_kill_pre_response.py | SIGKILL after audit-log commit, before HTTP response | 1, 2 | None |
| F03_db_kill_mid_tx.py | Corrupt DB write mid-transaction | 1, 2, 7 | None |
| F04_hsm_disconnect.py | HSM session severed during C_Sign | 1, 7 | PKCS#11 HSM |
| F05_crl_disk_full.py | Disk full during CRL write | 3 | tmpfs bind-mount |
| F06_audit_disk_full.py | Disk full during audit-log write | 1, 7 | tmpfs bind-mount |
| F07_webhook_hang.py | Webhook receiver hangs indefinitely | 1 (non-blocking) | None |
| F08_webhook_500.py | Webhook receiver returns 500 repeatedly | 1, 7 | None |
| F09_pg_failover.py | Postgres primary failover during issuance | 2, 3, 4, 8 | Postgres |
| F10_replica_lag.py | Postgres replica lag at OCSP query | 4, 6 | Postgres |
| F11_ocsp_partition.py | Network partition to OCSP responder | 6 | iptables |
| F12_clock_forward.py | Clock jump forward (NTP sync) | 6 | libfaketime |
| F13_clock_backward.py | Clock jump backward | 3 | libfaketime |
| F14_concurrent_issue.py | Two threads issuing concurrently | 2, 3, 8 | None |

## Running

```bash
# Full suite (long; nightly/pre-release only)
./run_tests.sh --chaos

# Single scenario
python3 chaos/F14_concurrent_issue.py

# Invariant check only (on an existing DB)
python3 chaos/invariants/no_duplicate_serials.py /path/to/certificates.db
```

## Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `PYPKI_CHAOS_ITERATIONS` | How many issuance cycles per scenario | 100 |
| `PYPKI_CHAOS_POSTGRES_DSN` | Enable Postgres scenarios (F09, F10) | unset → skip |
| `PYPKI_CHAOS_HSM_LIB` | Enable HSM scenarios (F04) | unset → skip |
| `PYPKI_CHAOS_TMPFS` | Path to a small tmpfs for disk-full scenarios | unset → skip |
| `PYPKI_CHAOS_LIBFAKETIME` | Path to libfaketime.so for clock scenarios | unset → skip |

## Adding a new scenario

1. Create `chaos/F<nn>_<name>.py` with `setup()`, `inject()`, `assertions()`, `teardown()`.
2. Add it to `run_chaos.sh`.
3. If it needs special infrastructure, add the env-var skip check at the top.
4. Run it locally to verify it produces at least one `PASS` and documents what it tests.

## Infrastructure notes

- **No production data.** All scenarios run against ephemeral test CAs in `tempfile.mkdtemp()`.
- **State wiped between scenarios.** Each `setup()` creates a fresh CA directory.
- **Postgres scenarios** skip when `PYPKI_CHAOS_POSTGRES_DSN` is unset.
- **HSM scenarios** skip when `PYPKI_CHAOS_HSM_LIB` is unset.
- **Disk-full scenarios** require a tmpfs bind-mount at `PYPKI_CHAOS_TMPFS`; skip otherwise.
- **libfaketime scenarios** require the `LD_PRELOAD` path; skip otherwise.
