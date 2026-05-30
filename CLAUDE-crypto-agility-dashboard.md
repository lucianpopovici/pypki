# CLAUDE-crypto-agility-dashboard.md — Cryptographic Agility & PQ Migration Tracker

Companion to `CLAUDE.md`. Follow all conventions there. Mostly views,
metrics, and UI over existing tables — small implementation footprint
(~600 LoC), high operator value. The lever that lets PyPKI users
answer "where am I in the PQ migration?" without writing SQL.

---

## What this is

PyPKI already stores everything needed to answer "what's my crypto
posture?" — every issued cert is in `certificates`, every algorithm
choice is in the cert's DER, every client request is in
`audit_log`. What's missing is the synthesis: a dashboard that turns
raw data into the four questions operators actually ask.

The four questions:

1. **Distribution** — what fraction of my active certs is classical-only,
   hybrid (RFC 9763), composite, ML-DSA-only, SLH-DSA?
2. **Migration progress** — at the current renewal rate, when does the
   PQ-capable fraction cross 50%, 90%, 99%?
3. **Hotspots** — which sub-CAs, profiles, or tenants are lagging?
4. **Demand** — are clients actually asking for PQ algorithms in CSRs
   yet? Where are the early adopters?

Bonus: surfacing the same data as Prometheus metrics so operators can
build their own dashboards in Grafana (the project already produces a
Grafana dashboard JSON; this extends it).

---

## Data sources

Everything is derivable from existing tables. No new authoritative
schema, just views and aggregations:

| Source                            | What it gives us                       |
| --------------------------------- | -------------------------------------- |
| `certificates.der`                | Algorithm of subject key, signature algorithm |
| `certificates.profile`            | Issuance category                      |
| `certificates.tenant_id` (if MT)  | Per-tenant slices                      |
| `certificates.not_after`, `revoked` | Active set definition                |
| `ca_keys.backend`                 | Where signing keys live (file/HSM/KMS) |
| `audit_log`                       | Issuance rate, CSR algorithm preferences (logged at request time) |
| `policy_decisions`                | What was allowed/denied                |

Parsing the DER for algorithm classification happens lazily — store
the classification in a denormalized column at issuance time so the
dashboard doesn't re-parse every cert on every refresh:

```sql
-- db_migrations/pki/00X_crypto_classification.sql
ALTER TABLE certificates ADD COLUMN crypto_class TEXT;
-- enum: 'classical-rsa' | 'classical-ec' | 'classical-eddsa'
--     | 'hybrid-9763'    | 'composite-mldsa'
--     | 'mldsa-only'     | 'slhdsa-only'
--     | 'unknown'

CREATE INDEX idx_certs_crypto_class ON certificates(crypto_class);
```

Backfill once at migration; populate at issuance going forward.

Audit-log CSR-algo capture is similarly denormalized:

```sql
ALTER TABLE audit_log ADD COLUMN requested_algo TEXT;
-- 'rsa-2048' | 'ecdsa-p256' | 'ed25519' | 'ml-dsa-44'
-- | 'composite-mldsa44-ecdsa-p256' | etc.
```

These two columns are the whole schema change.

---

## API

```
GET /api/agility/summary
GET /api/agility/breakdown?by=profile|ca|tenant|month
GET /api/agility/migration-forecast
GET /api/agility/csr-demand?since=<iso>
```

### `summary`

```json
{
  "as_of": "2026-05-25T03:00:00Z",
  "total_active_certs": 14823,
  "by_class": {
    "classical-rsa":     {"count": 8412, "pct": 56.7},
    "classical-ec":      {"count": 5102, "pct": 34.4},
    "hybrid-9763":       {"count":  982, "pct":  6.6},
    "composite-mldsa":   {"count":  201, "pct":  1.4},
    "mldsa-only":        {"count":  124, "pct":  0.8},
    "slhdsa-only":       {"count":    2, "pct":  0.0},
    "unknown":           {"count":    0, "pct":  0.0}
  },
  "pq_capable_pct": 8.8,
  "signature_algo_distribution": {
    "rsa-pss-sha256":     8412,
    "ecdsa-sha256":       5102,
    "ml-dsa-65":          1307
  },
  "ca_key_backends": {
    "file":   3,
    "pkcs11": 1,
    "aws-kms": 2
  }
}
```

### `breakdown`

Group-by axis:

```json
GET /api/agility/breakdown?by=profile
{
  "groups": [
    {
      "profile": "tls_server",
      "total": 12104,
      "by_class": {"classical-ec": 11203, "composite-mldsa": 901, ...}
    },
    {
      "profile": "code_signing",
      "total": 47,
      "by_class": {"classical-rsa": 47}
    }
  ]
}
```

`by=month` is the time series for migration trend lines — 24 months
back by default.

### `migration-forecast`

```json
{
  "model": "linear-extrapolation",
  "model_inputs": {
    "window_days": 180,
    "renewal_rate_per_day": 412.5,
    "pq_adoption_rate_per_day": 18.3
  },
  "milestones": [
    {"target_pq_pct": 50,  "estimated_at": "2027-08-14"},
    {"target_pq_pct": 90,  "estimated_at": "2029-02-09"},
    {"target_pq_pct": 99,  "estimated_at": "2030-11-22"}
  ],
  "caveats": [
    "Linear extrapolation; real adoption is typically S-shaped.",
    "Forecast assumes no policy intervention. Setting a PQ deadline policy will compress the timeline."
  ]
}
```

The forecast is intentionally simple — pure linear extrapolation from
recent renewal mix. Anything more sophisticated invites false
precision. The caveats are part of the response, not buried in docs.

### `csr-demand`

How many recent CSRs requested PQ algorithms, even if not always
granted by policy. The forward-looking signal: "my clients are ready
even if my policy isn't."

```json
{
  "window": "30d",
  "csrs_total": 13420,
  "by_requested_algo": {
    "rsa-2048":             6112,
    "ecdsa-p256":           5984,
    "ml-dsa-44":             912,
    "composite-mldsa44-ecdsa-p256": 412
  },
  "denial_rate": {
    "ml-dsa-44":              0.04,
    "composite-mldsa44-ecdsa-p256": 0.12
  }
}
```

---

## Prometheus metrics

```
# HELP pypki_certs_active_total Number of active (not expired, not revoked) certificates.
# TYPE pypki_certs_active_total gauge
pypki_certs_active_total{crypto_class="classical-rsa",profile="tls_server"} 8412
pypki_certs_active_total{crypto_class="composite-mldsa",profile="tls_server"} 201

# HELP pypki_pq_migration_progress Fraction of active certs using PQ-capable algorithms.
# TYPE pypki_pq_migration_progress gauge
pypki_pq_migration_progress{tenant="__system",ca="root-2026"} 0.088

# HELP pypki_csr_requested_algo_total CSRs received by requested algorithm.
# TYPE pypki_csr_requested_algo_total counter
pypki_csr_requested_algo_total{algo="rsa-2048"} 6112
pypki_csr_requested_algo_total{algo="ml-dsa-44"} 912

# HELP pypki_certs_signature_algo Active certs by signature algorithm used.
# TYPE pypki_certs_signature_algo gauge
pypki_certs_signature_algo{algo="ml-dsa-65"} 1307

# HELP pypki_ca_key_backend Number of CAs using each key backend.
# TYPE pypki_ca_key_backend gauge
pypki_ca_key_backend{backend="aws-kms"} 2
pypki_ca_key_backend{backend="file"} 3
```

Computed in a background sweeper every 60s (configurable). All gauges
read directly from the denormalized columns — no DER parsing in the
hot path.

---

## Web UI

New `/admin/agility` page (and `/portal/agility` for tenant admins).
Charts use the existing dashboard's plotting (no new JS framework).

Sections, top to bottom:

1. **Distribution** — donut chart of active certs by `crypto_class`,
   with a "drill-in" to break out by profile.
2. **Trend** — stacked area chart of monthly issuance by `crypto_class`
   over 24 months.
3. **Hotspots** — table of profiles/sub-CAs/tenants sorted by
   "fraction PQ-capable, ascending" so the worst lags float to the
   top. Each row links to its filtered cert list.
4. **CSR demand** — bar chart of requested algorithms in the last 30
   days, with denial-rate badges.
5. **Forecast** — text card with the three milestones from
   `/agility/migration-forecast` plus the caveats.

No new dependencies. SVG charts rendered server-side from the existing
helpers in `web_ui.py`.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `agility.py`      | New module: classifier, aggregator, forecaster               |
| `pki_server.py`   | New `/api/agility/*` endpoints, classification at issuance, metrics exposition |
| `web_ui.py`       | `/admin/agility` page, chart helpers                         |
| `db_migrations/pki/00X_crypto_classification.sql` | Schema             |
| `db_migrations/pki/00X_crypto_classification_backfill.py` | Backfill   |
| `test_pki_server.py` | `TestCryptoClassifier`, `TestAgilityAggregator`,           |
|                   | `TestMigrationForecaster`, `TestAgilityMetrics`              |
| `README.md`       | New section, Grafana dashboard link                          |
| `CHANGELOG.md`    | `### Added`                                                  |
| `docs/AGILITY.md` | Operator playbook for PQ migration                           |
| `dashboards/pypki-agility.json` | Grafana dashboard with all the metrics above |

### Classifier

```python
# agility.py
def classify(der: bytes) -> str:
    """Return one of the canonical crypto_class strings."""
    cert = x509.load_der_x509_certificate(der)
    spki_oid = cert.public_key().public_numbers...        # algorithm OID
    sig_algo = cert.signature_algorithm_oid

    is_pq_subject = _is_pq_algo(spki_oid)
    is_pq_signature = _is_pq_algo(sig_algo)

    if _is_composite(spki_oid):
        return "composite-mldsa"
    if _is_ml_dsa(spki_oid):
        return "mldsa-only"
    if _is_slh_dsa(spki_oid):
        return "slhdsa-only"
    if _is_paired_9763(cert):                              # checks for paired cert via extension
        return "hybrid-9763"
    if _is_eddsa(spki_oid):
        return "classical-eddsa"
    if _is_ec(spki_oid):
        return "classical-ec"
    if _is_rsa(spki_oid):
        return "classical-rsa"
    return "unknown"
```

The classifier is the central truth — if it's wrong, every dashboard
number is wrong. Test exhaustively against fixture certs from every
supported algorithm.

### Aggregator

```python
def summary(db: Database, tenant_id: str | None = None) -> Summary:
    where_tenant = "AND tenant_id = ?" if tenant_id else ""
    params = (tenant_id,) if tenant_id else ()
    rows = db.fetchall(f"""
        SELECT crypto_class, COUNT(*) AS n
        FROM certificates
        WHERE revoked = 0
          AND not_after > strftime('%s', 'now')
          {where_tenant}
        GROUP BY crypto_class
    """, params)
    # ... build Summary
```

Simple group-bys; no business logic.

### Forecaster

```python
def forecast(db: Database, window_days: int = 180) -> Forecast:
    # Linear regression on monthly PQ-capable fraction over the window.
    # Stdlib only — no numpy.
    points = _monthly_pq_fraction(db, window_days)
    slope, intercept = _least_squares(points)
    if slope <= 0:
        return Forecast(model="linear-extrapolation",
                        milestones=[], caveats=["No upward trend in window."])
    today_fraction = points[-1].fraction
    milestones = []
    for target in (0.5, 0.9, 0.99):
        if target <= today_fraction:
            milestones.append(Milestone(target=target, eta="already met"))
        else:
            days = (target - today_fraction) / slope
            eta = (datetime.now(UTC) + timedelta(days=days)).date()
            milestones.append(Milestone(target=target, eta=eta.isoformat()))
    return Forecast(model="linear-extrapolation", milestones=milestones,
                    caveats=DEFAULT_CAVEATS)
```

---

## CLI flags

```
--agility-enabled true
--agility-sweep-interval-seconds 60
--agility-forecast-window-days 180
--agility-prometheus-prefix pypki
```

`pypki_admin.py`:

- `agility-summary` — print the summary as a table
- `agility-reclassify` — re-run the classifier over all certs (rarely
  needed; useful after fixing a classifier bug)
- `agility-export --format csv` — bulk export for offline analysis

---

## Tests

```
class TestCryptoClassifier(unittest.TestCase):
    def test_rsa_2048_classified(self): ...
    def test_ecdsa_p256_classified(self): ...
    def test_ed25519_classified(self): ...
    def test_ml_dsa_44_classified(self): ...
    def test_ml_dsa_65_classified(self): ...
    def test_slh_dsa_sha2_128f_classified(self): ...
    def test_composite_mldsa44_ecdsa_p256_classified(self): ...
    def test_hybrid_9763_classified(self): ...
    def test_unknown_algo_classified_as_unknown(self): ...
    def test_corrupt_cert_does_not_raise(self): ...

class TestAgilityAggregator(unittest.TestCase):
    def test_summary_counts_only_active_certs(self): ...
    def test_summary_excludes_revoked(self): ...
    def test_summary_excludes_expired(self): ...
    def test_breakdown_by_profile(self): ...
    def test_breakdown_by_ca(self): ...
    def test_breakdown_by_tenant_isolation(self): ...
    def test_monthly_trend_24_months(self): ...

class TestMigrationForecaster(unittest.TestCase):
    def test_linear_extrapolation_basic(self): ...
    def test_already_met_milestone(self): ...
    def test_no_upward_trend_returns_no_milestones(self): ...
    def test_window_too_short_returns_caveat(self): ...

class TestAgilityMetrics(unittest.TestCase):
    def test_prometheus_format_valid(self): ...
    def test_sweeper_updates_gauges(self): ...
    def test_metrics_isolated_per_tenant(self): ...
```

---

## Per-change checklist

- [ ] `agility.py` — new module
- [ ] `pki_server.py` — endpoints, classification at issuance,
      Prometheus exposition
- [ ] `web_ui.py` — `/admin/agility` page
- [ ] `db_migrations/pki/00X_crypto_classification.sql` — schema
- [ ] `db_migrations/pki/00X_crypto_classification_backfill.py` —
      backfill
- [ ] `pypki_admin.py` — `agility-summary`,
      `agility-reclassify`, `agility-export`
- [ ] `test_pki_server.py` — four test classes
- [ ] `README.md` — new section, Grafana link
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `docs/AGILITY.md` — PQ migration playbook
- [ ] `dashboards/pypki-agility.json` — Grafana dashboard

Run `./run_tests.sh`.

---

## Open questions

1. **Forecast model sophistication**: linear extrapolation is honest
   about its limits but operators may want logistic curves or
   change-point detection. Defer; add only if users ask. The caveats
   in the response are the right answer for now.

2. **Public benchmarks**: aggregate PQ-adoption statistics across
   PyPKI instances would be a useful industry contribution if
   operators opted in to anonymous reporting. Out of scope here;
   would need a separate aggregation service and clear privacy story.

3. **Action recommendations**: the dashboard shows the data; the next
   step is "what should I do about it?" Could add suggested policy
   changes ("set a min algo of `ecdsa-p256` for `tls_server` to
   retire RSA-2048 by 2027") generated from the data. Defer to v2 —
   prescriptive recommendations require careful UX design.

4. **Algorithm taxonomy stability**: `crypto_class` enum values are a
   versioned API surface (Prometheus labels, dashboard JSON, external
   consumers). Adding values is safe; renaming or removing is not.
   Document the stability promise in `docs/AGILITY.md`.

5. **Per-CSR algorithm logging cost**: writing `requested_algo` on
   every issuance audit row adds ~10 bytes per row. At 1M
   issuances/day that's ~3.5GB/year. Acceptable; document the
   storage impact so operators sizing audit retention know.
