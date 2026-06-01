# PyPKI Performance Baseline

This document defines the performance envelope for PyPKI deployments. Numbers
here are measured on the reference hardware profile below. They are reproducible
from the source tree using the bench harness in `bench/`.

**A > 20% regression on any metric documented here blocks release.**
See `scripts/check_perf_regression.sh`.

---

## 1. Reference hardware

| Attribute | Value |
|-----------|-------|
| CPU | 8-core x86_64, 3.0 GHz base (typical mid-tier cloud VM) |
| RAM | 16 GB |
| Disk | NVMe SSD, ext4, no sync forced |
| OS | Linux (kernel 6.x) |
| Python | 3.12.x |
| Backend | SQLite (WAL mode) unless noted |

Numbers taken with PyPKI in advisory-lock mode (default). Postgres numbers
will differ; see §6 (Postgres notes).

---

## 2. How to reproduce

```bash
# Full bench suite (writes results to bench/results/)
./run_tests.sh --bench

# Single metric
python3 bench/issuance.py --n 500
python3 bench/ocsp.py --n 1000 --certs 200
python3 bench/crl_gen.py --max-revoked 100000
python3 bench/storage.py --n 2000
```

Results are timestamped Markdown files in `bench/results/`. Each run is
independent; compare two runs by diffing the result files.

---

## 3. Issuance throughput

**Method:** `CertificateAuthority.issue_certificate()` called in a tight loop
with `audit=AuditLog(...)` (full signing + DB write + audit write). No HTTP.
Warmup: 20 iterations discarded.

> **Note:** These are baseline numbers from the bench harness. Populate with
> real measurements by running `python3 bench/issuance.py --n 500` on the
> reference hardware and replacing the table below.

| CA key type | Backend | p50 (ms) | p95 (ms) | p99 (ms) | certs/s (sustained) |
|-------------|---------|---------|---------|---------|---------------------|
| ECDSA P-256 | SQLite  | TBD     | TBD     | TBD     | TBD                 |
| ECDSA P-384 | SQLite  | TBD     | TBD     | TBD     | TBD                 |
| Ed25519     | SQLite  | TBD     | TBD     | TBD     | TBD                 |
| RSA-2048    | SQLite  | TBD     | TBD     | TBD     | TBD                 |
| RSA-4096    | SQLite  | TBD     | TBD     | TBD     | TBD                 |
| ML-DSA-44   | SQLite  | TBD     | TBD     | TBD     | TBD (--enable-mldsa)|

Run `./run_tests.sh --bench` and copy the issuance table from
`bench/results/issuance-*.md` here.

**Bottleneck analysis:**
- ECDSA P-256: signing-bound for small workloads; DB write dominates at high
  concurrency due to SQLite's write serialization.
- RSA-4096: strongly signing-bound (RSA key generation is O(key_size^3)).
- ML-DSA-44: signing is fast (lattice ops); DER encoding overhead is the
  differentiator.

---

## 4. OCSP throughput

**Method:** `CA._is_revoked(serial)` DB lookup for live signing; in-memory
dict lookup for pre-generated (models file-system read at O(1)).

| Mode | p50 (ms) | p95 (ms) | queries/s |
|------|---------|---------|-----------|
| Live (DB lookup) | TBD | TBD | TBD |
| Pre-generated (dict lookup) | TBD | TBD | TBD |

Run `python3 bench/ocsp.py` and copy results here.

**Notes:**
- Pre-generated OCSP is 2–3 orders of magnitude faster than live signing.
- For deployments > 100 OCSP req/s, pre-generation is the recommended path.
- Disk I/O for the pre-generated case is not modeled in the bench (dict lookup
  approximates an in-kernel page-cached file read).

---

## 5. CRL generation time

**Method:** `CertificateAuthority.generate_crl()` with N revoked certs pre-populated.

| Revoked certs | CRL gen time (p50) | Notes |
|---------------|--------------------|-------|
| 1,000         | TBD                | |
| 10,000        | TBD                | |
| 100,000       | TBD                | |
| 1,000,000     | TBD                | May hit SQLite full-scan limit |

Run `python3 bench/crl_gen.py` and copy results here.

**Cliff analysis:** Document at which revoked-cert count CRL generation time
crosses 10s, 30s, 60s. Beyond the 60s cliff, operators should consider
partitioned CRLs or delta-CRLs (not yet implemented).

---

## 6. Storage growth

**Method:** Issue N certs, checkpoint WAL, measure DB size before/after.

| Metric | Value |
|--------|-------|
| Bytes per cert (certificates table) | TBD |
| Bytes per audit row | TBD |
| Projected growth at 1 cert/s | TBD MB/day |
| Projected growth at 10 certs/s | TBD MB/day |
| Projected growth at 100 certs/s | TBD MB/day |

Run `python3 bench/storage.py --n 2000` and copy results here.

**Capacity planning example:**
At TBD certs/s sustained on ECDSA P-256, the `certificates` table grows
approximately TBD MB/day. At this rate, a 1 TB NVMe drive holds approximately
TBD days of certs before rotation is needed. The audit DB grows independently at
TBD MB/day.

---

## 7. Concurrent issuance scaling

SQLite serializes write transactions via advisory lock. Throughput does not scale
linearly with thread count; the curve is expected to plateau at 2–4 threads.

| Concurrency | certs/s (sustained) | Notes |
|-------------|---------------------|-------|
| 1 thread    | TBD                 | Baseline |
| 4 threads   | TBD                 | |
| 16 threads  | TBD                 | Expected to plateau |
| 64 threads  | TBD                 | |

Measure with: `python3 bench/issuance.py` with modified concurrency
(not yet exposed as a flag — add `--threads` when this table is populated).

**Postgres:** With Postgres, write parallelism is handled by the advisory lock
on the `serial_counter` row rather than WAL serialization. Expected throughput
scales better than SQLite at high concurrency.

---

## 8. ACME and CMP latency

These require an HTTP server running and are not yet automated in the bench
harness. To measure manually:

```bash
# ACME order completion (http-01 with local responder)
time certbot certonly --server http://localhost:8090/acme/directory \
  --standalone --domain test.local --agree-tos -n

# CMP ir latency
time openssl cmp -cmd ir -server http://localhost:8090/cmp \
  -subject "/CN=cmp-bench" -newkey /tmp/key.pem -out /tmp/cert.pem
```

Target p50 for ACME http-01 end-to-end: < 500ms on local network.
Target p50 for CMP ir: < 100ms.

---

## 9. Methodology notes

- **No microbenchmarks of internal functions.** All benches exercise the public
  `CertificateAuthority` Python API.
- **No averaged-only numbers.** Always p50/p95/p99 for latency.
- **Warm-up discarded.** First 10–20 calls are discarded; numbers represent
  steady-state performance.
- **Audit logging enabled by default.** Numbers include both cert DB write and
  audit row write. "no_audit" baseline is separately documented.
- **No marketing.** Numbers in this doc must be reproducible by running the bench
  commands above. Spike numbers are not reported.

---

## 10. Updating this document

After each release, run the full bench suite on the reference hardware profile,
copy the tables from `bench/results/` into this doc, and commit alongside the
release tag. The git history of this file is the performance record.

To add a result for a new hardware profile, add it in a separate section (e.g.,
§11) and do not modify the reference numbers in §3–8.
