# Tier 6.7 — Performance Baseline

Benchmarks drive PyPKI's public Python API directly (in-process) to measure
real signing + DB + audit overhead without HTTP round-trip noise.

## Running

```bash
# Full suite (pre-release only — takes ~10 minutes)
./run_tests.sh --bench

# Single benchmark
python3 bench/issuance.py
python3 bench/ocsp.py
python3 bench/crl_gen.py
python3 bench/storage.py
```

## Reference hardware

Results committed to `bench/results/` are tagged with:
- CPU, RAM, disk
- Python version
- PyPKI commit SHA

Results from different hardware profiles go in separate files.
**Never overwrite a reference result from a different machine.**

## Regression gate

Pre-release CI compares the new result against the last committed baseline
for the same hardware profile. > 20% regression on any metric blocks release.

Check: `./scripts/check_perf_regression.sh`
