# Tier 6 — Release Gating Policy

**Status**: Confirmed 2026-05-31

This document is the authoritative policy for which CI gates block which
events. The per-tier docs (6.1–6.7) describe *how* each harness works; this
doc describes *when* the harness has to be green.

## Summary

### Per-PR (blocking — must be green to merge)

| Gate            | From | Wallclock        | What it runs                                            |
| --------------- | ---- | ---------------- | ------------------------------------------------------- |
| `unit-tests`    | —    | ~2 min           | `./run_tests.sh` (existing fast path)                   |
| `fuzz`          | 6.1  | 5 min per target | Atheris harnesses with fast budget                      |
| `interop`       | 6.2  | ~5 min           | "Required" matrix only (containerized reference clients)|
| `supply-chain`  | 6.4  | ~1 min           | `pip-audit` + lockfile hash verification                |
| `conformance`   | 6.6  | ~2 min           | NIST PKITS + RFC 5280 corner cases                      |

### Pre-release tag (blocking — must be green to publish)

| Gate                  | From | Wallclock        | What it runs                                       |
| --------------------- | ---- | ---------------- | -------------------------------------------------- |
| all per-PR gates      | —    | —                | Re-run on the tag commit for safety                |
| `fuzz-extended`       | 6.1  | 1 h per target   | Full nightly fuzz budget                           |
| `interop-full`        | 6.2  | ~15 min          | Required + best-effort matrices                    |
| `supply-chain-release`| 6.4  | ~3 min           | SBOM generation, cosign signing, reproducibility   |
| `conformance-full`    | 6.6  | ~10 min          | PKITS + Pebble + BetterTLS + corners               |
| `chaos`               | 6.5  | ~30 min          | Full chaos suite                                   |
| `bench`               | 6.7  | ~20 min          | Performance bench + >20% regression check          |

### Nightly cron (informational — files issues, doesn't block)

| Gate                  | From | Wallclock        | Purpose                                            |
| --------------------- | ---- | ---------------- | -------------------------------------------------- |
| `fuzz-extended`       | 6.1  | 1 h per target   | Corpus expansion, latent-bug discovery             |
| `interop-full`        | 6.2  | ~15 min          | Detect drift from upstream reference clients       |
| `chaos`               | 6.5  | ~30 min          | Catch flakes and slow regressions                  |
| `conformance-full`    | 6.6  | ~10 min          | Catch upstream battery updates                     |

## Activation schedule

**Gates activate as their underlying harness ships, not before.** Before a
gate's harness exists, the corresponding CI job is absent — it is not
auto-green and not silently skipped. The CI configuration is updated in
the same PR that lands the harness.

Activation order follows the Tier 6 priority:

1. **6.1 fuzz** — activates first
2. **6.2 interop** — next
3. **6.4 supply chain** — in parallel with 6.2 (independent surface)
4. **6.6 conformance** — after 6.2 (some interop fixtures feed conformance corpus)
5. **6.5 chaos** — after 6.3 threat-model walkback (the walkback informs which invariants matter)
6. **6.7 perf bench** — last; requires reference-hardware runner setup

Each activation lands with a CHANGELOG entry under `### Security` (fuzz,
chaos) or `### Changed` (interop, conformance, supply-chain, bench).

## Failure semantics

| Outcome  | Per-PR meaning                              | Pre-release meaning              |
| -------- | ------------------------------------------- | -------------------------------- |
| PASS     | Green; mergeable                            | Green; publishable               |
| FAIL     | Red; blocking. Fix forward.                 | Red; blocking. No release.       |
| FLAKE    | Same as FAIL — no retry policy for CA code  | Same as FAIL                     |
| BYPASSED | Yellow; non-blocking (see policy below)     | Cannot ship while bypass active  |
| N/A      | Harness doesn't exist yet; absent from CI   | Same                             |

We do **not** have an automatic flake-retry policy. A flake on CA software
is a bug; intermittent passes on randomized harnesses (fuzz, chaos) are the
intended signal, not noise to be retried away.

## Bypass policy

Sometimes a gate blocks legitimate work — an upstream battery bug, a
transient infrastructure issue, a temporarily broken interop client. The
bypass mechanism exists for these and only these.

**Process:**

1. Open a `gate-bypass:<gate>` issue with:
   - Which gate is bypassed
   - Why (root cause and link to upstream issue if applicable)
   - Expiration date — maximum 7 days from issue creation
   - Risk acknowledgment (what we're choosing not to verify)
2. Apply the `gate-bypass:<gate>` label to the PR.
3. CI reports the gate as `BYPASSED` instead of blocking.
4. Bypass expires automatically at the documented date. Re-bypass requires
   a new issue.

**Hard rules:**

- A release tag cannot publish while any bypass is active.
- Any bypass that crossed a release tag generates a CHANGELOG
  `### Security` entry.
- More than two active bypasses simultaneously is a stop-the-line event —
  no merges to main until reduced.
- Bypass cannot be used to ship code that triggered the gate. It exists
  only for gates failing due to external causes.

## Workflow templates

These are the target final state. Real `.github/workflows/*.yml` files
land incrementally as each Tier 6.x harness ships.

### `.github/workflows/ci.yml` (per-PR — final state)

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  unit-tests:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install --require-hashes -r requirements.txt -r requirements-dev.txt
      - run: ./run_tests.sh

  fuzz:
    runs-on: ubuntu-24.04
    needs: unit-tests
    strategy:
      matrix:
        target: [tlv, scep_envelope, cmp_pkimessage, crmf_popo,
                 est_csr, ocsp_request, tsa_request, mldsa_roundtrip]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install --require-hashes -r requirements.txt -r requirements-dev.txt
      - run: ./run_tests.sh --fuzz --target ${{ matrix.target }} --budget 300

  interop:
    runs-on: ubuntu-24.04
    needs: unit-tests
    strategy:
      matrix:
        proto: [scep, acme, est, cmp, ocsp, tsa, crl, smime, mldsa, pkcs12]
    steps:
      - uses: actions/checkout@v4
      - run: ./interop/${{ matrix.proto }}/run.sh

  supply-chain:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install --require-hashes -r requirements-dev.txt
      - run: pip-audit -r requirements.txt --strict
      - run: ./scripts/verify_lockfile_hashes.sh

  conformance:
    runs-on: ubuntu-24.04
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install --require-hashes -r requirements.txt -r requirements-dev.txt
      - run: ./run_tests.sh --conformance --pkits --rfc5280-corners
```

### `.github/workflows/release.yml` (release tag + nightly — final state)

```yaml
name: release
on:
  push:
    tags: ['v*.*.*']
  schedule:
    - cron: '0 3 * * *'   # 03:00 UTC

jobs:
  # Per-PR gates re-run here on tag push (omitted for brevity —
  # the jobs from ci.yml are reusable via workflow_call).

  fuzz-extended:
    runs-on: ubuntu-24.04
    timeout-minutes: 90
    strategy:
      matrix:
        target: [tlv, scep_envelope, cmp_pkimessage, crmf_popo,
                 est_csr, ocsp_request, tsa_request, mldsa_roundtrip]
    steps:
      - uses: actions/checkout@v4
      - run: ./run_tests.sh --fuzz --target ${{ matrix.target }} --budget 3600

  interop-full:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: ./interop/run_all.sh --include-best-effort

  supply-chain-release:
    runs-on: ubuntu-24.04
    if: startsWith(github.ref, 'refs/tags/')
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/build_release.sh
      - run: ./scripts/verify_reproducibility.sh
      - uses: sigstore/cosign-installer@v3
      - run: cosign sign-blob --yes pypki-main.zip > pypki-main.zip.sig
      - run: ./scripts/generate_sbom.sh > pypki-sbom.cdx.json
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            pypki-main.zip
            pypki-main.zip.sig
            pypki-sbom.cdx.json

  conformance-full:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: ./run_tests.sh --conformance --all

  chaos:
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
      - run: ./run_tests.sh --chaos

  bench:
    runs-on: [self-hosted, bench]   # dedicated bench runner
    if: startsWith(github.ref, 'refs/tags/')
    steps:
      - uses: actions/checkout@v4
      - run: ./run_tests.sh --bench
      - run: ./scripts/check_perf_regression.sh
```

## Per-change checklist (modifying a gate)

- [ ] Reason documented in PR description
- [ ] If loosening a gate (shorter budget, removed matrix entry), threat
      implication assessed
- [ ] If tightening a gate, repo is currently green against the new bar
      before the change merges
- [ ] CHANGELOG `### Changed` entry
- [ ] If activating a new gate, CHANGELOG `### Security` (fuzz/chaos) or
      `### Changed` (interop/conformance/supply-chain/bench)

## Success criteria

The release gating policy is "live" when:

1. `.github/workflows/ci.yml` exists and enforces every per-PR gate whose
   harness has shipped.
2. `.github/workflows/release.yml` exists and enforces every pre-release
   gate whose harness has shipped.
3. At least one bypass has gone through the documented process end-to-end
   (proves the mechanism works in practice, not just on paper).
4. CHANGELOG documents the activation date of each gate.
5. The README's "Releases" section links here and explains to consumers
   what each release tag has been gated against.
