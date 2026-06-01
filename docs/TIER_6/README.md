# Tier 6 — Hardening

Tier 6 is the production-posture pass. Tiers 1–4 shipped the RFC catalogue;
Tier 5 shipped operational features (HSM, Postgres, RA workflow, etc.). Tier 6
proves what's there is sound before Tier 7 pushes for adoption.

## Ordering rationale

The seven workstreams are ranked by attack-surface reduction per unit effort,
not by what's easiest to ship:

| #   | Workstream                  | Why this order                                                                                  |
| --- | --------------------------- | ----------------------------------------------------------------------------------------------- |
| 6.1 | Fuzz hand-rolled ASN.1      | Highest-risk code, only bug class the unit suite cannot find. Do first.                         |
| 6.2 | Interop matrix              | Proves the RFCs we claim are actually wire-compatible with reference clients.                   |
| 6.3 | Threat-model walkback       | The doc predates RA, EAB, cross-signing, paired-issue, webhooks, HSM. Refresh after 6.2.        |
| 6.4 | Supply chain                | SBOM, signed releases, pinned deps, reproducible builds. Independent — run in parallel.         |
| 6.5 | Chaos & failure injection   | Defends the audit-log invariant. Cheap once 6.1/6.2 have stabilized the surface.                |
| 6.6 | Conformance batteries       | NIST PKITS, Pebble, RFC 5280 corner cases. Mostly third-party suites; little new code.          |
| 6.7 | Performance baseline        | Required for Tier 7 messaging. Numbers, not adjectives.                                         |

6.1 and 6.4 can run concurrently with the rest. 6.2 is the longest stretch
(plan for 2 sessions). 6.3 lands best after 6.2 because interop testing tends
to surface threat-model assumptions you didn't know you were making.

## Cross-cutting conventions

These apply to every Tier 6 workstream and supplement the rules in the root
`CLAUDE.md`:

- **Dev-only dependencies are permitted** in `requirements-dev.txt` (Atheris,
  pip-audit, cyclonedx-py, cosign). They MUST NOT be imported by any
  server-side module. The "no new pip dependencies" rule applies to runtime.
- **All new test runners** are invoked from `run_tests.sh` with explicit
  flags: `--fuzz`, `--interop`, `--chaos`, `--conformance`, `--bench`. The
  default fast path stays as it is today.
- **Findings become tests.** Every fuzz crash, interop failure, chaos
  invariant break, or conformance regression gets a permanent regression test
  added to `test_pki_server.py` under the appropriate `TestRFC<nnnn>` class
  or a new `TestTier6<area>` class.
- **CHANGELOG**: Tier 6 entries go under `### Security` (fuzz, chaos, threat
  model fixes), `### Fixed` (interop bugs), or `### Documentation`
  (performance, threat model updates).
- **Release gating** (confirmed 2026-05-31): per-PR blocking gates are 6.1
  (fuzz, 5-minute budget per target), 6.2 (required interop matrix), 6.4
  (`pip-audit` + lockfile hash check), and 6.6 (PKITS + RFC 5280 corners).
  Pre-release tag adds 6.1-extended (1 hour per target), 6.2-full, 6.4
  release artifacts (SBOM + cosign + reproducibility), 6.5 (full chaos),
  6.6-full (Pebble + BetterTLS), and 6.7 (bench + regression check).
  Gates activate as their harness ships — no auto-green stubs. Full
  policy, bypass procedure, and workflow templates in
  [`RELEASE_GATING.md`](./RELEASE_GATING.md).

## Per-workstream docs

- [`6.1-FUZZING.md`](./6.1-FUZZING.md) — fuzz the hand-rolled ASN.1 layer
- [`6.2-INTEROP.md`](./6.2-INTEROP.md) — interop matrix against reference clients
- [`6.3-THREAT-MODEL-WALKBACK.md`](./6.3-THREAT-MODEL-WALKBACK.md) — refresh threat model for post-Tier-4 surfaces
- [`6.4-SUPPLY-CHAIN.md`](./6.4-SUPPLY-CHAIN.md) — SBOM, signed releases, reproducible builds
- [`6.5-CHAOS.md`](./6.5-CHAOS.md) — failure-injection harnesses
- [`6.6-CONFORMANCE.md`](./6.6-CONFORMANCE.md) — third-party conformance batteries
- [`6.7-PERFORMANCE.md`](./6.7-PERFORMANCE.md) — documented performance envelope
- [`RELEASE_GATING.md`](./RELEASE_GATING.md) — confirmed CI gating policy (per-PR / pre-release / nightly)

## Exit criteria for Tier 6

Tier 6 is "done" when:

1. Fuzz harnesses run clean for 1 hour per target with no new unique paths.
2. The interop matrix is green for every protocol PyPKI claims in the README
   compliance table (S/MIME and NDES may remain manual / known-gap).
3. `docs/THREAT_MODEL.md` covers every feature listed in the Tier 5 inventory,
   with a test reference per mitigation.
4. Every release tag produces a CycloneDX SBOM, cosign-signed artifacts, and
   a byte-identical reproducible build verification.
5. The chaos suite proves the audit-log invariant under all documented
   failure modes.
6. NIST PKITS and Pebble compliance run green in CI.
7. `docs/PERFORMANCE.md` documents the numbers operators need to size a
   deployment.

Only then does Tier 7 (cert-manager external issuer, Helm chart, Terraform
provider, OpenAPI spec) become the right place to spend effort.
