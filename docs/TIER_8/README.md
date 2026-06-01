# Tier 8 — Documentation Refresh

Tier 6 hardened the code and tightened release gating. Tier 7 (in flight)
makes PyPKI consumable as a Kubernetes / Terraform building block. Tier 8
makes sure the docs reflect both — and adds the missing per-service
deployment how-tos operators are actually asking for.

## Ordering rationale

| #   | Workstream                       | Why this order                                                                                          |
| --- | -------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 8.1 | Documentation audit              | Existing docs predate Tier 5 features (HSM, RA workflow, ML-DSA) and Tier 6 (fuzz, chaos, gating). Must reconcile before adding new docs that link into them. |
| 8.2 | Per-service deployment guides    | Operators ask "how do I deploy the ACME server" first, then pick a topology. The existing `docs/DEPLOYMENT/` is organized topology-first; 8.2 adds the missing service-first layer. |

8.1 lands first. 8.2 builds on top — every service guide cross-references
audited docs, not the pre-audit versions.

## When this runs

Cleanest position is between Tier 6 and Tier 7: hardening lands first
(makes the docs worth refreshing), docs get refreshed, then Tier 7
adoption infrastructure (cert-manager, Helm, Terraform, OpenAPI) ships
against an accurate doc set.

If Tier 7 ships first, 8.1 audits Tier 7 docs as well. The audit
checklist is the same.

## Cross-cutting conventions

- **All docs live under `docs/`.** No floating READMEs in feature
  directories. The root `README.md` and `CHANGELOG.md` are the only
  exceptions.
- **Every command shown must be executable as written** against a fresh
  checkout. "Should work" is not acceptable; if it isn't tested, it
  doesn't ship.
- **Every CLI flag mentioned must match `--help` output** at the head
  commit. Drift is a bug.
- **File references include line numbers**: `pki_server.py:606` — they
  rot loudly when the code moves, which is the desired behaviour.
- **"Last reviewed" header on every doc**: `> Last reviewed: 2026-MM-DD
  (commit abc1234)`. Audit pass updates these.
- **No marketing language.** "Easy", "powerful", "robust" — none of it.
  Operators want facts and commands.

## Per-workstream docs

- [`8.1-DOC-AUDIT.md`](./8.1-DOC-AUDIT.md) — reconcile every existing doc with current code
- [`8.2-SERVICE-DEPLOYMENT-GUIDES.md`](./8.2-SERVICE-DEPLOYMENT-GUIDES.md) — new per-service how-to guides

## Success criteria

Tier 8 is "done" when:

1. Every file under `docs/` (plus `README.md` and `CHANGELOG.md`) has a
   "Last reviewed" header within the last 30 days.
2. Every service exposed by PyPKI has a how-to guide in `docs/HOWTO/`
   following the standard template (see 8.2).
3. `README.md`'s Documentation section is a single index pointing into
   `docs/CPS.md`, `docs/THREAT_MODEL.md`, `docs/PERFORMANCE.md`,
   `docs/DEPLOYMENT/` (topology), and `docs/HOWTO/` (service).
4. No documented CLI flag is missing from `--help`; no `--help` flag is
   absent from the docs (or explicitly noted as undocumented with reason).
5. CHANGELOG `### Documentation` entries cover the audit pass and each
   new guide.
6. A new operator can deploy any single service from scratch using only
   the relevant `docs/HOWTO/<service>.md` plus the homelab quickstart.
