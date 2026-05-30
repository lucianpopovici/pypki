# CLAUDE-code-signing-portal.md — Code Signing Portal with Build Attestations

Companion to `CLAUDE.md`. Follow all conventions there. Builds on the
existing TSA (`tsa_server.py`) and the `code_signing` CertProfile.
Adds a software-supply-chain-aware signing service: artifacts come in
with their build provenance, signatures go out, and both are recorded
in an internal transparency log.

---

## What this is

Today, `code_signing` is a CertProfile — PyPKI can issue code-signing
certs, but the actual signing happens on the developer's machine.
That's how most code signing works, and it's also where the supply
chain attacks happen: a developer's laptop is the weakest link.

The portal moves signing into PyPKI itself:

1. CI submits an artifact + in-toto attestations to PyPKI.
2. PyPKI validates the attestations against policy (who built it,
   from which commit, with which builder).
3. PyPKI signs the artifact with an ephemeral code-signing cert tied
   to the CI identity (OIDC token from the build runner).
4. The signature, the cert, and the attestation chain go into the
   internal transparency log.
5. PyPKI returns the signature + cert to the CI runner, which attaches
   it to the release.
6. Anyone can later fetch the verification bundle from PyPKI by
   artifact digest.

This is "Sigstore for your private code." Pairs naturally with GitHub
Actions, GitLab CI, Buildkite, Tekton, anything that produces an OIDC
token and an in-toto attestation.

---

## In-toto in 60 seconds

[in-toto](https://in-toto.io) is an IETF-tracked framework for software
supply chain integrity. The relevant artifacts:

- **Statement**: a JSON document describing what was built. Contains
  `predicateType` (e.g. `https://slsa.dev/provenance/v1`),
  `subject` (artifact digests), and `predicate` (arbitrary
  metadata about how it was built).
- **Envelope** (DSSE, "Dead Simple Signing Envelope"): wraps the
  statement and adds signatures. Signature target is a canonical
  payload encoding (PAE) — well-defined, reproducible, signature-
  friendly.

A SLSA Provenance v1 statement carries `builder.id` (the runner),
`buildType` (the workflow), `invocation.configSource` (the source
ref), `materials` (input artifacts and dependencies), and similar
fields. This is what PyPKI inspects against policy.

---

## Wire surface

### Submit for signing

```
POST /api/codesign/submit
{
  "artifacts": [
    {
      "name": "myapp_1.2.3_linux_amd64",
      "digest": {"sha256": "abc...def"}
    }
  ],
  "attestations": [
    "base64(DSSE envelope for SLSA Provenance v1)",
    "base64(DSSE envelope for SLSA VSA, optional)",
    "base64(DSSE envelope for SBOM, optional)"
  ],
  "oidc_token": "eyJhbGciOi..."           // CI runner's OIDC token
}
```

Response:

```json
{
  "log_entry_id": "0042-abc...def",
  "bundle": "base64(verification bundle)",
  "ephemeral_cert_pem": "-----BEGIN CERTIFICATE-----...",
  "signature": "base64(ECDSA P-256 signature over the DSSE PAE)"
}
```

The signature is over the DSSE PAE of a final attestation that PyPKI
adds: `predicateType:
"https://pypki.dev/attestations/codesign/v1"`, listing the input
attestations' hashes and the signing identity. This is the chain
anchor that ties everything together.

### Verify

```
GET /api/codesign/verify/<artifact-digest>
```

Response:

```json
{
  "found": true,
  "log_entries": [
    {
      "id": "0042-abc...def",
      "logged_at": "2026-05-25T03:00:00Z",
      "signing_identity": "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main",
      "ephemeral_cert_pem": "...",
      "signature": "...",
      "attestations_summary": [
        {"predicate_type": "https://slsa.dev/provenance/v1", "issuer": "https://token.actions.githubusercontent.com"}
      ],
      "policy_decisions": [
        {"policy": "release-from-main", "decision": "allow"}
      ]
    }
  ]
}
```

### Transparency log endpoints

Rekor-compatible REST shape (just enough that operators familiar with
Sigstore feel at home), but a private log scoped to this PyPKI
instance:

- `GET /api/codesign/log/entries/<id>` — individual entry
- `GET /api/codesign/log/proof/<id>` — inclusion proof
- `GET /api/codesign/log/checkpoint` — signed tree head
- `GET /api/codesign/log/search?artifact-digest=...&issuer=...`

The internal log is an append-only Merkle tree, with the checkpoint
periodically anchored to a configured external location (file, S3,
public Sigstore). The audit chain from `CLAUDE-audit-chain.md` doesn't
suffice here — code-signing audit needs proofs of inclusion, not just
tamper-evidence.

---

## OIDC trust for build runners

PyPKI accepts OIDC tokens from configured issuers:

```yaml
# /etc/pypki/codesign-issuers.yaml
issuers:
  - url: https://token.actions.githubusercontent.com
    audience: pypki-codesign
    identity_claim: sub
    identity_pattern: "repo:my-org/.*:ref:refs/heads/(main|release-.*)"
  - url: https://gitlab.com
    audience: pypki-codesign
    identity_claim: sub
    identity_pattern: "project_path:my-group/.*:ref_type:branch:ref:main"
  - url: https://buildkite.com
    audience: pypki-codesign
    identity_claim: sub
    identity_pattern: "organization:my-org:pipeline:.*"
```

Verification reuses the JWS infrastructure from `CLAUDE-sso.md`:
discovery, JWKS cache, signature check. The identity becomes the
SAN of the ephemeral signing cert.

Ephemeral cert lifetime: 10 minutes by default. Long enough to sign,
short enough that compromise of the cert+key gives a minutes-wide
window. The cert ends up in the transparency log; verifiers see a
historical cert that's been expired for months and trust it via the
log entry, not via OCSP/CRL freshness.

---

## Policy integration

Reuses the policy engine (`CLAUDE-policy-engine.md`) with extended
predicates:

```yaml
rules:
  - name: "production-releases-from-main"
    match:
      profile: code_signing
      codesign:
        oidc.issuer: https://token.actions.githubusercontent.com
        oidc.identity_pattern: "repo:my-org/myapp:ref:refs/heads/main"
        slsa.build_type: "https://github.com/Attestations/GitHubActionsWorkflow@v1"
        slsa.builder_id_pattern: "https://github.com/actions/runner.*"
        subject.size_max: 524288000      # 500 MB
    decide: allow

  - name: "deny-self-hosted-runners"
    match:
      profile: code_signing
      codesign:
        slsa.builder_id_pattern: ".*self-hosted.*"
    decide: deny
    reason: "Self-hosted runners not trusted for release signing"
```

The `codesign.*` predicate namespace is added to `policy.py`. Pure data
extraction from attestations; no new evaluation primitives.

---

## Implementation

### Files touched

| File              | Change                                                       |
| ----------------- | ------------------------------------------------------------ |
| `codesign.py`     | New module: orchestrator, DSSE handling, ephemeral cert issuance |
| `intoto.py`       | New module: DSSE envelope parse/serialize, PAE encoding,     |
|                   | SLSA statement decoders                                      |
| `merkle_log.py`   | New module: append-only Merkle tree, inclusion proofs        |
| `pki_server.py`   | New endpoints, routing                                       |
| `policy.py`       | `codesign.*` predicate namespace                             |
| `web_ui.py`       | Verification UI page (paste a digest, get the bundle)        |
| `db_migrations/pki/00X_codesign.sql` | New tables                          |
| `test_pki_server.py` | `TestCodeSignSubmit`, `TestCodeSignVerify`, `TestDSSE`, `TestMerkleLog`, `TestSLSAPolicyExtraction` |
| `README.md`       | New section                                                  |
| `CHANGELOG.md`    | `### Added`                                                  |
| `docs/CODESIGN.md`| Operator + CI-author runbook                                 |

### Schema

```sql
-- db_migrations/pki/00X_codesign.sql
CREATE TABLE codesign_log_entries (
    id                  TEXT PRIMARY KEY,            -- e.g. "0042-abc...def"
    sequence            INTEGER NOT NULL UNIQUE,     -- monotonic tree index
    logged_at           INTEGER NOT NULL,
    artifact_digests    TEXT NOT NULL,               -- JSON: {"sha256": "..."}, ...
    signing_identity    TEXT NOT NULL,               -- OIDC sub
    issuer              TEXT NOT NULL,               -- OIDC iss
    ephemeral_cert_pem  TEXT NOT NULL,
    ephemeral_serial    TEXT NOT NULL,
    signature           BLOB NOT NULL,
    attestation_chain   TEXT NOT NULL,               -- JSON array of envelope hashes
    policy_decisions    TEXT NOT NULL,               -- JSON array
    tree_node_hash      BLOB NOT NULL                -- Merkle node hash for this entry
);

CREATE INDEX idx_codesign_log_digest_lookup ON codesign_log_entries(artifact_digests);
CREATE INDEX idx_codesign_log_identity     ON codesign_log_entries(signing_identity);
CREATE INDEX idx_codesign_log_logged_at    ON codesign_log_entries(logged_at);

CREATE TABLE codesign_attestations (
    hash                TEXT PRIMARY KEY,             -- sha256 of DSSE envelope
    envelope_json       TEXT NOT NULL,
    statement_predicate_type TEXT NOT NULL,
    received_at         INTEGER NOT NULL
);

CREATE TABLE codesign_tree_nodes (
    level               INTEGER NOT NULL,
    index_at_level      INTEGER NOT NULL,
    hash                BLOB NOT NULL,
    PRIMARY KEY (level, index_at_level)
);

CREATE TABLE codesign_checkpoints (
    tree_size           INTEGER PRIMARY KEY,
    root_hash           BLOB NOT NULL,
    signed_at           INTEGER NOT NULL,
    signature           BLOB NOT NULL,                -- by the log's own key
    anchored_at         INTEGER,                       -- if externally anchored
    anchor_uri          TEXT
);
```

### Merkle log

Standard binary Merkle tree (RFC 6962 §2 semantics, simpler than
RFC 9162 — we don't need consistency proofs across snapshots for v1).
Append takes `O(log n)` time; inclusion proofs are `O(log n)` sized.

```python
def append(payload_hash: bytes, conn: Database) -> tuple[int, bytes]:
    """Append a leaf, return (sequence, tree_node_hash)."""
    with conn.advisory_lock("codesign-merkle"):
        seq = _next_sequence(conn)
        leaf_hash = hashlib.sha256(b"\x00" + payload_hash).digest()
        _store_leaf(conn, seq, leaf_hash)
        _propagate_upward(conn, seq, leaf_hash)
        return seq, leaf_hash

def inclusion_proof(seq: int, current_size: int, conn: Database
                    ) -> list[bytes]:
    """Return the sibling path from leaf to current root."""
    ...
```

The Merkle log is per-tenant if multi-tenancy is enabled (tenants
shouldn't see each other's signing activity). Per-tenant tree adds
`tenant_id` to keys but doesn't change the algorithm.

### Ephemeral cert issuance

Reuses `pki_server.py:issue_certificate` with profile
`code_signing_ephemeral` (new CertProfile entry):

```python
"code_signing_ephemeral": CertProfile(
    key_usage=KeyUsage(digital_signature=True),
    extended_key_usages=[ExtendedKeyUsageOID.CODE_SIGNING],
    validity_seconds=600,                              # 10 min
    allowed_algorithms={"ecdsa-p256"},
    portal_self_revoke=False,
    portal_self_renew=False,
),
```

SANs include the OIDC identity as a URI SAN (Sigstore convention):
`URI: https://github.com/my-org/myapp/.github/workflows/release.yml@refs/heads/main`.
Verifiers check the URI SAN matches the expected identity.

Key pair is generated server-side, used once, never persisted (kept in
memory only long enough to sign). The cert is persisted (it's in the
log); the private key is zeroized immediately after signing.

---

## CLI flags

```
--codesign-enabled true
--codesign-issuers-file /etc/pypki/codesign-issuers.yaml
--codesign-ephemeral-validity-seconds 600
--codesign-log-checkpoint-interval 60         # seconds between signed tree heads
--codesign-log-anchor-target file:///var/lib/pypki/codesign-anchors/
--codesign-log-anchor-target https://anchor.example.com/codesign/
--codesign-max-artifact-bytes 524288000       # 500 MB
--codesign-max-attestation-count 16
```

`pypki_admin.py codesign-log-verify` — full re-hash of the Merkle tree
from leaves up; matches each checkpoint signature. Catches log
corruption.

---

## Tests

```
class TestDSSE(unittest.TestCase):
    def test_pae_encoding_matches_spec(self): ...
    def test_envelope_signature_verifies(self): ...
    def test_envelope_with_multiple_signatures(self): ...
    def test_in_toto_io_official_test_vectors(self): ...

class TestSLSAPolicyExtraction(unittest.TestCase):
    def test_builder_id_extracted(self): ...
    def test_build_type_extracted(self): ...
    def test_source_ref_extracted(self): ...
    def test_materials_list_extracted(self): ...
    def test_malformed_statement_rejected(self): ...

class TestCodeSignSubmit(unittest.TestCase):
    def test_valid_submission_returns_bundle(self): ...
    def test_expired_oidc_token_rejected(self): ...
    def test_unknown_issuer_rejected(self): ...
    def test_identity_pattern_mismatch_rejected(self): ...
    def test_artifact_too_large_rejected(self): ...
    def test_attestation_count_capped(self): ...
    def test_policy_denial_returns_specific_error(self): ...
    def test_ephemeral_key_not_persisted(self): ...
    def test_submission_recorded_in_log(self): ...
    def test_signature_verifies_with_returned_cert(self): ...

class TestCodeSignVerify(unittest.TestCase):
    def test_verify_by_digest_returns_entries(self): ...
    def test_unknown_digest_returns_404(self): ...
    def test_multiple_signings_returns_all(self): ...
    def test_verify_includes_policy_decisions(self): ...

class TestMerkleLog(unittest.TestCase):
    def test_empty_log_returns_consistent_state(self): ...
    def test_append_increments_sequence(self): ...
    def test_inclusion_proof_verifies_against_root(self): ...
    def test_log_verify_catches_corruption(self): ...
    def test_concurrent_appends_under_advisory_lock(self): ...
    def test_checkpoint_signed_with_log_key(self): ...
    def test_externally_anchored_checkpoint_published(self): ...
```

The Merkle correctness tests use RFC 6962 test vectors.

---

## Per-change checklist

- [ ] `intoto.py`, `merkle_log.py`, `codesign.py` — new modules
- [ ] `pki_server.py` — endpoints, ephemeral cert path
- [ ] `policy.py` — `codesign.*` predicates
- [ ] `web_ui.py` — verification UI
- [ ] `db_migrations/pki/00X_codesign.sql` — schema
- [ ] `pypki_admin.py` — `codesign-log-verify`,
      `codesign-replay-policy`, `codesign-anchor-now`
- [ ] `test_pki_server.py` — five new test classes
- [ ] `README.md` — Code signing portal section
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `docs/CODESIGN.md` — operator + CI-author runbook, GitHub Actions
      / GitLab CI sample workflows
- [ ] `pypki-flows.html` — submit + verify flows
- [ ] `examples/github-actions/sign-and-release.yml` — reference CI

Run `./run_tests.sh`.

---

## Open questions

1. **Public Sigstore anchoring**: instead of an internal log, anchor
   into the public Sigstore Rekor instance. Pros: free public
   transparency. Cons: leaks the existence of every internal release.
   For most users the internal log is the right default; document
   Rekor anchoring as a per-tenant opt-in for open-source projects
   that *want* their signatures publicly logged.

2. **Replay protection**: an attacker who steals a 10-minute ephemeral
   cert + key could re-sign different artifacts in that window.
   Mitigation: bind the cert to the specific artifact digest via a
   custom certificate extension (`pypki-bound-artifact-digest`,
   OID under PyPKI's private arc). Verifiers check that the
   signature target's digest matches the binding extension. Closes
   the replay window.

3. **Signature format**: ECDSA P-256 over DSSE PAE is the v1 baseline.
   Future: ML-DSA when supply-chain tooling catches up; composite
   signatures for the transition. Plumb `signature.algorithm` through
   the bundle now so v2 can extend without breaking v1 verifiers.

4. **Verification client library**: PyPKI returns a bundle but doesn't
   ship a verifier. Sigstore's `cosign verify-blob` is the model.
   Ship a small Python verifier in `pypki_verify.py` as a single-file
   script with no deps, and document how to call it from CI (the
   verify step happens at deploy time, not build time).

5. **TSA timestamping inside the bundle**: include an RFC 3161
   timestamp from PyPKI's TSA over the signature. Lets verifiers
   confirm the signature was made before the ephemeral cert expired
   without needing to query the transparency log. Add to the bundle
   format from v1.
