# CLAUDE-cloud-kms.md — Cloud KMS Backends (AWS, GCP, Azure)

Companion to `CLAUDE.md`. Follow all conventions there. Extends the
existing `hsm_backend.py` key-protection abstraction with three cloud
implementations. The CA private key never leaves the provider's
HSM-backed key store; PyPKI submits hashes and receives signatures.

---

## What this is

Today, key protection in PyPKI is binary: either a passphrase-encrypted
file on disk (homelab, default) or a PKCS#11 HSM (`hsm_backend.py`,
enterprise). PKCS#11 covers Thales, Entrust nShield, YubiHSM, SoftHSM,
and AWS CloudHSM, but it doesn't cover the much more common case of
"my CA runs in AWS/GCP/Azure and I want the key in the native KMS."

Cloud KMS gives 90% of the HSM security guarantee at a fraction of the
operational cost: FIPS 140-2 Level 3 backing keys, no key material
crossing the network, native IAM-based authorization, audit trail in
the provider's logging stack. The tradeoff is sign latency (50–150ms
per call vs <5ms for a local HSM) and per-operation cost.

---

## Provider matrix (verify capabilities before each release)

| Capability                | AWS KMS                  | GCP Cloud KMS          | Azure Key Vault          |
| ------------------------- | ------------------------ | ---------------------- | ------------------------ |
| RSA 2048/3072/4096        | yes                      | yes                    | yes                      |
| ECDSA P-256               | yes                      | yes                    | yes                      |
| ECDSA P-384               | yes                      | yes                    | yes                      |
| ECDSA P-521               | yes                      | no (as of mid-2025)    | yes                      |
| ECDSA secp256k1           | yes                      | yes                    | yes (Managed HSM only)   |
| Ed25519                   | no (as of mid-2025)      | yes (regional)         | yes (Managed HSM only)   |
| ML-DSA / PQ               | announced; verify GA     | roadmap                | roadmap                  |
| Bring-your-own-key (BYOK) | yes                      | yes                    | yes                      |
| FIPS 140-2 Level          | 3 (HSM tier)             | 3 (HSM keys)           | 2 (vault) / 3 (Managed HSM) |
| Signature mode for RSA    | PKCS#1v1.5 + PSS         | PKCS#1v1.5 + PSS       | PKCS#1v1.5 + PSS         |

Re-check at release time:

- AWS: https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html
- GCP: https://cloud.google.com/kms/docs/algorithms
- Azure: https://learn.microsoft.com/azure/key-vault/keys/about-keys-details

Algorithms outside this matrix fall back to file/local HSM transparently;
PyPKI logs a startup warning if the operator selects an unavailable
combo and refuses to start (fail-closed).

---

## Abstraction

Refactor (don't replace) `hsm_backend.py` so backend selection is
per-key, not global. A CA may sign certs with cloud KMS while CRLs and
OCSP responses use a local key, or vice versa. The `ca_keys` table
gains a `backend` column plus a `backend_ref` opaque string.

```python
class KeyBackend(Protocol):
    name: str           # 'file' | 'pkcs11' | 'aws-kms' | 'gcp-kms' | 'azure-kv'

    def sign(self, ref: str, digest: bytes, algorithm: str) -> bytes:
        """Sign a pre-computed digest. algorithm is one of
        'rsa-pkcs1-sha256', 'rsa-pss-sha256', 'ecdsa-sha256',
        'ecdsa-sha384', 'ed25519', etc."""

    def public_key(self, ref: str) -> PublicKeyTypes: ...
    def healthy(self, ref: str) -> bool: ...
```

Every issuance path computes the TBS hash locally and calls
`backend.sign(...)`. This keeps the cloud-KMS-specific code small and
isolated — three modules, each ~400 LoC.

---

## Dependency philosophy

Do **not** add `boto3`, `google-cloud-kms`, or `azure-identity` as deps.
Use the providers' REST/JSON APIs with stdlib `urllib.request` and
hand-rolled auth. This is consistent with the project's stdlib-first
posture and avoids transitive-dep sprawl.

| Provider | Auth                            | Effort                          |
| -------- | ------------------------------- | ------------------------------- |
| AWS      | SigV4 over IRSA / IMDSv2 / static creds | ~250 LoC for SigV4 + IMDSv2     |
| GCP      | OAuth2 JWT bearer via metadata server / service-account JSON | ~200 LoC |
| Azure    | AAD bearer via IMDS / client-credential flow | ~250 LoC                  |

Each `auth_aws.py`, `auth_gcp.py`, `auth_azure.py` lives next to its
KMS module and is reused if/when we add other cloud features (S3
backup target, etc.).

---

## Implementation per provider

### `kms_aws.py`

Endpoint: `kms.<region>.amazonaws.com` (regional). API: `Sign`,
`GetPublicKey`, `DescribeKey`. Signature input is the digest;
`MessageType: DIGEST`. Algorithm specifier maps PyPKI's algorithm string
to AWS's (`RSASSA_PKCS1_V1_5_SHA_256`, `ECDSA_SHA_256`, etc.).

`backend_ref` format: `arn:aws:kms:<region>:<acct>:key/<key-id>` or the
shorter `alias/<name>`. Aliases preferred — they survive key rotation
where the underlying key ID changes.

Retry policy: exponential backoff on `ThrottlingException`, max 3
retries, ~5s ceiling. Surface `AccessDeniedException` immediately —
that's an IAM misconfiguration, not a transient error.

### `kms_gcp.py`

Endpoint: `cloudkms.googleapis.com`. API: `asymmetricSign`,
`getPublicKey`. Signature input: digest in base64, plus the digest
algorithm. Algorithm specifier maps to
`RSA_SIGN_PKCS1_2048_SHA256`, `EC_SIGN_P256_SHA256`, etc.

`backend_ref` format: `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<v>`.
Pin a version explicitly; do not use "primary" — version drift breaks
CT-log-anchored deployments.

Authentication: prefer Workload Identity (in GKE) or service-account
impersonation. Static JSON keys allowed but discouraged in docs.

### `kms_azure.py`

Endpoint: `https://<vault-name>.vault.azure.net/` (standard tier) or
`https://<hsm-name>.managedhsm.azure.net/` (Managed HSM tier). API:
`POST /keys/<name>/<version>/sign`. Body: `{"alg": "PS256", "value": "<base64url digest>"}`.

`backend_ref` format: full URL including version
(`https://<v>.vault.azure.net/keys/<name>/<version>`). Version pinning
matches the GCP rationale.

Authentication: prefer Managed Identity (in Azure VMs/AKS) or
workload identity federation. Client-secret flow allowed but
discouraged.

Note: Standard tier is FIPS 140-2 Level 2; for Level 3 use Managed HSM
tier. Log a warning at startup if Level 3 is required by profile and
the backend is standard tier.

---

## Schema

```sql
-- db_migrations/pki/00X_kms_backend.sql
ALTER TABLE ca_keys ADD COLUMN backend TEXT NOT NULL DEFAULT 'file';
ALTER TABLE ca_keys ADD COLUMN backend_ref TEXT;
ALTER TABLE ca_keys ADD COLUMN backend_meta_json TEXT;   -- algorithm, region hints

CREATE INDEX idx_ca_keys_backend ON ca_keys(backend);
```

`backend_meta_json` carries hints the backend wants to cache: the
public key's last-fetched timestamp, the algorithm capabilities the
provider advertised, etc. Optional and tolerant of schema drift.

Existing file-backed keys get `backend='file'`, `backend_ref=<path>`
during migration. Reversible.

---

## CLI flags

```
# At ca-init time
--ca-key-backend file|pkcs11|aws-kms|gcp-kms|azure-kv
--ca-key-backend-ref <provider-specific-ref>

# AWS
--aws-region us-east-1
--aws-auth iam-role|imdsv2|static
--aws-static-credentials-file /etc/pypki/aws.creds        # discouraged

# GCP
--gcp-project <id>
--gcp-auth workload-identity|metadata-server|service-account-file
--gcp-service-account-file /etc/pypki/gcp.json            # discouraged

# Azure
--azure-vault-url https://<v>.vault.azure.net/
--azure-auth managed-identity|workload-identity|client-secret
--azure-client-secret-file /etc/pypki/azure.secret        # discouraged
```

`pypki_admin.py` subcommands:

- `kms-import-ca --backend aws-kms --backend-ref alias/pypki-root --name root-2026`
  — onboards an existing KMS key as a PyPKI CA
- `kms-test-sign --ca <name>` — round-trip test, useful in deployment CI
- `kms-rotate-version --ca <name> --new-ref <ref>` — atomic switch to a
  new key version, with overlap window for rollback

---

## Latency and rate limits

Cloud-KMS signing is I/O-bound. Document these envelopes:

| Operation                  | Frequency                          | Latency impact                 |
| -------------------------- | ---------------------------------- | ------------------------------ |
| Cert issuance              | per request                        | +1 RTT (50–150ms)              |
| CRL signing                | scheduled, ~hourly                 | irrelevant                     |
| OCSP responder cert signing | once at responder startup         | irrelevant                     |
| OCSP response signing      | per request (if not pre-computed) | +1 RTT — **use pre-computed**  |
| TSA signing                | per request                        | +1 RTT (acceptable)            |
| SCEP/EST/CMP issuance      | per request                        | +1 RTT                         |

OCSP per-request signing against cloud KMS is the failure mode to
avoid. The existing OCSP pre-computation path is the right answer for
KMS-backed CAs; document loudly and consider making pre-computation
the default when `--ca-key-backend` is cloud.

Rate limits (verify at release time): AWS KMS ~10k req/s per region,
GCP Cloud KMS ~3k req/s per project, Azure Key Vault ~2k req/s per
vault. For high-throughput CAs the per-region/project ceiling matters
— operators may need to spread across vaults or regions.

---

## Tests

```
class TestKeyBackendInterface(unittest.TestCase):
    def test_file_backend_implements_protocol(self): ...
    def test_pkcs11_backend_implements_protocol(self): ...
    def test_aws_backend_implements_protocol(self): ...
    def test_gcp_backend_implements_protocol(self): ...
    def test_azure_backend_implements_protocol(self): ...
    def test_backend_selection_per_key(self): ...

class TestAWSKMSBackend(unittest.TestCase):
    # Mock provider over HTTP
    def test_sign_request_signed_with_sigv4(self): ...
    def test_imdsv2_token_refresh_on_401(self): ...
    def test_throttling_retried_with_backoff(self): ...
    def test_access_denied_surfaced_immediately(self): ...
    def test_algorithm_mapping_pkcs1_sha256(self): ...
    def test_algorithm_mapping_pss_sha256(self): ...
    def test_algorithm_mapping_ecdsa_sha256(self): ...
    def test_alias_resolution_to_key_id(self): ...
    def test_public_key_cached_after_first_fetch(self): ...

class TestGCPKMSBackend(unittest.TestCase): ...    # symmetric
class TestAzureKVBackend(unittest.TestCase): ...   # symmetric

class TestKMSIntegration(unittest.TestCase):
    # Skipped unless env vars set; run against real providers in nightly CI
    @skip_unless_env("PYPKI_TEST_AWS_KMS_ARN")
    def test_aws_kms_round_trip_signs_and_verifies(self): ...
    @skip_unless_env("PYPKI_TEST_GCP_KMS_REF")
    def test_gcp_kms_round_trip(self): ...
    @skip_unless_env("PYPKI_TEST_AZURE_KV_URL")
    def test_azure_kv_round_trip(self): ...

class TestKMSAuthFallback(unittest.TestCase):
    def test_imdsv2_unreachable_falls_back_to_static_creds(self): ...
    def test_static_creds_missing_fails_at_startup(self): ...
    def test_invalid_credentials_logged_redacted(self): ...
```

The integration tests are gated on env vars so the main suite stays
hermetic. Nightly CI runs them with rotation-only service accounts.

---

## Per-change checklist

- [ ] `hsm_backend.py` — extract `KeyBackend` protocol, refactor to
      per-key selection
- [ ] `kms_aws.py`, `kms_gcp.py`, `kms_azure.py` — new modules
- [ ] `auth_aws.py`, `auth_gcp.py`, `auth_azure.py` — auth helpers
- [ ] `pki_server.py` — issuance paths use the resolved backend per CA
- [ ] `db_migrations/pki/00X_kms_backend.sql` — schema
- [ ] `pypki_admin.py` — `kms-import-ca`, `kms-test-sign`,
      `kms-rotate-version`
- [ ] `ceremony.py` — offline root ceremony aware of cloud-KMS roots
- [ ] `test_pki_server.py` — five new test classes
- [ ] `README.md` — Key-protection matrix, cloud-KMS section
- [ ] `CHANGELOG.md` — `### Added`
- [ ] `docs/KMS.md` — per-provider setup runbook (IAM policy snippets,
      Workload Identity manifests, Managed Identity assignment)
- [ ] `pypki-flows.html` — sign-via-cloud-KMS flow

Run `./run_tests.sh`. Nightly CI runs `TestKMSIntegration` against
real providers; document the env var contract in `docs/KMS.md`.

---

## Open questions

1. **Cross-cloud DR**: a CA whose key lives in AWS KMS can't be
   restored if AWS is unreachable. For genuinely critical roots,
   recommend the offline-root pattern (`ceremony.py`) with cloud KMS
   only at the intermediate tier — losing access to cloud KMS means
   reissuing intermediates from the offline root, painful but tractable.
   Document the matrix in `docs/KMS.md`.

2. **PQ algorithms via cloud KMS**: AWS announced ML-DSA in 2024; verify
   GA status and supported parameter sets before claiming compliance.
   GCP and Azure are on roadmaps. Until all three are GA, PQ keys
   remain file-backed or PKCS#11 only — surface this clearly so users
   don't pick an unbuildable combination.

3. **Audit log integration**: cloud KMS provides its own audit trail
   (CloudTrail, Cloud Audit Logs, Azure Monitor). Should PyPKI's
   `audit_log` correlate with those, or stand alone? Recommend the
   latter: PyPKI audit captures "what we asked KMS to do"; cloud audit
   captures "what KMS actually did"; auditors cross-reference. Document
   the join key (we log the KMS request ID returned in the response).

4. **Cost ceiling**: at $0.03 per 10k sign operations (AWS) and similar
   for GCP/Azure, a busy CA doing 1M signs/day is ~$3/day. Surface a
   `pypki_kms_signs_total{provider}` metric and document the back-of-
   envelope cost calculation so operators can forecast.

5. **Pre-computed OCSP at cloud-KMS scale**: pre-computing responses
   for every active cert every refresh cycle hits the rate limit on
   busy CAs. Document the math (refresh interval × active certs ≤
   provider rate limit × seconds) and offer batching guidance.
