# PyPKI Cloud KMS Key Backends

<!-- Last reviewed: 2026-06-02 -->

PyPKI supports AWS KMS, GCP Cloud KMS, and Azure Key Vault as CA signing key
backends. The CA private key never leaves the cloud provider's HSM-backed
store; PyPKI computes TBS hashes locally and submits them for signing.

No pip dependencies required: `boto3`, `google-cloud-kms`, and `azure-identity`
are **not** used. All cloud API calls use stdlib `urllib.request` with
hand-rolled SigV4 / OAuth2 / AAD authentication.

---

## Provider comparison

| Capability            | AWS KMS   | GCP Cloud KMS | Azure Key Vault |
|-----------------------|-----------|----------------|-----------------|
| RSA 2048/3072/4096    | ✓         | ✓              | ✓               |
| ECDSA P-256           | ✓         | ✓              | ✓               |
| ECDSA P-384           | ✓         | ✓              | ✓               |
| Ed25519               | ✗ (2025)  | ✓ (regional)   | ✓ (Managed HSM) |
| FIPS 140-2 Level      | 3 (HSM)   | 3 (HSM keys)   | 2 (vault) / 3 (Managed HSM) |
| Auth (cloud-native)   | IRSA/IMDS | Workload Identity | Managed Identity |
| Sign latency          | 50–150ms  | 50–150ms       | 50–150ms        |

Re-verify at release: AWS/GCP/Azure algorithm pages change.

---

## Latency note

Cloud KMS adds ~50–150 ms per signature. Implications:

- **OCSP per-request signing**: use pre-computed OCSP responses
  (`--ocsp-prefix` enables the pre-compute path). Never sign OCSP
  responses live when the CA key is in cloud KMS.
- **CRL signing**: scheduled/hourly — latency irrelevant.
- **Cert issuance**: one RTT overhead, acceptable.

---

## AWS KMS

### IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:us-east-1:123456789:key/*"
    }
  ]
}
```

### Key creation

```bash
# Create an asymmetric signing key (EC P-256 recommended)
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --description "PyPKI root CA 2026"

# Create an alias (preferred over ARN — survives rotation)
aws kms create-alias --alias-name alias/pypki-root-2026 --target-key-id <key-id>
```

### PyPKI configuration

```bash
pypki serve \
  --ca-key-backend aws-kms \
  --ca-key-backend-ref alias/pypki-root-2026 \
  --aws-region us-east-1 \
  --aws-auth imdsv2 \
  ...
```

**Authentication modes:**
- `imdsv2` (default): EC2/ECS instance credentials via IMDSv2
- `static`: JSON file with `AccessKeyId` / `SecretAccessKey` (discouraged)
- `iam-role`: alias for `imdsv2`

### Register an existing KMS key

```bash
pypki_admin kms-import-ca \
  --backend aws-kms \
  --backend-ref alias/pypki-root-2026 \
  --name root-2026 \
  --aws-region us-east-1
```

### Test connectivity

```bash
pypki_admin kms-test-sign \
  --backend aws-kms \
  --backend-ref alias/pypki-root-2026 \
  --aws-region us-east-1
```

### Key rotation

```bash
# 1. Create the new key version in AWS console / CLI
# 2. Update PyPKI's reference
pypki_admin kms-rotate-version \
  --name root-2026 \
  --new-ref alias/pypki-root-2026-v2

# 3. Restart the server
```

Cross-sign the old intermediate CA cert with the new root key so
relying parties that haven't received the new root can still verify.

---

## GCP Cloud KMS

### IAM role

Assign `roles/cloudkms.signerVerifier` to the service account or workload identity.

### Key creation

```bash
gcloud kms keyrings create pypki --location global
gcloud kms keys create root-2026 \
  --keyring pypki \
  --location global \
  --purpose asymmetric-signing \
  --default-algorithm ec-sign-p256-sha256

# Pin the first version explicitly:
# projects/my-project/locations/global/keyRings/pypki/cryptoKeys/root-2026/cryptoKeyVersions/1
```

### PyPKI configuration

```bash
pypki serve \
  --ca-key-backend gcp-kms \
  --ca-key-backend-ref "projects/my-project/locations/global/keyRings/pypki/cryptoKeys/root-2026/cryptoKeyVersions/1" \
  --gcp-auth workload-identity \
  ...
```

**Authentication modes:**
- `metadata-server` / `workload-identity` (default): GCE/GKE metadata server
- `service-account-file`: JSON key file (discouraged)

**Always pin the version number in the ref.** Never use `cryptoKeyVersions/latest`.

---

## Azure Key Vault

### RBAC assignment

Assign `Key Vault Crypto User` (or `Key Vault Crypto Officer` to create keys)
to the managed identity.

### Key creation

```bash
az keyvault key create \
  --vault-name my-vault \
  --name pypki-root-2026 \
  --kty EC \
  --curve P-256

# Pin version from:
az keyvault key show --vault-name my-vault --name pypki-root-2026 \
  | jq -r '.key.kid'
# → https://my-vault.vault.azure.net/keys/pypki-root-2026/<version>
```

### PyPKI configuration

```bash
pypki serve \
  --ca-key-backend azure-kv \
  --ca-key-backend-ref "https://my-vault.vault.azure.net/keys/pypki-root-2026/<version>" \
  --azure-auth managed-identity \
  ...
```

**FIPS note:** Standard Key Vault = FIPS 140-2 Level 2.
For Level 3 use Managed HSM (`*.managedhsm.azure.net`).

**Authentication modes:**
- `managed-identity` / `workload-identity` (default): Azure IMDS
- `client-secret`: client ID + secret file (discouraged)

---

## Disaster recovery

**Cloud KMS-backed intermediate, offline root (recommended)**

Keep the root CA key in an offline ceremony (`ceremony.py`). Issue an
intermediate whose signing key lives in cloud KMS. If cloud KMS becomes
unreachable, re-issue the intermediate from the offline root.

**Losing cloud KMS access**

If the KMS endpoint is unreachable, PyPKI cannot sign new certs or CRLs.
OCSP pre-computed responses continue to serve until they expire (default 8h
TTL). CRL distribution continues from the cached file until next update.
Alert on `pypki_kms_signs_total{provider}` going to zero.

---

## Cost estimation

| Provider | Cost per 10k signs | At 100k signs/day |
|----------|--------------------|-------------------|
| AWS KMS  | $0.03             | ~$0.30/day         |
| GCP KMS  | ~$0.03            | ~$0.30/day         |
| Azure KV | ~$0.03            | ~$0.30/day         |

These are estimates; verify current pricing in provider docs.
Monitor `pypki_kms_signs_total` to track actual sign volume.
