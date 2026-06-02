# PyPKI Code-Signing Portal

<!-- Last reviewed: 2026-06-02 -->

"Sigstore for your private code." CI/CD pipelines submit artifacts with
in-toto attestations and an OIDC identity token; PyPKI issues an ephemeral
code-signing certificate, signs the provenance, and records everything in
a Merkle transparency log.

---

## How it works

1. CI submits an artifact digest + in-toto attestations + OIDC token to `POST /api/codesign/submit`.
2. PyPKI validates the OIDC token against configured trusted issuers.
3. PyPKI issues a 10-minute ephemeral ECDSA P-256 cert (URI SAN = OIDC identity).
4. PyPKI signs a PyPKI codesign attestation (DSSE envelope) with the ephemeral key.
5. The entry is appended to the internal Merkle transparency log.
6. The signature, cert, and inclusion proof are returned as a **verification bundle**.
7. Anyone can verify the bundle against the log by digest: `GET /api/codesign/verify/<sha256>`.

---

## Enabling

```bash
pypki serve \
  --codesign-enabled \
  --codesign-issuers-file /etc/pypki/codesign-issuers.json \
  --codesign-ephemeral-validity-seconds 600 \
  ...
```

---

## Issuers configuration (`codesign-issuers.json`)

```json
{
  "issuers": [
    {
      "url": "https://token.actions.githubusercontent.com",
      "audience": "pypki-codesign",
      "identity_claim": "sub",
      "identity_pattern": "repo:my-org/my-repo:ref:refs/heads/main"
    },
    {
      "url": "https://gitlab.com",
      "audience": "pypki-codesign",
      "identity_claim": "sub",
      "identity_pattern": "project_path:my-group/.*:ref_type:branch:ref:main"
    }
  ]
}
```

---

## GitHub Actions integration

`.github/workflows/sign-and-release.yml`:

```yaml
name: Sign and Release

on:
  push:
    tags: ["v*"]

permissions:
  id-token: write
  contents: read

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build artifact
        run: |
          make release
          sha256sum dist/myapp_* > dist/checksums.txt

      - name: Get OIDC token
        id: oidc
        run: |
          TOKEN=$(curl -sSf \
            -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=pypki-codesign" \
            | jq -r '.value')
          echo "token=$TOKEN" >> "$GITHUB_OUTPUT"

      - name: Submit to PyPKI code-signing portal
        run: |
          DIGEST=$(sha256sum dist/myapp_linux_amd64 | cut -d' ' -f1)
          
          curl -X POST https://pki.example.com/api/codesign/submit \
            -H "Authorization: Bearer ${{ secrets.PYPKI_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d '{
              "artifacts": [{"name": "myapp_linux_amd64", "digest": {"sha256": "'"$DIGEST"'"}}],
              "attestations": [],
              "oidc_token": "${{ steps.oidc.outputs.token }}"
            }' \
            -o codesign-bundle.json
          
          echo "Log entry: $(jq -r .log_entry_id codesign-bundle.json)"

      - name: Upload bundle
        uses: actions/upload-artifact@v4
        with:
          name: codesign-bundle
          path: codesign-bundle.json
```

---

## Verify a signed artifact

```bash
# By artifact digest
curl https://pki.example.com/api/codesign/verify/sha256:abc123... \
  | jq .

# By entry ID
curl https://pki.example.com/api/codesign/log/entries/0042-abc... \
  | jq .

# Search by identity
curl "https://pki.example.com/api/codesign/log/search?issuer=repo:my-org/my-repo"

# Current Merkle tree head
curl https://pki.example.com/api/codesign/log/checkpoint
```

---

## Transparency log

The log uses an RFC 6962-compatible binary Merkle tree:
- Leaf hash: `SHA256(0x00 || payload_hash)`
- Node hash: `SHA256(0x01 || left || right)`
- Inclusion proof: sibling path from leaf to root

Every verify response includes the inclusion proof for each entry, so
verifiers can independently confirm inclusion without trusting PyPKI.

---

## Admin CLI

```bash
# Verify the full log from leaves up
pypki_admin codesign-log-verify

# Write a signed tree checkpoint immediately
pypki_admin codesign-anchor-now
```

---

## DSSE / in-toto

Attestations must be base64-encoded DSSE (Dead Simple Signing Envelope) envelopes.
The `payloadType` should be `application/vnd.in-toto+json` with an in-toto
Statement JSON body.

SLSA Provenance v1 (`predicateType: https://slsa.dev/provenance/v1`) is
the recommended predicate type. PyPKI extracts `builder.id`, `buildType`,
and `invocation.configSource.ref` for display and future policy matching.

---

## Ephemeral certificate

- Algorithm: ECDSA P-256
- Validity: 10 minutes (configurable with `--codesign-ephemeral-validity-seconds`)
- Subject: `CN=ephemeral-codesign`
- URI SAN: OIDC `sub` claim value (Sigstore convention)
- Profile: `code_signing_ephemeral` (no CRL/OCSP — RFC 9608 noRevAvail)

The private key is generated in memory, used once to sign, then discarded.
It is never persisted. The certificate is stored in the log.

---

## Security notes

- **Replay window**: the ephemeral cert is valid for 10 minutes. An attacker
  who obtains the cert + key (they're in memory) could sign other artifacts
  in that window. Mitigation: bind the cert to the specific artifact digest
  via `--codesign-artifact-binding` (planned for v2).
- **OIDC token freshness**: tokens are verified at submission time; the
  ephemeral cert lifetime is the window of concern, not the token lifetime.
- **Log integrity**: `pypki_admin codesign-log-verify` re-hashes the full
  tree and checks against the last checkpoint signature. Schedule this in
  a nightly cron job.
