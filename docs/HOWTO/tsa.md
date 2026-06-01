# HOWTO: Timestamp Authority (RFC 3161)

> Last reviewed: 2026-06-01 (commit 453e7ba)

## 1. When to use this

Use PyPKI's Timestamp Authority to bind a document, binary, or git commit to a
point in time with a cryptographic proof. The TSA issues a TimeStampToken (TST):
a signed assertion that a given hash existed before a specific timestamp. TSTs
are the basis of trusted document signing, code signing audit trails, and long-
term evidence preservation.

Typical users: software release pipelines that sign binaries, legal document
systems, GDPR evidence logs, build systems that need a verifiable build time.

If you need certificates for document signing (not timestamps), use the
`email_signing` CertProfile with S/MIME instead — see [`smime.md`](smime.md).

## 2. Prerequisites

- PyPKI installed, CA initialized → [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- **Inbound ports**: 80 (TSA is typically plain HTTP)
- **No outbound dependencies**
- The TSA signing cert is auto-provisioned from the CA (`tsa_signing` profile,
  EKU=timeStamping, 1-year validity). Pass `--tsa-cert` / `--tsa-key` to bring
  your own.

## 3. Configuration

### CLI flags

| Flag | Default | When to change |
|------|---------|----------------|
| `--tsa-prefix PREFIX` | (disabled) | Required — set to `/tsa` to enable |
| `--tsa-policy-oid OID` | `1.3.6.1.4.1.99999.1` | Set to your IANA-assigned PEN OID for production |
| `--tsa-accuracy-seconds N` | 1 | Declared clock accuracy; reduce if you have NTP sync |
| `--tsa-cert PATH` | (auto) | External TSA signing cert (PEM) |
| `--tsa-key PATH` | (auto) | External TSA signing key (PEM) |

### Policy OID

The `--tsa-policy-oid` is embedded in every TimeStampToken. For production use,
obtain a real OID arc via IANA Private Enterprise Numbers (PEN). The default
`1.3.6.1.4.1.99999.1` is a placeholder and MUST be changed before deployment.

Apply for a PEN: https://www.iana.org/assignments/enterprise-numbers/

### TSA signing cert

The auto-provisioned TSA cert has:
- `extKeyUsage=timeStamping` (critical)
- `keyUsage=digitalSignature` (critical)
- 1-year validity
- CA=FALSE

The cert is auto-renewed 30 days before expiry. View the current cert:
```bash
openssl x509 -in <ca-dir>/tsa-signer.crt -noout -text | grep -A5 "Extended Key"
```

## 4. Starting the service

### Bare-metal

```bash
python3 pki_server.py \
  --ca-dir /etc/pypki/ca \
  --port 8080 \
  --tsa-prefix /tsa \
  --tsa-policy-oid 1.3.6.1.4.1.YOUR_PEN.1
```

### Systemd unit

```bash
cp docs/HOWTO/units/pypki-tsa.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pypki-tsa
```

### Health check

```bash
# Send a minimal TimeStampRequest for the SHA-256 of "test"
echo -n "test" | openssl ts -query -sha256 -no_nonce \
  | curl -s -X POST http://localhost:8080/tsa \
    -H "Content-Type: application/timestamp-query" \
    --data-binary @- \
    | openssl ts -reply -text 2>&1 | head -5
# Expected: "Received from server: Time Stamp Response:"
```

## 5. Client configuration

### openssl ts (standard)

```bash
# Step 1: Create a timestamp request for a file
openssl ts -query \
  -data myfile.tar.gz \
  -sha256 \
  -cert \
  -out request.tsq

# Step 2: Send the request to PyPKI TSA
curl -s -X POST http://pki.internal:8080/tsa \
  -H "Content-Type: application/timestamp-query" \
  --data-binary @request.tsq \
  -o response.tsr

# Step 3: Verify the response
openssl ts -verify \
  -in response.tsr \
  -queryfile request.tsq \
  -CAfile /etc/pypki/ca/ca.crt
# Expected: Verification: OK

# Inspect the token
openssl ts -reply -in response.tsr -text
```

### Sigstore / cosign (with custom TSA)

```bash
# Sign a file and timestamp it with PyPKI TSA
cosign sign-blob \
  --timestamp-server-url http://pki.internal:8080/tsa \
  myfile.tar.gz
```

### Java (Apache PDFBox / Bouncy Castle)

```java
// Point your TSA client at the PyPKI endpoint
TSAClient tsaClient = new TSAClient(
    new URL("http://pki.internal:8080/tsa"),
    null,  // username (not used)
    null,  // password (not used)
    MessageDigest.getInstance("SHA-256")
);
```

### Git commit signing with TSA

```bash
# Configure GPG to use a TSA for signature timestamps
# (gpg uses TSA via the --rfc2634 / --timestamps flags)
gpg --detach-sign \
  --openpgp \
  --timestamp-url http://pki.internal:8080/tsa \
  myfile.tar.gz
```

## 6. Verification (smoke test)

```bash
tmpdir=$(mktemp -d)
python3 pki_server.py --ca-dir "$tmpdir" --port 18086 \
  --tsa-prefix /tsa &
PYPKI_PID=$!
sleep 2

# Create a TSR for "hello world"
echo -n "hello world" | openssl ts -query -sha256 -no_nonce \
  | curl -s -X POST http://localhost:18086/tsa \
    -H "Content-Type: application/timestamp-query" \
    --data-binary @- \
    -o /tmp/test.tsr

# Verify
openssl ts -reply -in /tmp/test.tsr -text 2>&1 | grep -E "Status|Policy|Hash|Time"
# Expected: Status info: Status: Granted.
#           Policy OID: 1.3.6.1.4.1.99999.1
#           Hash Algorithm: sha256
#           Time stamp: ...

kill $PYPKI_PID; rm -rf "$tmpdir" /tmp/test.tsr
echo "TSA smoke test passed"
```

## 7. Day-2 operations

**TSA signing cert rotation**: Auto-renewed 30 days before expiry. Manual renewal:
```bash
python3 pypki_admin.py --ca-dir /etc/pypki/ca renew-tsa-cert
```

**Verifying old tokens**: TSTs embed a copy of the TSA signing cert. Old tokens
remain verifiable as long as:
1. The CA cert is still trusted.
2. The hash algorithm is not broken.
Tokens signed with SHA-256 remain valid indefinitely (barring algorithm break).

**Audit log**: TSA events are logged as `event='tsa_timestamp'` with the hash
and policy OID in the detail field.

## 8. Monitoring

| Metric | Type | Alert when |
|--------|------|------------|
| `pypki_issuance_duration_seconds` | histogram | p99 > 2s (TSA should be fast) |
| TSA signing cert expiry | external check | < 30 days (run `openssl x509 -checkend 2592000`) |

The TSA signing cert is separate from the CA cert. Monitor both:
```bash
# Days until TSA cert expiry
openssl x509 -in <ca-dir>/tsa-signer.crt -noout -enddate
```

## 9. Troubleshooting

**"PKIFailureInfo: badAlg"**
: The client requested a hash algorithm not supported by PyPKI's TSA. Supported:
SHA-256, SHA-384, SHA-512. SHA-1 is rejected.

**"PKIFailureInfo: badRequest"**
: Malformed TSQ. Verify the request was generated with `openssl ts -query` or an
equivalent tool and that `Content-Type: application/timestamp-query` is set.

**Clock drift in tokens**
: `--tsa-accuracy-seconds` is declared but not enforced by the server. If the
system clock drifts, tokens will have incorrect timestamps. Use NTP (chrony):
`chronyc tracking | grep offset`.

**"time stamp not in expected window"** (during openssl ts -verify)
: The token's timestamp is outside the window the verifier accepts. This can
happen if the system clock was wrong when the token was issued. The token is
still cryptographically valid — it was signed at the time stated.

Regression tests: `TestRFC3161TSA` in `test_pki_server.py`.

## 10. Security considerations

- The TSA's clock is the system clock. If the system clock is wrong, all timestamps
  are wrong. Run NTP and monitor drift: `chronyc makestep`.
- `--tsa-policy-oid` is self-declared. Anyone can claim any OID. For legally
  significant timestamping, use a qualified TSA under a recognized trust list
  (e.g., EU TSL). PyPKI's TSA is suitable for internal audit trails and
  build-system provenance.
- The auto-provisioned TSA signing key is on disk. Protect it with filesystem
  ACLs. An attacker who steals the TSA key can issue backdated timestamps but
  cannot forge CA-signed certificates.

## 11. References

- RFC 3161 — Time Stamp Protocol (TSP)
- RFC 5816 — ESSCertIDv2 update to RFC 3161
- `tsa_server.py` — TSA server implementation
- ETSI EN 319 421 — Policy and Security Requirements for Trust Service Providers
  Issuing Time-Stamps (for qualified TSA requirements)
