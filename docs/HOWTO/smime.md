# HOWTO: S/MIME Server (RFC 8551)

> Last reviewed: 2026-06-01 (commit 453e7ba)

## 1. When to use this

Use PyPKI's S/MIME service to sign, verify, encrypt, and decrypt email messages
with RFC 8551 S/MIME v4 format. The service exposes a REST API that wraps the
CMS (Cryptographic Message Syntax) operations — clients POST a message and
receive a signed or encrypted version without needing a local S/MIME library.

Typical users: email automation pipelines that need signed outbound mail,
compliance systems that must encrypt sensitive emails, custom mail clients that
offload cryptography to a central service.

If your users need individual S/MIME certs for Outlook or Thunderbird rather
than a server-side signing service, this guide covers issuing those certs; see
section 5 for client configuration.

## 2. Prerequisites

- PyPKI installed, CA initialized → [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- **Inbound ports**: 80 or 443 (the S/MIME REST API)
- A CA initialized with a key type that supports S/MIME signing (ECDSA or RSA —
  not ML-DSA, which doesn't have CMS support in current `cryptography` versions)
- Client email software must trust the PyPKI CA cert

## 3. Configuration

### CLI flags

| Flag | Default | When to change |
|------|---------|----------------|
| `--smime-prefix PREFIX` | (disabled) | Required — set to `/smime` to enable |

No additional flags. The S/MIME REST API uses the `email_signing` CertProfile
for issuing subscriber certs, and the CA key for server-side signing operations.

### Certificate profile

The `email_signing` profile (defined in `pki_server.py:CertProfile.PROFILES`):
- `keyUsage=digitalSignature + contentCommitment` (non-repudiation)
- `extKeyUsage=emailProtection`
- SAN type: `rfc822Name` (email address)
- 365-day validity

Issue a cert for a specific email address:
```bash
# Via REST API (see §5 below)
# Or via Web UI: Certs → Issue → Profile: email_signing → SAN: user@domain.com
```

## 4. Starting the service

### Bare-metal

```bash
python3 pki_server.py \
  --ca-dir /etc/pypki/ca \
  --port 8080 \
  --smime-prefix /smime
```

### Systemd unit

```bash
cp docs/HOWTO/units/pypki-smime.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pypki-smime
```

### Health check

```bash
# POST an empty message to each endpoint — expect 400 (bad request) not 404
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8080/smime/sign \
  -H "Content-Type: application/json" \
  -d '{}'
# Expected: 400 (endpoint exists; request is malformed — missing cert/key)
```

## 5. Client configuration

### Issuing an S/MIME cert for a user

```bash
# 1. Generate a key and CSR for the user
openssl req -newkey rsa:2048 -nodes \
  -keyout alice.key -out alice.csr \
  -subj "/CN=Alice Smith/emailAddress=alice@example.com"

# 2. Issue the cert via PyPKI REST API (server-side signing)
curl -s -X POST http://pki.internal:8080/smime/sign \
  -H "Content-Type: application/json" \
  -d '{
    "csr_pem": "'"$(cat alice.csr | sed ':a;N;$!ba;s/\n/\\n/g')"'",
    "email": "alice@example.com"
  }' > alice-cert-response.json

# Or via Web UI → Certs → Issue → Profile: email_signing → SAN=alice@example.com
# Then export as PKCS#12 for import into Outlook/Thunderbird
```

### Signing a message (REST API)

```bash
# Prepare the message (base64-encoded)
MSG_B64=$(echo "Hello, this is a signed message." | base64 -w0)

# Sign via the REST API (uses the CA-held signing cert and key)
curl -s -X POST http://pki.internal:8080/smime/sign \
  -H "Content-Type: application/json" \
  -d "{
    \"message\": \"$MSG_B64\",
    \"cert_pem\": \"$(cat alice.crt | base64 -w0)\",
    \"key_pem\": \"$(cat alice.key | base64 -w0)\"
  }" | python3 -m json.tool
# Response: {"signed_message": "<base64-encoded CMS SignedData>"}
```

### Verifying a signed message

```bash
# Verify a CMS SignedData message
SIGNED_MSG_B64="<from the sign response>"

curl -s -X POST http://pki.internal:8080/smime/verify \
  -H "Content-Type: application/json" \
  -d "{
    \"signed_message\": \"$SIGNED_MSG_B64\",
    \"ca_cert_pem\": \"$(cat /etc/pypki/ca/ca.crt | base64 -w0)\"
  }" | python3 -m json.tool
# Response: {"valid": true, "signer_email": "alice@example.com", "message": "..."}
```

### Encrypting a message

```bash
# Encrypt for the recipient using their cert
curl -s -X POST http://pki.internal:8080/smime/encrypt \
  -H "Content-Type: application/json" \
  -d "{
    \"message\": \"$MSG_B64\",
    \"recipient_cert_pem\": \"$(cat recipient.crt | base64 -w0)\"
  }" | python3 -m json.tool
# Response: {"encrypted_message": "<base64-encoded CMS EnvelopedData>"}
```

### Thunderbird configuration

1. Issue an S/MIME cert for the user email address (see above).
2. Export the cert as PKCS#12 (Web UI → Certs → Export → PKCS#12).
3. In Thunderbird: Account Settings → End-To-End Encryption → Add Certificate
   → select the P12 file.
4. Thunderbird will use the cert for signing and decryption automatically.

### Outlook configuration

1. Same cert issuance process.
2. Double-click the `.p12` file → Windows Certificate Import Wizard.
3. Outlook → File → Options → Trust Center → Email Security → Import/Export.

## 6. Verification (smoke test)

```bash
tmpdir=$(mktemp -d)
python3 pki_server.py --ca-dir "$tmpdir" --port 18087 \
  --smime-prefix /smime &
PYPKI_PID=$!
sleep 2

# Confirm endpoints exist
for endpoint in sign verify encrypt decrypt; do
  HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:18087/smime/$endpoint \
    -H "Content-Type: application/json" -d '{}')
  echo "$endpoint → HTTP $HTTP (expected 400, not 404)"
done

kill $PYPKI_PID; rm -rf "$tmpdir"
echo "S/MIME smoke test passed"
```

## 7. Day-2 operations

**Revoking a user's S/MIME cert**: Web UI → *Certs* → *Revoke* by serial number.
The recipient's mail client should check revocation before trusting signed messages.

**Renewing an expiring cert**: Web UI → *Certs* → *Renew*, or `POST /api/renew`
with the serial. Issue the new PKCS#12 to the user.

**Audit log**: S/MIME cert issuance: `event='issue'` with `profile=email_signing`.
Signing/verify/encrypt/decrypt operations: `event='smime_sign'` etc.

## 8. Monitoring

| Metric | Type | Alert when |
|--------|------|------------|
| `pypki_issuance_duration_seconds` | histogram | p99 > 5s |
| `pypki_certs_expiring_7d` | gauge | > 0 (email certs need renewal) |

## 9. Troubleshooting

**"400: missing cert_pem or key_pem"** (sign endpoint)
: The REST API requires the signing cert and private key in the request body.
They are not persisted server-side — the caller must provide them each time.

**"Signature verification failed"** (verify endpoint)
: The signing cert's CA is not trusted (wrong `ca_cert_pem`) or the message
was tampered with after signing.

**"unsupported algorithm"** (encrypt endpoint)
: The recipient cert uses an algorithm that the CMS library doesn't support for
key wrapping. RSA-OAEP and ECDH-ES are supported. Check the recipient cert's
public key algorithm.

**Thunderbird "Certificate not trusted"**
: The CA cert is not in the system trust store or Thunderbird's cert database.
Import `ca.crt` into Thunderbird: Preferences → Privacy & Security →
Certificates → Manage Certificates → Authorities → Import.

Regression tests: `TestSMIMEServer`, `TestRFC8551` in `test_pki_server.py`.

## 10. Security considerations

- The S/MIME REST API accepts raw private keys in JSON request bodies. Use TLS
  on the endpoint (reverse proxy) and restrict network access to trusted clients.
  A man-in-the-middle on the API can steal private keys.
- S/MIME keys should ideally be generated on the user's device, not server-side.
  The REST API supports externally-generated keys — prefer that for security-sensitive
  deployments.
- Email encryption in S/MIME is point-to-point (to the recipient's public key).
  PyPKI holds no encryption keys — it only helps with the cert management and
  signing operations.

## 11. References

- RFC 8551 — S/MIME 4.0
- RFC 5652 — Cryptographic Message Syntax (CMS)
- `smime_server.py` — S/MIME REST API implementation
- [`webui-rest.md`](webui-rest.md) — issuing S/MIME certs via the Web UI
