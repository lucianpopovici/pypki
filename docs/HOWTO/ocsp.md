# HOWTO: OCSP Responder (RFC 6960)

> Last reviewed: 2026-06-01 (commit 453e7ba)

## 1. When to use this

Use PyPKI's OCSP responder to let clients check certificate revocation status
in real time. Every modern TLS stack (browsers, curl, OpenSSL) can query OCSP
before trusting a certificate. OCSP is embedded in the AIA extension of every
cert PyPKI issues via `--ocsp-url`.

If your relying parties are offline or use batch processing, CRL distribution
(see [`crl.md`](crl.md)) is the alternative. For high-throughput deployments,
use pre-generated responses (default: 300s cache TTL).

## 2. Prerequisites

- PyPKI installed, CA initialized → [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- **Inbound ports**: 80 (OCSP is typically HTTP/80, not HTTPS — the response is signed)
- **No outbound dependencies**

## 3. Configuration

### CLI flags

| Flag | Default | When to change |
|------|---------|----------------|
| `--ocsp-prefix PREFIX` | (disabled) | Required — set to `/ocsp` to enable |
| `--ocsp-url URL` | `""` | Embed this URL in AIA of issued certs |
| `--ocsp-cache-seconds N` | 300 | Response cache TTL; lower = fresher, higher = faster |
| `--ocsp-require-nonce` | off | RFC 8954 strict mode: reject requests without nonce |
| `--crl-url URL` | `""` | Also embed CRL URL in CDP extension (belt and suspenders) |

### OCSP signer

PyPKI auto-issues a delegated OCSP signing cert from the CA on startup. The
signer cert has `id-pkix-ocsp-nocheck` and `extKeyUsage=ocspSigning`. It is
valid for 7 days and auto-renewed before expiry.

To use your own OCSP signer cert: currently not exposed as a CLI flag — the
auto-provisioned signer is the supported path.

## 4. Starting the service

### Bare-metal

```bash
python3 pki_server.py \
  --ca-dir /etc/pypki/ca \
  --port 8080 \
  --ocsp-prefix /ocsp \
  --ocsp-url http://pki.internal:8080/ocsp \
  --ocsp-cache-seconds 300
```

### Systemd unit

```bash
cp docs/HOWTO/units/pypki-ocsp.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pypki-ocsp
```

### Health check

```bash
# Must return OCSP response for the CA's own cert
openssl ocsp \
  -issuer /etc/pypki/ca/ca.crt \
  -cert /etc/pypki/ca/ca.crt \
  -url http://localhost:8080/ocsp \
  -text | head -5
```

## 5. Client configuration

### openssl ocsp

```bash
# Check a cert against PyPKI OCSP
openssl ocsp \
  -issuer /etc/pypki/ca/ca.crt \
  -cert /tmp/myservice.crt \
  -url http://pki.internal:8080/ocsp \
  -text

# With nonce (recommended for anti-replay)
openssl ocsp \
  -issuer /etc/pypki/ca/ca.crt \
  -cert /tmp/myservice.crt \
  -url http://pki.internal:8080/ocsp \
  -nonce \
  -text

# Expected output: /tmp/myservice.crt: good
#   This Update: ...  Next Update: ...
```

### TLS clients (curl, nginx, etc.)

Configure clients to embed the OCSP URL in their TLS stack — no explicit
configuration needed if the URL is in the cert's AIA extension (which PyPKI
embeds automatically when `--ocsp-url` is set).

```bash
# Verify OCSP stapling with openssl s_client
openssl s_client \
  -connect myservice.internal:443 \
  -status \
  -CAfile /etc/pypki/ca/ca.crt \
  2>&1 | grep -A3 "OCSP response"
```

## 6. Verification (smoke test)

```bash
tmpdir=$(mktemp -d)
python3 pki_server.py --ca-dir "$tmpdir" --port 18082 \
  --ocsp-prefix /ocsp \
  --ocsp-url http://localhost:18082/ocsp &
PYPKI_PID=$!
sleep 2

# Issue a cert (needed for a meaningful OCSP check)
python3 -c "
import sys; sys.path.insert(0, '.')
import pki_server as pki
from pathlib import Path
ca = pki.CertificateAuthority(ca_dir='$tmpdir')
from cryptography.hazmat.primitives.asymmetric import ec
key = ec.generate_private_key(ec.SECP256R1())
cert = ca.issue_certificate('CN=smoke', key.public_key())
from cryptography.hazmat.primitives import serialization
open('/tmp/smoke.crt', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
"

# Query OCSP
openssl ocsp \
  -issuer "$tmpdir/ca.crt" \
  -cert /tmp/smoke.crt \
  -url http://localhost:18082/ocsp \
  -nonce 2>&1 | grep "smoke.crt"
# Expected: /tmp/smoke.crt: good

kill $PYPKI_PID; rm -rf "$tmpdir" /tmp/smoke.crt
echo "OCSP smoke test passed"
```

## 7. Day-2 operations

**Revoking a cert**: Web UI → *Certs* → *Revoke*. The OCSP responder reflects the
revocation within `--ocsp-cache-seconds` (default 300s). For immediate effect,
lower the cache TTL or restart the server to flush the cache.

**Rotating the OCSP signer**: Happens automatically every 7 days. The CA
generates a new signer cert; old responses signed by the previous signer
continue to be accepted by relying parties until their `nextUpdate` timestamp.

**Audit log**: OCSP events are not individually audit-logged (too noisy). Revocation
events are: `event='revoke'` entries trigger the cache invalidation.

**Prometheus metrics**:
- `pypki_ocsp_duration_seconds` (histogram, per-request response time)

## 8. Monitoring

| Metric | Type | Alert when |
|--------|------|------------|
| `pypki_ocsp_duration_seconds` | histogram | p99 > 1s |
| `pypki_certs_revoked_total` | counter | Spike (may indicate compromise) |
| `pypki_ca_days_remaining` | gauge | < 30 days |

The OCSP signer auto-renews, but if it fails, clients will receive unsigned
or invalid responses. Monitor for `ERROR ocsp` log lines.

## 9. Troubleshooting

**"Response Verify Failure"** (openssl output)
: The OCSP response signature doesn't match the CA. Common cause: the OCSP signer
cert was just rotated and the client is using a cached copy. Wait for the
TTL to expire or restart the client.

**"Unauthorized" response**
: `--ocsp-require-nonce` is on but the client didn't include a nonce. Either disable
the flag or configure the client to send nonces.

**Slow OCSP responses under load**
: The responder is doing a live DB lookup per request. Increase `--ocsp-cache-seconds`
or pre-generate responses (not yet exposed as a CLI flag — planned for a future release).

**OCSP stapling not working in nginx**
: nginx requires `ssl_stapling on`, `ssl_stapling_verify on`, and the CA cert in
`ssl_trusted_certificate`. The OCSP URL must be accessible from the nginx host.

Regression tests: `TestOCSP`, `TestOCSPParsing` in `test_pki_server.py`.

## 10. Security considerations

See [`docs/THREAT_MODEL.md §3b.10`](../THREAT_MODEL.md) (pre-generated OCSP),
`§3.2` (OCSP signer key compromise).

- The maximum stale revocation window is `--ocsp-cache-seconds`. A cert revoked
  one second after the last cache update may appear `good` for up to 300s.
  Lower the TTL for high-security deployments.
- Without `--ocsp-require-nonce`, cached responses can be replayed up to
  `nextUpdate`. Set `--ocsp-require-nonce` and `--ocsp-cache-seconds 0` for
  environments that require replay protection.
- The OCSP signer key is on disk at `<ca-dir>/ocsp-signer.key`. Protect it with
  filesystem ACLs; its compromise allows forging revocation responses (not certs).

## 11. References

- RFC 6960 — OCSP
- RFC 5019 — Lightweight OCSP Profile
- RFC 8954 — OCSP Nonce extension (`--ocsp-require-nonce`)
- `ocsp_server.py` — OCSP responder implementation
- [`crl.md`](crl.md) — CRL distribution (alternative / complement)
