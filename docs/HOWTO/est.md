# HOWTO: EST Server (RFC 7030)

> Last reviewed: 2026-06-01 (commit 453e7ba)

## 1. When to use this

Use PyPKI's EST server (Enrollment over Secure Transport) for device certificate
enrollment over TLS. EST is the successor to SCEP for RFC-compliant devices:
it runs over HTTPS, supports mTLS for device authentication, and exposes
`/cacerts`, `/simpleenroll`, `/simplereenroll`, `csrattrs`, and `serverkeygen`.

Typical users: Linux endpoints using `estclient`, Cisco IOS XE, strongSwan
IKEv2 setups, IoT device fleets that support RFC 7030, Docker/Kubernetes
workloads that need a TLS cert on startup.

If your target devices only support SCEP, use [`scep.md`](scep.md). If you want
fully automated HTTPS cert renewal without pre-shared credentials, use
[`acme.md`](acme.md).

## 2. Prerequisites

- PyPKI installed, CA initialized → [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- **Inbound ports**: 443 (EST requires TLS — PyPKI auto-issues a server cert from
  the CA if `--est-tls-cert` is not provided)
- **Trust anchor**: clients must trust the CA cert before they can verify the EST
  server's TLS certificate. Distribute `<ca-dir>/ca.crt` to devices in advance
  or use `--est-tls-cert` with a cert from a mutually-trusted CA.

## 3. Configuration

### CLI flags

| Flag | Default | When to change |
|------|---------|----------------|
| `--est-prefix PREFIX` | (disabled) | Required — set to `/est` to enable |
| `--est-user USER:PASS` | (none) | Add HTTP Basic auth user (repeat for multiple) |
| `--est-require-auth` | off | Require authentication for all EST operations |
| `--est-tls-cert PATH` | (auto from CA) | Provide your own TLS cert for the EST endpoint |
| `--est-tls-key PATH` | — | Private key for `--est-tls-cert` |

### Certificate profile

EST simpleenroll uses the `tls_client` profile (EKU=clientAuth, 365-day validity).
`serverkeygen` returns a CA-generated key + cert — the key is encrypted in the
PKCS#7 response. Profile: `pki_server.py:CertProfile.PROFILES["tls_client"]`.

### Authentication modes

**No auth** (development/trusted-network only):
```bash
python3 pki_server.py --est-prefix /est ...
```

**HTTP Basic** (per-device username:password):
```bash
python3 pki_server.py --est-prefix /est \
  --est-user device1:pass1 \
  --est-user device2:pass2 \
  --est-require-auth
```

**mTLS** (device cert authenticates device): The `--est-require-auth` flag
also accepts TLS client certificates issued by the same CA. Configure the
reverse proxy (nginx/traefik) for mTLS and pass the client cert DN to PyPKI.

## 4. Starting the service

### Bare-metal

```bash
python3 pki_server.py \
  --ca-dir /etc/pypki/ca \
  --port 8443 \
  --est-prefix /est \
  --est-user admin:password \
  --est-require-auth
```

The EST server auto-issues a TLS cert from the CA for the HTTPS endpoint.

### Systemd unit

```bash
cp docs/HOWTO/units/pypki-est.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pypki-est
```

### Health check

```bash
# cacerts — always unauthenticated, returns CA cert bundle as PKCS#7
curl -k https://localhost:8443/est/.well-known/est/cacerts \
  | openssl cms -certs -noout -inform DER
# Expected: one or more certificates listed
```

## 5. Client configuration

### curl (quickest test)

```bash
# Fetch CA certs
curl -k https://pki.internal:8443/est/.well-known/est/cacerts \
  > /tmp/cacerts.p7
openssl cms -certs -noout -inform DER -in /tmp/cacerts.p7

# Simple enroll (Basic auth, CSR from file)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -keyout /tmp/dev.key -out /tmp/dev.csr \
  -subj "/CN=mydevice.internal"

curl -k \
  -u "admin:password" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @/tmp/dev.csr \
  https://pki.internal:8443/est/.well-known/est/simpleenroll \
  > /tmp/dev.p7

# Extract cert from PKCS#7
openssl cms -certificates -noout -inform DER -in /tmp/dev.p7

# Renewal (same endpoint, using existing cert for auth)
curl -k \
  --cert /tmp/dev.pem --key /tmp/dev.key \
  -H "Content-Type: application/pkcs10" \
  --data-binary @/tmp/dev-new.csr \
  https://pki.internal:8443/est/.well-known/est/simplereenroll
```

### libest estclient

```bash
# Install (build from source or package manager)
apt install libest-dev   # Ubuntu 22.04+

# Enroll
estclient -e \
  -s pki.internal \
  -p 8443 \
  -o /tmp/est/ \
  -u admin -h password \
  --common-name mydevice.internal

# The private key is in /tmp/est/cert-key-pair.pem
# The cert chain is in /tmp/est/cert.pem
```

## 6. Verification (smoke test)

```bash
tmpdir=$(mktemp -d)
python3 pki_server.py --ca-dir "$tmpdir" --port 18443 \
  --est-prefix /est &
PYPKI_PID=$!
sleep 2

# cacerts — must return CA cert
curl -sk https://localhost:18443/est/.well-known/est/cacerts \
  | openssl cms -certs -noout -inform DER -text 2>&1 | grep -c "Certificate:"
# Expected: 1

# csrattrs — returns CSR attribute hints (may be empty 204)
CODE=$(curl -sko /dev/null -w "%{http_code}" https://localhost:18443/est/.well-known/est/csrattrs)
echo "csrattrs HTTP $CODE"  # 200 or 204

kill $PYPKI_PID; rm -rf "$tmpdir"
echo "EST smoke test passed"
```

## 7. Day-2 operations

**Rotating the CA key**: See [`docs/CEREMONY.md`](../CEREMONY.md). Devices using mTLS
with the old CA cert must re-enroll after the CA is rotated.

**Revoking a device cert**: Web UI → *Certs* → *Revoke*, or:
```bash
curl -X POST http://pki.internal:8080/api/revoke \
  -H "Content-Type: application/json" \
  -d '{"serial": 1234, "reason": 4}'
```

**Audit log**: EST events are logged as `event='issue'` with `detail LIKE '%est%'`.

## 8. Monitoring

| Metric | Type | Alert when |
|--------|------|------------|
| `pypki_issuance_duration_seconds` | histogram | p99 > 10s |
| `pypki_certs_issued_total` | counter | Sustained drop to 0 |
| `pypki_certs_expiring_7d` | gauge | > 0 |

## 9. Troubleshooting

**"SSL certificate verify failed" from estclient**
: The client doesn't trust the PyPKI CA cert. Run `estclient -e ... --cacert /path/to/ca.crt`
or add the CA cert to the OS trust store.

**"401 Unauthorized"**
: `--est-require-auth` is set but credentials are missing or wrong. For curl, pass
`-u username:password`. For mTLS, confirm the client cert is from the same CA.

**"413 Request Entity Too Large" on simpleenroll**
: The CSR includes a very large public key or many SANs. PyPKI's HTTP server has a
default body size limit; increase it if needed.

**serverkeygen returns empty**
: `serverkeygen` requires that the profile permits key archiving. Check that
`--p12-allow-unencrypted` is NOT set (the key is returned encrypted in the PKCS#7).

Regression tests: `TestEST`, `TestRFC7030EST` in `test_pki_server.py`.

## 10. Security considerations

- EST requires TLS. PyPKI auto-issues a server cert from the CA for the EST
  endpoint. Devices must pre-trust this CA cert before connecting. This is the
  classic bootstrap problem; distribute `ca.crt` out-of-band (MDM profile, USB,
  Ansible).
- Without `--est-require-auth`, any client that trusts the CA can enroll a cert.
  Enable authentication for production deployments.
- The `serverkeygen` endpoint generates the private key on the CA host and returns
  it encrypted. The key is briefly in process memory. Use only when the device
  cannot generate its own key (constrained hardware).

## 11. References

- RFC 7030 — EST
- `est_server.py` — EST server implementation
- [`docs/DEPLOYMENT/iot-devices-est.md`](../DEPLOYMENT/iot-devices-est.md)
