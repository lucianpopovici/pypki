# HOWTO: CMP Server (RFC 4210 / RFC 9480)

> Last reviewed: 2026-06-01 (commit 453e7ba)

## 1. When to use this

Use PyPKI's CMP server for full X.509 certificate lifecycle management: initial
registration (`ir`), certificate request (`cr`), key update (`kur`), revocation
(`rr`), and GenMsg exchanges including algorithm advertisement.

Typical users: VPN gateway operators (strongSwan, Cisco, Palo Alto), enterprise
PKI integrators (EJBCA clients, proprietary PKI agents), and any client that
needs the full CMP request-confirmation-certConf flow.

CMPv2 (RFC 4210) and CMPv3 (RFC 9480) are auto-negotiated based on the client's
`pvno` field. If your client is a simple TLS or ACME client, use [`acme.md`](acme.md).

## 2. Prerequisites

- PyPKI installed, CA initialized → [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- **Inbound ports**: 80 or 443 (CMP uses HTTP or HTTPS)
- **Shared secret**: CMP protection uses PBMAC1 with a shared secret between
  client and CA, or client cert (mTLS)
- **Trust anchor**: clients need the CA cert for verifying signed responses

## 3. Configuration

### CLI flags

| Flag | Default | When to change |
|------|---------|----------------|
| `--cmp-prefix PREFIX` | `/cmp` | Change mount point if needed |
| `--cmpv3` | on | Auto-negotiate CMPv3; use `--no-cmpv3` to force CMPv2 |
| `--default-profile PROFILE` | `default` | CertProfile for CMPv2 issuance (choices: default, tls_server, tls_client, code_signing, email_signing, …) |
| `--end-entity-days N` | 365 | Validity for end-entity certs |
| `--rate-limit N` | 0 | Requests per IP per minute |

### Authentication

CMP requests are authenticated using one of:
- **Shared secret** (PBMAC1): agreed out-of-band; passed in the PKIHeader `sender`
  and protection algorithm.
- **Certificate** (signature-based): client uses an existing cert to sign requests.

PyPKI validates PBMAC1 and verifies certificate-protected requests. The shared
secret is set per-client in `pypki.auth.json` (Web UI → *Config* → *API Keys*),
not as a global CLI flag.

## 4. Starting the service

### Bare-metal

```bash
python3 pki_server.py \
  --ca-dir /etc/pypki/ca \
  --port 8080 \
  --cmp-prefix /cmp \
  --default-profile tls_server
```

### Systemd unit

```bash
cp docs/HOWTO/units/pypki-cmp.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pypki-cmp
```

### Health check

```bash
# GenMsg with empty content — tests the server is up and CMPv2 works
openssl cmp \
  -cmd genm \
  -server http://localhost:8080/cmp \
  -recipient "/CN=PyPKI CA" \
  -unprotected_requests \
  2>&1 | grep -i "successfully\|error\|GenRep"
```

## 5. Client configuration

### openssl cmp (OpenSSL ≥ 3.0)

```bash
# Generate key for the request
openssl genrsa -out /tmp/ee.key 2048

# Initial registration (ir) — first cert from this client
openssl cmp \
  -cmd ir \
  -server http://pki.internal:8080/cmp \
  -recipient "/CN=PyPKI CA" \
  -secret "pass:your-shared-secret" \
  -subject "/CN=myservice.internal" \
  -newkey /tmp/ee.key \
  -cert /tmp/ee.crt \
  -cacertsout /tmp/chain.pem \
  -out /tmp/ee.crt

# Key update request (kur) — renew with existing cert
openssl cmp \
  -cmd kur \
  -server http://pki.internal:8080/cmp \
  -recipient "/CN=PyPKI CA" \
  -cert /tmp/ee.crt \
  -key /tmp/ee.key \
  -newkey /tmp/ee-new.key \
  -out /tmp/ee-new.crt

# Revocation request (rr)
openssl cmp \
  -cmd rr \
  -server http://pki.internal:8080/cmp \
  -recipient "/CN=PyPKI CA" \
  -cert /tmp/ee.crt \
  -key /tmp/ee.key \
  -revreason 1    # 0=unspecified 1=keyCompromise 4=superseded
```

### strongSwan (IKEv2 with CMP)

```conf
# /etc/strongswan.conf
libstrongswan {
  plugins {
    include strongswan.d/charon/*.conf
  }
}

charon {
  load_modular = yes
  # CMP configuration in /etc/swanctl/swanctl.conf
}
```

```yaml
# /etc/swanctl/swanctl.conf
connections:
  site-to-site:
    version: 2
    local_addrs: 10.0.0.1

credentials:
  cmp:
    type: cmp
    url: http://pki.internal:8080/cmp
    secret: your-shared-secret
```

See [`docs/DEPLOYMENT/vpn-strongswan-cmp.md`](../DEPLOYMENT/vpn-strongswan-cmp.md) for the
full strongSwan CMP deployment.

## 6. Verification (smoke test)

```bash
tmpdir=$(mktemp -d)
python3 pki_server.py --ca-dir "$tmpdir" --port 18083 \
  --cmp-prefix /cmp &
PYPKI_PID=$!
sleep 2

# GenMsg (no auth needed for genm with no OIDs)
openssl cmp \
  -cmd genm \
  -server http://localhost:18083/cmp \
  -recipient "/CN=PyPKI CA" \
  -unprotected_requests \
  2>&1 | grep -E "successfully|GenRep|error"

kill $PYPKI_PID; rm -rf "$tmpdir"
echo "CMP smoke test passed"
```

## 7. Day-2 operations

**Rotating the CA key**: See [`docs/CEREMONY.md`](../CEREMONY.md). Existing CMP clients
must re-register after rotation.

**Revoking a cert**: Via CMP `rr` (above) or Web UI → *Certs* → *Revoke*.

**Audit log**: CMP events: `event='issue'`, `event='revoke'`, `event='kur'`.

**Prometheus metrics**:
- `pypki_issuance_duration_seconds{protocol="cmp"}` (histogram)

## 8. Monitoring

| Metric | Type | Alert when |
|--------|------|------------|
| `pypki_issuance_duration_seconds` | histogram | p99 > 5s |
| `pypki_certs_issued_total` | counter | Sustained drop to 0 |

## 9. Troubleshooting

**"Protection verification failed"**
: The shared secret doesn't match, or the client is using a wrong PBMAC1 iteration
count. Check that `--secret` on the client matches the secret registered in PyPKI.

**"Transaction already in progress"**
: The client sent a duplicate ir/cr with the same `transactionID`. Each new cert
request needs a fresh random `transactionID`.

**"certConf missing"**
: Some CMP clients skip the `certConf` step. PyPKI issues the cert regardless
(implicit confirmation). The cert is in `certificates.db` even without `certConf`.

**"pvno not supported"**
: The client sent a CMPv3 request but `--no-cmpv3` is set. Remove `--no-cmpv3`
or downgrade the client to pvno=2.

Regression tests: `TestCMPv2`, `TestCMPv3` in `test_pki_server.py`.

## 10. Security considerations

- CMP over plain HTTP means the request/response body is signed (PBMAC1 or cert
  signature) but not encrypted — anyone on the network can read the CSR and cert.
  Use a reverse proxy with TLS for production.
- The shared secret must be communicated out-of-band. If it's the same secret
  for all clients, a compromised client can impersonate any other client. Use
  per-client API keys (Web UI → *Config* → *API Keys*).

## 11. References

- RFC 4210 — CMPv2
- RFC 4211 — CRMF
- RFC 9480 — Lightweight CMP Profile (CMPv3)
- RFC 9481 — CMP Algorithm Requirements
- `cmp_server.py` — CMP server implementation
- [`docs/DEPLOYMENT/vpn-strongswan-cmp.md`](../DEPLOYMENT/vpn-strongswan-cmp.md)
