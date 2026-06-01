# HOWTO: ACME Server (RFC 8555)

> Last reviewed: 2026-06-01 (commit 453e7ba)

## 1. When to use this

Use PyPKI's ACME server when you want automated certificate issuance driven
by certbot, acme.sh, lego, Caddy, or cert-manager — the same protocol used by
Let's Encrypt, but running entirely on your own infrastructure.

Typical users: operators issuing TLS certs for internal services, Kubernetes
teams using cert-manager against a private CA, homelab operators who want
automatic renewal without cloud dependency.

If your fleet is k8s-only and you want native cert-manager integration, pair
this guide with [`docs/DEPLOYMENT/kubernetes-cert-manager.md`](../DEPLOYMENT/kubernetes-cert-manager.md).
If your operators prefer to issue certs manually via a browser, use the
[`webui-rest.md`](webui-rest.md) guide instead.

## 2. Prerequisites

- PyPKI installed, CA initialized, running → [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- **Inbound ports**: 80 (http-01 challenge responder — clients reach back to this port)
  or DNS access for dns-01
- **Outbound**: none (no external dependencies)
- **Trust anchor**: clients must trust the CA cert at `<ca-dir>/ca.crt`. Import
  it into the OS trust store or configure the ACME client with `--ca-bundle`.

## 3. Configuration

### CLI flags

| Flag | Default | When to change |
|------|---------|----------------|
| `--acme-prefix PREFIX` | (disabled) | Required — set to `/acme` to enable ACME |
| `--acme-base-url URL` | `http://<host>:<port><prefix>` | Set when behind a reverse proxy with a different public URL |
| `--acme-cert-days N` | 90 | Validity of issued certs; 90 is the Let's Encrypt default |
| `--acme-auto-approve-dns` | off | Turn on for internal-only CAs that skip DNS propagation checks |
| `--acme-allow-private-ip` | off | Enable for homelab or internal deployments (RFC 8738 IP identifiers) |
| `--acme-require-eab` | off | On for multi-tenant or controlled-access deployments |
| `--acme-eab-file PATH` | — | JSON file of `{kid: hmac_key}` when `--acme-require-eab` is on |
| `--acme-per-account-cert-limit N` | 0 (unlimited) | Per-account rate limit; set to prevent abuse |
| `--acme-per-account-window-days N` | 7 | Rolling window for the above |
| `--acme-star-enabled` | off | RFC 8739 short-term auto-renewed certs |
| `--acme-onion-enabled` | off | RFC 9799 ACME for `.onion` hidden services |
| `--ocsp-url URL` | — | Embed OCSP URL in issued certs' AIA extension |
| `--crl-url URL` | — | Embed CRL URL in issued certs' CDP extension |

### Certificate profile

ACME issuance uses the `tls_server` profile (SAN=dNSName, keyUsage=digitalSignature+keyEncipherment,
EKU=serverAuth, 90-day validity). Override the validity with `--acme-cert-days`.
The profile is defined in `pki_server.py:CertProfile.PROFILES["tls_server"]`.

### External Account Binding (EAB)

For controlled access — when only pre-authorized clients may register:

```bash
# 1. Generate an EAB key pair
python3 -c "
import secrets, base64, json
kid = secrets.token_hex(16)
key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
print(json.dumps({kid: key}, indent=2))
"

# 2. Save to eab-keys.json and pass to PyPKI
python3 pki_server.py --acme-prefix /acme \
  --acme-require-eab --acme-eab-file /etc/pypki/eab-keys.json \
  ...
```

## 4. Starting the service

### Bare-metal (development)

```bash
python3 pki_server.py \
  --ca-dir /etc/pypki/ca \
  --port 8080 \
  --acme-prefix /acme \
  --acme-base-url http://pki.internal:8080/acme \
  --ocsp-url http://pki.internal:8080/ocsp \
  --crl-url http://pki.internal:8080/ca/crl
```

### Systemd unit

Install `docs/HOWTO/units/pypki-acme.service` to `/etc/systemd/system/`:

```bash
cp docs/HOWTO/units/pypki-acme.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pypki-acme
```

### Health check

```bash
curl http://localhost:8080/acme/directory
# Returns JSON with newAccount, newOrder, newNonce, revokeCert URLs.
```

### docker-compose snippet

```yaml
services:
  pypki:
    image: python:3.12-slim
    command: >
      python3 /app/pki_server.py
        --ca-dir /data/ca
        --port 8080
        --acme-prefix /acme
        --acme-base-url http://pypki:8080/acme
    ports:
      - "8080:8080"
    volumes:
      - pypki-ca:/data/ca
      - .:/app
volumes:
  pypki-ca:
```

## 5. Client configuration

### certbot

```bash
# Install
apt install certbot   # or pip install certbot

# First enrolment (http-01, standalone mode)
certbot certonly \
  --server http://pki.internal:8080/acme/directory \
  --standalone \
  --domain myservice.internal \
  --email admin@internal \
  --agree-tos \
  --no-eff-email

# The CA cert must be trusted. If not in system trust store:
# certbot ... --ca-bundle /etc/pypki/ca/ca.crt

# Renewal (via systemd timer or cron)
certbot renew

# Revocation
certbot revoke --cert-name myservice.internal
```

### acme.sh

```bash
# Install
curl https://get.acme.sh | sh

# Register and issue (dns-01 with Pi-hole hook — see pihole-acme-dns01.md)
acme.sh --register-account -m admin@internal \
  --server http://pki.internal:8080/acme/directory

acme.sh --issue -d myservice.internal \
  --dns dns_pihole \
  --server http://pki.internal:8080/acme/directory

# Renewal is automatic via cron entry acme.sh installs.
```

### Caddy (built-in ACME client)

```caddyfile
{
  acme_ca http://pki.internal:8080/acme/directory
  acme_ca_root /etc/pypki/ca.crt
}

myservice.internal {
  reverse_proxy localhost:3000
}
```

## 6. Verification (smoke test)

Run against a fresh PyPKI instance. Total time: under 30 seconds.

```bash
# Start PyPKI (background, fresh CA dir for test)
tmpdir=$(mktemp -d)
python3 pki_server.py --ca-dir "$tmpdir" --port 18080 \
  --acme-prefix /acme &
PYPKI_PID=$!
sleep 2

# Confirm directory is reachable
curl -s http://localhost:18080/acme/directory | python3 -m json.tool

# Issue a cert with acme.sh (or certbot --test-cert)
# Using curl to simulate the ACME new-nonce / new-account flow manually:
NONCE=$(curl -si http://localhost:18080/acme/new-nonce | grep -i replay-nonce | awk '{print $2}' | tr -d '\r')
echo "Got nonce: $NONCE"

# Fetch the CA cert
curl -s http://localhost:18080/ca/cert.pem | openssl x509 -noout -subject -issuer

kill $PYPKI_PID
rm -rf "$tmpdir"
echo "Smoke test passed"
```

Expected output: directory JSON with `newAccount`, `newOrder`, `newNonce`, `revokeCert` keys;
CA cert `subject=Issuer=` matching the initialized CA name.

## 7. Day-2 operations

**Rotating the CA key**: Follow [`docs/CEREMONY.md`](../CEREMONY.md). After rotation,
existing ACME accounts retain their keys; new certs are issued by the new CA.
Clients must re-import the new CA cert.

**Revoking an issued cert**: Either via the ACME `revoke-cert` endpoint (requires the
original account key or the cert key) or via the Web UI: navigate to *Certs* → *Revoke*.
The cert appears in the next CRL and OCSP responses immediately.

**Auditing ACME events**: Filter the audit log for `event LIKE 'issue%'` with
`detail LIKE '%acme%'`:
```sql
SELECT ts, detail FROM audit WHERE event='issue' AND detail LIKE '%acme%' ORDER BY id DESC LIMIT 20;
```

**Prometheus metrics**:
- `pypki_issuance_duration_seconds` (histogram, label `protocol=acme`)
- `pypki_acme_order_duration_seconds` (histogram, full order lifecycle)
- `pypki_certs_issued_total`

## 8. Monitoring

| Metric | Type | What to alert on |
|--------|------|-----------------|
| `pypki_acme_order_duration_seconds` | histogram | p99 > 30s |
| `pypki_certs_issued_total` | counter | sustained rate drops to 0 |
| `pypki_certs_expiring_7d` | gauge | any cert within 7 days not renewed |
| `pypki_ca_days_remaining` | gauge | < 30 days (CA expiry) |

Grafana: dashboard `pypki-grafana-dashboard.json`, panel "ACME Order Latency".

**Alert rule** (Prometheus YAML):
```yaml
- alert: PypkiACMEOrderSlow
  expr: histogram_quantile(0.99, rate(pypki_acme_order_duration_seconds_bucket[5m])) > 30
  for: 5m
  labels: { severity: warning }
  annotations:
    summary: "ACME order p99 > 30s"
```

## 9. Troubleshooting

**"Connection refused" from certbot**
: PyPKI is not running or is bound to a different address. Confirm `systemctl status pypki-acme`
and that `--port` matches what certbot is hitting.

**"certificate verify failed" from certbot**
: The PyPKI CA cert is not in the system trust store. Either import it
(`trust anchor --store /etc/pypki/ca/ca.crt` on Fedora/RHEL) or pass
`--ca-bundle /etc/pypki/ca/ca.crt` to certbot.

**"order not ready" after challenge**
: The challenge responder (port 80 for http-01) is not reachable from PyPKI.
Check firewall rules and that `--acme-base-url` reflects the actual public URL.
For internal-only CAs, use `--acme-auto-approve-dns` to skip the check.

**ACME accounts accumulating in `acme.db`**
: Expected — every certbot invocation with a new `--email` creates an account.
Clean up with `pypki_admin.py acme-prune-accounts --older-than 90d` (once shipped).

**EAB: "externalAccountRequired" returned to certbot**
: `--acme-require-eab` is on but certbot was invoked without EAB credentials.
Pass `--eab-kid` and `--eab-hmac-key` from the key file.

Regression tests: `TestACMERFC8555`, `TestACMEEAB` in `test_pki_server.py`.

## 10. Security considerations

See [`docs/THREAT_MODEL.md §3b.2`](../THREAT_MODEL.md) (EAB) and `§3b.3` (per-account rate limiting).

- Do not expose the ACME endpoint to the open internet without `--rate-limit`
  and `--acme-require-eab`. Without EAB, anyone can create an account and
  request certs for any name your CA accepts.
- The `--acme-auto-approve-dns` flag bypasses DNS propagation checks entirely.
  Use only on air-gapped or fully-controlled-DNS networks.
- Short-lived certs (`--acme-cert-days 7` or less) qualify for RFC 9608
  `id-ce-noRevAvail`, suppressing OCSP/CRL entries. This reduces revocation
  overhead but means compromised short-lived certs cannot be revoked — the
  design intent.

## 11. References

- RFC 8555 — ACME
- RFC 8737 — ACME tls-alpn-01 challenge
- RFC 8738 — ACME for IP identifiers (`--acme-allow-private-ip`)
- RFC 8739 — ACME STAR (`--acme-star-enabled`)
- RFC 9773 — ACME Renewal Information (ARI)
- RFC 9799 — ACME for .onion (`--acme-onion-enabled`)
- `acme_server.py` — ACME server implementation
- `pki_server.py` — CertProfile catalog, ACME CLI flags
- [`docs/DEPLOYMENT/kubernetes-cert-manager.md`](../DEPLOYMENT/kubernetes-cert-manager.md)
- [`docs/DEPLOYMENT/pihole-acme-dns01.md`](../DEPLOYMENT/pihole-acme-dns01.md)
