# HOWTO: Web UI and REST API

> Last reviewed: 2026-06-01 (commit 453e7ba)

## 1. When to use this

Use the PyPKI Web UI for browser-based CA administration: issuing certs, revoking
them, viewing the audit log, managing sub-CAs, and monitoring expiry. Use the
REST API for automation scripts, CI/CD pipelines, and integrations that don't
use a protocol-specific client (ACME, CMP, etc.).

Typical users: CA operators (web browser), DevOps automation (REST), Ansible
roles, monitoring systems that scrape `/metrics`.

If you want automated certificate lifecycle management by an application, use
[`acme.md`](acme.md) (certbot) or [`cmp.md`](cmp.md) (openssl cmp) instead.

## 2. Prerequisites

- PyPKI installed, CA initialized → [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- **Inbound ports**: 80 or 443 (the web UI serves over HTTP; use a reverse proxy
  for HTTPS in production)
- **Authentication**: PAM-based by default (Linux system accounts). Disable with
  `--web-no-auth` in development environments only.

## 3. Configuration

### CLI flags

| Flag | Default | When to change |
|------|---------|----------------|
| `--web-prefix PREFIX` | (disabled) | Set to `/` to enable Web UI at the root |
| `--web-no-auth` | off | **Development only**: disable PAM login |
| `--web-pam-service SERVICE` | `login` | PAM service to authenticate against |
| `--rate-limit N` | 0 | API rate limit per IP per minute |
| `--expiry-warn-days N` | 30 | Days before cert expiry to show in Web UI |

### API key authentication

REST API endpoints under `/api/` accept either:
1. **PAM session cookie** (after browser login)
2. **X-API-Key header** — key defined in `pypki.auth.json` (manage via Web UI → Config)

Generate an API key:
```bash
# Via Web UI: Settings → API Keys → Add Key
# Via CLI:
python3 pypki_admin.py --ca-dir /etc/pypki/ca add-api-key \
  --name "ci-pipeline" --profiles tls_server
```

## 4. Starting the service

### Bare-metal

```bash
python3 pki_server.py \
  --ca-dir /etc/pypki/ca \
  --port 8080 \
  --web-prefix / \
  --ocsp-prefix /ocsp \
  --ocsp-url http://pki.internal:8080/ocsp \
  --crl-url http://pki.internal:8080/ca/crl
```

### Systemd unit

```bash
cp docs/HOWTO/units/pypki-webui.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pypki-webui
```

### Health check

```bash
curl http://localhost:8080/health
# Expected: {"status": "ok", "ca_serial": "...", "certs_issued": N}
```

## 5. Client configuration

### Browser (Web UI)

Navigate to `http://pki.internal:8080/`. Log in with a system (PAM) account.
The main pages:
- `/certs` — list, search, revoke certificates
- `/sub-ca` — issue sub-CAs
- `/ra-queue` — review and approve/deny pending RA requests
- `/audit` — audit log viewer
- `/expiring` — certs expiring within `--expiry-warn-days`
- `/metrics-ui` — Prometheus metrics summary

### REST API

All REST endpoints accept JSON and return JSON. Authentication via X-API-Key header:

```bash
export PYPKI_URL="http://pki.internal:8080"
export PYPKI_KEY="your-api-key"

# List all certs
curl -H "X-API-Key: $PYPKI_KEY" $PYPKI_URL/api/certs

# Issue a cert (sub-CA)
curl -X POST $PYPKI_URL/api/issue-sub-ca \
  -H "X-API-Key: $PYPKI_KEY" \
  -H "Content-Type: application/json" \
  -d '{"cn": "Intermediate CA", "validity_days": 1825}'

# Revoke a cert by serial
curl -X POST $PYPKI_URL/api/revoke \
  -H "X-API-Key: $PYPKI_KEY" \
  -H "Content-Type: application/json" \
  -d '{"serial": 1234, "reason": 0}'

# Renew a cert by serial
curl -X POST $PYPKI_URL/api/renew \
  -H "X-API-Key: $PYPKI_KEY" \
  -H "Content-Type: application/json" \
  -d '{"serial": 1234}'

# Search certs
curl "$PYPKI_URL/api/certs?q=myservice" \
  -H "X-API-Key: $PYPKI_KEY"

# Audit log (last 100 entries)
curl "$PYPKI_URL/api/audit" \
  -H "X-API-Key: $PYPKI_KEY"

# Prometheus metrics
curl "$PYPKI_URL/metrics"   # no auth required
```

## 6. Verification (smoke test)

```bash
tmpdir=$(mktemp -d)
python3 pki_server.py --ca-dir "$tmpdir" --port 18085 \
  --web-prefix / --web-no-auth &
PYPKI_PID=$!
sleep 2

# Health
curl -s http://localhost:18085/health | python3 -m json.tool | grep status
# Expected: "status": "ok"

# Metrics
curl -s http://localhost:18085/metrics | grep pypki_certs_issued_total
# Expected: pypki_certs_issued_total 0 (or N)

# API: list certs (empty initially)
curl -s http://localhost:18085/api/certs | python3 -m json.tool
# Expected: [] or list of cert objects

kill $PYPKI_PID; rm -rf "$tmpdir"
echo "Web UI smoke test passed"
```

## 7. Day-2 operations

**Adding an operator**: Create a Linux system account (`useradd`, `adduser`). The
user can log in via the Web UI with their system password (PAM).

**Rotating the CA key**: See [`docs/CEREMONY.md`](../CEREMONY.md). The Web UI
displays the new CA cert automatically after rotation.

**Bulk revocation**: Web UI → *Certs* → select multiple → *Revoke*, or:
```bash
python3 pypki_admin.py --ca-dir /etc/pypki/ca revoke-batch \
  --serials 1001,1002,1003 --reason 4
```

**Audit log query**:
```bash
# Last 50 issuance events
curl -s "http://pki.internal:8080/api/audit?n=50&filter=issue" \
  -H "X-API-Key: $PYPKI_KEY" | python3 -m json.tool
```

**Prometheus metrics**:
- `pypki_certs_issued_total`
- `pypki_certs_valid`
- `pypki_certs_revoked_total`
- `pypki_certs_expiring_7d` / `_30d`
- `pypki_ca_days_remaining`

## 8. Monitoring

| Metric | Alert when |
|--------|------------|
| `pypki_ca_days_remaining` | < 30 days |
| `pypki_certs_expiring_7d` | > 0 (trigger renewal) |
| `pypki_certs_revoked_total` rate | Spike (investigate compromise) |

Grafana: `pypki-grafana-dashboard.json` panels "Cert Inventory", "CA Expiry".

## 9. Troubleshooting

**"403 Forbidden" on login**
: PAM authentication failed. Confirm the username/password matches a Linux system
account. For development, add `--web-no-auth`.

**CSRF error on form submission**
: The browser session expired. Log in again. Don't bypass CSRF tokens.

**"500 Internal Server Error" on `/api/issue-sub-ca`**
: Sub-CA issuance requires a CA key that supports `keyCertSign`. Check that the
CA was initialized with an ECDSA or RSA key (not ML-DSA for sub-CA signing).

**Web UI shows wrong cert count**
: The metrics endpoint caches for 5s. Reload the page or wait for the next scrape.

Regression tests: `TestWebUIBasic`, `TestWebUIRATAQueue`, `TestWebUISearch`
in `test_pki_server.py`.

## 10. Security considerations

- `--web-no-auth` disables authentication entirely. Never use in production.
- PAM brute-force lockout is active by default (5 failures → 15 min lockout).
  Adjust via `/etc/security/faillock.conf`.
- API keys are stored in `pypki.auth.json`. Restrict file permissions:
  `chmod 600 /etc/pypki/pypki.auth.json`.
- Session cookies are `HttpOnly` + `SameSite=Strict`. TLS via reverse proxy
  adds `Secure`. Without TLS, cookies are exposed on the network.
- The `/metrics` endpoint is unauthenticated (Prometheus convention). If cert
  inventory counts are sensitive, restrict access with a reverse proxy.

## 11. References

- `web_ui.py` — Web UI and REST API implementation
- `pki_server.py` — CertProfile catalog, Prometheus metrics
- [`docs/DEPLOYMENT/homelab-single-node.md`](../DEPLOYMENT/homelab-single-node.md)
- [`docs/THREAT_MODEL.md §3.1`](../THREAT_MODEL.md) (Web UI session security)
